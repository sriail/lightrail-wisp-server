"""
Light Rail WISP Server
======================
WISP 1.2 protocol server running on Cloudflare Workers (Python).

This module is the Cloudflare Workers entry point. It:
  * Accepts inbound WebSocket connections on /wisp/
  * Sends the initial CONTINUE packet (stream_id=0) advertising buffer size
  * Uses the Cloudflare Workers Python WebSocket receive() loop pattern
    (NOT addEventListener — async functions don't work with addEventListener)
  * Parses inbound WISP packets (little-endian) and routes by type
      CONNECT  -> tcp.py (non 80/443) or http.py (80/443)
      DATA     -> queued in per-stream FIFO buffer, drained to outbound conn
      CONTINUE -> updates client flow-control state, flushes outbound queue
      CLOSE    -> tears down the stream and its outbound connection
  * Encodes all outbound packets into WISP 1.2 format before sending
  * Sends CONTINUE packets for flow control when inbound buffer < 50% full
  * Per-stream FIFO queue (64 packets) for inbound DATA (client -> server)
  * Per-stream FIFO queue (128 packets) for outbound DATA (server -> client)
  * Cleans up all streams on WebSocket close/error
  * Uses ctx.waitUntil() to keep background tasks alive after fetch() returns

API surface (Cloudflare Workers Python ONLY):
    from workers import WorkerEntrypoint, Response, WebSocketPair, fetch
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any, Dict, Optional

from workers import WorkerEntrypoint, Response, WebSocketPair, fetch

from tcp import TcpManager
from http import HttpManager


# ---------------------------------------------------------------------------
# WISP 1.2 protocol constants
# ---------------------------------------------------------------------------

# Packet types
PACKET_CONNECT = 0x01
PACKET_DATA = 0x02
PACKET_CONTINUE = 0x03
PACKET_CLOSE = 0x04

# Close reason codes (client/server agnostic)
CLOSE_UNSPECIFIED = 0x01
CLOSE_VOLUNTARY = 0x02
CLOSE_NETWORK_ERROR = 0x03

# Server-only close reasons
CLOSE_INVALID_PAYLOAD = 0x41
CLOSE_HOST_UNREACHABLE = 0x42
CLOSE_TIMEOUT = 0x43
CLOSE_REFUSED = 0x44
CLOSE_TCP_TIMEOUT = 0x47
CLOSE_BLOCKED = 0x48
CLOSE_THROTTLED = 0x49

# Client-only close reasons
CLOSE_CLIENT_ERROR = 0x81

# Flow-control buffer sizes (in packets)
BUFFER_SIZE = 64  # Per-stream FIFO buffer (recommended by spec)
CONTINUE_THRESHOLD = 32  # 50% of BUFFER_SIZE -> send another CONTINUE
OUTBOUND_QUEUE_SIZE = 256  # Outbound queue (4x buffer for headroom)


# ---------------------------------------------------------------------------
# WISP packet codec  (everything is little-endian)
# ---------------------------------------------------------------------------

# Header layout:  uint8  type  |  uint32  stream_id  |  payload...
_HEADER = struct.Struct("<BI")  # 1 + 4 = 5 bytes


def encode_packet(packet_type: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Encode a WISP packet (type + stream_id + payload)."""
    return _HEADER.pack(packet_type, stream_id) + payload


def encode_data(stream_id: int, data: bytes) -> bytes:
    return encode_packet(PACKET_DATA, stream_id, data)


def encode_continue(stream_id: int, buffer_remaining: int) -> bytes:
    return encode_packet(PACKET_CONTINUE, stream_id, struct.pack("<I", buffer_remaining))


def encode_close(stream_id: int, reason: int) -> bytes:
    return encode_packet(PACKET_CLOSE, stream_id, struct.pack("<B", reason))


def parse_packet(raw: bytes) -> Optional[Dict[str, Any]]:
    """Parse a raw WISP packet into {type, stream_id, payload}."""
    if raw is None or len(raw) < _HEADER.size:
        return None
    packet_type, stream_id = _HEADER.unpack(raw[: _HEADER.size])
    return {
        "type": packet_type,
        "stream_id": stream_id,
        "payload": raw[_HEADER.size:],
    }


def parse_connect_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse a CONNECT payload:  uint16  port  |  char[]  hostname."""
    if payload is None or len(payload) < 2:
        return None
    port = struct.unpack("<H", payload[:2])[0]
    try:
        hostname = payload[2:].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if not hostname:
        return None
    return {"port": port, "hostname": hostname}


# ---------------------------------------------------------------------------
# Per-stream state with FIFO queue system
# ---------------------------------------------------------------------------


class WispStream:
    """Represents one multiplexed WISP stream and its outbound connection.

    Implements the per-stream FIFO buffer system required by the spec:
      * Inbound queue (client -> server): 64-packet FIFO for DATA packets
        from the client. A background drain task forwards queued data to
        the outbound connection. When the queue drops below 50% capacity,
        a CONTINUE packet is sent to the client advertising more space.

      * Outbound queue (server -> client): 256-packet FIFO for DATA
        packets to the client. When the client's advertised buffer is
        exhausted (client_buffer_remaining == 0), data is queued here.
        When the client sends CONTINUE, the queue is flushed up to the
        new buffer_remaining limit.

    Flow control direction:
      * Server -> Client CONTINUE: advertises server's inbound buffer.
        Client decrements per DATA sent, waits at 0.
      * Client -> Server CONTINUE: advertises client's outbound buffer.
        Server decrements per DATA sent, queues at 0.

    The initial client_buffer_remaining is BUFFER_SIZE (64) — the WISP
    spec says "Per-stream FIFO buffer (64 packets recommended)" which
    applies to both directions. The server advertises 64 (via CONTINUE),
    and we assume the client can also buffer 64 until told otherwise via
    the client's CONTINUE.
    """

    __slots__ = (
        "stream_id",
        "websocket",
        "connection",
        "closed",
        # Inbound flow control (client -> server DATA)
        "_inbound_queue",
        "_drain_task",
        # Outbound flow control (server -> client DATA)
        "_outbound_queue",
        "client_buffer_remaining",
        # Lock for cleanup
        "_cleanup_lock",
        "_cleaned_up",
        "_continue_in_flight",
        "_initial_continue_sent",
    )

    def __init__(self, stream_id: int, websocket: Any):
        self.stream_id = stream_id
        self.websocket = websocket
        # Set by tcp.py / http.py after CONNECT succeeds
        self.connection: Optional[Any] = None
        self.closed = False

        # --- Inbound flow control (client -> server DATA) ---
        # Per-stream FIFO buffer: 64 packets max (spec requirement)
        self._inbound_queue: asyncio.Queue = asyncio.Queue(maxsize=BUFFER_SIZE)
        self._drain_task: Optional[asyncio.Task] = None

        # --- Outbound flow control (server -> client DATA) ---
        # Queue for DATA when client buffer is full
        self._outbound_queue: asyncio.Queue = asyncio.Queue(maxsize=OUTBOUND_QUEUE_SIZE)
        # How many DATA packets the *client* says it can buffer for us.
        # Initialized to BUFFER_SIZE — the WISP spec says "Per-stream FIFO
        # buffer (64 packets recommended)" which applies to both directions.
        # The server advertises 64 (via CONTINUE), and we assume the client
        # can also buffer 64 until told otherwise via the client's CONTINUE.
        # This is CRITICAL: if we start at 0, the server can NEVER send DATA
        # to the client until the client sends a CONTINUE. For HTTP responses
        # and TCP data forwarding, this would cause the server to hang.
        self.client_buffer_remaining = BUFFER_SIZE

        self._cleanup_lock = asyncio.Lock()
        # Simple flag to ensure cleanup runs exactly once
        self._cleaned_up = False
        # Track whether we've sent a CONTINUE for the current "low" state
        # to avoid spamming CONTINUE packets.
        self._continue_in_flight = False
        # Track whether the initial per-stream CONTINUE has been sent
        self._initial_continue_sent = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_drain_task(self) -> None:
        """Start the background task that drains the inbound queue."""
        if self._drain_task is None or self._drain_task.done():
            self._drain_task = asyncio.create_task(self._drain_loop())

    # ------------------------------------------------------------------
    # Inbound: client -> server DATA path
    # ------------------------------------------------------------------

    async def on_client_data(self, data: bytes) -> None:
        """Called when a DATA packet arrives from the client.

        Adds the data to the per-stream FIFO queue. A background task
        drains the queue and forwards data to the outbound connection.
        If the queue is full (client violated flow control), the stream
        is closed with a network error.
        """
        if self.closed:
            return
        try:
            self._inbound_queue.put_nowait(data)
            # Reset the CONTINUE flag - queue is no longer low
            self._continue_in_flight = False
        except asyncio.QueueFull:
            # Client sent more DATA than advertised - flow control violation.
            # Close the stream to protect the server.
            await self.send_close(CLOSE_NETWORK_ERROR)

    async def _drain_loop(self) -> None:
        """Background task: drain the inbound queue and forward to outbound.

        After forwarding each DATA packet, checks if the inbound queue
        has dropped below 50% capacity. If so, sends a CONTINUE packet
        to the client advertising the remaining buffer space.
        """
        try:
            while not self.closed:
                # Wait for the next DATA packet from the queue
                data = await self._inbound_queue.get()
                if data is None:
                    # Sentinel - drain loop is being asked to stop
                    break

                if self.connection is not None:
                    try:
                        await self.connection.write(data)
                    except Exception:
                        if not self.closed:
                            await self.send_close(CLOSE_NETWORK_ERROR)
                        return

                # Flow control: when buffer < 50% remaining (i.e., queue
                # has more than 50% free space), send a CONTINUE to the
                # client advertising the available space.
                queue_size = self._inbound_queue.qsize()
                remaining = BUFFER_SIZE - queue_size
                if remaining >= CONTINUE_THRESHOLD and not self._continue_in_flight:
                    await self._send_continue(remaining)
                    self._continue_in_flight = True
        except asyncio.CancelledError:
            pass
        except Exception:
            # Unexpected error - close the stream
            try:
                if not self.closed:
                    await self.send_close(CLOSE_NETWORK_ERROR)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Outbound: server -> client DATA path
    # ------------------------------------------------------------------

    async def on_outbound_data(self, data: bytes) -> None:
        """Called by tcp.py / http.py when the upstream produces data.

        If the client has advertised buffer space (client_buffer_remaining
        > 0), sends the DATA packet immediately and decrements the counter.
        Otherwise, queues the data in the outbound FIFO for later flushing
        when the client sends CONTINUE.
        """
        if self.closed:
            return

        if self.client_buffer_remaining > 0:
            await self._send_data(data)
            if not self.closed:
                self.client_buffer_remaining -= 1
        else:
            # Client buffer is full - queue the data
            try:
                self._outbound_queue.put_nowait(data)
            except asyncio.QueueFull:
                # Outbound queue is also full. We do NOT force-send
                # (that would violate flow control). Drop the data
                # to protect the client's buffer. This is the correct
                # WISP behavior — the upstream will retransmit if needed
                # (TCP) or the data is lost (UDP-like).
                pass

    async def on_outbound_close(self, reason: int) -> None:
        """Called by tcp.py / http.py when the upstream connection dies."""
        await self.send_close(reason)

    # ------------------------------------------------------------------
    # CONTINUE from client: flush outbound queue
    # ------------------------------------------------------------------

    async def on_client_continue(self, buffer_remaining: int) -> None:
        """Called when the client sends a CONTINUE packet.

        Updates the client's advertised buffer space and flushes any
        queued outbound DATA packets up to the new limit.
        """
        if self.closed:
            return

        self.client_buffer_remaining = buffer_remaining

        # Flush the outbound queue
        while (not self.closed
               and self.client_buffer_remaining > 0
               and not self._outbound_queue.empty()):
            try:
                data = self._outbound_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            await self._send_data(data)
            if not self.closed:
                self.client_buffer_remaining -= 1

    # ------------------------------------------------------------------
    # CLOSE from client
    # ------------------------------------------------------------------

    async def on_client_close(self, reason: int) -> None:
        """Called when the client sends a CLOSE for this stream."""
        await self._cleanup()

    # ------------------------------------------------------------------
    # Outbound packet sending (WISP encoded)
    # ------------------------------------------------------------------

    async def _send_data(self, data: bytes) -> None:
        """Send a WISP DATA packet to the client."""
        if self.closed:
            return
        try:
            self.websocket.send(encode_data(self.stream_id, data))
        except Exception:
            await self._cleanup()

    async def _send_continue(self, buffer_remaining: int) -> None:
        """Send a WISP CONTINUE packet to the client.

        Payload: uint32_t buffer_remaining (packets the server can buffer).
        The client should set its counter to this value and decrement
        for each DATA sent.
        """
        if self.closed:
            return
        try:
            self.websocket.send(encode_continue(self.stream_id, buffer_remaining))
        except Exception:
            await self._cleanup()

    async def send_close(self, reason: int) -> None:
        """Send CLOSE and tear down the stream. Idempotent."""
        if self.closed:
            return
        self.closed = True
        try:
            self.websocket.send(encode_close(self.stream_id, reason))
        except Exception:
            pass
        await self._cleanup()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def _cleanup(self) -> None:
        """Idempotent cleanup of the stream and its outbound connection.

        Uses a simple _cleaned_up flag to ensure cleanup runs exactly once.
        Individual operations (cancel, close, clear) are idempotent, so
        even if called concurrently, they won't cause issues.
        """
        async with self._cleanup_lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True
            self.closed = True

        # Cancel the drain task
        if self._drain_task is not None and not self._drain_task.done():
            self._drain_task.cancel()
            try:
                # Push sentinel to unblock the queue.get()
                self._inbound_queue.put_nowait(None)
            except Exception:
                pass

        # Close the outbound connection
        conn = self.connection
        self.connection = None
        if conn is not None:
            try:
                await conn.close()
            except Exception:
                pass

        # Clear queues
        try:
            while not self._inbound_queue.empty():
                self._inbound_queue.get_nowait()
        except Exception:
            pass
        try:
            while not self._outbound_queue.empty():
                self._outbound_queue.get_nowait()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Bytes coercion helper - robust for Pyodide JS proxies
# ---------------------------------------------------------------------------


def _coerce_bytes(value: Any) -> bytes:
    """Best-effort coercion of inbound WS message payloads to bytes.

    Cloudflare Workers Python typically hands us a `bytes`/`bytearray`
    object for binary frames. In some edge cases it may surface a JS
    proxy (Uint8Array or ArrayBuffer). Handle all cases robustly.

    Epoxy compatibility: Epoxy's onmessage handler passes `A.buffer`
    (the underlying ArrayBuffer) to its WASM callback. When the server
    receives data, the Workers Python runtime may pass it as:
      - bytes/bytearray (native Python)
      - memoryview
      - str (text frame)
      - JS Uint8Array proxy (Pyodide JsProxy)
      - JS ArrayBuffer proxy (Pyodide JsProxy)
    """
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    # JS proxy / array-like fallback
    try:
        return bytes(value)
    except Exception:
        pass
    # Pyodide JsProxy: try to_py() which converts Uint8Array/ArrayBuffer
    # to the corresponding Python type (bytes for Uint8Array, memoryview
    # for ArrayBuffer).
    try:
        converted = value.to_py()
        if isinstance(converted, (bytes, bytearray)):
            return bytes(converted)
        if isinstance(converted, memoryview):
            return bytes(converted)
        if isinstance(converted, str):
            return converted.encode("utf-8")
        # If to_py() returned something else (e.g., a list for ArrayBuffer),
        # try bytes() on it.
        return bytes(converted)
    except Exception:
        pass
    # For ArrayBuffer JsProxy: try accessing byteLength and slice
    try:
        if hasattr(value, "byteLength") and hasattr(value, "slice"):
            # This looks like an ArrayBuffer
            length = int(value.byteLength)
            # Copy byte by byte using a Uint8Array view
            return bytes(int(value[i]) for i in range(length))
    except Exception:
        pass
    # Last resort: iterate as integers
    try:
        return bytes(int(x) for x in value)
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Event data extraction - handles multiple message event shapes
# ---------------------------------------------------------------------------


def _extract_message_data(message_or_event: Any) -> bytes:
    """Extract bytes from a WebSocket message or message event.

    Cloudflare Workers Python may pass:
      - The raw message data directly (bytes/str)
      - A MessageEvent with .data attribute
      - A dict with 'data' key
      - A JS proxy with .data property

    This function handles all cases robustly.
    """
    # Fast path: already bytes/bytearray
    if isinstance(message_or_event, (bytes, bytearray, memoryview)):
        return bytes(message_or_event)

    # Fast path: string (text frame)
    if isinstance(message_or_event, str):
        return message_or_event.encode("utf-8")

    # Try .data attribute (MessageEvent pattern)
    data = getattr(message_or_event, "data", None)
    if data is not None:
        return _coerce_bytes(data)

    # Try dict-style access
    if isinstance(message_or_event, dict):
        data = message_or_event.get("data")
        if data is not None:
            return _coerce_bytes(data)

    # Try JS proxy .data access (Pyodide)
    try:
        data = message_or_event.data
        if data is not None:
            return _coerce_bytes(data)
    except Exception:
        pass

    # Treat the whole thing as the data
    return _coerce_bytes(message_or_event)


# ---------------------------------------------------------------------------
# WebSocket / Worker entry point
# ---------------------------------------------------------------------------


class WispServer(WorkerEntrypoint):
    """Cloudflare Workers entry point. Handles /  and /wisp/ routes."""

    # -------------------------------------------------------------------
    # HTTP / WS routing
    # -------------------------------------------------------------------

    async def fetch(self, request: Any, env: Any = None, ctx: Any = None) -> Response:
        # Store ctx for waitUntil() calls
        self._ctx = ctx
        self._env = env

        # Cheap path extraction without pulling in urllib.
        url = request.url
        if "://" in url:
            rest = url.split("://", 1)[1]
        else:
            rest = url
        if "/" in rest:
            path_and_query = rest.split("/", 1)[1]
        else:
            path_and_query = ""
        path = path_and_query.split("?", 1)[0]
        if not path.startswith("/"):
            path = "/" + path

        # Health check
        if path == "/" or path == "":
            return Response(
                "Light Rail WISP server running",
                status=200,
                headers={"Content-Type": "text/plain"},
            )

        # WebSocket endpoint - accept both /wisp and /wisp/
        if path in ("/wisp", "/wisp/"):
            upgrade_header = request.headers.get("Upgrade")
            if upgrade_header is None or upgrade_header.lower() != "websocket":
                return Response("Expected WebSocket upgrade", status=426)
            return await self._handle_websocket(request, ctx)

        return Response("Not Found", status=404)

    # -------------------------------------------------------------------
    # WebSocket handler - uses receive() loop pattern
    # -------------------------------------------------------------------

    async def _handle_websocket(self, request: Any, ctx: Any) -> Response:
        pair = WebSocketPair()
        client_ws = pair[0]  # returned to the platform -> forwarded to client
        server_ws = pair[1]  # we drive this side

        # Get the subprotocol from the client's request (Epoxy sends a UUID).
        # The Sec-WebSocket-Protocol header may contain a comma-separated
        # list of subprotocols. We select the first one for accept().
        subprotocol = None
        try:
            raw_subprotocol = request.headers.get("Sec-WebSocket-Protocol")
            if raw_subprotocol:
                # Parse comma-separated list and select the first subprotocol
                # (stripping whitespace). Epoxy sends a single UUID, but other
                # clients may send multiple.
                subprotocol = raw_subprotocol.split(",")[0].strip()
        except Exception:
            pass

        # Accept the WebSocket. If the client requested a subprotocol,
        # echo it back so Epoxy and other clients that validate it work.
        try:
            if subprotocol:
                server_ws.accept(subprotocol)
            else:
                server_ws.accept()
        except Exception:
            server_ws.accept()

        # Per-connection state
        streams: Dict[int, WispStream] = {}
        streams_lock = asyncio.Lock()
        tcp_manager = TcpManager()
        http_manager = HttpManager()
        connection_alive = True

        # Send the initial CONTINUE packet (stream_id=0, buffer_size).
        # This advertises protocol version 1.2 via stream_id 0 and tells
        # the client how many packets we can buffer per stream.
        try:
            server_ws.send(encode_continue(0, BUFFER_SIZE))
        except Exception:
            # If we cannot even send the initial packet, abort the socket.
            try:
                server_ws.close()
            except Exception:
                pass
            # Return the client WS anyway - the platform will handle it.
            return Response(None, status=101, web_socket=client_ws)

        # ----------------------------------------------------------------
        # Main WebSocket receive loop.
        #
        # CRITICAL: We use server_ws.receive() in a loop, NOT
        # addEventListener. In Cloudflare Workers Python, addEventListener
        # does NOT properly await async callbacks — the coroutine is
        # treated as a resolved Promise and the body never executes.
        #
        # The receive() loop runs as a background task kept alive by
        # ctx.waitUntil(). This is the official pattern for long-lived
        # WebSocket handlers in Python Workers.
        # ----------------------------------------------------------------

        async def _ws_loop() -> None:
            nonlocal connection_alive
            try:
                while connection_alive:
                    # receive() blocks until the next message or close.
                    # Returns a dict-like: {"type": "message"/"close"/"error", ...}
                    msg = await server_ws.receive()

                    if msg is None:
                        break

                    # Determine the event type
                    msg_type = None
                    if isinstance(msg, dict):
                        msg_type = msg.get("type")
                    else:
                        msg_type = getattr(msg, "type", None)

                    if msg_type == "close" or msg_type == "error":
                        connection_alive = False
                        break

                    if msg_type != "message":
                        continue

                    # Extract the data from the message
                    raw = _extract_message_data(msg)
                    if not raw:
                        continue

                    packet = parse_packet(raw)
                    if packet is None:
                        continue  # silently drop truncated packets

                    ptype = packet["type"]
                    stream_id = packet["stream_id"]
                    payload = packet["payload"]

                    try:
                        if ptype == PACKET_CONNECT:
                            await self._handle_connect(
                                stream_id,
                                payload,
                                streams,
                                streams_lock,
                                tcp_manager,
                                http_manager,
                                server_ws,
                            )
                        elif ptype == PACKET_DATA:
                            await self._handle_data(stream_id, payload, streams, streams_lock)
                        elif ptype == PACKET_CONTINUE:
                            await self._handle_continue(stream_id, payload, streams, streams_lock)
                        elif ptype == PACKET_CLOSE:
                            await self._handle_close(stream_id, payload, streams, streams_lock)
                        # Unknown packet types are silently ignored per WISP 1.2.
                    except Exception:
                        # Never let one bad packet crash the WS task.
                        pass

            except Exception:
                pass
            finally:
                # Cleanup all streams on WS close
                connection_alive = False
                async with streams_lock:
                    pending = list(streams.values())
                    streams.clear()
                for stream in pending:
                    try:
                        await stream._cleanup()
                    except Exception:
                        pass
                # Close the WebSocket cleanly so the client knows
                # the connection is done.
                try:
                    server_ws.close(1000, "Server closing")
                except Exception:
                    pass

        # Launch the WebSocket loop as a background task.
        # ctx.waitUntil() keeps it alive after fetch() returns.
        # We wrap the coroutine in asyncio.ensure_future() to ensure
        # it's a proper Task before passing to ctx.waitUntil().
        # Some Workers Python runtime versions may not auto-convert
        # a bare coroutine to a JS Promise for ctx.waitUntil().
        if ctx is not None:
            try:
                ws_task = asyncio.ensure_future(_ws_loop())
                ctx.waitUntil(ws_task)
            except Exception:
                # Fallback: if ctx.waitUntil fails, create the task anyway.
                # It may be GC'd, but it's the best we can do.
                asyncio.create_task(_ws_loop())
        else:
            # Fallback: if no ctx, create the task anyway (may be GC'd)
            asyncio.create_task(_ws_loop())

        # Return the *client* side of the pair - the platform keeps the
        # WS open after the fetch handler returns.
        # NOTE: Cloudflare Workers Python uses `web_socket` (snake_case).
        return Response(None, status=101, web_socket=client_ws)

    # -------------------------------------------------------------------
    # Packet handlers
    # -------------------------------------------------------------------

    async def _handle_connect(
        self,
        stream_id: int,
        payload: bytes,
        streams: Dict[int, WispStream],
        lock: asyncio.Lock,
        tcp_manager: TcpManager,
        http_manager: HttpManager,
        websocket: Any,
    ) -> None:
        # Validate the CONNECT payload
        info = parse_connect_payload(payload)
        if info is None:
            try:
                websocket.send(encode_close(stream_id, CLOSE_INVALID_PAYLOAD))
            except Exception:
                pass
            return

        port = info["port"]
        hostname = info["hostname"]
        if port == 0 or port > 65535 or not hostname:
            try:
                websocket.send(encode_close(stream_id, CLOSE_INVALID_PAYLOAD))
            except Exception:
                pass
            return

        # If a stream with this ID already exists, retire it first.
        async with lock:
            old = streams.pop(stream_id, None)
        if old is not None:
            try:
                await old._cleanup()
            except Exception:
                pass

        stream = WispStream(stream_id, websocket)

        # Route by port - 80/443 to fetch(), everything else to connect()
        if port in (80, 443):
            if http_manager.is_full():
                try:
                    websocket.send(encode_close(stream_id, CLOSE_THROTTLED))
                except Exception:
                    pass
                return
            ok = await http_manager.create_connection(hostname, port, stream)
        else:
            if tcp_manager.is_full():
                try:
                    websocket.send(encode_close(stream_id, CLOSE_THROTTLED))
                except Exception:
                    pass
                return
            ok = await tcp_manager.create_connection(hostname, port, stream)

        if not ok:
            # The manager already sent the appropriate CLOSE packet.
            return

        async with lock:
            streams[stream_id] = stream

        # Advertise the per-stream buffer to the client. Per WISP 1.2 the
        # initial CONTINUE for a stream comes after the server accepts the
        # CONNECT (i.e. after the outbound connection is established).
        # This CONTINUE tells the client how many DATA packets the server
        # can buffer for this stream.
        try:
            websocket.send(encode_continue(stream_id, BUFFER_SIZE))
        except Exception:
            await self._destroy_stream(stream_id, streams, lock, CLOSE_NETWORK_ERROR)
            return

        # Mark that the initial CONTINUE has been sent, then start the
        # drain task. We start the drain task AFTER the initial CONTINUE
        # to avoid a race where the drain loop sends its own CONTINUE
        # before the initial one, confusing the client's counter.
        stream._initial_continue_sent = True
        stream.start_drain_task()

    async def _handle_data(
        self,
        stream_id: int,
        payload: bytes,
        streams: Dict[int, WispStream],
        lock: asyncio.Lock,
    ) -> None:
        async with lock:
            stream = streams.get(stream_id)
        if stream is None:
            return
        await stream.on_client_data(payload)

    async def _handle_continue(
        self,
        stream_id: int,
        payload: bytes,
        streams: Dict[int, WispStream],
        lock: asyncio.Lock,
    ) -> None:
        if len(payload) < 4:
            return
        buffer_remaining = struct.unpack("<I", payload[:4])[0]
        async with lock:
            stream = streams.get(stream_id)
        if stream is None:
            return
        # Update client flow control state and flush outbound queue.
        await stream.on_client_continue(buffer_remaining)

    async def _handle_close(
        self,
        stream_id: int,
        payload: bytes,
        streams: Dict[int, WispStream],
        lock: asyncio.Lock,
    ) -> None:
        reason = payload[0] if payload else CLOSE_UNSPECIFIED
        async with lock:
            stream = streams.pop(stream_id, None)
        if stream is None:
            return
        # Reason is informational - we just tear down.
        await stream.on_client_close(reason)

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    async def _destroy_stream(
        self,
        stream_id: int,
        streams: Dict[int, WispStream],
        lock: asyncio.Lock,
        reason: int,
    ) -> None:
        async with lock:
            stream = streams.pop(stream_id, None)
        if stream is None:
            return
        try:
            await stream.send_close(reason)
        except Exception:
            pass

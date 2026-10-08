"""
WISP 1.2 Server - Cloudflare Workers Python Implementation
Light Rail WISP Server - Stable Multi-Connection Architecture

Entry point for Cloudflare Python Workers. Accepts WebSocket upgrades on /wisp/,
performs the initial CONTINUE handshake on stream ID 0, and routes CONNECT/DATA/
CONTINUE/CLOSE packets between the WebSocket client and the tcp.py / http.py
outbound handlers.

All packet encoding uses little-endian byte order per the WISP 1.2 spec.
"""

import asyncio
import struct

# Cloudflare Workers Python runtime imports.
from workers import Response
from js import WebSocketPair, URL, Uint8Array

from js import connect  # noqa: F401  (re-exported below)
from js import fetch       # noqa: F401  (re-exported below)

# Outbound handlers (loaded lazily to keep startup cheap).
import tcp as tcp_handler
import http as http_handler


# ---------------------------------------------------------------------------
# WISP 1.2 protocol constants
# ---------------------------------------------------------------------------

PACKET_CONNECT = 0x01   # Client -> Server : request new stream
PACKET_DATA = 0x02      # Bidirectional     : raw payload
PACKET_CONTINUE = 0x03   # Bidirectional     : flow-control window update
PACKET_CLOSE = 0x04     # Bidirectional     : close stream

# Close reason codes (shared - both client and server may send these).
REASON_UNSPECIFIED = 0x01
REASON_VOLUNTARY = 0x02
REASON_NETWORK_ERROR = 0x03

# Server-only close reason codes.
REASON_INVALID_INFO = 0x41        # Bad CONNECT payload (hostname/port).
REASON_HOST_UNREACHABLE = 0x42   # DNS failure / host unreachable.
REASON_CONNECTION_TIMEOUT = 0x43
REASON_CONNECTION_REFUSED = 0x44
REASON_TCP_TIMEOUT = 0x47
REASON_BLOCKED = 0x48
REASON_THROTTLED = 0x49           # Pool full.

# Client-only close reason code (server may echo back).
REASON_CLIENT_ERROR = 0x81


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Initial flow-control window advertised to the client per stream.
INITIAL_BUFFER_SIZE = 64

# Maximum concurrent streams per WebSocket connection.
# ~1.2 KB per stream * 100 = ~120 KB, well within the 128 MB worker memory.
MAX_STREAMS = 100

# Per-pool size. 6 total outbound connections on Cloudflare Workers.
TCP_POOL_SIZE = 3
HTTP_POOL_SIZE = 3

# Minimum free buffer slots before we send another CONTINUE upstream.
CONTINUE_THRESHOLD = INITIAL_BUFFER_SIZE // 2   # 32

# Header layout: 1 byte type + 4 byte stream id (LE).
WISP_HEADER = struct.Struct("<BI")
# CONTINUE payload: 4 byte buffer_remaining (LE).
WISP_CONTINUE_PAYLOAD = struct.Struct("<I")
# CLOSE payload: 1 byte reason_code.
WISP_CLOSE_PAYLOAD = struct.Struct("<B")
# CONNECT payload prefix: 2 byte port (LE).
WISP_CONNECT_PORT = struct.Struct("<H")


# ---------------------------------------------------------------------------
# Packet encoding helpers (server -> client direction)
# ---------------------------------------------------------------------------

def encode_data(stream_id: int, payload: bytes) -> bytes:
    """Build a WISP DATA packet (server -> client)."""
    return WISP_HEADER.pack(PACKET_DATA, stream_id) + payload


def encode_continue(stream_id: int, buffer_remaining: int) -> bytes:
    """Build a WISP CONTINUE packet (flow-control window update)."""
    return WISP_HEADER.pack(PACKET_CONTINUE, stream_id) \
        + WISP_CONTINUE_PAYLOAD.pack(buffer_remaining)


def encode_close(stream_id: int, reason_code: int) -> bytes:
    """Build a WISP CLOSE packet."""
    return WISP_HEADER.pack(PACKET_CLOSE, stream_id) \
        + WISP_CLOSE_PAYLOAD.pack(reason_code)


# ---------------------------------------------------------------------------
# Packet decoding helpers (client -> server direction)
# ---------------------------------------------------------------------------

def parse_packet(data: bytes):
    """Split a raw WISP packet into (packet_type, stream_id, payload)."""
    if len(data) < WISP_HEADER.size:
        raise ValueError("packet shorter than WISP header")
    packet_type, stream_id = WISP_HEADER.unpack(data[:WISP_HEADER.size])
    return packet_type, stream_id, data[WISP_HEADER.size:]


def parse_connect_payload(payload: bytes):
    """Parse a CONNECT payload (uint16 port + UTF-8 hostname)."""
    if len(payload) < WISP_CONNECT_PORT.size:
        raise ValueError("CONNECT payload too short")
    port = WISP_CONNECT_PORT.unpack(payload[:WISP_CONNECT_PORT.size])[0]
    hostname = payload[WISP_CONNECT_PORT.size:].decode("utf-8", errors="replace")
    return port, hostname


def parse_continue_payload(payload: bytes) -> int:
    """Parse a CONTINUE payload (uint32 buffer_remaining)."""
    if len(payload) < WISP_CONTINUE_PAYLOAD.size:
        return 0
    return WISP_CONTINUE_PAYLOAD.unpack(payload[:WISP_CONTINUE_PAYLOAD.size])[0]


def parse_close_payload(payload: bytes) -> int:
    """Parse a CLOSE payload (uint8 reason_code)."""
    if len(payload) < WISP_CLOSE_PAYLOAD.size:
        return REASON_UNSPECIFIED
    return WISP_CLOSE_PAYLOAD.unpack(payload[:WISP_CLOSE_PAYLOAD.size])[0]


# ---------------------------------------------------------------------------
# JS <-> Python byte conversion helpers
# ---------------------------------------------------------------------------

def js_to_bytes(js_data) -> bytes:
    """Best-effort conversion of any JS ArrayBuffer / typed array / string
    into Python bytes. Used for WebSocket message events and TCP reads."""
    # Already Python bytes?
    if isinstance(js_data, (bytes, bytearray)):
        return bytes(js_data)

    # Pyodide typed arrays / buffers expose `to_py()`.
    to_py = getattr(js_data, "to_py", None)
    if callable(to_py):
        try:
            converted = to_py()
            if isinstance(converted, (bytes, bytearray, list)):
                if isinstance(converted, list):
                    return bytes(converted)
                return bytes(converted)
        except Exception:
            pass

    # Fall back to interpreting as an iterable of byte values.
    try:
        return bytes(int(b) for b in js_data)
    except Exception:
        pass

    # Last resort - try to read via Uint8Array view.
    try:
        view = Uint8Array.new(js_data)
        return bytes(view.to_py())
    except Exception:
        return b""


def bytes_to_js_uint8(data: bytes):
    """Convert Python bytes into a JS Uint8Array suitable for writer.write()."""
    if not data:
        return Uint8Array.new(0)
    arr = Uint8Array.new(len(data))
    # `assign` accepts an iterable of integers in Pyodide.
    try:
        arr.assign(data)
    except Exception:
        # Fallback: copy element-by-element.
        for i, b in enumerate(data):
            arr[i] = b
    return arr


# ---------------------------------------------------------------------------
# Stream model
# ---------------------------------------------------------------------------

class WispStream:
    """Represents a single WISP stream and its associated outbound connection.

    The stream owns:
      * a reference to the parent server (for sending packets to the client)
      * an outbound connection (tcp.TCPConnection or http.HTTPConnection)
      * an outbound flow-control window (how many DATA packets the client
        has authorised us to send before we must wait for another CONTINUE)
      * an inbound buffer of DATA packets awaiting forwarding
    """

    def __init__(self, stream_id: int, server: "WispServer"):
        self.stream_id = stream_id
        self.server = server
        self.outbound = None  # set by tcp.py / http.py establish()

        # Inbound: data received from the client awaiting forwarding.
        self.inbound_queue: "asyncio.Queue[bytes]" = asyncio.Queue(
            maxsize=INITIAL_BUFFER_SIZE
        )
        # Free slots the client thinks it still has on our inbound buffer.
        self.inbound_window = INITIAL_BUFFER_SIZE

        # Outbound: how many DATA packets the client has authorised.
        self.outbound_window = INITIAL_BUFFER_SIZE
        self.outbound_backlog: "asyncio.Queue[bytes]" = asyncio.Queue()

        self.closed = False
        self.send_lock = asyncio.Lock()

    # -- sending packets to the client -------------------------------

    async def send_data(self, data: bytes) -> None:
        """Send a DATA packet to the client. Respects outbound flow control."""
        if self.closed or not data:
            return

        if self.outbound_window == 0:
            # Hold the packet until the client authorises more.
            await self.outbound_backlog.put(data)
            return

        async with self.send_lock:
            if self.closed:
                return
            await self.server.send_to_client(encode_data(self.stream_id, data))
            self.outbound_window -= 1

    async def send_continue(self, buffer_remaining: int) -> None:
        """Send a CONTINUE packet, telling the client how much buffer we have."""
        if self.closed:
            return
        async with self.send_lock:
            if self.closed:
                return
            await self.server.send_to_client(
                encode_continue(self.stream_id, buffer_remaining)
            )

    async def send_close(self, reason_code: int) -> None:
        """Send a CLOSE packet and tear the stream down."""
        if self.closed:
            return
        self.closed = True
        async with self.send_lock:
            try:
                await self.server.send_to_client(
                    encode_close(self.stream_id, reason_code)
                )
            except Exception:
                pass
        await self._cleanup_outbound()

    # -- handling inbound packets from the client --------------------

    async def handle_data(self, data: bytes) -> None:
        """Client sent us DATA - forward it to the outbound connection."""
        if self.closed or self.outbound is None:
            return

        # Track the inbound window so we know when to top it up.
        if self.inbound_window > 0:
            self.inbound_window -= 1

        try:
            await self.outbound.write(data)
        except Exception:
            await self.send_close(REASON_NETWORK_ERROR)
            return

        # If our advertised buffer is more than half empty, replenish it.
        if self.inbound_window <= CONTINUE_THRESHOLD:
            refill = INITIAL_BUFFER_SIZE - self.inbound_window
            self.inbound_window = INITIAL_BUFFER_SIZE
            await self.send_continue(self.inbound_window)
            # `refill` is implicitly communicated via the new full window.

    async def handle_continue(self, buffer_remaining: int) -> None:
        """Client authorised us to send `buffer_remaining` more DATA packets."""
        self.outbound_window += buffer_remaining

        # Flush anything that was held in the backlog.
        while self.outbound_window > 0 and not self.outbound_backlog.empty() \
                and not self.closed:
            data = await self.outbound_backlog.get()
            async with self.send_lock:
                if self.closed:
                    return
                await self.server.send_to_client(
                    encode_data(self.stream_id, data)
                )
                self.outbound_window -= 1

    async def handle_close(self, reason_code: int) -> None:
        """Client asked us to close the stream."""
        if not self.closed:
            self.closed = True
        await self._cleanup_outbound()

    # -- outbound callbacks (called by tcp.py / http.py) -------------

    async def on_outbound_data(self, data: bytes) -> None:
        """Outbound connection received bytes - forward as DATA to client."""
        await self.send_data(data)

    async def on_outbound_close(self, reason_code: int) -> None:
        """Outbound connection closed - propagate as CLOSE to client."""
        await self.send_close(reason_code)

    # -- cleanup ---------------------------------------------------

    async def _cleanup_outbound(self) -> None:
        if self.outbound is not None:
            try:
                await self.outbound.close()
            except Exception:
                pass
            self.outbound = None
        # Drain backlog so the GC can reclaim the memory.
        while not self.outbound_backlog.empty():
            try:
                self.outbound_backlog.get_nowait()
            except Exception:
                break
        self.server.remove_stream(self.stream_id)


# ---------------------------------------------------------------------------
# Server model
# ---------------------------------------------------------------------------

class WispServer:
    """Per-WebSocket WISP server. Owns the stream dictionary and serialises
    writes to the underlying WebSocket so we never interleave partial packets.
    """

    def __init__(self, websocket):
        self.ws = websocket
        self.streams: "dict[int, WispStream]" = {}
        self.send_lock = asyncio.Lock()
        self.closed = False

    async def initialize(self) -> None:
        """Accept the WebSocket and send the initial CONTINUE on stream 0."""
        self.ws.accept()
        await self.send_to_client(encode_continue(0, INITIAL_BUFFER_SIZE))

    async def send_to_client(self, data: bytes) -> None:
        """Send raw bytes to the WebSocket client (serialised)."""
        if self.closed:
            return
        async with self.send_lock:
            if self.closed:
                return
            try:
                # Cloudflare Python Workers auto-convert Python bytes to
                # an ArrayBuffer payload when passed to ws.send().
                self.ws.send(data)
            except Exception:
                # Socket is gone - mark closed and let the close handler
                # finish cleaning up streams.
                self.closed = True

    async def handle_message(self, data: bytes) -> None:
        """Dispatch a single inbound WISP packet.

        Per the spec's Server Errors table:
            Task exception → Send CLOSE 0x81 (client error)
        We therefore wrap the per-packet dispatch in a try/except: on any
        unexpected exception we send a CLOSE with reason 0x81 on the
        affected stream (if we could parse the stream id) and then tear
        that stream down.
        """
        try:
            packet_type, stream_id, payload = parse_packet(data)
        except ValueError:
            # Malformed packet - silently drop. We cannot reliably tell
            # which stream it belonged to, so we cannot send CLOSE.
            return

        try:
            if packet_type == PACKET_CONNECT:
                await self.handle_connect(stream_id, payload)
            elif packet_type == PACKET_DATA:
                await self.handle_data(stream_id, payload)
            elif packet_type == PACKET_CONTINUE:
                buffer_remaining = parse_continue_payload(payload)
                await self.handle_continue(stream_id, buffer_remaining)
            elif packet_type == PACKET_CLOSE:
                reason = parse_close_payload(payload)
                await self.handle_close(stream_id, reason)
            # Unknown packet types are silently ignored per the spec's tolerance.
        except Exception:
            # Spec: "Task exception → Send CLOSE 0x81 (client error)".
            # We know the stream_id (we parsed it above), so we can send a
            # CLOSE on that specific stream rather than killing the socket.
            await self._handle_task_exception(stream_id)

    async def _handle_task_exception(self, stream_id: int) -> None:
        """Recover from an unexpected exception while processing a packet
        for `stream_id`. Per the spec we send CLOSE with reason 0x81
        (REASON_CLIENT_ERROR) and tear the stream down.

        Note: although the close-reason table lists 0x81 as "Client Only",
        the spec's "Server Errors" table explicitly requires the *server*
        to send 0x81 on a task exception, treating the failure as a
        client-side problem.
        """
        try:
            await self.send_to_client(encode_close(stream_id, REASON_CLIENT_ERROR))
        except Exception:
            pass
        # Tear down any outbound connection associated with this stream.
        stream = self.streams.pop(stream_id, None)
        if stream is not None:
            try:
                await stream._cleanup_outbound()
            except Exception:
                pass

    async def handle_connect(self, stream_id: int, payload: bytes) -> None:
        """Route a CONNECT packet to the appropriate outbound handler."""
        # Parse the requested hostname / port.
        try:
            port, hostname = parse_connect_payload(payload)
        except ValueError:
            await self.send_to_client(encode_close(stream_id, REASON_INVALID_INFO))
            return

        # Validate fields.
        if not hostname or port == 0 or port > 65535:
            await self.send_to_client(encode_close(stream_id, REASON_INVALID_INFO))
            return

        # Enforce the per-WebSocket stream cap.
        if len(self.streams) >= MAX_STREAMS:
            await self.send_to_client(encode_close(stream_id, REASON_THROTTLED))
            return

        # Reject duplicate stream IDs.
        if stream_id in self.streams:
            await self.send_to_client(encode_close(stream_id, REASON_INVALID_INFO))
            return

        stream = WispStream(stream_id, self)
        self.streams[stream_id] = stream

        # Route based on the destination port.
        if port in (80, 443):
            await http_handler.establish(
                hostname=hostname,
                port=port,
                stream=stream,
                pool=http_pool,
                on_data=stream.on_outbound_data,
                on_close=stream.on_outbound_close,
            )
        else:
            await tcp_handler.establish(
                hostname=hostname,
                port=port,
                stream=stream,
                pool=tcp_pool,
                on_data=stream.on_outbound_data,
                on_close=stream.on_outbound_close,
            )

    async def handle_data(self, stream_id: int, payload: bytes) -> None:
        """Forward DATA from the client to the matching stream."""
        stream = self.streams.get(stream_id)
        if stream is None or stream.closed:
            return
        await stream.handle_data(payload)

    async def handle_continue(self, stream_id: int, buffer_remaining: int) -> None:
        """Apply a CONTINUE from the client to the matching stream."""
        stream = self.streams.get(stream_id)
        if stream is None or stream.closed:
            return
        await stream.handle_continue(buffer_remaining)

    async def handle_close(self, stream_id: int, reason_code: int) -> None:
        """Tear down a stream after the client requested CLOSE."""
        stream = self.streams.pop(stream_id, None)
        if stream is None:
            return
        await stream.handle_close(reason_code)

    def remove_stream(self, stream_id: int) -> None:
        """Called by WispStream during its own cleanup."""
        self.streams.pop(stream_id, None)

    async def cleanup_all(self) -> None:
        """Tear down every active stream when the WebSocket closes."""
        self.closed = True
        for stream_id in list(self.streams.keys()):
            stream = self.streams.pop(stream_id, None)
            if stream is None:
                continue
            try:
                await stream._cleanup_outbound()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Lazy singletons for the connection pools
# ---------------------------------------------------------------------------

# Initialised on first request to avoid touching module-level asyncio at
# import time (which can interact poorly with the Workers cold-start path).
tcp_pool = None
http_pool = None


def _ensure_pools():
    global tcp_pool, http_pool
    if tcp_pool is None:
        tcp_pool = tcp_handler.ConnectionPool(TCP_POOL_SIZE)
    if http_pool is None:
        http_pool = http_handler.ConnectionPool(HTTP_POOL_SIZE)


# ---------------------------------------------------------------------------
# Cloudflare Workers entry point
# ---------------------------------------------------------------------------

async def on_fetch(request, env):
    """HTTP request handler. Performs WebSocket upgrades on /wisp/ and
    returns a small JSON health-check on /."""
    _ensure_pools()

    try:
        parsed_url = URL.new(request.url)
        pathname = str(parsed_url.pathname)
    except Exception:
        pathname = "/"

    # Normalise trailing slash for /wisp (spec: always end with trailing /).
    if pathname in ("/wisp", "/wisp/"):
        return await _handle_websocket_upgrade(request)

    if pathname in ("/", ""):
        return Response.json({
            "status": "ok",
            "service": "light-rail-wisp",
            "version": "WISP 1.2",
            "runtime": "cloudflare-workers-python",
        })

    return Response("Not Found", {"status": 404})


async def _handle_websocket_upgrade(request):
    """Validate the Upgrade header and wire up the WebSocket to a WispServer."""
    upgrade_header = ""
    try:
        upgrade_header = request.headers.get("Upgrade") or ""
    except Exception:
        upgrade_header = ""

    if upgrade_header.lower() != "websocket":
        return Response(
            "Expected WebSocket upgrade",
            {"status": 426, "headers": {"Upgrade": "websocket"}},
        )

    pair = WebSocketPair()
    client = pair[0]
    server_ws = pair[1]

    server = WispServer(server_ws)

    async def on_message(event):
        try:
            data = js_to_bytes(event.data)
            if data:
                await server.handle_message(data)
        except Exception:
            # On any internal error, signal an unexpected client-side issue.
            # We don't know which stream failed, so we can only log/ignore.
            pass

    async def on_close(_event):
        await server.cleanup_all()

    async def on_error(_event):
        await server.cleanup_all()

    # Cloudflare Python Workers accepts coroutine callables for addEventListener.
    server_ws.addEventListener("message", on_message)
    server_ws.addEventListener("close", on_close)
    server_ws.addEventListener("error", on_error)

    # Accept the socket and send the initial CONTINUE on stream 0.
    await server.initialize()

    return Response(None, {"status": 101, "webSocket": client})


# ---------------------------------------------------------------------------
# Exports expected by the Workers runtime
# ---------------------------------------------------------------------------

__all__ = [
    "on_fetch",
    "WispServer",
    "WispStream",
    "encode_data",
    "encode_continue",
    "encode_close",
    "parse_packet",
    "parse_connect_payload",
    "parse_continue_payload",
    "parse_close_payload",
    "PACKET_CONNECT",
    "PACKET_DATA",
    "PACKET_CONTINUE",
    "PACKET_CLOSE",
    "REASON_UNSPECIFIED",
    "REASON_VOLUNTARY",
    "REASON_NETWORK_ERROR",
    "REASON_INVALID_INFO",
    "REASON_HOST_UNREACHABLE",
    "REASON_CONNECTION_TIMEOUT",
    "REASON_CONNECTION_REFUSED",
    "REASON_TCP_TIMEOUT",
    "REASON_BLOCKED",
    "REASON_THROTTLED",
    "REASON_CLIENT_ERROR",
    "INITIAL_BUFFER_SIZE",
    "MAX_STREAMS",
    "TCP_POOL_SIZE",
    "HTTP_POOL_SIZE",
    # Re-exported from cloudflare:sockets / cloudflare:fetch per spec checklist.
    "connect",
    "fetch",
]
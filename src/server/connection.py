"""Wisp v1 packet handling and one WebSocket connection."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

from js import WebSocketPair, console
from pyodide.ffi import create_proxy, to_js

from server.net import StreamTable
from server.rates import (
    CONNECT_TIMEOUT_SECONDS,
    MAX_CONNECTION_ATTEMPTS_PER_MINUTE,
    MAX_DATA_PAYLOAD_BYTES,
    MAX_HOSTNAME_BYTES,
    MAX_PACKET_BYTES,
    MAX_STREAMS,
)
from server.streams import TCPStream
from server.udp import is_udp_stream, note_udp_attempt


# Packet types.
CONNECT = 0x01
DATA = 0x02
CONTINUE = 0x03
CLOSE = 0x04

# Stream types.
TCP = 0x01
UDP = 0x02

# Close reasons.
CLOSE_UNSPECIFIED = 0x01
CLOSE_VOLUNTARY = 0x02
CLOSE_NETWORK_ERROR = 0x03
CLOSE_INVALID = 0x41
CLOSE_UNREACHABLE = 0x42
CLOSE_TIMEOUT = 0x43
CLOSE_REFUSED = 0x44
CLOSE_DATA_TIMEOUT = 0x47
CLOSE_BLOCKED = 0x48
CLOSE_THROTTLED = 0x49


def build_packet(packet_type: int, stream_id: int, payload: bytes = b"") -> bytes:
    """Build the fixed Wisp header plus payload."""
    if not 0 <= packet_type <= 0xFF:
        raise ValueError("packet type must fit in uint8")
    if not 0 <= stream_id <= 0xFFFFFFFF:
        raise ValueError("stream id must fit in uint32")
    if len(payload) > MAX_PACKET_BYTES - 5:
        raise ValueError("payload exceeds configured Wisp packet size")
    return bytes((packet_type,)) + stream_id.to_bytes(4, "little") + payload


def parse_packet(data: bytes) -> tuple[int, int, bytes]:
    """Parse one complete Wisp packet."""
    if len(data) < 5:
        raise ValueError("packet is shorter than the 5-byte Wisp header")
    if len(data) > MAX_PACKET_BYTES:
        raise ValueError("packet exceeds the configured packet size")
    packet_type = data[0]
    stream_id = int.from_bytes(data[1:5], "little")
    return packet_type, stream_id, data[5:]


def parse_connect_payload(payload: bytes) -> tuple[int, int, str]:
    """Parse CONNECT payload: stream type, little-endian port, UTF-8 hostname."""
    if len(payload) < 4:
        raise ValueError("CONNECT payload is too short")

    stream_type = payload[0]
    port = int.from_bytes(payload[1:3], "little")
    hostname_raw = payload[3:]

    if not hostname_raw:
        raise ValueError("CONNECT hostname is empty")
    if len(hostname_raw) > MAX_HOSTNAME_BYTES:
        raise ValueError("CONNECT hostname is too long")
    if b"\x00" in hostname_raw:
        raise ValueError("CONNECT hostname contains NUL")

    try:
        hostname = hostname_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("CONNECT hostname is not valid UTF-8") from exc

    if not 1 <= port <= 65535:
        raise ValueError("CONNECT destination port is invalid")
    if any(ch.isspace() for ch in hostname):
        raise ValueError("CONNECT hostname contains whitespace")
    if len(hostname) > MAX_HOSTNAME_BYTES:
        raise ValueError("CONNECT hostname is too long")

    return stream_type, port, hostname


def _is_disallowed_literal_host(hostname: str) -> bool:
    """Reject obvious local/private IP literals and local-only hostnames."""
    lowered = hostname.rstrip(".").lower()
    if lowered in {"localhost", "localhost.localdomain", "broadcasthost"}:
        return True
    if lowered.endswith(".localhost") or lowered.endswith(".local"):
        return True

    # IPv4 / IPv6 literals are checked locally before connect(). Cloudflare also
    # blocks private/local destinations at the runtime socket layer.
    try:
        addr = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def classify_connect_error(exc: BaseException) -> int:
    """Map common socket errors to Wisp close reasons."""
    message = str(exc).lower()
    if isinstance(exc, asyncio.TimeoutError) or "timed out" in message or "timeout" in message:
        return CLOSE_TIMEOUT
    if "refused" in message or "econnrefused" in message:
        return CLOSE_REFUSED
    if "not found" in message or "resolve" in message or "dns" in message:
        return CLOSE_UNREACHABLE
    if "disallowed" in message or "private" in message or "localhost" in message:
        return CLOSE_BLOCKED
    return CLOSE_NETWORK_ERROR


async def _message_to_bytes(data) -> bytes:
    """Convert a JS WebSocket message into Python bytes."""
    # Current Workers can be configured to deliver ArrayBuffer. Handle Blob too
    # because newer compatibility dates use the standard Blob default elsewhere.
    if hasattr(data, "arrayBuffer"):
        data = await data.arrayBuffer()

    try:
        converted = data.to_py()
    except AttributeError:
        converted = data

    try:
        return bytes(converted)
    except TypeError:
        # A few JS typed-array proxies expose an iterable rather than a Python
        # buffer. Converting through a list keeps the fallback small and robust.
        return bytes(list(converted))


class WispConnection:
    """A single accepted Wisp WebSocket and its multiplexed TCP streams."""

    def __init__(self, websocket):
        self.websocket = websocket
        self.streams = StreamTable(max_streams=MAX_STREAMS)
        self.tasks: set[asyncio.Task] = set()
        self._proxies = []
        self._closed = False
        self._connect_timestamps: list[float] = []

    def start(self) -> None:
        """Accept the WebSocket and install event listeners."""
        self.websocket.binaryType = "arraybuffer"
        self.websocket.accept({"allowHalfOpen": True})

        message_proxy = create_proxy(self._on_message)
        close_proxy = create_proxy(self._on_close)
        error_proxy = create_proxy(self._on_error)
        self._proxies.extend((message_proxy, close_proxy, error_proxy))

        self.websocket.addEventListener("message", message_proxy)
        self.websocket.addEventListener("close", close_proxy)
        self.websocket.addEventListener("error", error_proxy)

        # stream id 0 is the Wisp v1 protocol-control stream. Send the initial
        # buffer size immediately after the WebSocket is accepted.
        self.send_continue(0, self.streams.max_buffered_packets)

        console.log("[wisp] websocket accepted")

    def _track_task(self, task: asyncio.Task) -> None:
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    def _on_message(self, event) -> None:
        if self._closed:
            return
        task = asyncio.create_task(self._handle_message(event.data))
        self._track_task(task)

    def _on_close(self, _event) -> None:
        task = asyncio.create_task(self.close(send_ws_close=False))
        self._track_task(task)

    def _on_error(self, _event) -> None:
        console.log("[wisp] websocket transport error")
        task = asyncio.create_task(self.close(send_ws_close=False))
        self._track_task(task)

    async def _handle_message(self, raw_data) -> None:
        try:
            data = await _message_to_bytes(raw_data)
        except Exception as exc:
            console.log(f"[wisp] could not read websocket message: {exc}")
            await self._close_stream(0, CLOSE_UNSPECIFIED)
            return

        # Wisp packets are binary. Text frames are invalid and will normally fail
        # conversion above or arrive as UTF-8 bytes that are too short/incorrect.
        try:
            packet_type, stream_id, payload = parse_packet(data)
        except ValueError as exc:
            console.log(f"[wisp] malformed packet: {exc}")
            stream_id = int.from_bytes(data[1:5], "little") if len(data) >= 5 else 0
            await self._close_stream(stream_id, CLOSE_INVALID)
            return

        try:
            if packet_type == CONNECT:
                await self._handle_connect(stream_id, payload)
            elif packet_type == DATA:
                await self._handle_data(stream_id, payload)
            elif packet_type == CLOSE:
                await self._handle_close(stream_id, payload)
            else:
                await self._close_stream(stream_id, CLOSE_INVALID)
        except Exception as exc:
            console.log(f"[wisp] packet handler failed for stream {stream_id}: {exc}")
            await self._close_stream(stream_id, CLOSE_NETWORK_ERROR)

    def _connect_rate_allowed(self) -> bool:
        now = asyncio.get_running_loop().time()
        cutoff = now - 60.0
        self._connect_timestamps = [t for t in self._connect_timestamps if t >= cutoff]
        if len(self._connect_timestamps) >= MAX_CONNECTION_ATTEMPTS_PER_MINUTE:
            return False
        self._connect_timestamps.append(now)
        return True

    async def _handle_connect(self, stream_id: int, payload: bytes) -> None:
        try:
            stream_type, port, hostname = parse_connect_payload(payload)
        except ValueError:
            await self._close_stream(stream_id, CLOSE_INVALID)
            return

        # Per the requested Cloudflare Worker behavior, UDP is deliberately
        # ignored: the client is not told that UDP was disabled.
        if is_udp_stream(stream_type):
            note_udp_attempt(stream_id, hostname, port)
            return
        if stream_type != TCP:
            await self._close_stream(stream_id, CLOSE_INVALID)
            return

        if stream_id == 0 or self.streams.contains(stream_id):
            await self._close_stream(stream_id, CLOSE_INVALID)
            return
        if self.streams.count >= self.streams.max_streams:
            await self._close_stream(stream_id, CLOSE_THROTTLED)
            return
        if not self._connect_rate_allowed():
            await self._close_stream(stream_id, CLOSE_THROTTLED)
            return
        if _is_disallowed_literal_host(hostname):
            await self._close_stream(stream_id, CLOSE_BLOCKED)
            return

        stream = TCPStream(
            stream_id=stream_id,
            hostname=hostname,
            port=port,
            send_packet=self.send_packet,
            on_closed=self._stream_closed,
        )
        self.streams.add(stream)

        console.log(f"[wisp] TCP connect stream={stream_id} {hostname}:{port}")

        # Permit the client to queue DATA immediately after CONNECT, as allowed
        # by Wisp, without forcing it to wait for TCP connection establishment.
        self.send_continue(stream_id, stream.buffer_remaining)

        task = asyncio.create_task(stream.open(CONNECT_TIMEOUT_SECONDS))
        self._track_task(task)

    async def _handle_data(self, stream_id: int, payload: bytes) -> None:
        if stream_id == 0 or len(payload) > MAX_DATA_PAYLOAD_BYTES:
            await self._close_stream(stream_id, CLOSE_INVALID)
            return

        stream = self.streams.get(stream_id)
        if stream is None:
            await self._close_stream(stream_id, CLOSE_INVALID)
            return

        if not stream.enqueue(payload):
            await self._close_stream(stream_id, CLOSE_THROTTLED)

    async def _handle_close(self, stream_id: int, payload: bytes) -> None:
        if len(payload) != 1:
            await self._close_stream(stream_id, CLOSE_INVALID)
            return
        stream = self.streams.get(stream_id)
        if stream is None:
            return
        await stream.close(send_packet=False)

    async def _close_stream(self, stream_id: int, reason: int) -> None:
        # A CLOSE packet is itself one complete Wisp packet, and receiving it on
        # the peer means the associated stream must be closed immediately.
        if stream_id != 0:
            self.send_packet(build_packet(CLOSE, stream_id, bytes((reason,))))
            stream = self.streams.get(stream_id)
            if stream is not None:
                await stream.close(send_packet=False)
        else:
            # There is no normal data stream 0 in this implementation. For a
            # malformed connection-level packet, close the WebSocket transport.
            await self.close(send_ws_close=True)

    def _stream_closed(self, stream_id: int) -> None:
        self.streams.remove(stream_id)

    def send_packet(self, packet: bytes) -> None:
        if self._closed:
            return
        try:
            self.websocket.send(to_js(packet))
        except Exception as exc:
            console.log(f"[wisp] websocket send failed: {exc}")

    def send_continue(self, stream_id: int, remaining: int) -> None:
        remaining = max(0, min(0xFFFFFFFF, int(remaining)))
        self.send_packet(
            build_packet(CONTINUE, stream_id, remaining.to_bytes(4, "little"))
        )

    async def close(self, send_ws_close: bool = True, **kwargs) -> None:
        """Close every stream and optionally the WebSocket itself."""
        if self._closed:
            return
        self._closed = True

        await self.streams.close_all()

        if send_ws_close:
            try:
                self.websocket.close(1000, "Wisp connection closed")
            except Exception:
                pass

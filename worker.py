"""
worker.py — Wisp v1 multiplexing proxy server for Cloudflare Workers (Python).

A single-file port of wisp-server-python (MercuryWorkshop, AGPL-3.0) to the
Cloudflare Workers Python runtime, implementing the Workers-revised Wisp v1
specification (TCP-only, no UDP, no websocket forwarding).

Architecture (dual-head outbound, strict 3+3 concurrency, queued):
  * Client-facing heads (single `fetch()` entrypoint):
      - WebSocket + path ending in "/"            -> Wisp v1 session  (spec)
      - WebSocket + path ending in "/host:port"   -> legacy wsproxy tunnel
      - Plain HTTP GET / or /index.html           -> landing page
  * Outbound heads (the "dual head"):
      - GET/HTTP head: streams destined to ports 80/443 whose payload parses as
        HTTP/1.1 are delegated to `fetch()` subrequests (3 concurrent slots).
      - live-TCP head: all other TCP traffic is tunneled over raw TCP sockets via
        the `cloudflare:sockets` connect() API (3 concurrent slots).
      - Transparent fallback: TLS records (0x16), HTTP `Upgrade:`/`CONNECT`
        requests, or unparsable data on an HTTP-head stream are replayed into a
        live-TCP tunnel so standard clients (epoxy/wisp) keep working.
  * ConcurrencyGovernor: per-isolate singleton enforcing 3 live-TCP + 3 GET/HTTP
    in-flight outbound requests (strict ceiling of 6) with a FIFO request queue.
    Waiting past `WISP_QUEUE_TIMEOUT` rejects the stream with CLOSE 0x49.

Everything runs on a single-threaded asyncio event loop: no threads, no
processes, no UDP. See PLAN.MD for the reference-codebase analysis and
REPORT.MD for validation results and deployment steps.
"""

from __future__ import annotations

import asyncio
import random
import re
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, AsyncIterator, Awaitable, Callable, Optional, Sequence
from urllib.parse import urlsplit

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Section 1: platform imports (guarded so the module also imports on CPython,
# where the local test harness injects a fake platform and websocket socket).
# ---------------------------------------------------------------------------

try:  # pragma: no cover - only importable inside the Workers runtime
    from js import Array as _JsArray
    from js import Object as _JsObject
    from js import WebSocketPair as _JsWebSocketPair
    from js import fetch as _js_fetch
    from pyodide.ffi import to_js as _to_js
    from workers import Response as _WorkersResponse
    from workers import WorkerEntrypoint as _WorkerEntrypoint
    from workers import import_from_javascript as _import_from_javascript

    WORKERS_RUNTIME: bool = True
except ImportError:  # local development / conformance harness
    WORKERS_RUNTIME = False
    _WorkerEntrypoint = object  # type: ignore[assignment,misc]
    _WorkersResponse = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Section 2: constants, close reasons, configuration
# ---------------------------------------------------------------------------


class PacketType(IntEnum):
    CONNECT = 0x01
    DATA = 0x02
    CONTINUE = 0x03
    CLOSE = 0x04


class StreamType(IntEnum):
    TCP = 0x01
    UDP = 0x02


class CloseReason(IntEnum):
    """Wisp close reasons (see WISP-SPEC.MD)."""

    UNSPECIFIED = 0x01
    VOLUNTARY = 0x02
    NETWORK_ERROR = 0x03
    INVALID_INFO = 0x41
    UNREACHABLE = 0x42
    CONNECT_TIMEOUT = 0x43
    REFUSED = 0x44
    TRANSFER_TIMEOUT = 0x47
    ADDRESS_BLOCKED = 0x48
    THROTTLED = 0x49


# Wire formats (all little-endian, per spec).
HEADER_STRUCT = struct.Struct("<BI")          # packet_type: u8, stream_id: u32
CONNECT_PAYLOAD_STRUCT = struct.Struct("<BH")  # stream_type: u8, dest_port: u16
CONTINUE_PAYLOAD_STRUCT = struct.Struct("<I")  # buffer_remaining: u32
CLOSE_PAYLOAD_STRUCT = struct.Struct("<B")     # reason: u8

# Strict outbound concurrency: three live-TCP sockets + three GET/HTTP fetches
# (== the platform's six-simultaneous-connection budget), FIFO-queued.
TCP_SLOTS = 3
HTTP_SLOTS = 3
TOTAL_OUTBOUND_SLOTS = TCP_SLOTS + HTTP_SLOTS

DEFAULT_BUFFER_SIZE = 128        # per-stream inbound FIFO (packets), as reference
CONTINUE_INTERVAL = 32           # queue_size // 4, as reference
DEFAULT_CONNECT_TIMEOUT = 15.0   # seconds; exceeding => CLOSE 0x43
DEFAULT_QUEUE_TIMEOUT = 30.0     # seconds waiting for a slot => CLOSE 0x49
DEFAULT_MAX_HTTP_BODY = 8 * 1024 * 1024
DEFAULT_MAX_STREAMS = 64         # per session; exceeding => CLOSE 0x49
HTTP_HEADER_LIMIT = 65536        # request head size cap for the GET/HTTP head
WS_SESSION_QUEUE_LIMIT = 1024    # inbound ws frames buffered per session
DEFAULT_HTTP_HEAD_PORTS = frozenset({80, 443})

REASON_PHRASES: dict[int, str] = {
    100: "Continue", 101: "Switching Protocols", 200: "OK", 201: "Created",
    202: "Accepted", 204: "No Content", 206: "Partial Content", 301: "Moved Permanently",
    302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 409: "Conflict", 410: "Gone", 413: "Payload Too Large",
    418: "I'm a teapot", 426: "Upgrade Required", 429: "Too Many Requests",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}

# Hop-by-hop headers never forwarded in either direction (RFC 9110 + proxies).
HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
})


def _env_get(env: Any, name: str, default: Optional[str]) -> Optional[str]:
    """Read a setting from a Workers env binding or a plain dict (tests)."""
    if env is None:
        return default
    if isinstance(env, dict):
        value = env.get(name)
    else:
        try:
            value = getattr(env, name, None)
        except Exception:
            value = None
    if value is None or value == "":
        return default
    return str(value)


@dataclass
class ServerConfig:
    """Runtime configuration, sourced from env vars in production."""

    buffer_size: int = DEFAULT_BUFFER_SIZE
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    queue_timeout: float = DEFAULT_QUEUE_TIMEOUT
    max_http_body: int = DEFAULT_MAX_HTTP_BODY
    max_streams: int = DEFAULT_MAX_STREAMS
    http_head_ports: frozenset[int] = DEFAULT_HTTP_HEAD_PORTS
    https_ports: frozenset[int] = frozenset({443})
    password: Optional[str] = None
    allowed_host_regex: Optional[re.Pattern[str]] = None
    log_level: str = "info"

    @classmethod
    def from_env(cls, env: Any) -> "ServerConfig":
        def ival(name: str, default: int) -> int:
            raw = _env_get(env, name, None)
            try:
                return int(raw) if raw is not None else default
            except ValueError:
                LOG.warning("config invalid int for %s=%r, using default", name, raw)
                return default

        def fval(name: str, default: float) -> float:
            raw = _env_get(env, name, None)
            try:
                return float(raw) if raw is not None else default
            except ValueError:
                LOG.warning("config invalid float for %s=%r, using default", name, raw)
                return default

        def portset(name: str, default: frozenset[int]) -> frozenset[int]:
            raw = _env_get(env, name, None)
            if not raw:
                return default
            try:
                return frozenset(int(p.strip()) for p in raw.split(",") if p.strip())
            except ValueError:
                LOG.warning("config invalid %s=%r, using default", name, raw)
                return default

        ports: frozenset[int] = portset("WISP_HTTP_HEAD_PORTS", DEFAULT_HTTP_HEAD_PORTS)

        host_re_raw = _env_get(env, "WISP_ALLOWED_HOST_REGEX", None)
        host_re: Optional[re.Pattern[str]] = None
        if host_re_raw:
            try:
                host_re = re.compile(host_re_raw)
            except re.error:
                LOG.warning("config invalid WISP_ALLOWED_HOST_REGEX, ignoring")

        return cls(
            buffer_size=max(1, ival("WISP_BUFFER_SIZE", DEFAULT_BUFFER_SIZE)),
            connect_timeout=fval("WISP_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT),
            queue_timeout=fval("WISP_QUEUE_TIMEOUT", DEFAULT_QUEUE_TIMEOUT),
            max_http_body=max(1024, ival("WISP_MAX_HTTP_BODY", DEFAULT_MAX_HTTP_BODY)),
            max_streams=max(1, ival("WISP_MAX_STREAMS", DEFAULT_MAX_STREAMS)),
            http_head_ports=ports,
            https_ports=portset("WISP_HTTPS_PORTS", frozenset({443})),
            password=_env_get(env, "WISP_PASSWORD", None),
            allowed_host_regex=host_re,
            log_level=(_env_get(env, "WISP_LOG_LEVEL", "info") or "info").lower(),
        )


# ---------------------------------------------------------------------------
# Section 3: logging (print-based; workerd forwards console output)
# ---------------------------------------------------------------------------


class LogLevel(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40


_LEVEL_NAMES = {10: "DEBUG", 20: "INFO", 30: "WARN", 40: "ERROR"}


class Logger:
    """Minimal level-gated, printf-style logger.

    Uses print() so output reaches the Workers console from pyodide. Callers
    embed their component tag (e.g. ``[stream 3]``) directly in the message:
    ``LOG.info("[%s] started", label)``.
    """

    def __init__(self, level: int = LogLevel.INFO) -> None:
        self.level = level

    def set_level(self, name: str) -> None:
        try:
            self.level = LogLevel[str.strip(name or "info").upper()]
        except KeyError:
            self.level = LogLevel.INFO

    def _emit(self, level: int, message: str) -> None:
        if level < self.level:
            return
        stamp = time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime())
        print(f"[{stamp}] [{_LEVEL_NAMES.get(level, 'LOG')}] [wisp] {message}", flush=True)

    def debug(self, fmt: str, *args: Any) -> None:
        self._emit(LogLevel.DEBUG, fmt % args if args else fmt)

    def info(self, fmt: str, *args: Any) -> None:
        self._emit(LogLevel.INFO, fmt % args if args else fmt)

    def warning(self, fmt: str, *args: Any) -> None:
        self._emit(LogLevel.WARNING, fmt % args if args else fmt)

    def error(self, fmt: str, *args: Any) -> None:
        self._emit(LogLevel.ERROR, fmt % args if args else fmt)


LOG = Logger()


def configure_logging(level_name: str) -> None:
    LOG.set_level(level_name)


# ---------------------------------------------------------------------------
# Section 4: protocol codec (pure functions; no I/O)
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """Base class for wisp protocol violations."""


class InvalidConnectPayload(ProtocolError):
    """CONNECT payload is malformed -> CLOSE 0x41."""


class UdpUnsupported(ProtocolError):
    """UDP streams are not supported on Workers -> CLOSE 0x48."""


@dataclass(frozen=True)
class ConnectRequest:
    stream_type: int
    port: int
    hostname: str

    @property
    def dest(self) -> str:
        return f"{self.hostname}:{self.port}"


def parse_connect_payload(payload: bytes) -> ConnectRequest:
    """Validate and decode a CONNECT payload (stream_type, port, hostname)."""
    if len(payload) < 4:
        raise InvalidConnectPayload("CONNECT payload too short")
    stream_type, port = CONNECT_PAYLOAD_STRUCT.unpack_from(payload, 0)
    if stream_type not in (int(StreamType.TCP), int(StreamType.UDP)):
        raise InvalidConnectPayload(f"invalid stream type 0x{stream_type:02x}")
    if stream_type == int(StreamType.UDP):
        # Workers-revised spec: UDP is intentionally blocked on the server.
        raise UdpUnsupported("UDP streams are not supported on this server")
    try:
        hostname = payload[3:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidConnectPayload("hostname is not valid UTF-8") from exc
    if not 1 <= port <= 65535:
        raise InvalidConnectPayload(f"invalid destination port {port}")
    if not hostname or len(hostname) > 255:
        raise InvalidConnectPayload("invalid hostname length")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in hostname):
        raise InvalidConnectPayload("hostname contains control characters")
    return ConnectRequest(stream_type=stream_type, port=port, hostname=hostname)


def build_frame(packet_type: int, stream_id: int, payload: bytes) -> bytes:
    return HEADER_STRUCT.pack(packet_type, stream_id) + payload


def data_frame(stream_id: int, payload: bytes) -> bytes:
    return build_frame(int(PacketType.DATA), stream_id, payload)


def continue_frame(stream_id: int, buffer_remaining: int) -> bytes:
    return build_frame(
        int(PacketType.CONTINUE), stream_id, CONTINUE_PAYLOAD_STRUCT.pack(buffer_remaining)
    )


def close_frame(stream_id: int, reason: int) -> bytes:
    return build_frame(int(PacketType.CLOSE), stream_id, CLOSE_PAYLOAD_STRUCT.pack(reason))


# ---------------------------------------------------------------------------
# Section 5: concurrency governor — strict 3+3 slots, FIFO request queue
# ---------------------------------------------------------------------------


class SlotTimeoutError(Exception):
    """A slot could not be acquired within the queue timeout (=> 0x49)."""


class Lease:
    """A held concurrency slot. Idempotent release; never leaks past close()."""

    __slots__ = ("_pool", "_released")

    def __init__(self, pool: "SlotPool") -> None:
        self._pool = pool
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._pool._release_slot()


class SlotPool:
    """A fixed-size slot pool with strict FIFO waiters (the request queue)."""

    def __init__(self, name: str, size: int) -> None:
        self.name = name
        self._size = size
        self._used = 0
        self._waiters: "asyncio.Queue[asyncio.Future[None]]" = asyncio.Queue()

    @property
    def in_flight(self) -> int:
        return self._used

    @property
    def waiting(self) -> int:
        return self._waiters.qsize()

    def stats(self) -> str:
        return f"{self.name}={self._used}/{self._size} queued={self.waiting}"

    async def acquire(self, timeout: float) -> Lease:
        loop = asyncio.get_running_loop()
        if self._used < self._size and self._waiters.empty():
            self._used += 1
            LOG.debug("[governor] acquire %s -> immediate (%s)", self.name, self.stats())
            return Lease(self)
        fut: "asyncio.Future[None]" = loop.create_future()
        await self._waiters.put(fut)
        LOG.debug("[governor] queueing for %s slot (%s)", self.name, self.stats())
        try:
            await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            LOG.warning(
                "[governor] timeout waiting %.1fs for %s slot (%s)",
                timeout, self.name, self.stats(),
            )
            raise SlotTimeoutError(
                f"timed out waiting for a {self.name} outbound slot"
            ) from None
        return Lease(self)

    def _release_slot(self) -> None:
        self._used -= 1
        if self._used < 0:  # defensive: never allow negative accounting
            self._used = 0
        while not self._waiters.empty():
            fut = self._waiters.get_nowait()
            if not fut.done():
                self._used += 1
                fut.set_result(None)
                LOG.debug("[governor] handed %s slot to next waiter (%s)",
                          self.name, self.stats())
                break


class ConcurrencyGovernor:
    """Per-isolate governor: 3 live-TCP + 3 GET/HTTP in-flight (strict 6)."""

    def __init__(
        self,
        tcp_slots: int = TCP_SLOTS,
        http_slots: int = HTTP_SLOTS,
    ) -> None:
        self.tcp = SlotPool("live-tcp", tcp_slots)
        self.http = SlotPool("get-http", http_slots)

    def stats(self) -> str:
        return f"{self.tcp.stats()} | {self.http.stats()}"


_GOVERNOR: Optional[ConcurrencyGovernor] = None


def get_governor() -> ConcurrencyGovernor:
    """Module-level singleton: the 6-slot ceiling is enforced per isolate."""
    global _GOVERNOR
    if _GOVERNOR is None:
        _GOVERNOR = ConcurrencyGovernor()
        LOG.info("[governor] initialized: %d live-tcp + %d get-http slots (strict)",
                 TCP_SLOTS, HTTP_SLOTS)
    return _GOVERNOR


# ---------------------------------------------------------------------------
# Section 6: outbound transport abstractions + the two heads
# ---------------------------------------------------------------------------


class OutboundConnectError(Exception):
    """Outbound connection setup failed; carries the wisp CLOSE reason."""

    def __init__(self, reason: CloseReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def classify_connect_failure(exc: BaseException) -> CloseReason:
    """Map a platform connect error onto a spec close reason."""
    text = f"{type(exc).__name__}: {exc}".lower()
    if "econnrefused" in text or "refused" in text:
        return CloseReason.REFUSED
    if "etimedout" in text or "timed out" in text or "timeout" in text:
        return CloseReason.CONNECT_TIMEOUT
    if (
        "enotfound" in text
        or "eai_again" in text
        or "getaddrinfo" in text
        or "resolve" in text
        or "dns" in text
    ):
        return CloseReason.UNREACHABLE
    if "eblocked" in text or "not allowed" in text or "blocked" in text:
        return CloseReason.ADDRESS_BLOCKED
    return CloseReason.UNREACHABLE


# Structural interfaces a platform must provide (implemented by
# CloudflarePlatform in production and by the local harness in tests):
#   tcp_connect(host, port, timeout) -> TcpConnection
#       TcpConnection: async read() -> bytes|None (None = EOF),
#                      async write(bytes), close()
#   http_fetch(method, url, headers, body, timeout) -> FetchResponse
#       FetchResponse: status:int, status_text:str,
#                      headers:list[tuple[str,str]],
#                      body_chunks() -> async iterator of bytes


def _looks_like_http_start(data: bytes) -> bool:
    """Heuristic: first bytes look like an HTTP/1.1 request (method start)."""
    if not data:
        return False
    first = data[0]
    return 0x41 <= first <= 0x5A  # 'A'..'Z' — every HTTP method starts uppercase


def _looks_like_tls_start(data: bytes) -> bool:
    """Heuristic: first bytes look like a TLS record (ClientHello)."""
    return len(data) >= 1 and data[0] == 0x16


class TcpHead:
    """Live-TCP head: raw bidirectional tunnel via cloudflare:sockets."""

    kind = "live-tcp"

    def __init__(self, stream: "Stream") -> None:
        self.stream = stream
        self._conn: Any = None
        self._lease: Optional[Lease] = None
        self._reader_task: Optional["asyncio.Task[None]"] = None
        self.closed = False

    async def start(self, initial: bytes) -> None:
        cfg = self.stream.config
        gov = get_governor()
        lease = await gov.tcp.acquire(cfg.queue_timeout)  # may raise SlotTimeoutError
        self._lease = lease
        try:
            self._conn = await self.stream.platform.tcp_connect(
                self.stream.host, self.stream.port, cfg.connect_timeout
            )
        except BaseException:
            lease.release()
            self._lease = None
            raise
        self._reader_task = asyncio.ensure_future(self._reader_loop())
        if initial:
            await self._conn.write(initial)

    async def _reader_loop(self) -> None:
        stream = self.stream
        sid = stream.stream_id
        try:
            while True:
                data = await self._conn.read()
                if not data:  # graceful EOF from the destination
                    break
                await stream.send_to_client(data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # network error mid-transfer
            LOG.warning("[stream %d] tcp read failed: %s", sid, exc)
            await stream.end_stream(CloseReason.NETWORK_ERROR, notify=True)
            return
        await stream.end_stream(CloseReason.VOLUNTARY, notify=True)

    async def on_data(self, data: bytes) -> None:
        if self._conn is None or self.closed:
            return
        await self._conn.write(data)

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        await _cancel_task(self._reader_task)
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception as exc:
                LOG.debug("[stream %d] tcp close error: %s", self.stream.stream_id, exc)
        if self._lease is not None:
            self._lease.release()
            self._lease = None


@dataclass
class HttpRequest:
    """A fully-buffered HTTP/1. request parsed off a wisp stream."""

    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: Optional[bytes]
    connection_close: bool


class _TcpFallback(Exception):
    """Internal signal: replay buffered bytes into a live-TCP tunnel."""

    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


class HttpFetchHead:
    """GET/HTTP head: relays HTTP/1.1 on the stream through `fetch()`.

    Parses requests from the stream, issues them as fetch subrequests (one
    HTTP slot per in-flight request), and serializes responses back with
    chunked (or absent) framing. Falls back to a live-TCP tunnel — replaying
    every byte received so far — when the payload turns out to be a TLS
    record, an HTTP Upgrade/CONNECT, or unparsable, as long as no response
    bytes have been emitted yet.
    """

    kind = "get-http"

    def __init__(self, stream: "Stream") -> None:
        self.stream = stream
        self.scheme = (
            "https" if stream.port in stream.config.https_ports else "http"
        )
        self.buf = bytearray()
        self.pos = 0  # parse offset; bytes before it are committed on fallback
        self._data_evt = asyncio.Event()
        self.closed = False
        self._responses_sent = 0
        self._task: "asyncio.Task[None]" = asyncio.ensure_future(self._run())

    # -- buffer helpers ----------------------------------------------------

    def _available(self) -> int:
        return len(self.buf) - self.pos

    async def _wait_for_data(self, needed: int) -> bool:
        """Await until `needed` bytes are available; False if closed."""
        while self._available() < needed:
            if self.closed:
                return False
            self._data_evt.clear()
            if self._available() >= needed:
                return True
            await self._data_evt.wait()
        return True

    async def _read_until(self, delimiter: bytes, cap: int) -> Optional[bytes]:
        """Read up to (and including) `delimiter`; None when closed/over cap."""
        while True:
            idx = self.buf.find(delimiter, self.pos)
            if idx != -1:
                end = idx + len(delimiter)
                out = bytes(self.buf[self.pos:end])
                self.pos = end
                return out
            if self.closed:
                return None  # client is gone; partial requests are dropped
            if self._available() > cap:
                raise _TcpFallback("http head exceeds size cap")
            await self._wait_for_data(self._available() + 1)

    async def _read_exact(self, n: int) -> Optional[bytes]:
        if not await self._wait_for_data(n):
            return None
        out = bytes(self.buf[self.pos:self.pos + n])
        self.pos += n
        return out

    # -- request parsing ----------------------------------------------------

    async def _read_request(self) -> Optional[HttpRequest]:
        """Parse one request; raises _TcpFallback when tunneled traffic is
        detected; returns None when the stream closed cleanly."""
        head = await self._read_until(b"\r\n\r\n", HTTP_HEADER_LIMIT)
        if head is None:
            return None
        try:
            text = head.decode("latin-1")
        except UnicodeDecodeError:
            raise _TcpFallback("undecodable request head") from None
        lines = text.split("\r\n")
        m = re.match(r"^([A-Za-z!#$%&'*+.^_`|~0-9-]+) (\S+) (HTTP/\d\.\d)$", lines[0])
        if m is None:
            raise _TcpFallback(f"malformed request line: {lines[0][:64]!r}")
        method, target, version = m.group(1).upper(), m.group(2), m.group(3)

        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line:
                continue
            if line[0] in " \t":
                raise _TcpFallback("obsolete header folding not supported")
            name, sep, value = line.partition(":")
            if not sep or not name.strip():
                raise _TcpFallback(f"malformed header line: {line[:64]!r}")
            headers.append((name.strip().lower(), value.strip()))

        header_map: dict[str, str] = {}
        for name, value in headers:
            header_map[name] = value  # last value wins for lookup purposes

        if method == "CONNECT":
            raise _TcpFallback("CONNECT method must be tunneled")
        if "upgrade" in header_map:
            raise _TcpFallback(f"upgrade to {header_map['upgrade']!r} must be tunneled")

        connection_tokens = {
            tok.strip().lower()
            for tok in header_map.get("connection", "").split(",")
            if tok.strip()
        }
        connection_close = "close" in connection_tokens

        body: Optional[bytes] = None
        if "content-length" in header_map:
            try:
                clen = int(header_map["content-length"])
            except ValueError:
                raise _TcpFallback("invalid content-length") from None
            if clen < 0 or clen > self.stream.config.max_http_body:
                raise _TcpFallback(f"content-length {clen} out of bounds")
            if clen > 0:
                body = await self._read_exact(clen)
                if body is None:
                    return None
        elif header_map.get("transfer-encoding", "").lower() == "chunked":
            body = await self._read_chunked_body()
            if body is None:
                return None
        return HttpRequest(
            method=method, target=target, version=version,
            headers=headers, body=body, connection_close=connection_close,
        )

    async def _read_chunked_body(self) -> Optional[bytes]:
        chunks: list[bytes] = []
        total = 0
        cap = self.stream.config.max_http_body
        while True:
            size_line = await self._read_until(b"\r\n", HTTP_HEADER_LIMIT)
            if size_line is None:
                return None
            try:
                size = int(size_line.strip().split(b";")[0], 16)
            except ValueError:
                raise _TcpFallback("invalid chunk size") from None
            if size == 0:
                # trailers until blank line (usually immediate)
                _ = await self._read_until(b"\r\n", HTTP_HEADER_LIMIT)
                return b"".join(chunks)
            total += size
            if total > cap:
                raise _TcpFallback("chunked body exceeds cap")
            chunk = await self._read_exact(size)
            if chunk is None:
                return None
            chunks.append(chunk)
            crlf = await self._read_exact(2)
            if crlf != b"\r\n":
                raise _TcpFallback("malformed chunk terminator")

    # -- fetch + response serialization -------------------------------------

    def _build_url(self, req: HttpRequest) -> str:
        target = req.target
        if target.startswith("http://") or target.startswith("https://"):
            return target  # absolute-form: honor the client's URL
        host = self.stream.host
        default_port = (self.scheme == "http" and self.stream.port == 80) or (
            self.scheme == "https" and self.stream.port == 443
        )
        if not default_port:
            host = f"{host}:{self.stream.port}"
        return f"{self.scheme}://{host}{target}"

    def _forwarded_request_headers(
        self, req: HttpRequest, body: Optional[bytes]
    ) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        has_host = False
        for name, value in req.headers:
            if name in HOP_BY_HOP_HEADERS or name == "content-length":
                continue
            if name == "host":
                # Honor the client's Host header (transparent-proxy semantics):
                # a wisp CONNECT already fixed the destination, and standard
                # clients send a Host matching it.
                has_host = True
            out.append((name, value))
        if not has_host:
            host = self.stream.host
            default_port = (self.scheme == "http" and self.stream.port == 80) or (
                self.scheme == "https" and self.stream.port == 443
            )
            if not default_port:
                host = f"{host}:{self.stream.port}"
            out.insert(0, ("host", host))
        if body is not None:
            out.append(("content-length", str(len(body))))
        return out

    async def _run(self) -> None:
        stream = self.stream
        sid = stream.stream_id
        try:
            while not self.closed:
                req = await self._read_request()
                if req is None:
                    # Client closed the stream without another request.
                    await stream.end_stream(CloseReason.VOLUNTARY, notify=False)
                    return
                url = self._build_url(req)
                fwd_headers = self._forwarded_request_headers(req, req.body)
                lease = get_governor().http.acquire  # noqa: E731 (readability)
                gov_lease = await lease(stream.config.queue_timeout)
                try:
                    resp = await stream.platform.http_fetch(
                        method=req.method,
                        url=url,
                        headers=fwd_headers,
                        body=req.body,
                        timeout=stream.config.connect_timeout,
                    )
                    await self._send_response(req, resp)
                finally:
                    gov_lease.release()
                # Commit consumed bytes only after the response was emitted.
                del self.buf[:self.pos]
                self.pos = 0
                if req.connection_close:
                    await stream.end_stream(CloseReason.VOLUNTARY, notify=False)
                    return
        except _TcpFallback as fb:
            await self._fallback_to_tcp(fb.why)
        except SlotTimeoutError:
            LOG.warning("[stream %d] http head throttled (queue timeout)", sid)
            await stream.end_stream(CloseReason.THROTTLED, notify=True)
        except OutboundConnectError as exc:
            LOG.warning("[stream %d] fetch connect failed: %s", sid, exc.detail)
            await stream.end_stream(exc.reason, notify=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.error("[stream %d] http head crashed: %r", sid, exc)
            await stream.end_stream(CloseReason.NETWORK_ERROR, notify=True)

    async def _send_response(self, req: HttpRequest, resp: Any) -> None:
        stream = self.stream
        sid = stream.stream_id
        status = int(getattr(resp, "status", 502))
        reason = str(getattr(resp, "status_text", "") or "") or REASON_PHRASES.get(
            status, ""
        )
        bodyless = status in (204, 304) or req.method == "HEAD"

        lines = [f"HTTP/1.1 {status} {reason}".rstrip()]
        for name, value in getattr(resp, "headers", []):
            lname = name.lower()
            if lname in HOP_BY_HOP_HEADERS or lname in ("content-length", "content-encoding"):
                # Never trust upstream length/encoding: fetch() re-frames and
                # may transparently decompress, so we always re-frame chunked.
                continue
            lines.append(f"{name}: {value}")
        lines.append("connection: close" if req.connection_close else "connection: keep-alive")
        if not bodyless:
            lines.append("transfer-encoding: chunked")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")
        self._responses_sent += 1  # from here on, fallback is impossible
        await stream.send_to_client(head)
        if bodyless:
            return
        async for chunk in resp.body_chunks():
            if not chunk:
                continue
            await stream.send_to_client(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
        await stream.send_to_client(b"0\r\n\r\n")

    async def _fallback_to_tcp(self, why: str) -> None:
        stream = self.stream
        if self._responses_sent > 0:
            LOG.warning(
                "[stream %d] cannot fall back after response sent (%s); closing",
                stream.stream_id, why,
            )
            await stream.end_stream(CloseReason.NETWORK_ERROR, notify=True)
            return
        pending = bytes(self.buf)  # every byte the client sent so far
        self.closed = True  # stop accepting data into this head
        await _cancel_task(self._task)
        LOG.info("[stream %d] falling back to live-tcp head: %s", stream.stream_id, why)
        tcp = TcpHead(stream)
        stream.head = tcp
        try:
            await tcp.start(pending)
        except (SlotTimeoutError, OutboundConnectError) as exc:
            reason = (
                CloseReason.THROTTLED
                if isinstance(exc, SlotTimeoutError)
                else exc.reason
            )
            await stream.end_stream(reason, notify=True)

    # -- head interface ------------------------------------------------------

    async def on_data(self, data: bytes) -> None:
        if self.closed:
            return
        self.buf += data
        if len(self.buf) > 2 * self.stream.config.max_http_body:
            # Hard memory guard; extremely unlikely to be legitimate HTTP.
            self.closed = True
            self._data_evt.set()
            await _cancel_task(self._task)
            await self.stream.end_stream(CloseReason.UNSPECIFIED, notify=True)
            return
        self._data_evt.set()

    async def close(self) -> None:
        if self.closed and self._task.done():
            return
        self.closed = True
        self._data_evt.set()
        await _cancel_task(self._task)


async def _cancel_task(task: Optional["asyncio.Task[Any]"]) -> None:
    """Cancel a task safely, never cancelling the current task."""
    if task is None or task.done():
        return
    if task is asyncio.current_task():
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


# ---------------------------------------------------------------------------
# Section 7: Stream — per-stream state, head selection, CONTINUE pacing
# ---------------------------------------------------------------------------


class Stream:
    """One multiplexed wisp stream (or one wsproxy tunnel).

    The channel object (WispSession or WsProxySession) supplies framing:
    `send_data` wraps payloads in DATA frames for wisp and sends raw bytes for
    wsproxy; `terminate` sends CLOSE frames for wisp and closes the tunnel for
    wsproxy; `send_control` emits CONTINUE frames (no-op for wsproxy).
    """

    def __init__(
        self,
        channel: "StreamChannel",
        stream_id: int,
        host: str,
        port: int,
        platform: Any,
        config: ServerConfig,
    ) -> None:
        self.channel = channel
        self.stream_id = stream_id
        self.host = host
        self.port = port
        self.platform = platform
        self.config = config
        self.inbound: "asyncio.Queue[bytes]" = asyncio.Queue(maxsize=config.buffer_size)
        self.head: Optional[Any] = None
        self.packets_handed = 0
        self.closed = False
        self._closed_evt = asyncio.Event()
        # Server->client flow control: ungated until the client announces a
        # buffer via a CONTINUE packet (epoxy never does; reference ignores it).
        self.client_buffer_remaining: Optional[int] = None
        self._client_continue_evt = asyncio.Event()
        self._client_continue_evt.set()
        self._pump_task: "asyncio.Task[None]" = asyncio.ensure_future(self._pump())

    # -- client -> destination ----------------------------------------------

    async def on_client_data(self, payload: bytes) -> None:
        """Enqueue a DATA payload; backpressures per the reference design."""
        if self.closed or not payload:
            return
        try:
            self.inbound.put_nowait(payload)
            return
        except asyncio.QueueFull:
            pass
        # Queue full (client violated CONTINUE pacing, or head is slow).
        # Wait for space, but bail out immediately if the stream closes.
        put_fut = asyncio.ensure_future(self.inbound.put(payload))
        closed_fut = asyncio.ensure_future(self._closed_evt.wait())
        done, pending = await asyncio.wait(
            {put_fut, closed_fut}, return_when=asyncio.FIRST_COMPLETED
        )
        for fut in pending:
            fut.cancel()

    def on_client_continue(self, buffer_remaining: int) -> None:
        LOG.debug("[stream %d] client CONTINUE buffer=%d", self.stream_id, buffer_remaining)
        self.client_buffer_remaining = max(0, buffer_remaining)
        if buffer_remaining > 0:
            self._client_continue_evt.set()
        else:
            self._client_continue_evt.clear()

    async def _pump(self) -> None:
        try:
            # Spec: "the server must immediately try to establish a TCP socket to
            # the specified hostname and port" — for non-head ports we connect
            # right away; for GET/HTTP head ports (80/443) the outbound is a
            # fetch, so head selection is deferred to the first payload bytes.
            if self.port not in self.config.http_head_ports:
                head = TcpHead(self)
                await head.start(b"")
                self.head = head
            first = await self.inbound.get()
            if self.head is None:
                head = await self._select_head(first)
                if head is None:
                    return  # teardown already handled
                self.head = head
                self.packets_handed = 1
                self._maybe_send_continue()
            else:
                await self.head.on_data(first)
                self.packets_handed = 1
                self._maybe_send_continue()
            while True:
                payload = await self.inbound.get()
                # Re-read self.head: the GET/HTTP head may have swapped itself
                # for a live-TCP head via fallback in the meantime.
                head = self.head
                if head is None or self.closed:
                    return
                await head.on_data(payload)
                self.packets_handed += 1
                self._maybe_send_continue()
        except asyncio.CancelledError:
            raise
        except OutboundConnectError as exc:
            LOG.warning("[stream %d] outbound connect failed: %s", self.stream_id, exc.detail)
            await self.end_stream(exc.reason, notify=True)
        except SlotTimeoutError:
            LOG.warning("[stream %d] outbound slot queue timeout", self.stream_id)
            await self.end_stream(CloseReason.THROTTLED, notify=True)
        except Exception as exc:
            LOG.error("[stream %d] pump crashed: %r", self.stream_id, exc)
            await self.end_stream(CloseReason.NETWORK_ERROR, notify=True)

    async def _select_head(self, first: bytes) -> Optional[Any]:
        """Dual-head routing for HTTP-head ports (80/443): HTTP-shaped payload
        goes to the GET/HTTP (fetch) head; TLS records or anything else go to
        the live-TCP head."""
        if not _looks_like_tls_start(first) and _looks_like_http_start(first):
            LOG.debug("[stream %d] routing %s:%d to get-http head",
                      self.stream_id, self.host, self.port)
            head = HttpFetchHead(self)
            await head.on_data(first)
            return head
        if _looks_like_tls_start(first):
            LOG.debug("[stream %d] TLS ClientHello on port %d -> live-tcp head",
                      self.stream_id, self.port)
        head = TcpHead(self)
        await head.start(first)
        return head

    def _maybe_send_continue(self) -> None:
        """Reference pacing: CONTINUE every queue_size//4 packets handed."""
        if self.packets_handed % CONTINUE_INTERVAL == 0:
            remaining = max(0, self.config.buffer_size - self.inbound.qsize())
            self.channel.send_control(continue_frame(self.stream_id, remaining))

    # -- destination -> client ----------------------------------------------

    async def send_to_client(self, data: bytes) -> None:
        if self.closed:
            return
        if self.client_buffer_remaining is not None:
            while self.client_buffer_remaining <= 0 and not self.closed:
                await self._client_continue_evt.wait()
            if self.closed:
                return
            self.client_buffer_remaining -= 1
        await self.channel.send_data(self, data)

    async def end_stream(self, reason: CloseReason, notify: bool) -> None:
        if self.closed:
            return
        await self.channel.terminate(self, reason, notify=notify)

    async def close(self) -> None:
        """Tear down tasks and the head. Idempotent. Sends nothing."""
        if self.closed:
            return
        self.closed = True
        self._closed_evt.set()
        self._client_continue_evt.set()
        if self.head is not None:
            try:
                await self.head.close()
            except Exception as exc:
                LOG.debug("[stream %d] head close error: %r", self.stream_id, exc)
            self.head = None
        await _cancel_task(self._pump_task)


# ---------------------------------------------------------------------------
# Section 8: sessions — Wisp v1 (framed) and legacy wsproxy (raw tunnel)
# ---------------------------------------------------------------------------

OnMessage = Callable[[bytes], None]
OnClose = Callable[[int, str], None]
OnError = Callable[[str], None]


class WispSession:
    """One websocket carrying the Wisp v1 multiplexing protocol.

    Implements the StreamChannel interface used by Stream/heads:
    send_data / send_control / terminate.
    """

    def __init__(self, ws: Any, platform: Any, config: ServerConfig, label: str) -> None:
        self.ws = ws
        self.platform = platform
        self.config = config
        self.label = label
        self.streams: "dict[int, Stream]" = {}
        self.inbound: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue(
            maxsize=WS_SESSION_QUEUE_LIMIT
        )
        self.frames_in = 0
        self.frames_out = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.total_streams = 0
        self.started = time.monotonic()
        self._stopping = False

    # -- lifecycle ------------------------------------------------------------

    async def run(self) -> None:
        self.ws.set_handlers(self._on_ws_message, self._on_ws_close, self._on_ws_error)
        # Wisp v1 handshake: initial CONTINUE, stream id 0 = protocol version.
        self.send_frame(continue_frame(0, self.config.buffer_size))
        LOG.info("[%s] wisp v1 session started (buffer=%d)",
                 self.label, self.config.buffer_size)
        try:
            while True:
                data = await self.inbound.get()
                if data is None or self._stopping:
                    break
                self.frames_in += 1
                self.bytes_in += len(data)
                await self._handle_frame(data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.error("[%s] session loop crashed: %r", self.label, exc)
        finally:
            await self._teardown()

    async def _teardown(self) -> None:
        self._stopping = True
        for sid in list(self.streams.keys()):
            await self.close_stream(sid, CloseReason.VOLUNTARY, notify=False)
        try:
            self.ws.close()
        except Exception:
            pass
        LOG.info(
            "[%s] session closed: %d streams, %d frames in / %d KiB, %d frames out / %d KiB, %.1fs",
            self.label, self.total_streams, self.frames_in,
            self.bytes_in // 1024, self.frames_out,
            self.bytes_out // 1024,
            time.monotonic() - self.started,
        )

    # -- websocket callbacks (synchronous, called by the platform) ------------

    def _on_ws_message(self, data: bytes) -> None:
        if self._stopping:
            return
        try:
            self.inbound.put_nowait(data)
        except asyncio.QueueFull:
            # Only reachable when a client floods far beyond CONTINUE pacing.
            LOG.error("[%s] inbound frame queue overflow; aborting session", self.label)
            self._abort()

    def _on_ws_close(self, code: int, reason: str) -> None:
        LOG.debug("[%s] websocket closed (code=%s reason=%r)", self.label, code, reason)
        self._stopping = True
        try:
            self.inbound.put_nowait(None)
        except asyncio.QueueFull:
            pass  # loop drains and checks _stopping

    def _on_ws_error(self, message: str) -> None:
        LOG.warning("[%s] websocket error: %s", self.label, message)
        self._stopping = True
        try:
            self.inbound.put_nowait(None)
        except asyncio.QueueFull:
            pass

    def _abort(self) -> None:
        self._stopping = True
        try:
            self.inbound.put_nowait(None)
        except asyncio.QueueFull:
            pass
        try:
            self.ws.close()
        except Exception:
            pass

    # -- frame dispatch --------------------------------------------------------

    async def _handle_frame(self, data: bytes) -> None:
        if len(data) < 5:
            LOG.debug("[%s] dropping short frame (%d bytes)", self.label, len(data))
            return
        ptype, sid = HEADER_STRUCT.unpack_from(data, 0)
        payload = data[5:]
        if ptype == int(PacketType.CONNECT):
            await self._handle_connect(sid, payload)
        elif ptype == int(PacketType.DATA):
            stream = self.streams.get(sid)
            if stream is None:
                LOG.debug("[%s] DATA for unknown stream %d ignored", self.label, sid)
                return
            await stream.on_client_data(payload)
        elif ptype == int(PacketType.CONTINUE):
            if len(payload) != 4:
                LOG.debug("[%s] malformed CONTINUE on stream %d ignored", self.label, sid)
                return
            (value,) = CONTINUE_PAYLOAD_STRUCT.unpack(payload)
            stream = self.streams.get(sid)
            if stream is not None:
                stream.on_client_continue(value)
        elif ptype == int(PacketType.CLOSE):
            reason = payload[0] if payload else int(CloseReason.UNSPECIFIED)
            LOG.debug("[%s] CLOSE stream %d from client (reason=0x%02x)",
                      self.label, sid, reason)
            await self.close_stream(sid, CloseReason.VOLUNTARY, notify=False)
        else:
            LOG.debug("[%s] unknown packet type 0x%02x ignored", self.label, ptype)

    async def _handle_connect(self, sid: int, payload: bytes) -> None:
        if sid == 0:
            LOG.warning("[%s] CONNECT with reserved stream id 0 rejected", self.label)
            self.send_frame(close_frame(sid, int(CloseReason.INVALID_INFO)))
            return
        if sid in self.streams:
            LOG.warning("[%s] CONNECT reusing live stream id %d rejected", self.label, sid)
            self.send_frame(close_frame(sid, int(CloseReason.INVALID_INFO)))
            return
        if len(self.streams) >= self.config.max_streams:
            LOG.warning("[%s] stream limit %d reached (0x49)",
                        self.label, self.config.max_streams)
            self.send_frame(close_frame(sid, int(CloseReason.THROTTLED)))
            return
        try:
            req = parse_connect_payload(payload)
        except UdpUnsupported:
            LOG.info("[%s] CONNECT stream %d: UDP is blocked on this server (0x48)",
                     self.label, sid)
            self.send_frame(close_frame(sid, int(CloseReason.ADDRESS_BLOCKED)))
            return
        except InvalidConnectPayload as exc:
            LOG.info("[%s] CONNECT stream %d invalid: %s (0x41)", self.label, sid, exc)
            self.send_frame(close_frame(sid, int(CloseReason.INVALID_INFO)))
            return
        if (
            self.config.allowed_host_regex is not None
            and self.config.allowed_host_regex.match(req.hostname) is None
        ):
            LOG.info("[%s] CONNECT stream %d to %s blocked by policy (0x48)",
                     self.label, sid, req.dest)
            self.send_frame(close_frame(sid, int(CloseReason.ADDRESS_BLOCKED)))
            return
        LOG.info("[%s] stream %d connect -> %s", self.label, sid, req.dest)
        self.total_streams += 1
        self.streams[sid] = Stream(self, sid, req.hostname, req.port,
                                   self.platform, self.config)

    # -- StreamChannel interface ------------------------------------------------

    def send_frame(self, frame: bytes) -> None:
        self.frames_out += 1
        self.bytes_out += len(frame)
        try:
            self.ws.send(frame)
        except Exception as exc:
            LOG.debug("[%s] ws send failed (socket closed?): %r", self.label, exc)

    async def send_data(self, stream: "Stream", data: bytes) -> None:
        self.send_frame(data_frame(stream.stream_id, data))

    def send_control(self, frame: bytes) -> None:
        self.send_frame(frame)

    async def terminate(
        self, stream: "Stream", reason: CloseReason, notify: bool = True
    ) -> None:
        await self.close_stream(stream.stream_id, reason, notify=notify)

    async def close_stream(self, sid: int, reason: CloseReason, notify: bool = True) -> None:
        stream = self.streams.pop(sid, None)
        if stream is None:
            return
        if notify:
            self.send_frame(close_frame(sid, int(reason)))
        await stream.close()


class WsProxySession:
    """Legacy wsproxy tunnel: one raw TCP connection over one websocket.

    Path shape: anything not ending in "/", whose final segment parses as
    "host:port" (e.g. /proxy/example.com:443). No wisp framing: every binary
    websocket message is a raw TCP chunk in either direction.
    """

    def __init__(
        self, ws: Any, platform: Any, config: ServerConfig,
        host: str, port: int, label: str,
    ) -> None:
        self.ws = ws
        self.platform = platform
        self.config = config
        self.host = host
        self.port = port
        self.label = label
        self.stream: Optional[Stream] = None
        self.inbound: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue(
            maxsize=WS_SESSION_QUEUE_LIMIT
        )
        self.bytes_in = 0
        self.bytes_out = 0
        self.started = time.monotonic()
        self._stopping = False

    async def run(self) -> None:
        self.ws.set_handlers(self._on_ws_message, self._on_ws_close, self._on_ws_error)
        LOG.info("[%s] wsproxy tunnel to %s:%d", self.label, self.host, self.port)
        self.stream = Stream(self, 0, self.host, self.port, self.platform, self.config)
        try:
            while True:
                data = await self.inbound.get()
                if data is None or self._stopping or self.stream is None:
                    break
                self.bytes_in += len(data)
                await self.stream.on_client_data(data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.error("[%s] wsproxy loop crashed: %r", self.label, exc)
        finally:
            await self._teardown()

    async def _teardown(self) -> None:
        self._stopping = True
        if self.stream is not None:
            await self.stream.close()
            self.stream = None
        try:
            self.ws.close()
        except Exception:
            pass
        LOG.info("[%s] wsproxy tunnel closed: %d KiB in / %d KiB out, %.1fs",
                 self.label, self.bytes_in // 1024, self.bytes_out // 1024,
                 time.monotonic() - self.started)

    def _on_ws_message(self, data: bytes) -> None:
        if self._stopping:
            return
        try:
            self.inbound.put_nowait(data)
        except asyncio.QueueFull:
            LOG.error("[%s] wsproxy inbound overflow; aborting", self.label)
            self._stopping = True
            try:
                self.inbound.put_nowait(None)
            except asyncio.QueueFull:
                pass
            try:
                self.ws.close()
            except Exception:
                pass

    def _on_ws_close(self, code: int, reason: str) -> None:
        self._stopping = True
        try:
            self.inbound.put_nowait(None)
        except asyncio.QueueFull:
            pass

    def _on_ws_error(self, message: str) -> None:
        LOG.warning("[%s] wsproxy websocket error: %s", self.label, message)
        self._on_ws_close(0, message)

    # -- StreamChannel interface (no wisp framing on this path) -----------------

    def send_frame(self, frame: bytes) -> None:
        self.bytes_out += len(frame)
        try:
            self.ws.send(frame)
        except Exception as exc:
            LOG.debug("[%s] ws send failed: %r", self.label, exc)

    async def send_data(self, stream: "Stream", data: bytes) -> None:
        self.send_frame(data)

    def send_control(self, frame: bytes) -> None:
        pass  # CONTINUE frames are wisp-only; wsproxy has no flow control

    async def terminate(
        self, stream: "Stream", reason: CloseReason, notify: bool = True
    ) -> None:
        LOG.debug("[%s] tunnel ended (reason=0x%02x)", self.label, int(reason))
        if stream is self.stream:
            self.stream = None
        await stream.close()
        self._stopping = True
        try:
            self.ws.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Section 9: platform bridge — Cloudflare Workers (pyodide) implementation
# ---------------------------------------------------------------------------

_CF_CONNECT: Any = None


def _cf_connect() -> Any:
    """Lazily resolve cloudflare:sockets.connect (per-isolate cache)."""
    global _CF_CONNECT
    if _CF_CONNECT is None:
        if not WORKERS_RUNTIME:
            raise RuntimeError(
                "cloudflare:sockets is only available inside the Workers runtime"
            )
        _CF_CONNECT = _import_from_javascript("cloudflare:sockets").connect
    return _CF_CONNECT


class CloudflareTcpConnection:
    """A cloudflare:sockets TCP socket exposed as read()/write()/close()."""

    def __init__(self, js_socket: Any) -> None:
        self._sock = js_socket
        self._reader = js_socket.readable.getReader()
        self._writer = js_socket.writable.getWriter()

    async def read(self) -> Optional[bytes]:
        result = await self._reader.read()
        if bool(result.done):
            return None
        return bytes(result.value.to_bytes())

    async def write(self, data: bytes) -> None:
        await self._writer.write(_to_js(data))

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass


class CloudflareFetchResponse:
    """A fetch() Response with a list of headers and a chunk async-iterator."""

    def __init__(self, status: int, status_text: str,
                 headers: "list[tuple[str, str]]", reader: Any) -> None:
        self.status = status
        self.status_text = status_text
        self.headers = headers
        self._reader = reader

    async def body_chunks(self):
        if self._reader is None:
            return
        while True:
            chunk = await self._reader.read()
            if bool(chunk.done):
                break
            data = bytes(chunk.value.to_bytes())
            if data:
                yield data


class CloudflarePlatform:
    """Production platform: cloudflare:sockets for live-TCP, fetch for HTTP."""

    async def _await_js(self, promise: Any) -> Any:
        """Await a JS promise inside a real coroutine so asyncio.wait_for's
        ensure_future accepts it (a bare JsProxy is not always a Future)."""
        return await promise

    async def tcp_connect(self, host: str, port: int, timeout: float) -> CloudflareTcpConnection:
        address = f"{host}:{port}"
        try:
            sock = _cf_connect()(address)
        except Exception as exc:
            raise OutboundConnectError(
                classify_connect_failure(exc), f"connect({address}) failed: {exc}"
            ) from exc
        try:
            await asyncio.wait_for(self._await_js(sock.opened), timeout)
        except asyncio.TimeoutError:
            try:
                sock.close()
            except Exception:
                pass
            raise OutboundConnectError(
                CloseReason.CONNECT_TIMEOUT,
                f"connect({address}) timed out after {timeout:.1f}s",
            ) from None
        except Exception as exc:
            try:
                sock.close()
            except Exception:
                pass
            raise OutboundConnectError(
                classify_connect_failure(exc), f"connect({address}) failed: {exc}"
            ) from exc
        return CloudflareTcpConnection(sock)

    async def http_fetch(
        self,
        method: str,
        url: str,
        headers: "list[tuple[str, str]]",
        body: Optional[bytes],
        timeout: float,
    ) -> CloudflareFetchResponse:
        init: "dict[str, Any]" = {
            "method": method,
            "redirect": "manual",
            "headers": dict(headers),
        }
        if body is not None:
            init["body"] = _to_js(body)
        try:
            resp = await asyncio.wait_for(
                self._await_js(_js_fetch(url, _to_js(init, dict_converter=_JsObject.fromEntries))),
                timeout,
            )
        except asyncio.TimeoutError:
            raise OutboundConnectError(
                CloseReason.CONNECT_TIMEOUT, f"fetch({url}) timed out after {timeout:.1f}s"
            ) from None
        except Exception as exc:
            raise OutboundConnectError(
                classify_connect_failure(exc), f"fetch({url}) failed: {exc}"
            ) from exc
        status = int(resp.status)
        status_text = str(getattr(resp, "statusText", "") or "")
        header_list: "list[tuple[str, str]]" = []
        try:
            # NB: `Array.from` cannot be spelled `_JsArray.from(...)` in Python
            # (`from` is a keyword), hence the getattr indirection.
            js_from = getattr(_JsArray, "from")
            for pair in js_from(resp.headers.entries()).to_py():
                header_list.append((str(pair[0]), str(pair[1])))
        except Exception as exc:
            LOG.debug("fetch(%s): header enumeration failed: %r", url, exc)
        try:  # preserve multiple Set-Cookie headers if the runtime exposes them
            for value in resp.headers.getSetCookie().to_py():
                header_list.append(("set-cookie", str(value)))
        except Exception:
            pass
        reader = None
        if resp.body is not None:
            reader = resp.body.getReader()
        return CloudflareFetchResponse(status, status_text, header_list, reader)


class JsWsServerSocket:
    """The server end of a WebSocketPair behind the harness-compatible
    interface: set_handlers / send / close (all binary frames)."""

    def __init__(self, js_ws: Any) -> None:
        self.ws = js_ws
        try:
            self.ws.binaryType = "arraybuffer"  # must be set before accept()
        except Exception:
            pass
        # Keep strong references so pyodide never GCs the closures.
        self._message_impl: Optional[Callable[[Any], None]] = None
        self._close_impl: Optional[Callable[[Any], None]] = None
        self._error_impl: Optional[Callable[[Any], None]] = None

    def accept(self) -> None:
        self.ws.accept()

    def set_handlers(self, on_message: OnMessage, on_close: OnClose, on_error: OnError) -> None:
        def _message(evt: Any) -> None:
            try:
                data = evt.data
                if isinstance(data, str):
                    LOG.debug("[ws] ignoring non-binary frame (%d chars)", len(data))
                    return
                on_message(bytes(data.to_bytes()))
            except Exception as exc:
                LOG.error("[ws] message handler failed: %r", exc)

        def _close(evt: Any) -> None:
            try:
                code = int(evt.code)
            except Exception:
                code = 0
            try:
                reason = str(evt.reason or "")
            except Exception:
                reason = ""
            on_close(code, reason)

        def _error(evt: Any) -> None:
            on_error(str(evt))

        self._message_impl, self._close_impl, self._error_impl = _message, _close, _error
        self.ws.onmessage = _message
        self.ws.onclose = _close
        self.ws.onerror = _error

    def send(self, data: bytes) -> None:
        self.ws.send(_to_js(data))

    def close(self) -> None:
        try:
            self.ws.close(1000, "server closing")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Section 10: HTTP routing + the Workers entrypoint
# ---------------------------------------------------------------------------

_BACKGROUND_TASKS: "set[asyncio.Task[Any]]" = set()
_STARTUP_LOGGED = False


def _new_conn_label() -> str:
    return f"{random.getrandbits(32):08x}"


@dataclass
class WorkerResponse:
    """Environment-neutral response; converted per runtime at the edges."""

    status: int
    body: bytes = b""
    content_type: str = "text/plain; charset=utf-8"
    websocket: Any = None  # client end of the pair for 101 responses


def _parse_wsproxy_target(path: str) -> "tuple[Optional[str], Optional[int], Optional[str]]":
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    host, sep, port_s = segment.rpartition(":")
    if not sep or not host:
        return None, None, "expected .../host:port path"
    try:
        port = int(port_s)
    except ValueError:
        return None, None, f"invalid port {port_s!r}"
    if not 1 <= port <= 65535:
        return None, None, f"port {port} out of range"
    if len(host) > 255:
        return None, None, "hostname too long"
    return host, port, None


LANDING_HTML = f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>wisp-workers-python</title>
    <style>
      html {{ color-scheme: light dark; }}
      body {{ font-family: sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }}
      code {{ background: rgba(127,127,127,.15); padding: .1rem .3rem; border-radius: .3rem; }}
      pre {{ white-space: pre-wrap; background: rgba(127,127,127,.1); padding: 1rem; border-radius: .5rem; }}
    </style>
  </head>
  <body>
    <h1>wisp-workers-python</h1>
    <p>A <a href="https://github.com/MercuryWorkshop/wisp-protocol">Wisp v1</a> server running on
      Cloudflare Workers (Python) — v{__version__}.</p>
    <ul>
      <li>Protocol: Wisp v1 over WebSocket — connect to any path ending in <code>/</code>
        (traditionally <code>/wisp/</code>).</li>
      <li>Legacy wsproxy tunnels: <code>/host:port</code> paths.</li>
      <li>Outbound dual head: ports 80/443 HTTP traffic is delegated to <code>fetch()</code>;
        all other TCP traffic is tunneled via <code>cloudflare:sockets</code>.</li>
      <li>Congestion: {TCP_SLOTS} live-TCP + {HTTP_SLOTS} GET/HTTP in-flight requests
        (strict {TOTAL_OUTBOUND_SLOTS}), FIFO queued.</li>
      <li>UDP is not supported (Workers runtime limitation).</li>
    </ul>
    <pre>wisp-workers-python: a Wisp v1 server for Cloudflare Workers, written in Python
Ported from wisp-server-python — Copyright (C) 2025 Mercury Workshop (AGPL-3.0)

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.</pre>
  </body>
</html>
""".encode("utf-8")


async def route_request(
    request: Any,
    platform: Any,
    config: ServerConfig,
    ws_factory: Callable[[], "tuple[Any, Any]"],
    keep_alive: Callable[["asyncio.Task[Any]"], None],
) -> WorkerResponse:
    """Shared request routing, used by the Workers entrypoint and the local
    test harness (which supplies its own platform/websocket factory)."""
    url = str(getattr(request, "url", "/") or "/")
    method = str(getattr(request, "method", "GET") or "GET").upper()
    headers = getattr(request, "headers", None)

    def hget(name: str) -> str:
        try:
            value = headers.get(name)
        except Exception:
            value = None
        return str(value) if value is not None else ""

    upgrade = hget("Upgrade").strip().lower()
    path = urlsplit(url).path or "/"

    if upgrade == "websocket":
        if config.password is not None and f"/{config.password}/" not in path:
            LOG.warning("websocket rejected: bad password in path %r", path)
            return WorkerResponse(401, b"401 unauthorized: missing or wrong password\n")
        if path.endswith("/"):
            client_ws, server_ws = ws_factory()
            label = _new_conn_label()
            session = WispSession(server_ws, platform, config, label)
        else:
            host, port, err = _parse_wsproxy_target(path)
            if err is not None:
                LOG.warning("websocket path %r invalid: %s", path, err)
                return WorkerResponse(400, f"400 bad request: {err}\n".encode())
            client_ws, server_ws = ws_factory()
            label = _new_conn_label()
            session = WsProxySession(server_ws, platform, config, host, port, label)
        task = asyncio.ensure_future(session.run())
        keep_alive(task)
        return WorkerResponse(101, b"", websocket=client_ws)

    # Plain HTTP: informational landing page (parity with the reference).
    if path in ("/", "/index.html"):
        return WorkerResponse(200, LANDING_HTML, "text/html; charset=utf-8")
    return WorkerResponse(404, b"404 not found\n")


def _make_workers_response(resp: WorkerResponse) -> Any:
    if resp.status == 101:
        return _WorkersResponse(None, status=101, web_socket=resp.websocket)
    return _WorkersResponse(
        resp.body, status=resp.status,
        headers={"content-type": resp.content_type},
    )


class Default(_WorkerEntrypoint):  # type: ignore[misc,valid-type]
    """Cloudflare Workers entrypoint.

    Routes websocket upgrades to Wisp v1 sessions (paths ending in "/") or
    legacy wsproxy tunnels (/host:port), and serves a landing page otherwise.
    """

    async def fetch(self, request: Any) -> Any:
        global _STARTUP_LOGGED
        config = ServerConfig.from_env(getattr(self, "env", None))
        configure_logging(config.log_level)
        if not _STARTUP_LOGGED:
            _STARTUP_LOGGED = True
            LOG.info("wisp-workers-python v%s ready (workers_runtime=%s, %s)",
                     __version__, WORKERS_RUNTIME, get_governor().stats())

        def ws_factory() -> "tuple[Any, JsWsServerSocket]":
            pair = _JsWebSocketPair.new()
            client_ws, server_js = pair.object_values()
            wrapper = JsWsServerSocket(server_js)
            wrapper.accept()
            return client_ws, wrapper

        def keep_alive(task: "asyncio.Task[Any]") -> None:
            # Strong ref (GC safety) + waitUntil (invocation lifetime safety).
            _BACKGROUND_TASKS.add(task)
            task.add_done_callback(_BACKGROUND_TASKS.discard)
            ctx = getattr(self, "ctx", None)
            if ctx is not None:
                try:
                    ctx.waitUntil(task)
                except Exception as exc:
                    LOG.debug("waitUntil failed: %r", exc)

        try:
            resp = await route_request(
                request, CloudflarePlatform(), config, ws_factory, keep_alive
            )
        except Exception as exc:
            LOG.error("[entrypoint] route_request failed: %r", exc)
            return _make_workers_response(
                WorkerResponse(500, b"500 internal server error\n")
            )
        return _make_workers_response(resp)


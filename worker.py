"""Wisp proxy server for Cloudflare Workers (Python).

A single-file Wisp protocol server that runs on the Workers runtime via
Pyodide.  It implements the task's *dual-head architecture*:

  * **GET head**  - TCP streams destined for ports 80/443 are delegated to
    HTTP requests issued through the Workers ``fetch()`` API.  The client's
    plain-HTTP request is parsed off the Wisp stream, re-issued upstream and
    the response is synthesised back onto the stream.  (TLS-shaped traffic
    on 443 is detected and transparently falls back to the TCP head.)
  * **CONNECT head** - every other TCP stream is relayed through the
    ``connect()`` API from ``cloudflare:sockets`` (bridged by sockets.mjs).

Concurrency is governed by two global (per-isolate) pools with a hard limit
of 3 live TCP sockets and 3 in-flight GET/HTTP requests - six in-flight
outbound requests in total.  Streams beyond a pool's limit wait in a bounded
FIFO request queue with a timeout, exactly as required by the specification.

Wire-format compatibility (auto-detected per connection):

  * ``classic``  - the original MercuryWorkshop wisp v1 framing used by
    Scramjet / epoxy-tls clients: CONNECT=0x00, DATA=0x01, CONTINUE=0x02,
    CLOSE=0x03, big-endian integers, length-prefixed hostname, CONNECT
    acknowledgment from the server.
  * ``v1.2``     - the re-specified wisp-protocol v1.2 framing: CONNECT=0x01,
    DATA=0x02, CONTINUE=0x03 (u32 buffer-remaining), CLOSE=0x04, little-
    endian integers, hostname as rest-of-payload, server sends an initial
    CONTINUE on stream 0, no CONNECT ack.
  * ``v2``       - same framing as v1.2 plus the INFO handshake (selected
    when the client offers a ``Sec-WebSocket-Protocol`` header or opens with
    an INFO packet).  No extensions (and therefore no UDP) are advertised.

Multi-threading and UDP/datagram support are intentionally stripped: the
Workers runtime is single-threaded and exposes no UDP sockets.

Secure WebSockets: the Worker accepts ``Upgrade: websocket`` on any path and
always responds with a proper 101 (never a redirect), so it is fully usable
through ``wss://`` on ``*.workers.dev`` and custom domains.  Clients running
inside HTTPS pages/service workers MUST use ``wss://`` - browsers block
``ws://`` from secure contexts (Mixed Content / SecurityError).
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Coroutine, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from js import Object, Promise, Response, WebSocketPair, console, fetch
from pyodide.ffi import create_proxy, to_js

try:  # sockets.mjs re-exports cloudflare:sockets for the Python side
    from sockets import connect as _cf_connect
except ImportError:  # pragma: no cover - TCP head disabled, GET head still works
    _cf_connect = None  # type: ignore[assignment]

try:  # new-style entrypoint (workers-runtime-sdk)
    from workers import WorkerEntrypoint
except ImportError:  # old-style module handlers (older compatibility dates)
    WorkerEntrypoint = None  # type: ignore[assignment, misc]

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------


class _ClassicType:
    """Packet types of the original MercuryWorkshop wisp v1 framing."""

    CONNECT = 0x00
    DATA = 0x01
    CONTINUE = 0x02
    CLOSE = 0x03


class _V12Type:
    """Packet types of the wisp-protocol v1.2 / v2 framing."""

    CONNECT = 0x01
    DATA = 0x02
    CONTINUE = 0x03
    CLOSE = 0x04
    INFO = 0x05


STREAM_TCP = 0x01
STREAM_UDP = 0x02

# Close reasons (wisp specification, "server only" set).
REASON_UNSPECIFIED = 0x01
REASON_VOLUNTARY = 0x02
REASON_NETWORK_ERROR = 0x03
REASON_INVALID_INFO = 0x41
REASON_UNREACHABLE = 0x42
REASON_CONNECT_TIMEOUT = 0x43
REASON_REFUSED = 0x44
REASON_TRANSFER_TIMEOUT = 0x47
REASON_BLOCKED = 0x48
REASON_THROTTLED = 0x49

# ---------------------------------------------------------------------------
# Policy constants (strict task requirements + safety caps)
# ---------------------------------------------------------------------------

MAX_TCP_SLOTS = 3          # live TCP sockets via the CONNECT API (hard limit)
MAX_HTTP_SLOTS = 3         # in-flight GET/HTTP requests (hard limit)
GET_HEAD_PORTS = frozenset((80, 443))

MAX_FRAME_BYTES = 1 << 20  # largest accepted wisp packet (1 MiB)
MAX_DATA_FRAME = 65536     # largest DATA frame we send downstream
MAX_HTTP_HEAD = 16 * 1024  # request head cap for the GET head
MAX_HTTP_BODY = 10 << 20   # request body cap for the GET head
INBOUND_QUEUE_LIMIT = 256  # buffered client DATA packets per stream
SERVER_BUFFER_PACKETS = 64 # receive buffer announced to v1.2/v2 clients
INITIAL_TX_PACKETS = 8     # optimistic send budget before first CONTINUE
TX_PACKET_CAP = 512
DEFAULT_FLOW_WINDOW_BYTES = 262144

_HOP_BY_HOP_REQUEST = frozenset(
    (
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
    )
)
_HOP_BY_HOP_RESPONSE = frozenset(
    (
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    )
)

_HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"}
)

REASON_PHRASES: Dict[int, str] = {
    100: "Continue", 101: "Switching Protocols", 200: "OK", 201: "Created",
    202: "Accepted", 203: "Non-Authoritative Information", 204: "No Content",
    205: "Reset Content", 206: "Partial Content", 300: "Multiple Choices",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect", 400: "Bad Request",
    401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
    407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict",
    410: "Gone", 411: "Length Required", 412: "Precondition Failed",
    413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
    416: "Range Not Satisfiable", 417: "Expectation Failed",
    421: "Misdirected Request", 422: "Unprocessable Entity", 426: "Upgrade Required",
    429: "Too Many Requests", 431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons", 500: "Internal Server Error",
    501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
    504: "Gateway Timeout", 505: "HTTP Version Not Supported",
}

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WispProtocolError(Exception):
    """Malformed framing; the connection must be closed with 1002."""


class InvalidConnectPayload(Exception):
    """Malformed CONNECT payload; the stream must be closed with 0x41."""


class PoolQueueFullError(Exception):
    """The per-pool request queue is at its limit."""


class PoolAcquireTimeoutError(Exception):
    """A queued request waited longer than the configured timeout."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _env_get(env: Any, name: str) -> Optional[str]:
    if env is None:
        return None
    value: Any = None
    try:
        value = getattr(env, name, None)
    except Exception:  # noqa: BLE001 - JsProxy attribute access is best-effort
        value = None
    if value is None:
        try:
            value = env[name]
        except Exception:  # noqa: BLE001
            value = None
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:  # noqa: BLE001
        return None


def _env_int(env: Any, name: str, default: int, lo: int, hi: int) -> int:
    raw = _env_get(env, name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        console.warn(f"[wisp] invalid env {name}={raw!r}; using default {default}")
        return default
    if value < lo or value > hi:
        console.warn(f"[wisp] env {name}={value} out of range [{lo},{hi}]; using default {default}")
        return default
    return value


def _env_bool(env: Any, name: str, default: bool) -> bool:
    raw = _env_get(env, name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class WispConfig:
    """Runtime configuration (all values have safe defaults)."""

    log_level: str = "info"
    queue_limit: int = 64
    queue_timeout_ms: int = 15000
    connect_timeout_ms: int = 10000
    http_head_timeout_ms: int = 10000
    flow_window_bytes: int = DEFAULT_FLOW_WINDOW_BYTES
    continue_stall_ms: int = 30000
    greet_grace_ms: int = 250
    allow_tcp_fallback: bool = True
    classic_connect_ack: bool = True

    @classmethod
    def from_env(cls, env: Any) -> "WispConfig":
        level = (_env_get(env, "WISP_LOG_LEVEL") or "info").strip().lower()
        if level not in ("debug", "info", "warn", "error"):
            level = "info"
        return cls(
            log_level=level,
            queue_limit=_env_int(env, "WISP_QUEUE_LIMIT", 64, 0, 4096),
            queue_timeout_ms=_env_int(env, "WISP_QUEUE_TIMEOUT_MS", 15000, 100, 600000),
            connect_timeout_ms=_env_int(env, "WISP_CONNECT_TIMEOUT_MS", 10000, 100, 600000),
            http_head_timeout_ms=_env_int(env, "WISP_HTTP_HEAD_TIMEOUT_MS", 10000, 100, 600000),
            flow_window_bytes=_env_int(
                env, "WISP_FLOW_WINDOW_BYTES", DEFAULT_FLOW_WINDOW_BYTES, 4096, 1 << 24
            ),
            continue_stall_ms=_env_int(env, "WISP_CONTINUE_STALL_MS", 30000, 500, 600000),
            greet_grace_ms=_env_int(env, "WISP_GREET_GRACE_MS", 250, 0, 5000),
            allow_tcp_fallback=_env_bool(env, "WISP_ALLOW_TCP_FALLBACK", True),
            classic_connect_ack=_env_bool(env, "WISP_CLASSIC_CONNECT_ACK", True),
        )

    @property
    def queue_timeout_s(self) -> float:
        return self.queue_timeout_ms / 1000.0

    @property
    def connect_timeout_s(self) -> float:
        return self.connect_timeout_ms / 1000.0

    @property
    def http_head_timeout_s(self) -> float:
        return self.http_head_timeout_ms / 1000.0

    @property
    def continue_stall_s(self) -> float:
        return self.continue_stall_ms / 1000.0


# ---------------------------------------------------------------------------
# Logging (structured JSON lines)
# ---------------------------------------------------------------------------

_LEVELS: Dict[str, int] = {"debug": 10, "info": 20, "warn": 30, "error": 40}


class Logger:
    """Minimal structured logger writing single-line JSON to the console."""

    def __init__(self, level: str = "info", sink: Any = console, fields: Optional[Dict[str, Any]] = None) -> None:
        self._level = _LEVELS.get(level, 20)
        self._sink = sink
        self._fields: Dict[str, Any] = dict(fields or {})

    def bind(self, **fields: Any) -> "Logger":
        merged = dict(self._fields)
        merged.update(fields)
        return Logger(level=self._name_of(self._level), sink=self._sink, fields=merged)

    @staticmethod
    def _name_of(level: int) -> str:
        for name, value in _LEVELS.items():
            if value == level:
                return name
        return "info"

    def _emit(self, name: str, level: int, event: str, fields: Dict[str, Any]) -> None:
        if level < self._level:
            return
        record: Dict[str, Any] = {"ts": round(time.time(), 3), "level": name, "event": event}
        record.update(self._fields)
        record.update(fields)
        try:
            self._sink.log(json.dumps(record, separators=(",", ":"), default=str))
        except Exception:  # noqa: BLE001 - logging must never crash the worker
            pass

    def debug(self, event: str, **fields: Any) -> None:
        self._emit("debug", 10, event, fields)

    def info(self, event: str, **fields: Any) -> None:
        self._emit("info", 20, event, fields)

    def warn(self, event: str, **fields: Any) -> None:
        self._emit("warn", 30, event, fields)

    def error(self, event: str, **fields: Any) -> None:
        self._emit("error", 40, event, fields)


# ---------------------------------------------------------------------------
# Wire formats and packet codec
# ---------------------------------------------------------------------------


class WireFormat(Enum):
    CLASSIC = "classic"
    V12 = "v1.2"
    V2 = "v2"


@dataclass(frozen=True)
class WispPacket:
    ptype: int
    stream_id: int
    payload: bytes


@dataclass(frozen=True)
class ConnectRequest:
    protocol: int
    port: int
    hostname: str


def _encode_packet(wire: WireFormat, ptype: int, stream_id: int, payload: bytes = b"") -> bytes:
    if wire is WireFormat.CLASSIC:
        sid_bytes = stream_id.to_bytes(4, "big")
    else:
        sid_bytes = stream_id.to_bytes(4, "little")
    return bytes((ptype,)) + sid_bytes + payload


def _parse_packet(wire: WireFormat, buf: bytes) -> WispPacket:
    if len(buf) < 5:
        raise WispProtocolError("packet shorter than the 5-byte header")
    if wire is WireFormat.CLASSIC:
        stream_id = int.from_bytes(buf[1:5], "big")
    else:
        stream_id = int.from_bytes(buf[1:5], "little")
    return WispPacket(ptype=buf[0], stream_id=stream_id, payload=buf[5:])


def _parse_connect(wire: WireFormat, payload: bytes) -> ConnectRequest:
    if wire is WireFormat.CLASSIC:
        if len(payload) < 4:
            raise InvalidConnectPayload("classic CONNECT payload truncated")
        protocol = payload[0]
        port = int.from_bytes(payload[1:3], "big")
        host_len = payload[3]
        if len(payload) < 4 + host_len:
            raise InvalidConnectPayload("classic hostname overruns payload")
        if len(payload) != 4 + host_len:
            raise InvalidConnectPayload("trailing bytes after classic hostname")
        host_bytes = payload[4 : 4 + host_len]
    else:
        if len(payload) < 3:
            raise InvalidConnectPayload("v1.2 CONNECT payload truncated")
        protocol = payload[0]
        port = int.from_bytes(payload[1:3], "little")
        host_bytes = payload[3:]
    if protocol not in (STREAM_TCP, STREAM_UDP):
        raise InvalidConnectPayload(f"unknown stream type 0x{protocol:02x}")
    if not 1 <= port <= 65535:
        raise InvalidConnectPayload(f"invalid port {port}")
    if not 1 <= len(host_bytes) <= 255:
        raise InvalidConnectPayload(f"invalid hostname length {len(host_bytes)}")
    try:
        hostname = host_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidConnectPayload("hostname is not valid UTF-8") from exc
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in hostname):
        raise InvalidConnectPayload("hostname contains control characters")
    return ConnectRequest(protocol=protocol, port=port, hostname=hostname)


def _parse_continue_credit(wire: WireFormat, payload: bytes) -> Optional[int]:
    """Return the announced buffer-remaining (v1.2/v2) or None (classic)."""
    if wire is WireFormat.CLASSIC:
        return None
    if len(payload) < 4:
        return 1
    return int.from_bytes(payload[:4], "little")


# ---------------------------------------------------------------------------
# JS interop helpers
# ---------------------------------------------------------------------------


async def _await_js(promise: Any) -> Any:
    """Await a JS Promise (JsProxy) - wrapped so asyncio.wait_for can cancel."""
    return await promise


def _ws_payload_to_bytes(data: Any) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    if isinstance(data, str):
        return data.encode("utf-8")
    to_bytes = getattr(data, "to_bytes", None)
    if callable(to_bytes):
        try:
            return bytes(to_bytes())
        except Exception:  # noqa: BLE001 - fall through to buffer protocol
            pass
    try:
        return bytes(data)
    except Exception as exc:  # noqa: BLE001
        raise TypeError(f"unsupported websocket payload {type(data)!r}") from exc


def _to_bytes(value: Any) -> bytes:
    """Convert a stream chunk (bytes/JS typed array) to Python bytes."""
    return _ws_payload_to_bytes(value)


def _js_headers_to_dict(headers: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if headers is None:
        return result

    def _collect(value: Any, name: Any, _map: Any = None) -> None:
        result[str(name).lower()] = str(value)

    proxy = create_proxy(_collect)
    try:
        headers.forEach(proxy)
    except Exception:  # noqa: BLE001 - header collection is best-effort
        pass
    finally:
        destroy = getattr(proxy, "destroy", None)
        if callable(destroy):
            try:
                destroy()
            except Exception:  # noqa: BLE001
                pass
    return result


def _spawn_background(ctx: Any, coro: Coroutine[Any, Any, None], log: Logger) -> None:
    """Run a coroutine past the request lifetime via ctx.waitUntil."""
    task = asyncio.ensure_future(coro)
    wait_until = getattr(ctx, "waitUntil", None)
    if not callable(wait_until):
        return

    def _executor(resolve: Any, _reject: Any) -> None:
        def _done(completed: "asyncio.Task[None]") -> None:
            try:
                exc = completed.exception()
            except Exception:  # noqa: BLE001
                exc = None
            if exc is not None:
                log.error("background_task_failed", error=repr(exc))
            try:
                resolve(None)
            except Exception:  # noqa: BLE001
                pass

        task.add_done_callback(_done)

    try:
        wait_until(Promise.new(create_proxy(_executor)))
    except Exception:  # noqa: BLE001 - the task keeps running regardless
        pass


# ---------------------------------------------------------------------------
# Resource governance: 3 TCP + 3 HTTP slots with a bounded FIFO queue
# ---------------------------------------------------------------------------


class PoolSlot:
    """Handle proving ownership of one pool slot; release is idempotent."""

    def __init__(self, pool: "ResourcePool") -> None:
        self._pool = pool
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._pool.release_slot()


class ResourcePool:
    """Async pool with hard limit, bounded FIFO waiters and metrics."""

    def __init__(self, name: str, limit: int) -> None:
        self.name = name
        self._limit = limit
        self._semaphore = asyncio.Semaphore(limit)
        self._in_use = 0
        self._waiting = 0
        self._total_acquired = 0

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def in_use(self) -> int:
        return self._in_use

    @property
    def waiting(self) -> int:
        return self._waiting

    def metrics(self) -> Dict[str, int]:
        return {
            "limit": self._limit,
            "in_use": self._in_use,
            "waiting": self._waiting,
            "total_acquired": self._total_acquired,
        }

    async def acquire(
        self,
        queue_limit: int,
        timeout_s: float,
        log: Logger,
        stream_id: int,
    ) -> PoolSlot:
        """Acquire one slot, queueing behind at most ``queue_limit`` waiters.

        Every acquisition goes through the semaphore: a released credit is
        handed directly to the first waiter by asyncio.Semaphore, so a
        late arrival can never jump the queue (locked() stays true while a
        credit is in flight to a waiter)."""
        if self._semaphore.locked():
            # All slots are in use: apply queue admission control, then wait.
            if self._waiting >= queue_limit:
                raise PoolQueueFullError(
                    f"pool {self.name!r} queue full ({self._waiting}/{queue_limit})"
                )
            self._waiting += 1
            log.debug(
                "pool_queued",
                pool=self.name,
                stream=stream_id,
                waiting=self._waiting,
                in_use=self._in_use,
            )
            try:
                await asyncio.wait_for(self._semaphore.acquire(), timeout_s)
            except asyncio.TimeoutError as exc:
                raise PoolAcquireTimeoutError(
                    f"pool {self.name!r} queue timeout after {timeout_s:.2f}s"
                ) from exc
            finally:
                self._waiting -= 1
        else:
            # Fast path: a credit is available and no waiter can be queued
            # (waiters only exist while the semaphore is locked), so this
            # acquisition is immediate and cannot steal from anyone.
            await self._semaphore.acquire()
        self._in_use += 1
        self._total_acquired += 1
        log.debug("pool_acquired", pool=self.name, stream=stream_id, in_use=self._in_use)
        return PoolSlot(self)

    def release_slot(self) -> None:
        self._in_use = max(0, self._in_use - 1)
        self._semaphore.release()


class WispPools:
    """Global (per-isolate) pair of resource pools: 3 TCP + 3 GET/HTTP."""

    def __init__(self) -> None:
        self.tcp = ResourcePool("tcp", MAX_TCP_SLOTS)
        self.http = ResourcePool("http", MAX_HTTP_SLOTS)

    def snapshot(self) -> Dict[str, Dict[str, int]]:
        return {"tcp": self.tcp.metrics(), "http": self.http.metrics()}


_POOLS = WispPools()

# ---------------------------------------------------------------------------
# HTTP request parsing (GET head) + chunked decoding
# ---------------------------------------------------------------------------


class TcpFallbackNeeded(Exception):
    """The client's bytes are not plain HTTP; relay them over raw TCP."""

    def __init__(self, data: bytes) -> None:
        super().__init__("tcp fallback needed")
        self.data = data


class HttpHeadTooLarge(Exception):
    """Request head/body exceeded the configured cap."""


@dataclass(frozen=True)
class HttpRequest:
    method: str
    target: str
    version: str
    headers: Dict[str, str]
    body: Optional[bytes]


def _looks_like_http(chunk: bytes) -> bool:
    if not chunk:
        return False
    first = chunk[0:1]
    if not (b"A" <= first <= b"Z"):
        return False  # e.g. a TLS ClientHello starts with 0x16
    head = chunk[:32]
    return b" " in head or b"\r" in head or b"\n" in head


class HttpRequestParser:
    """Incremental HTTP/1.1 request parser with Content-Length/chunked body
    support.  Raises :class:`TcpFallbackNeeded` as soon as the stream is
    proven not to carry a plain-HTTP request."""

    def __init__(self, max_head: int, max_body: int) -> None:
        self._max_head = max_head
        self._max_body = max_body
        self._buf = bytearray()
        self._head: Optional[Tuple[str, str, str, Dict[str, str]]] = None
        self._body = bytearray()
        self._content_length: Optional[int] = None
        self._chunked = False
        self._chunk_size: Optional[int] = None
        self._chunk_final = False

    # -- public API ---------------------------------------------------------
    @property
    def complete(self) -> bool:
        if self._head is None:
            return False
        if self._chunked:
            return self._chunk_final
        if self._content_length is None:
            return True
        return len(self._body) >= self._content_length

    @property
    def raw(self) -> bytes:
        return bytes(self._buf) + bytes(self._body)

    def feed(self, chunk: bytes) -> None:
        if self._head is None:
            if not self._buf and chunk and not _looks_like_http(chunk):
                raise TcpFallbackNeeded(bytes(chunk))
            self._buf.extend(chunk)
            if len(self._buf) > self._max_head and b"\r\n\r\n" not in self._buf:
                raise HttpHeadTooLarge(f"head exceeds {self._max_head} bytes")
            self._try_parse_head()
        else:
            self._buf.extend(chunk)
            if len(self._buf) > self._max_head + self._max_body + 4096:
                raise HttpHeadTooLarge("body backlog exceeds cap")
            self._consume_body_buffer()

    def build(self) -> HttpRequest:
        if self._head is None or not self.complete:
            raise ValueError("parser is not complete")
        method, target, version, headers = self._head
        body: Optional[bytes] = None
        if self._chunked:
            body = bytes(self._body)
        elif self._content_length is not None and self._content_length > 0:
            body = bytes(self._body[: self._content_length])
        return HttpRequest(method=method, target=target, version=version, headers=headers, body=body)

    # -- internals ------------------------------------------------------------
    def _try_parse_head(self) -> None:
        idx = self._buf.find(b"\r\n\r\n")
        if idx < 0:
            return
        head_bytes = bytes(self._buf[:idx])
        self._buf = bytearray(self._buf[idx + 4 :])
        try:
            self._head = self._parse_head_bytes(head_bytes)
        except ValueError:
            # ASCII garbage that never parses as HTTP - fall back to raw TCP.
            raise TcpFallbackNeeded(head_bytes + b"\r\n\r\n" + bytes(self._buf)) from None
        self._consume_body_buffer()

    @staticmethod
    def _parse_head_bytes(head_bytes: bytes) -> Tuple[str, str, str, Dict[str, str]]:
        lines = head_bytes.split(b"\r\n")
        request_line = lines[0].decode("latin-1", "replace").strip()
        parts = request_line.split()
        if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
            raise ValueError(f"malformed request line: {request_line!r}")
        method, target, version = parts[0].upper(), parts[1], parts[2].upper()
        if method not in _HTTP_METHODS:
            raise ValueError(f"unknown method {method!r}")
        headers: Dict[str, str] = {}
        last_name: Optional[str] = None
        for raw_line in lines[1:]:
            if not raw_line:
                continue
            if raw_line[:1] in (b" ", b"\t") and last_name is not None:  # obs-fold
                headers[last_name] += " " + raw_line.decode("latin-1", "replace").strip()
                continue
            if b":" not in raw_line:
                raise ValueError("header line without colon")
            raw_name, _, raw_value = raw_line.partition(b":")
            name = raw_name.decode("latin-1", "replace").strip().lower()
            headers[name] = raw_value.decode("latin-1", "replace").strip()
            last_name = name
        return method, target, version, headers

    def _consume_body_buffer(self) -> None:
        assert self._head is not None
        headers = self._head[3]
        if self._content_length is None and not self._chunked:
            if headers.get("transfer-encoding", "").lower().find("chunked") >= 0:
                self._chunked = True
            else:
                cl = headers.get("content-length")
                if cl is None:
                    self._content_length = 0
                    return
                if not cl.strip().isdigit():
                    raise ValueError(f"bad content-length {cl!r}")
                self._content_length = int(cl)
                if self._content_length > self._max_body:
                    raise HttpHeadTooLarge(f"body exceeds {self._max_body} bytes")
        if self._chunked:
            self._consume_chunked()
        else:
            assert self._content_length is not None
            take = min(len(self._buf), self._content_length - len(self._body))
            if take > 0:
                self._body.extend(self._buf[:take])
                del self._buf[:take]

    def _consume_chunked(self) -> None:
        while True:
            if self._chunk_final:
                return
            if self._chunk_size is None:
                idx = self._buf.find(b"\r\n")
                if idx < 0:
                    if len(self._buf) > 64:
                        raise ValueError("chunk size line too long")
                    return
                size_token = bytes(self._buf[:idx]).split(b";", 1)[0].strip()
                del self._buf[: idx + 2]
                try:
                    size = int(size_token, 16)
                except ValueError as exc:
                    raise ValueError(f"bad chunk size {size_token!r}") from exc
                if size < 0:
                    raise ValueError("negative chunk size")
                if size == 0:
                    # trailer section: consume up to (and including) the blank line
                    if self._buf.startswith(b"\r\n"):
                        del self._buf[:2]
                        self._chunk_final = True
                    elif not self._buf:
                        return
                    else:
                        trailer_end = self._buf.find(b"\r\n\r\n")
                        single = self._buf.find(b"\r\n")
                        if trailer_end >= 0:
                            del self._buf[: trailer_end + 4]
                            self._chunk_final = True
                        elif single == 0:
                            del self._buf[:2]
                            self._chunk_final = True
                        elif single > 0:
                            # a trailer line arrived, the blank line has not:
                            del self._buf[: single + 2]
                    return
                self._chunk_size = size
                continue
            size = self._chunk_size
            needed = size + 2
            if len(self._buf) < needed:
                return
            if bytes(self._buf[size : size + 2]) != b"\r\n":
                raise ValueError("chunk data not CRLF terminated")
            self._body.extend(self._buf[:size])
            del self._buf[:needed]
            self._chunk_size = None
            if len(self._body) > self._max_body:
                raise HttpHeadTooLarge(f"chunked body exceeds {self._max_body} bytes")


# ---------------------------------------------------------------------------
# HTTP response synthesis (GET head)
# ---------------------------------------------------------------------------


def _chunk_encode(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n"


def _build_fetch_url(target: str, host: str, port: int) -> str:
    lowered = target.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return target
    path = target if target.startswith("/") else "/" + target
    if ":" in host and not host.startswith("["):
        authority = f"[{host}]"
    else:
        authority = host
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{authority}{path}"


# ---------------------------------------------------------------------------
# Wisp stream
# ---------------------------------------------------------------------------


class WispStream:
    """One multiplexed Wisp stream (client-side initiated TCP connection)."""

    def __init__(self, conn: "WispConnection", stream_id: int) -> None:
        self.conn = conn
        self.stream_id = stream_id
        self.inbound: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()
        self.slot: Optional[PoolSlot] = None
        self.tx_packets = INITIAL_TX_PACKETS
        self.tx_unacked_bytes = 0
        self.recv_packets = 0
        self.sent_packets = 0
        self.sent_bytes = 0
        self._tx_wake = asyncio.Event()
        self._client_closed = False
        self._server_closed = False
        self._disposed = False
        self.created = time.monotonic()

    # -- lifecycle ----------------------------------------------------------
    @property
    def is_finished(self) -> bool:
        return self._client_closed or self._server_closed or self._disposed

    @property
    def disposed(self) -> bool:
        return self._disposed

    def mark_client_closed(self) -> None:
        if self._client_closed or self._disposed:
            return
        self._client_closed = True
        self.inbound.put_nowait(None)

    def finish_server(self) -> None:
        self._server_closed = True
        self._tx_wake.set()

    def dispose(self) -> None:
        """Idempotent teardown: wake pumps and release the pool slot once."""
        if self._disposed:
            return
        self._disposed = True
        self._tx_wake.set()
        self.release_slot()

    def release_slot(self) -> None:
        slot, self.slot = self.slot, None
        if slot is not None:
            slot.release()

    def attach_slot(self, slot: PoolSlot) -> None:
        self.slot = slot

    # -- client -> server ------------------------------------------------------
    def feed(self, payload: bytes) -> None:
        if self.is_finished:
            return
        if self.inbound.qsize() >= INBOUND_QUEUE_LIMIT:
            self.conn.log.warn(
                "stream_throttled",
                stream=self.stream_id,
                buffered=self.inbound.qsize(),
            )
            self.conn.send_close(self.stream_id, REASON_THROTTLED)
            self.finish_server()
            return
        self.recv_packets += 1
        self.inbound.put_nowait(payload)

    async def recv(self, timeout_s: Optional[float] = None) -> Optional[bytes]:
        """Next inbound chunk, or None when the client closed the stream."""
        if timeout_s is None:
            item = await self.inbound.get()
        else:
            if timeout_s <= 0:
                raise asyncio.TimeoutError()
            item = await asyncio.wait_for(self.inbound.get(), timeout_s)
        return item

    # -- server -> client ------------------------------------------------------
    def notify_continue(self, credit: Optional[int]) -> None:
        if self.is_finished:
            return
        if credit is None:  # classic CONTINUE: one more packet may be sent
            self.tx_packets = min(self.tx_packets + 1, TX_PACKET_CAP)
        elif credit > 0:  # v1.2/v2: announced buffer-remaining
            self.tx_packets = min(max(self.tx_packets, credit), TX_PACKET_CAP)
        self.tx_unacked_bytes = 0  # client consumed everything sent so far
        self._tx_wake.set()

    async def send_data(self, data: bytes) -> bool:
        """Send bytes downstream in <=64KiB DATA frames, honouring the flow
        window (unacked bytes) and the packet budget.  Returns False when the
        stream or connection can no longer accept data."""
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            end = min(offset + MAX_DATA_FRAME, len(view))
            frame = bytes(view[offset:end])
            if not await self._await_send_budget(len(frame)):
                return False
            if not self.conn.send_data_frame(self.stream_id, frame):
                return False
            self.tx_packets -= 1
            self.tx_unacked_bytes += len(frame)
            self.sent_packets += 1
            self.sent_bytes += len(frame)
            offset = end
        return True

    async def _await_send_budget(self, frame_len: int) -> bool:
        stall_s = self.conn.config.continue_stall_s
        started = time.monotonic()
        while not self.is_finished:
            window_ok = self.tx_unacked_bytes + frame_len <= self.conn.config.flow_window_bytes
            if window_ok and self.tx_packets > 0:
                return True
            self._tx_wake.clear()
            # close the wakeup race before parking
            window_ok = self.tx_unacked_bytes + frame_len <= self.conn.config.flow_window_bytes
            if (window_ok and self.tx_packets > 0) or self.is_finished:
                continue
            waited = time.monotonic() - started
            if waited >= stall_s:
                self.conn.log.warn(
                    "stream_tx_stall_granted",
                    stream=self.stream_id,
                    waited_ms=int(waited * 1000),
                    unacked=self.tx_unacked_bytes,
                )
                self.tx_packets = max(self.tx_packets, 1)
                self.tx_unacked_bytes = 0
                return True
            try:
                await asyncio.wait_for(self._tx_wake.wait(), timeout=min(0.5, stall_s - waited))
            except asyncio.TimeoutError:
                pass
        return False


# ---------------------------------------------------------------------------
# Wisp connection (one WebSocket)
# ---------------------------------------------------------------------------


class WispConnection:
    """Per-WebSocket Wisp session: handshake detection, packet routing and
    stream supervision."""

    def __init__(
        self,
        server_ws: Any,
        config: WispConfig,
        pools: WispPools,
        log: Logger,
        conn_id: str,
        subprotocol_offered: bool,
    ) -> None:
        self.ws = server_ws
        self.config = config
        self.pools = pools
        self.log = log.bind(conn=conn_id)
        self.conn_id = conn_id
        self.subprotocol_offered = subprotocol_offered
        self.wire: Optional[WireFormat] = None
        self.streams: Dict[int, WispStream] = {}
        self._rx: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()
        self._tasks: Set["asyncio.Task[None]"] = set()
        self._proxies: List[Any] = []
        self._closing = False
        self._ws_closed = False
        self._info_sent = False
        self._v2_awaiting_client_info = False
        self._streams_opened = 0
        self._protocol_errors = 0
        self._started = time.monotonic()

    # -- setup ---------------------------------------------------------------
    def attach(self) -> None:
        """Accept the server socket and wire up the event listeners."""
        self.ws.accept()
        message_proxy = create_proxy(self._on_message)
        close_proxy = create_proxy(self._on_close_event)
        self._proxies = [message_proxy, close_proxy]
        self.ws.addEventListener("message", message_proxy)
        self.ws.addEventListener("close", close_proxy)

    # -- JS callbacks (called between awaits on the same thread) ---------------
    def _on_message(self, event: Any) -> None:
        if self._closing:
            return
        try:
            data = _ws_payload_to_bytes(getattr(event, "data", None))
        except Exception as exc:  # noqa: BLE001
            self.log.error("ws_binary_expected", error=repr(exc))
            self.close_ws(1003)
            return
        self._rx.put_nowait(data)

    def _on_close_event(self, _event: Any) -> None:
        self._rx.put_nowait(None)

    # -- main loop --------------------------------------------------------------
    async def run(self) -> None:
        try:
            await self._handshake_phase()
            while not self._closing:
                item = await self._rx.get()
                if item is None:
                    break
                if len(item) > MAX_FRAME_BYTES:
                    self.log.warn("frame_too_large", size=len(item), limit=MAX_FRAME_BYTES)
                    self.close_ws(1009)
                    break
                self._dispatch(item)  # WispProtocolError propagates to the handler below
        except WispProtocolError as exc:
            self._protocol_errors += 1
            self.log.warn("protocol_error", detail=str(exc))
            self.close_ws(1002)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - never let the task crash silently
            self.log.error("connection_loop_crash", error=repr(exc))
        finally:
            await self._teardown()

    # -- handshake / wire-format detection ----------------------------------------
    async def _handshake_phase(self) -> None:
        grace_s = max(0.0, self.config.greet_grace_ms / 1000.0)
        item: Optional[bytes] = None
        quiet = grace_s <= 0
        if grace_s > 0:
            try:
                item = await asyncio.wait_for(self._rx.get(), timeout=grace_s)
            except asyncio.TimeoutError:
                quiet = True
        if item is None:
            if not quiet:
                # The websocket closed while we were waiting for the client's
                # first packet: shut down cleanly (never mistake the close
                # sentinel for a quiet client - that would deadlock the queue).
                self._closing = True
                return
            # Quiet client: no packet within the grace window.  Committing to
            # v1.2 (or v2 when the client asked for a websocket subprotocol)
            # is safe: classic clients send their CONNECT immediately and are
            # detected inside the grace window.
            if self.subprotocol_offered:
                self._set_wire(WireFormat.V2)
                self._send_info_server()
                self._v2_awaiting_client_info = True
            else:
                self._set_wire(WireFormat.V12)
                self._send_initial_continue()
            item = await self._rx.get()
            if item is None:
                self._closing = True
                return
        self._classify_and_route(item)

    def _classify_and_route(self, data: bytes) -> None:
        if not data:
            raise WispProtocolError("empty frame")
        if len(data) > MAX_FRAME_BYTES:
            self.log.warn("frame_too_large", size=len(data), limit=MAX_FRAME_BYTES)
            self.close_ws(1009)
            self._closing = True
            return
        ptype = data[0]
        if ptype == _ClassicType.CONNECT:
            if self.wire is not WireFormat.CLASSIC:
                if self.wire is not None:
                    self.log.warn("late_classic_client", previous=self.wire.value)
                self._set_wire(WireFormat.CLASSIC)
            self._dispatch(data)
        elif ptype == _V12Type.CONNECT:
            if self.wire is None:
                self._set_wire(WireFormat.V12)
                self._send_initial_continue()
            elif self.wire is WireFormat.CLASSIC:
                raise WispProtocolError("v1.2 CONNECT after classic framing")
            self._dispatch(data)
        elif ptype == _V12Type.INFO:
            self._handle_v2_info(data)
        elif ptype == _V12Type.CLOSE:
            # v2 client rejected our handshake: close politely.
            self.log.info("handshake_rejected_by_client")
            self._closing = True
        else:
            raise WispProtocolError(f"unexpected leading packet type 0x{ptype:02x}")

    def _handle_v2_info(self, data: bytes) -> None:
        # Reaching here means the client's INFO packet has arrived (whether
        # it initiated or is answering ours): reply with the server INFO (if
        # not already sent) and finish the handshake with CONTINUE(0).
        self._set_wire(WireFormat.V2)
        if not self._info_sent:
            self._send_info_server()
        self._v2_awaiting_client_info = False
        self._send_initial_continue()
        self.log.debug("v2_handshake_complete", client_info_bytes=max(0, len(data) - 5))

    def _set_wire(self, wire: WireFormat) -> None:
        if self.wire is wire:
            return
        self.wire = wire
        self.log.info("wire_format_selected", wire=wire.value)

    # -- packet routing -----------------------------------------------------------
    def _dispatch(self, data: bytes) -> None:
        wire = self.wire
        if wire is None:
            raise WispProtocolError("dispatch before handshake")
        packet = _parse_packet(wire, data)
        if wire is WireFormat.CLASSIC:
            if packet.ptype == _ClassicType.CONNECT:
                self._handle_connect(packet)
            elif packet.ptype == _ClassicType.DATA:
                self._handle_data(packet)
            elif packet.ptype == _ClassicType.CONTINUE:
                self._handle_continue(packet, None)
            elif packet.ptype == _ClassicType.CLOSE:
                self._handle_close(packet)
            else:
                raise WispProtocolError(f"classic: unknown packet type 0x{packet.ptype:02x}")
        else:
            if packet.ptype == _V12Type.CONNECT:
                self._handle_connect(packet)
            elif packet.ptype == _V12Type.DATA:
                self._handle_data(packet)
            elif packet.ptype == _V12Type.CONTINUE:
                self._handle_continue(packet, _parse_continue_credit(wire, packet.payload))
            elif packet.ptype == _V12Type.CLOSE:
                self._handle_close(packet)
            elif packet.ptype == _V12Type.INFO:
                self._handle_info_packet(packet)
            else:
                raise WispProtocolError(f"v1.2: unknown packet type 0x{packet.ptype:02x}")

    def _handle_connect(self, packet: WispPacket) -> None:
        wire = self.wire
        assert wire is not None
        if packet.stream_id == 0:
            raise WispProtocolError("stream id 0 is reserved")
        if packet.stream_id in self.streams:
            self.log.warn("duplicate_stream_id", stream=packet.stream_id)
            self.send_close(packet.stream_id, REASON_INVALID_INFO)
            return
        try:
            request = _parse_connect(wire, packet.payload)
        except InvalidConnectPayload as exc:
            self.log.warn("invalid_connect", stream=packet.stream_id, detail=str(exc))
            self.send_close(packet.stream_id, REASON_INVALID_INFO)
            return
        if request.protocol == STREAM_UDP:
            self.log.info(
                "udp_rejected",
                stream=packet.stream_id,
                host=request.hostname,
                port=request.port,
            )
            self.send_close(packet.stream_id, REASON_BLOCKED)
            return
        stream = WispStream(self, packet.stream_id)
        self.streams[packet.stream_id] = stream
        self._streams_opened += 1
        head = "http" if request.port in GET_HEAD_PORTS else "tcp"
        self.log.info(
            "stream_open",
            stream=packet.stream_id,
            head=head,
            host=request.hostname,
            port=request.port,
        )
        self._spawn(self._open_stream(stream, request.hostname, request.port, head))

    def _handle_data(self, packet: WispPacket) -> None:
        stream = self.streams.get(packet.stream_id)
        if stream is None:
            self.log.debug("data_for_unknown_stream", stream=packet.stream_id)
            return
        stream.feed(packet.payload)

    def _handle_continue(self, packet: WispPacket, credit: Optional[int]) -> None:
        stream = self.streams.get(packet.stream_id)
        if stream is None:
            self.log.debug("continue_for_unknown_stream", stream=packet.stream_id)
            return
        stream.notify_continue(credit)

    def _handle_close(self, packet: WispPacket) -> None:
        if packet.stream_id == 0:
            self.log.info("handshake_rejected_by_client")
            self._closing = True
            return
        stream = self.streams.get(packet.stream_id)
        if stream is None:
            self.log.debug("close_for_unknown_stream", stream=packet.stream_id)
            return
        self.log.info("stream_close_by_client", stream=packet.stream_id)
        stream.mark_client_closed()

    def _handle_info_packet(self, packet: WispPacket) -> None:
        if self.wire is WireFormat.V2 and self._v2_awaiting_client_info:
            self._v2_awaiting_client_info = False
            self._send_initial_continue()
            self.log.debug("v2_handshake_complete")
        else:
            self.log.debug("unexpected_info_packet", stream=packet.stream_id)

    # -- outbound packets ------------------------------------------------------------
    def _send_raw(self, payload: bytes) -> bool:
        if self._closing:
            return False
        try:
            self.ws.send(to_js(payload))
            return True
        except Exception as exc:  # noqa: BLE001 - peer may vanish at any time
            self.log.debug("ws_send_failed", error=repr(exc))
            self._closing = True
            return False

    def send_data_frame(self, stream_id: int, chunk: bytes) -> bool:
        wire = self.wire or WireFormat.V12
        ptype = _ClassicType.DATA if wire is WireFormat.CLASSIC else _V12Type.DATA
        return self._send_raw(_encode_packet(wire, ptype, stream_id, chunk))

    def send_continue(self, stream_id: int) -> bool:
        wire = self.wire
        if wire is None:
            return False
        if wire is WireFormat.CLASSIC:
            payload = b""
            ptype = _ClassicType.CONTINUE
        else:
            payload = SERVER_BUFFER_PACKETS.to_bytes(4, "little")
            ptype = _V12Type.CONTINUE
        return self._send_raw(_encode_packet(wire, ptype, stream_id, payload))

    def _send_initial_continue(self) -> bool:
        wire = self.wire
        if wire is None or wire is WireFormat.CLASSIC:
            return False
        # v1.2/v2: CONTINUE on stream 0 announces the per-stream buffer size.
        return self.send_continue(0)

    def send_close(self, stream_id: int, reason: int) -> bool:
        wire = self.wire
        if wire is None:
            return False
        ptype = _ClassicType.CLOSE if wire is WireFormat.CLASSIC else _V12Type.CLOSE
        return self._send_raw(_encode_packet(wire, ptype, stream_id, bytes((reason,))))

    def _send_connect_ack(self, stream_id: int) -> bool:
        # classic-only: CONNECT (0x00) with a single status byte, 0x00 = OK
        return self._send_raw(_encode_packet(WireFormat.CLASSIC, _ClassicType.CONNECT, stream_id, b"\x00"))

    def _send_info_server(self) -> bool:
        # v2 INFO: version 2.1, no extensions (UDP is intentionally absent).
        if self._info_sent:
            return True
        self._info_sent = True
        payload = bytes((2, 1))
        return self._send_raw(_encode_packet(WireFormat.V12, _V12Type.INFO, 0, payload))

    # -- stream supervision ------------------------------------------------------------
    def _spawn(self, coro: Coroutine[Any, Any, None]) -> "asyncio.Task[None]":
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _open_stream(self, stream: WispStream, host: str, port: int, head: str) -> None:
        pool = self.pools.http if head == "http" else self.pools.tcp
        try:
            slot = await pool.acquire(
                self.config.queue_limit, self.config.queue_timeout_s, self.log, stream.stream_id
            )
        except PoolQueueFullError as exc:
            self.log.warn("stream_rejected_queue_full", stream=stream.stream_id, detail=str(exc))
            self.send_close(stream.stream_id, REASON_THROTTLED)
            self._drop_stream(stream)
            return
        except PoolAcquireTimeoutError as exc:
            self.log.warn("stream_queue_timeout", stream=stream.stream_id, detail=str(exc))
            self.send_close(stream.stream_id, REASON_CONNECT_TIMEOUT)
            self._drop_stream(stream)
            return
        except asyncio.CancelledError:
            self._drop_stream(stream)
            raise
        if stream.is_finished:
            slot.release()
            self._drop_stream(stream)
            return
        stream.attach_slot(slot)
        try:
            if head == "http":
                await self._run_http_head(stream, host, port)
            else:
                await self._run_tcp_head(stream, host, port, b"")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - one stream must not kill others
            self.log.error("stream_task_crash", stream=stream.stream_id, error=repr(exc))
            self.send_close(stream.stream_id, REASON_UNSPECIFIED)
        finally:
            stream.dispose()
            self._drop_stream(stream)

    def _drop_stream(self, stream: WispStream) -> None:
        existing = self.streams.pop(stream.stream_id, None)
        if existing is not None:
            self.log.info(
                "stream_closed",
                stream=stream.stream_id,
                recv_packets=stream.recv_packets,
                sent_packets=stream.sent_packets,
                sent_bytes=stream.sent_bytes,
                lifetime_ms=int((time.monotonic() - stream.created) * 1000),
            )

    # -- CONNECT head: raw TCP via cloudflare:sockets ------------------------------------
    async def _run_tcp_head(self, stream: WispStream, host: str, port: int, initial: bytes) -> None:
        sid = stream.stream_id
        if _cf_connect is None:
            self.log.error("tcp_head_unavailable", stream=sid)
            self.send_close(sid, REASON_INVALID_INFO)
            return
        address = f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"
        try:
            socket = _cf_connect(address)
        except Exception as exc:  # noqa: BLE001
            self.log.warn("tcp_connect_failed", stream=sid, address=address, error=repr(exc))
            self.send_close(sid, REASON_UNREACHABLE)
            return
        try:
            await asyncio.wait_for(_await_js(socket.opened), timeout=self.config.connect_timeout_s)
        except asyncio.TimeoutError:
            self.log.warn("tcp_connect_timeout", stream=sid, address=address)
            self.send_close(sid, REASON_CONNECT_TIMEOUT)
            self._safe_socket_close(socket)
            return
        except asyncio.CancelledError:
            self._safe_socket_close(socket)
            raise
        except Exception as exc:  # noqa: BLE001
            self.log.warn("tcp_connect_refused", stream=sid, address=address, error=repr(exc))
            self.send_close(sid, REASON_REFUSED)
            self._safe_socket_close(socket)
            return
        if self.wire is WireFormat.CLASSIC and self.config.classic_connect_ack:
            self._send_connect_ack(sid)
        self.log.debug("tcp_connected", stream=sid, address=address)

        writer: Any = None
        reader: Any = None
        upstream: Optional["asyncio.Task[None]"] = None
        downstream: Optional["asyncio.Task[None]"] = None
        try:
            writer = socket.writable.getWriter()
            reader = socket.readable.getReader()
            if initial:
                # The fallback bytes must reach the target before anything
                # the client queued behind them, so write before pumping.
                await writer.write(to_js(initial))
            upstream = self._spawn(self._pump_upstream(stream, writer))
            downstream = self._spawn(self._pump_downstream(stream, reader, socket))
            done, pending = await asyncio.wait(
                {upstream, downstream}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                done_error = task.exception()
                if done_error is not None:
                    self.log.debug("pump_failed", stream=sid, error=repr(done_error))
            if downstream in done and not stream.is_finished:
                # target EOF: report a normal server-side close to the client
                self.send_close(sid, REASON_VOLUNTARY)
        except asyncio.CancelledError:
            pending_tasks = [task for task in (upstream, downstream) if task is not None]
            for task in pending_tasks:
                task.cancel()
            await asyncio.gather(*pending_tasks, return_exceptions=True)
            raise
        finally:
            if writer is not None:
                await self._safe_close_writer(writer)
            self._safe_socket_close(socket)

    async def _pump_upstream(self, stream: WispStream, writer: Any) -> None:
        """Client DATA -> TCP socket; emits CONTINUE per consumed packet."""
        while True:
            chunk = await stream.inbound.get()
            if chunk is None:
                return
            if not chunk:
                continue
            try:
                await writer.write(to_js(chunk))
            except Exception as exc:  # noqa: BLE001 - target gone
                stream.conn.log.debug("tcp_write_failed", stream=stream.stream_id, error=repr(exc))
                stream.finish_server()
                return
            self.send_continue(stream.stream_id)

    async def _pump_downstream(self, stream: WispStream, reader: Any, socket: Any) -> None:
        """TCP socket -> client DATA frames (flow-window gated)."""
        while True:
            try:
                result = await reader.read()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - target gone
                stream.conn.log.debug("tcp_read_failed", stream=stream.stream_id, error=repr(exc))
                return
            if stream.is_finished:
                return
            if bool(getattr(result, "done", False)):
                return
            value = getattr(result, "value", None)
            if value is None:
                return
            data = _to_bytes(value)
            if not data:
                continue
            if not await stream.send_data(data):
                return

    @staticmethod
    async def _safe_close_writer(writer: Any) -> None:
        close = getattr(writer, "close", None)
        if not callable(close):
            return
        try:
            result = close()
        except Exception:  # noqa: BLE001
            return
        try:
            if asyncio.iscoroutine(result):
                await result
            elif result is not None and hasattr(result, "then"):
                await _await_js(result)
        except (Exception, asyncio.CancelledError):  # noqa: BLE001 - teardown path
            pass

    @staticmethod
    def _safe_socket_close(socket: Any) -> None:
        try:
            close = getattr(socket, "close", None)
            if callable(close):
                close()
        except Exception:  # noqa: BLE001
            pass

    # -- GET head: delegate 80/443 traffic to fetch() --------------------------------------
    async def _run_http_head(self, stream: WispStream, host: str, port: int) -> None:
        sid = stream.stream_id
        if self.wire is WireFormat.CLASSIC and self.config.classic_connect_ack:
            self._send_connect_ack(sid)
        parser = HttpRequestParser(MAX_HTTP_HEAD, MAX_HTTP_BODY)
        fallback: Optional[bytes] = None
        deadline = time.monotonic() + self.config.http_head_timeout_s
        while not parser.complete:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.log.warn("http_head_timeout", stream=sid)
                self.send_close(sid, REASON_TRANSFER_TIMEOUT)
                return
            try:
                chunk = await stream.recv(timeout_s=remaining)
            except asyncio.TimeoutError:
                self.log.warn("http_head_timeout", stream=sid)
                self.send_close(sid, REASON_TRANSFER_TIMEOUT)
                return
            if chunk is None:
                self.log.debug("http_client_closed_early", stream=sid)
                return
            try:
                parser.feed(chunk)
            except TcpFallbackNeeded as need:
                fallback = need.data
                break
            except HttpHeadTooLarge as exc:
                self.log.warn("http_head_too_large", stream=sid, detail=str(exc))
                self.send_close(sid, REASON_TRANSFER_TIMEOUT)
                return
            except ValueError as exc:
                self.log.warn("http_malformed", stream=sid, detail=str(exc))
                self.send_close(sid, REASON_TRANSFER_TIMEOUT)
                return
            if not parser.complete:
                self.send_continue(sid)
        if fallback is not None:
            await self._fallback_to_tcp(stream, host, port, fallback)
            return
        request = parser.build()
        self.log.info(
            "http_request",
            stream=sid,
            method=request.method,
            target=request.target,
            host=host,
            port=port,
        )
        try:
            response = await self._issue_fetch(request, host, port)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - upstream/network failure
            self.log.warn("fetch_failed", stream=sid, error=repr(exc))
            await self._send_http_synthetic(stream, 502, "wisp-worker: upstream fetch failed")
            return
        try:
            relayed = await self._relay_http_response(stream, request.method, response)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.log.warn("http_relay_failed", stream=sid, error=repr(exc))
            return
        if relayed and not stream.is_finished:
            self.send_close(sid, REASON_VOLUNTARY)

    async def _fallback_to_tcp(self, stream: WispStream, host: str, port: int, initial: bytes) -> None:
        sid = stream.stream_id
        self.log.info("http_fallback_tcp", stream=sid, host=host, port=port, bytes=len(initial))
        if not self.config.allow_tcp_fallback:
            self.send_close(sid, REASON_INVALID_INFO)
            return
        stream.release_slot()  # return the GET slot, then queue for a TCP slot
        try:
            slot = await self.pools.tcp.acquire(
                self.config.queue_limit, self.config.queue_timeout_s, self.log, sid
            )
        except PoolQueueFullError:
            self.send_close(sid, REASON_THROTTLED)
            return
        except PoolAcquireTimeoutError:
            self.send_close(sid, REASON_CONNECT_TIMEOUT)
            return
        if stream.is_finished:
            slot.release()
            return
        stream.attach_slot(slot)
        await self._run_tcp_head(stream, host, port, initial)

    async def _issue_fetch(self, request: HttpRequest, host: str, port: int) -> Any:
        url = _build_fetch_url(request.target, host, port)
        headers: Dict[str, str] = {}
        for name, value in request.headers.items():
            if name in _HOP_BY_HOP_REQUEST:
                continue
            headers[name] = value
        init: Dict[str, Any] = {"method": request.method, "headers": headers}
        if request.body:
            init["body"] = request.body
        self.log.debug("fetch_issue", url=url, method=request.method)
        return await fetch(url, to_js(init, dict_converter=Object.fromEntries))

    async def _relay_http_response(self, stream: WispStream, method: str, response: Any) -> bool:
        status = int(getattr(response, "status", 502) or 502)
        status_text = str(getattr(response, "statusText", "") or "")
        if not status_text:
            status_text = REASON_PHRASES.get(status, "Unknown")
        headers = _js_headers_to_dict(getattr(response, "headers", None))
        bodyless = status in (204, 304) or method == "HEAD"
        has_length = "content-length" in headers
        use_chunked = (not has_length) and (not bodyless)
        lines: List[str] = [f"HTTP/1.1 {status} {status_text}"]
        for name, value in headers.items():
            if name in _HOP_BY_HOP_RESPONSE:
                continue
            if name == "content-length" and use_chunked:
                continue
            lines.append(f"{name}: {value}")
        if use_chunked:
            lines.append("Transfer-Encoding: chunked")
        lines.append("Connection: close")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace")
        if not await stream.send_data(head):
            return False
        if bodyless:
            return True
        body = getattr(response, "body", None)
        if body is None:
            if use_chunked and not await stream.send_data(b"0\r\n\r\n"):
                return False
            return True
        reader = body.getReader()
        try:
            while True:
                result = await reader.read()
                if bool(getattr(result, "done", False)):
                    break
                chunk_value = getattr(result, "value", None)
                if chunk_value is None:
                    break
                data = _to_bytes(chunk_value)
                if not data:
                    continue
                if use_chunked:
                    data = _chunk_encode(data)
                if not await stream.send_data(data):
                    return False
            if use_chunked and not await stream.send_data(b"0\r\n\r\n"):
                return False
            return True
        finally:
            try:
                cancel = getattr(reader, "cancel", None)
                if callable(cancel):
                    cancel()
            except Exception:  # noqa: BLE001
                pass

    async def _send_http_synthetic(self, stream: WispStream, status: int, message: str) -> None:
        body = (message + "\n").encode("utf-8")
        head = (
            f"HTTP/1.1 {status} {REASON_PHRASES.get(status, 'Unknown')}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        await stream.send_data(head + body)

    # -- teardown ----------------------------------------------------------------------------
    def close_ws(self, code: int = 1000) -> None:
        """Close the underlying websocket; idempotent at the socket level."""
        if self._ws_closed:
            return
        self._ws_closed = True
        self._closing = True
        try:
            self.ws.close(code)
        except Exception:  # noqa: BLE001
            pass

    async def _teardown(self) -> None:
        self._closing = True
        for stream in list(self.streams.values()):
            stream.mark_client_closed()
            stream.finish_server()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        for stream in list(self.streams.values()):
            stream.dispose()
        self.streams.clear()
        self.close_ws(1000)
        for proxy in self._proxies:
            destroy = getattr(proxy, "destroy", None)
            if callable(destroy):
                try:
                    destroy()
                except Exception:  # noqa: BLE001
                    pass
        self._proxies.clear()
        self.log.info(
            "connection_closed",
            streams=self._streams_opened,
            protocol_errors=self._protocol_errors,
            duration_ms=int((time.monotonic() - self._started) * 1000),
        )


# ---------------------------------------------------------------------------
# HTTP surface: status document, CORS, 404
# ---------------------------------------------------------------------------


def _json_response(payload: Dict[str, Any], status: int = 200) -> Any:
    body = json.dumps(payload, indent=2, default=str)
    headers = {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "*",
        "access-control-allow-methods": "GET, HEAD, OPTIONS",
    }
    init: Dict[str, Any] = {"status": status, "headers": headers}
    return Response.new(body, to_js(init, dict_converter=Object.fromEntries))


def _status_document(request_url: str, pools: WispPools) -> Dict[str, Any]:
    parsed = urlparse(request_url)
    host = parsed.netloc or "your-worker.workers.dev"
    return {
        "status": "ok",
        "service": "wisp-worker",
        "endpoint": f"wss://{host}/",
        "protocol": {
            "wisp": ["v1-classic", "v1.2", "v2"],
            "udp": "disabled",
            "extensions": [],
        },
        "limits": {
            "tcp_slots": MAX_TCP_SLOTS,
            "http_slots": MAX_HTTP_SLOTS,
            "total_in_flight": MAX_TCP_SLOTS + MAX_HTTP_SLOTS,
            "queue": "bounded FIFO per pool",
        },
        "pools": pools.snapshot(),
        "note": (
            "Secure WebSocket only: clients loaded from HTTPS pages/service "
            "workers must use wss:// (ws:// is blocked as mixed content)."
        ),
    }


def _handle_plain_http(request: Any, config: WispConfig, log: Logger, pools: WispPools) -> Any:
    method = str(getattr(request, "method", "GET") or "GET").upper()
    url = str(getattr(request, "url", "/") or "/")
    path = urlparse(url).path or "/"
    if method == "OPTIONS":
        return _json_response({"status": "ok"}, status=204)
    if method in ("GET", "HEAD") and path in ("/", "/wisp/", "/health", "/status"):
        log.info("status_request", path=path, method=method)
        return _json_response(_status_document(url, pools))
    if path in ("/", "/wisp/", "/health", "/status"):
        return _json_response({"error": "method not allowed", "method": method}, status=405)
    return _json_response({"error": "not found", "path": path}, status=404)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


async def _handle_fetch(request: Any, env: Any, ctx: Any) -> Any:
    config = WispConfig.from_env(env)
    log = Logger(config.log_level)
    try:
        headers = getattr(request, "headers", None)
        upgrade = ""
        if headers is not None:
            try:
                upgrade = str(headers.get("Upgrade") or "").strip().lower()
            except Exception:  # noqa: BLE001
                upgrade = ""
    except Exception:  # noqa: BLE001
        upgrade = ""
    if upgrade == "websocket":
        return _accept_websocket(request, ctx, config, log)
    return _handle_plain_http(request, config, log, _POOLS)


def _accept_websocket(request: Any, ctx: Any, config: WispConfig, log: Logger) -> Any:
    pair = WebSocketPair.new()
    parts = pair.to_py() if hasattr(pair, "to_py") else list(pair)
    server_ws = parts[1]
    server_ws.accept()
    offered = ""
    headers = getattr(request, "headers", None)
    if headers is not None:
        try:
            offered = str(headers.get("sec-websocket-protocol") or "").strip()
        except Exception:  # noqa: BLE001
            offered = ""
    conn_id = uuid.uuid4().hex[:8]
    conn_log = log.bind(conn=conn_id)
    conn_log.info("websocket_accepted")
    connection = WispConnection(
        server_ws=server_ws,
        config=config,
        pools=_POOLS,
        log=log,
        conn_id=conn_id,
        subprotocol_offered=bool(offered),
    )
    connection.attach()
    _spawn_background(ctx, connection.run(), conn_log)
    init: Dict[str, Any] = {"status": 101, "webSocket": server_ws}
    if offered:
        # Echo the first offered subprotocol (some clients require it).
        init["headers"] = {"sec-websocket-protocol": offered.split(",")[0].strip()}
    return Response.new(None, to_js(init, dict_converter=Object.fromEntries))


if WorkerEntrypoint is not None:

    class Default(WorkerEntrypoint):
        """New-style Python Workers entrypoint (workers-runtime-sdk)."""

        async def fetch(self, request: Any) -> Any:
            return await _handle_fetch(
                request, getattr(self, "env", None), getattr(self, "ctx", None)
            )

else:

    async def on_fetch(request: Any, env: Any, ctx: Any) -> Any:
        """Old-style module handler (older compatibility dates)."""
        return await _handle_fetch(request, env, ctx)

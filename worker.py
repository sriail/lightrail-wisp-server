"""Wisp proxy server for Cloudflare Workers (Python).

A single-file Wisp protocol server that runs on the Workers runtime via
Pyodide.  It implements the task's *dual-head architecture*:

  * **GET head**  - TCP streams destined for plaintext-HTTP ports (port 80 by
    default, ``WISP_HTTP_HEAD_PORTS``) are delegated to HTTP requests issued
    through the Workers ``fetch()`` API.  The client's plain-HTTP request is
    parsed off the Wisp stream, re-issued upstream and the response is
    synthesised back onto the stream.  Bytes that are not plain HTTP (e.g. a
    TLS ClientHello, or an ``Upgrade:`` request) are transparently re-routed
    to the TCP head.
  * **CONNECT head** - every other TCP stream - **including port 443** - is
    relayed through the ``connect()`` API from ``cloudflare:sockets``
    (bridged by sockets.mjs).  Scramjet/Epoxy performs *client-side* TLS
    (rustls) on 443 streams and writes the handshake bytes straight into the
    Wisp stream, so 443 must be a transparent TCP tunnel: ``fetch()`` can
    neither carry nor answer those bytes.  ``connect()`` with the default
    ``secureTransport: "off"`` provides exactly such a raw socket (the
    runtime performs no automatic TLS upgrade on 443).

Wisp v1/v1.2 flow control is direction-asymmetric, exactly like the
reference servers (wisp-server-python and wisp-server-workers):

  * client -> server DATA is paced by **server-sent CONTINUE** packets that
    announce the server's per-stream receive buffer (``SERVER_BUFFER_PACKETS``
    packets); the server re-announces as it consumes queue items;
  * server -> client DATA is **not gated** on any client acknowledgement -
    the protocol defines no client->server CONTINUE.  (Epoxy 2.1.20 never
    sends one; gating on it stalls a tunnel after a handful of frames.)
    Memory is protected by per-stream inbound byte caps, optional
    ``bufferedAmount`` gating (``WISP_TX_BUFFER_GATE``) and idle watchdogs.

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


def _resolve_cf_connect() -> Any:
    """Locate the Cloudflare TCP ``connect()`` API for the CONNECT head.

    Two supported routes, tried in order:

    1. ``import_from_javascript("cloudflare:sockets")`` - the built-in
       runtime SDK route.  workerd pre-imports ``cloudflare:sockets``, so
       this works with no extra wrangler configuration.
    2. ``from sockets import connect`` - the ``sockets.mjs`` ES-module
       bridge, bundled when wrangler.toml carries an ``[[rules]]`` block
       with ``type = "ESModule"`` and ``globs = ["**/*.mjs"]``.

    Returns ``None`` when neither is importable: the TCP head is then
    disabled and only ports 80/443 (the fetch head) can be served.
    """
    try:
        from workers import import_from_javascript

        return import_from_javascript("cloudflare:sockets").connect
    except Exception:  # noqa: BLE001 - fall through to the .mjs bridge
        pass
    try:
        from sockets import connect

        return connect
    except Exception:  # noqa: BLE001 - TCP head disabled, GET head still works
        return None


_cf_connect = _resolve_cf_connect()
if _cf_connect is None:  # pragma: no cover - depends on the deployment bundle
    console.warn(
        "[wisp] cloudflare:sockets is not importable: the TCP head is "
        "disabled and only ports 80/443 (fetch head) will be served"
    )

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
DEFAULT_HTTP_HEAD_PORTS = frozenset((80,))
# Port 443 is intentionally NOT on the GET head: Scramjet/Epoxy does
# client-side TLS over a raw TCP tunnel for https:// URLs (verified on the
# wire: the first DATA frame on a 443 stream is a TLS ClientHello), and
# fetch() cannot transport TLS handshake bytes.

MAX_FRAME_BYTES = 1 << 20  # largest accepted wisp packet (1 MiB)
MAX_DATA_FRAME = 65536     # largest DATA frame we send downstream
MAX_HTTP_HEAD = 16 * 1024  # request head cap for the GET head
MAX_HTTP_BODY = 10 << 20   # request body cap for the GET head
INBOUND_QUEUE_LIMIT = 256  # buffered client DATA packets per stream
DEFAULT_INBOUND_MAX_BYTES = 16 << 20  # per-stream inbound byte cap
SERVER_BUFFER_PACKETS = 64 # receive buffer announced to clients
DEFAULT_TX_HIGH_WATER_BYTES = 1 << 20  # bufferedAmount gate threshold
DEFAULT_STREAM_IDLE_TIMEOUT_MS = 300_000
DEFAULT_HTTP_BODY_IDLE_TIMEOUT_MS = 30_000
DEFAULT_HTTP_FETCH_TIMEOUT_MS = 30_000
DEFAULT_HTTP_CLOSE_LINGER_MS = 350

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


def _env_ports(env: Any, name: str, default: frozenset) -> frozenset:
    """Parse a comma-separated port list (``WISP_HTTP_HEAD_PORTS``)."""
    raw = _env_get(env, name)
    if raw is None or not raw.strip():
        return default
    ports = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            console.warn(f"[wisp] invalid port {token!r} in {name}; using default")
            return default
        if not 1 <= port <= 65535:
            console.warn(f"[wisp] port {port} out of range in {name}; using default")
            return default
        ports.add(port)
    return frozenset(ports) if ports else default


@dataclass(frozen=True)
class WispConfig:
    """Runtime configuration (all values have safe defaults)."""

    log_level: str = "info"
    queue_limit: int = 64
    queue_timeout_ms: int = 15000
    connect_timeout_ms: int = 10000
    http_head_timeout_ms: int = 10000
    http_head_ports: frozenset = DEFAULT_HTTP_HEAD_PORTS
    http_fetch_timeout_ms: int = DEFAULT_HTTP_FETCH_TIMEOUT_MS
    http_body_idle_timeout_ms: int = DEFAULT_HTTP_BODY_IDLE_TIMEOUT_MS
    http_close_linger_ms: int = DEFAULT_HTTP_CLOSE_LINGER_MS
    stream_idle_timeout_ms: int = DEFAULT_STREAM_IDLE_TIMEOUT_MS
    inbound_max_bytes: int = DEFAULT_INBOUND_MAX_BYTES
    tx_buffer_gate: bool = False
    tx_high_water_bytes: int = DEFAULT_TX_HIGH_WATER_BYTES
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
            http_head_ports=_env_ports(env, "WISP_HTTP_HEAD_PORTS", DEFAULT_HTTP_HEAD_PORTS),
            http_fetch_timeout_ms=_env_int(
                env, "WISP_HTTP_FETCH_TIMEOUT_MS", DEFAULT_HTTP_FETCH_TIMEOUT_MS, 100, 600000
            ),
            http_body_idle_timeout_ms=_env_int(
                env,
                "WISP_HTTP_BODY_IDLE_TIMEOUT_MS",
                DEFAULT_HTTP_BODY_IDLE_TIMEOUT_MS,
                100,
                600000,
            ),
            http_close_linger_ms=_env_int(
                env, "WISP_HTTP_CLOSE_LINGER_MS", DEFAULT_HTTP_CLOSE_LINGER_MS, 0, 10_000
            ),
            stream_idle_timeout_ms=_env_int(
                env,
                "WISP_STREAM_IDLE_TIMEOUT_MS",
                DEFAULT_STREAM_IDLE_TIMEOUT_MS,
                1000,
                86_400_000,
            ),
            inbound_max_bytes=_env_int(
                env, "WISP_INBOUND_MAX_BYTES", DEFAULT_INBOUND_MAX_BYTES, 1024, 1 << 28
            ),
            tx_buffer_gate=_env_bool(env, "WISP_TX_BUFFER_GATE", False),
            tx_high_water_bytes=_env_int(
                env,
                "WISP_TX_HIGH_WATER_BYTES",
                DEFAULT_TX_HIGH_WATER_BYTES,
                1 << 16,
                1 << 26,
            ),
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
    def http_fetch_timeout_s(self) -> float:
        return self.http_fetch_timeout_ms / 1000.0

    @property
    def http_body_idle_s(self) -> float:
        return self.http_body_idle_timeout_ms / 1000.0

    @property
    def http_close_linger_s(self) -> float:
        return self.http_close_linger_ms / 1000.0

    @property
    def stream_idle_timeout_s(self) -> float:
        return self.stream_idle_timeout_ms / 1000.0


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


def _wisp_pair_endpoints(pair: Any) -> Tuple[Any, Any]:
    """Extract ``(client, server)`` from a workerd ``WebSocketPair`` result.

    ``new WebSocketPair()`` returns a plain JS object with two *named
    instance* properties ("0" = client, "1" = server) - it is NOT a JS
    Array (workerd ``src/workerd/api/web-socket.h`` registers them via
    ``JSG_READONLY_INSTANCE_PROPERTY(0/1)``; there is even a TODO there
    wishing they were indexed properties).  Pyodide therefore hands
    Python a ``JsProxy`` that:

      * is **not subscriptable** (``pair[1]`` raises ``TypeError`` - the
        production crash),
      * is not ``len()``-able,
      * and whose ``to_py()`` returns the *same proxy*, because Pyodide
        only converts Array/Map/Set/typed arrays, never plain objects
        (which is why ``pair.to_py()[1]`` crashed too).

    The documented extraction is ``Object.values()``; Pyodide exposes it
    as ``JsProxy.object_values()``.  Both return a JS Array proxy whose
    elements stay ``JsProxy`` (verified live on Pyodide 0.28.3, the
    version behind compatibility date 2026-08-01 / Python 3.13).
    """
    values: Any = None
    object_values = getattr(pair, "object_values", None)
    if callable(object_values):
        try:
            values = object_values()
        except Exception:  # noqa: BLE001 - fall through to Object.values
            values = None
    if values is None:
        try:
            values = Object.values(pair)
        except Exception:  # noqa: BLE001
            values = None
    if values is not None and isinstance(values, (str, bytes, bytearray)):
        values = None  # a list-like container of two sockets is required
    if values is not None:
        try:
            client, server = values[0], values[1]
            if client is not None and server is not None:
                return client, server
        except (TypeError, KeyError, IndexError):
            pass
        try:
            items = list(values)
            if len(items) == 2 and items[0] is not None and items[1] is not None:
                return items[0], items[1]
        except (TypeError, ValueError):
            pass
    raise TypeError(
        "WebSocketPair did not expose two endpoints via object_values()/"
        f"Object.values() (got {type(pair).__name__})"
    )


def _spawn_background(ctx: Any, coro: Coroutine[Any, Any, None], log: Logger) -> None:
    """Run a coroutine past the request lifetime via ctx.waitUntil."""
    task = asyncio.ensure_future(coro)
    wait_until = getattr(ctx, "waitUntil", None)
    if not callable(wait_until):
        return

    def _executor(resolve: Any, _reject: Any) -> None:
        def _done(completed: "asyncio.Task[None]") -> None:
            # CancelledError derives from BaseException, so a cancelled
            # task must be screened off before touching .exception();
            # otherwise every cancelled session logs a spurious
            # "Exception in callback" traceback into the event loop.
            if not completed.cancelled():
                exc = None
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

    # Promise.new() invokes the executor synchronously (JS semantics), so
    # the PyProxy can be released as soon as the call returns; keeping it
    # alive would leak one PyProxy per WebSocket session.
    executor_proxy = create_proxy(_executor)
    try:
        wait_until(Promise.new(executor_proxy))
    except Exception:  # noqa: BLE001 - the task keeps running regardless
        pass
    finally:
        destroy = getattr(executor_proxy, "destroy", None)
        if callable(destroy):
            try:
                destroy()
            except Exception:  # noqa: BLE001
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
        # Every byte fed to the parser, kept (bounded) so an Upgrade request
        # can be reconstructed byte-for-byte when re-routed to the TCP head.
        self._fed = bytearray()

    @property
    def raw_request(self) -> bytes:
        """Exact bytes fed so far (head + body), for transparent re-routing."""
        return bytes(self._fed)

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
        if len(self._fed) + len(chunk) > self._max_head + self._max_body + 4096:
            raise HttpHeadTooLarge("request exceeds head+body cap")
        self._fed.extend(chunk)
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
    """One multiplexed Wisp stream (client-side initiated TCP connection).

    Flow control follows the protocol (and the reference servers) exactly:

    * client -> server DATA is buffered in ``inbound`` (bounded by
      ``INBOUND_QUEUE_LIMIT`` packets and ``inbound_max_bytes`` bytes) and
      paced by server-sent CONTINUE announcements;
    * server -> client DATA is sent immediately in <=64KiB frames - the wisp
      v1/v1.2 protocol defines no client->server CONTINUE, so no client
      acknowledgement may ever gate the transmit side (epoxy 2.1.20 never
      sends one).  Memory safety comes from the inbound caps, the optional
      ``bufferedAmount`` gate and the idle watchdogs instead.
    """

    def __init__(self, conn: "WispConnection", stream_id: int) -> None:
        self.conn = conn
        self.stream_id = stream_id
        self.inbound: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()
        self.inbound_bytes = 0
        self.slot: Optional[PoolSlot] = None
        self.connect_acked = False
        self.recv_packets = 0
        self.sent_packets = 0
        self.sent_bytes = 0
        self.acked_packets = 0   # client CONTINUEs observed (informational)
        self.continues_sent = 0  # window announcements towards the client
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

    def dispose(self) -> None:
        """Idempotent teardown: release the pool slot exactly once."""
        if self._disposed:
            return
        self._disposed = True
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
        if self.inbound.qsize() >= INBOUND_QUEUE_LIMIT or (
            self.inbound_bytes + len(payload) > self.conn.config.inbound_max_bytes
        ):
            self.conn.log.warn(
                "wisp_stream_stalled",
                stream=self.stream_id,
                reason="inbound_overflow",
                buffered_packets=self.inbound.qsize(),
                buffered_bytes=self.inbound_bytes,
            )
            self.conn.send_close(self.stream_id, REASON_THROTTLED)
            self.finish_server()
            return
        self.recv_packets += 1
        self.inbound_bytes += len(payload)
        self.inbound.put_nowait(payload)

    async def recv(self, timeout_s: Optional[float] = None) -> Optional[bytes]:
        """Next inbound chunk, or None when the client closed the stream."""
        if timeout_s is None:
            item = await self.inbound.get()
        else:
            if timeout_s <= 0:
                raise asyncio.TimeoutError()
            item = await asyncio.wait_for(self.inbound.get(), timeout_s)
        if item is not None:
            self.inbound_bytes -= len(item)
        return item

    def note_consumed(self) -> None:
        """Call after one queued packet was consumed and forwarded: re-announce
        the receive window to keep the client sending (spec: 'the server
        should regularly send CONTINUE packets before the buffer fills)."""
        self.conn.send_continue(self.stream_id)

    def note_client_continue(self, credit: Optional[int]) -> None:
        """A client -> server CONTINUE was observed.  The wisp v1/v1.2
        protocols never define this direction, so it must not gate the
        transmit side; it is recorded for diagnostics only."""
        self.acked_packets += 1

    # -- server -> client ------------------------------------------------------
    async def send_data(self, data: bytes) -> bool:
        """Send bytes downstream in <=64KiB DATA frames.  Returns False when
        the stream or connection can no longer accept data."""
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if self.is_finished or self.conn.closing:
                return False
            end = min(offset + MAX_DATA_FRAME, len(view))
            frame = bytes(view[offset:end])
            self.conn.log.debug(
                "wisp_frame_queued", stream=self.stream_id, bytes=len(frame), sent_total=self.sent_bytes
            )
            if not await self.conn.await_tx_room(len(frame), self.stream_id):
                return False
            if not self.conn.send_data_frame(self.stream_id, frame):
                return False
            self.sent_packets += 1
            self.sent_bytes += len(frame)
            self.conn.log.debug(
                "wisp_frame_sent",
                stream=self.stream_id,
                bytes=len(frame),
                sent_packets=self.sent_packets,
                sent_bytes=self.sent_bytes,
            )
            offset = end
        return True


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
    @property
    def closing(self) -> bool:
        """True once the websocket session is winding down."""
        return self._closing

    def attach(self) -> None:
        """Prepare the server socket and wire up the event listeners.

        ``binaryType`` must be assigned *before* ``accept()``: on
        compatibility dates >= 2026-03-17 the
        ``websocket_standard_binary_type`` flag is on by default, binary
        frames are delivered as ``Blob`` objects and this server cannot
        parse them.  Assigning ``"arraybuffer"`` first guarantees
        ``ArrayBuffer`` delivery for every frame (the Workers runtime
        docs prescribe exactly this ordering).
        """
        try:
            self.ws.binaryType = "arraybuffer"
        except Exception:  # noqa: BLE001 - older runtimes may reject it
            self.log.debug("ws_binary_type_assign_failed")
        self.ws.accept()
        message_proxy = create_proxy(self._on_message)
        close_proxy = create_proxy(self._on_close_event)
        error_proxy = create_proxy(self._on_error_event)
        self._proxies = [message_proxy, close_proxy, error_proxy]
        self.ws.addEventListener("message", message_proxy)
        self.ws.addEventListener("close", close_proxy)
        self.ws.addEventListener("error", error_proxy)

    # -- JS callbacks (called between awaits on the same thread) ---------------
    def _on_message(self, event: Any) -> None:
        if self._closing:
            return
        try:
            data = _ws_payload_to_bytes(getattr(event, "data", None))
        except Exception as exc:  # noqa: BLE001
            self.log.error(
                "ws_binary_expected",
                error=repr(exc),
                hint="binaryType must be 'arraybuffer' for binary frames",
            )
            self.close_ws(1003)
            return
        self._rx.put_nowait(data)

    def _on_close_event(self, _event: Any) -> None:
        self._rx.put_nowait(None)

    def _on_error_event(self, event: Any) -> None:
        """Socket errors must not pass silently: log and end the session."""
        detail = ""
        try:
            detail = str(
                getattr(event, "message", None) or getattr(event, "type", "") or ""
            )
        except Exception:  # noqa: BLE001
            detail = ""
        self.log.warn("ws_error_event", detail=detail[:200])
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
        head = "http" if request.port in self.config.http_head_ports else "tcp"
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
        # Client -> server CONTINUE does not exist in wisp v1/v1.2 (the
        # direction is server -> client only); accept it tolerantly and
        # record it for diagnostics.  It must never gate the tx side.
        stream.note_client_continue(credit)
        self.log.debug(
            "wisp_ack_received",
            stream=packet.stream_id,
            credit=credit if credit is not None else -1,
            total=stream.acked_packets,
        )

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

    def _ws_buffered_amount(self) -> Optional[int]:
        """Pending send-buffer bytes if the runtime exposes ``bufferedAmount``."""
        try:
            value = getattr(self.ws, "bufferedAmount", None)
        except Exception:  # noqa: BLE001
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        buffered = int(value)
        return buffered if buffered >= 0 else None

    async def await_tx_room(self, incoming: int, stream_id: int) -> bool:
        """Optional transmit gate on the runtime's WebSocket send buffer.

        Off by default (``WISP_TX_BUFFER_GATE``): server -> client DATA is
        sent ungated, exactly like the reference wisp servers, and workerd
        applies TCP-level backpressure towards the client itself.  When
        enabled, a frame waits until ``bufferedAmount`` drops below the high
        water mark; a wedged client is eventually failed with 0x47 instead
        of buffering without bound.
        """
        if not self.config.tx_buffer_gate:
            return True
        high_water = self.config.tx_high_water_bytes
        waited = 0.0
        last_report = -1.0
        while not self._closing:
            buffered = self._ws_buffered_amount()
            if buffered is None or buffered + incoming <= high_water:
                return True
            now = time.monotonic()
            if now - last_report >= 1.0:
                self.log.warn(
                    "wisp_stream_stalled",
                    stream=stream_id,
                    reason="tx_buffer_full",
                    buffered=buffered,
                    high_water=high_water,
                    waited_ms=int(waited * 1000),
                )
                last_report = now
            if waited >= self.config.stream_idle_timeout_s:
                self.log.warn(
                    "wisp_stream_stalled",
                    stream=stream_id,
                    reason="tx_buffer_stuck",
                    buffered=buffered,
                    waited_ms=int(waited * 1000),
                )
                self.send_close(stream_id, REASON_TRANSFER_TIMEOUT)
                return False
            await asyncio.sleep(min(0.05, max(0.01, self.config.stream_idle_timeout_s - waited)))
            waited += 0.05
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
            buffer_remaining = SERVER_BUFFER_PACKETS
        else:
            buffer_remaining = SERVER_BUFFER_PACKETS
            payload = buffer_remaining.to_bytes(4, "little")
            ptype = _V12Type.CONTINUE
        sent = self._send_raw(_encode_packet(wire, ptype, stream_id, payload))
        if sent and stream_id in self.streams:
            stream = self.streams[stream_id]
            stream.continues_sent += 1
            self.log.debug(
                "wisp_window_updated",
                stream=stream_id,
                buffer_remaining=buffer_remaining,
                announcements=stream.continues_sent,
            )
        return sent

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

    def _maybe_send_connect_ack(self, stream: WispStream) -> None:
        """Classic-wire CONNECT acknowledgment, exactly once per stream (the
        fallback path re-enters the TCP head and must not double-ack)."""
        if stream.connect_acked:
            return
        if self.wire is WireFormat.CLASSIC and self.config.classic_connect_ack:
            stream.connect_acked = True
            self._send_connect_ack(stream.stream_id)

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

    def _drop_stream(self, stream: WispStream, reason: Optional[int] = None) -> None:
        existing = self.streams.pop(stream.stream_id, None)
        if existing is not None:
            self.log.info(
                "wisp_stream_closed",
                stream=stream.stream_id,
                reason=f"0x{reason:02x}" if reason is not None else None,
                recv_packets=stream.recv_packets,
                sent_packets=stream.sent_packets,
                sent_bytes=stream.sent_bytes,
                acked_packets=stream.acked_packets,
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
        self._maybe_send_connect_ack(stream)
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
            downstream = self._spawn(self._pump_downstream(stream, reader))
            done, pending = await asyncio.wait(
                {upstream, downstream}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                if task.cancelled():
                    continue
                done_error = None
                try:
                    done_error = task.exception()
                except Exception:  # noqa: BLE001
                    done_error = None
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
        idle_s = self.config.stream_idle_timeout_s
        while True:
            try:
                chunk = await stream.recv(timeout_s=idle_s)
            except asyncio.TimeoutError:
                if stream.is_finished:
                    return
                self.log.warn(
                    "wisp_stream_stalled",
                    stream=stream.stream_id,
                    reason="upstream_idle",
                    waited_ms=self.config.stream_idle_timeout_ms,
                )
                self.send_close(stream.stream_id, REASON_TRANSFER_TIMEOUT)
                stream.finish_server()
                return
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
            stream.note_consumed()

    async def _pump_downstream(self, stream: WispStream, reader: Any) -> None:
        """TCP socket -> client DATA frames.  Ungated by design: wisp v1/v1.2
        define no client->server CONTINUE, so no client acknowledgement may
        ever gate the transmit side (epoxy never sends one; gating here is
        what stalled tunnels after a handful of frames)."""
        idle_s = self.config.stream_idle_timeout_s
        while True:
            try:
                result = await asyncio.wait_for(_await_js(reader.read()), timeout=idle_s)
            except asyncio.TimeoutError:
                if stream.is_finished:
                    return
                self.log.warn(
                    "wisp_stream_stalled",
                    stream=stream.stream_id,
                    reason="downstream_idle",
                    waited_ms=self.config.stream_idle_timeout_ms,
                )
                self.send_close(stream.stream_id, REASON_TRANSFER_TIMEOUT)
                stream.finish_server()
                return
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

    # -- GET head: delegate plaintext-HTTP ports (default: 80) to fetch() ------------------
    async def _run_http_head(self, stream: WispStream, host: str, port: int) -> None:
        sid = stream.stream_id
        self._maybe_send_connect_ack(stream)
        parser = HttpRequestParser(MAX_HTTP_HEAD, MAX_HTTP_BODY)
        fallback: Optional[bytes] = None
        fallback_reason = "non_http_bytes"
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
        if fallback is None:
            request = parser.build()
            # A request that wants a protocol upgrade (e.g. a WebSocket
            # handshake riding on port 80) cannot be served by fetch(): relay
            # the original bytes verbatim through a raw TCP tunnel instead.
            wants_upgrade = "upgrade" in request.headers or "upgrade" in (
                request.headers.get("connection", "").lower()
            )
            if wants_upgrade:
                fallback = parser.raw_request
                fallback_reason = "upgrade_request"
        if fallback is not None:
            await self._fallback_to_tcp(stream, host, port, fallback, fallback_reason)
            return
        # target may carry a query string with secrets: log path only
        logged_target = request.target.split("?", 1)[0]
        self.log.info(
            "http_request_started",
            stream=sid,
            method=request.method,
            target=logged_target,
            host=host,
            port=port,
        )
        try:
            response = await asyncio.wait_for(
                self._issue_fetch(request, host, port),
                timeout=self.config.http_fetch_timeout_s,
            )
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self.log.warn(
                "http_request_failed",
                stream=sid,
                host=host,
                port=port,
                error=f"fetch timeout after {self.config.http_fetch_timeout_ms}ms",
            )
            await self._send_http_synthetic(stream, 504, "wisp-worker: upstream fetch timed out")
            return
        except Exception as exc:  # noqa: BLE001 - upstream/network failure
            self.log.warn("http_request_failed", stream=sid, host=host, port=port, error=repr(exc))
            await self._send_http_synthetic(stream, 502, "wisp-worker: upstream fetch failed")
            return
        self.log.info("http_request_completed", stream=sid, status=int(getattr(response, "status", 0)))
        relayed = False
        try:
            relayed = await self._relay_http_response(stream, request.method, response)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            self.log.warn("http_relay_failed", stream=sid, error=repr(exc))
            self.send_close(sid, REASON_NETWORK_ERROR)
            return
        if relayed and not stream.is_finished:
            await self._close_http_stream(stream)

    async def _close_http_stream(self, stream: WispStream) -> None:
        """End a completed GET-head exchange.

        The client announced ``Connection: close`` in our synthesized head, so
        a well-behaved client tears the stream down itself.  Give it a short
        linger window to do so before we send ours: epoxy's wasm client races
        its wisp CLOSE handling against hyper draining the buffered response
        frames, and an immediate CLOSE after the terminal chunk can truncate
        the body read on its side (observed as "unexpected EOF during chunk
        size line" / "connection closed before message complete")."""
        sid = stream.stream_id
        linger_s = self.config.http_close_linger_s
        if linger_s > 0:
            try:
                item = await asyncio.wait_for(stream.inbound.get(), timeout=linger_s)
            except asyncio.TimeoutError:
                item = "linger-expired"
            if item is None:
                # the client closed the stream itself: nothing to announce
                return
        self.send_close(sid, REASON_VOLUNTARY)

    async def _fallback_to_tcp(
        self, stream: WispStream, host: str, port: int, initial: bytes, reason: str
    ) -> None:
        sid = stream.stream_id
        self.log.info(
            "http_fallback_tcp",
            stream=sid,
            host=host,
            port=port,
            bytes=len(initial),
            reason=reason,
        )
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
        # Never negotiate a compressed upstream body: workerd's fetch()
        # transparently decompresses gzip/br/deflate responses but can leave
        # the (now false) Content-Encoding header in place, which makes the
        # client try to decode plain bytes ("brotli error").  Identity keeps
        # the relayed headers and body exact by construction.
        headers["accept-encoding"] = "identity"
        init: Dict[str, Any] = {
            "method": request.method,
            "headers": headers,
            # Transparent-proxy semantics: return the origin's redirect to
            # the client (epoxy implements its own redirect handling) rather
            # than transparently following it here.
            "redirect": "manual",
        }
        if request.body:
            init["body"] = request.body
        self.log.debug("fetch_issue", url=url, method=request.method)
        return await fetch(url, to_js(init, dict_converter=Object.fromEntries))

    async def _relay_http_response(self, stream: WispStream, method: str, response: Any) -> bool:
        """Relay a fetch() response onto the wisp stream.

        Framing: bodied responses are ALWAYS re-framed as chunked.  The
        origin's Content-Length is stripped, which makes a length mismatch
        (e.g. a runtime body transformation) impossible by construction and
        therefore eliminates the "bytes remaining on stream" class of client
        errors.  End-of-stream is signalled explicitly with the terminal
        ``0\\r\\n\\r\\n`` chunk, and binary bytes pass through verbatim.
        """
        sid = stream.stream_id
        status = int(getattr(response, "status", 502) or 502)
        status_text = str(getattr(response, "statusText", "") or "")
        if not status_text:
            status_text = REASON_PHRASES.get(status, "Unknown")
        headers = _js_headers_to_dict(getattr(response, "headers", None))
        bodyless = status in (204, 304) or method == "HEAD"
        lines: List[str] = [f"HTTP/1.1 {status} {status_text}"]
        for name, value in headers.items():
            if name in _HOP_BY_HOP_RESPONSE:
                continue
            if name == "content-length":
                continue  # chunked re-framing: announce no length ourselves
            lines.append(f"{name}: {value}")
        if not bodyless:
            lines.append("Transfer-Encoding: chunked")
        lines.append("Connection: close")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace")
        self.log.info(
            "http_response_received",
            stream=sid,
            status=status,
            headers=len(headers),
            bodyless=bodyless,
        )
        if not await stream.send_data(head):
            return False
        if bodyless:
            self.log.info("http_response_body_complete", stream=sid, bytes=0, chunks=0)
            return True
        body = getattr(response, "body", None)
        if body is None:
            if not await stream.send_data(b"0\r\n\r\n"):
                return False
            self.log.info("http_response_body_complete", stream=sid, bytes=0, chunks=0)
            return True
        reader = body.getReader()
        forwarded = 0
        chunks = 0
        try:
            while True:
                try:
                    result = await asyncio.wait_for(
                        _await_js(reader.read()), timeout=self.config.http_body_idle_s
                    )
                except asyncio.TimeoutError:
                    self.log.warn(
                        "http_response_body_timeout",
                        stream=sid,
                        forwarded=forwarded,
                        idle_ms=self.config.http_body_idle_timeout_ms,
                    )
                    self.send_close(sid, REASON_TRANSFER_TIMEOUT)
                    return False
                if bool(getattr(result, "done", False)):
                    break
                chunk_value = getattr(result, "value", None)
                if chunk_value is None:
                    break
                data = _to_bytes(chunk_value)
                if not data:
                    continue
                forwarded += len(data)
                chunks += 1
                self.log.debug(
                    "http_response_body_chunk",
                    stream=sid,
                    bytes=len(data),
                    forwarded=forwarded,
                    chunk=chunks,
                )
                if not await stream.send_data(_chunk_encode(data)):
                    return False
            if not await stream.send_data(b"0\r\n\r\n"):
                return False
            self.log.info(
                "http_response_body_complete", stream=sid, bytes=forwarded, chunks=chunks
            )
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


def _status_document(request_url: str, pools: WispPools, config: WispConfig) -> Dict[str, Any]:
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
        "transport": {
            "tcp_head": "cloudflare:sockets" if _cf_connect is not None else "unavailable",
            "http_head_ports": sorted(config.http_head_ports),
            "port_443": "raw TCP tunnel (client-side TLS; connect() with secureTransport off)",
            "flow_control": {
                "client_to_server": f"CONTINUE pacing, buffer {SERVER_BUFFER_PACKETS} packets",
                "server_to_client": "ungated (protocol defines no client ack)",
            },
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
        return _json_response(_status_document(url, pools, config))
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
    # workerd's WebSocketPair is a plain JS object {0: client, 1: server};
    # Pyodide wraps it in a JsProxy that is not subscriptable and whose
    # to_py() returns it unchanged, so the endpoints must be extracted via
    # object_values()/Object.values() (see _wisp_pair_endpoints).
    client_ws, server_ws = _wisp_pair_endpoints(WebSocketPair.new())
    offered = ""
    headers = getattr(request, "headers", None)
    if headers is not None:
        try:
            offered = str(headers.get("sec-websocket-protocol") or "").strip()
        except Exception:  # noqa: BLE001
            offered = ""
    conn_id = uuid.uuid4().hex[:8]
    conn_log = log.bind(conn=conn_id)
    connection = WispConnection(
        server_ws=server_ws,
        config=config,
        pools=_POOLS,
        log=log,
        conn_id=conn_id,
        subprotocol_offered=bool(offered),
    )
    # attach() assigns binaryType, accepts the server socket exactly once
    # and registers the message/close/error listeners BEFORE the 101 goes
    # out, so no frame can arrive unhandled.
    connection.attach()
    _spawn_background(ctx, connection.run(), conn_log)
    conn_log.info(
        "websocket_accepted",
        tcp_head=_cf_connect is not None,
        subprotocol=offered.split(",")[0].strip() if offered else "",
    )
    # The 101 response MUST carry the *client* end of the pair: workerd
    # rejects a Response whose socket was already accept()ed ("Can't
    # return WebSocket in a Response after calling accept()."), and the
    # server end is the one this worker drives.
    init: Dict[str, Any] = {"status": 101, "webSocket": client_ws}
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

"""
WISP 1.2 - HTTP/HTTPS outbound handler (native Cloudflare fetch API)

Handles HTTP (port 80) and HTTPS (port 443) requests using the native
Cloudflare Workers `fetch()` API, which is significantly cheaper than
opening a raw TCP socket and is required because Cloudflare blocks
arbitrary TCP to ports 80/443.

The flow is:

    1. server.py receives a CONNECT packet for port 80 or 443.
    2. server.py calls `establish(...)` here.
    3. We acquire a slot from the HTTP connection pool (max 3).
    4. We spin up an asyncio task that drains the per-stream write queue
       into a real HTTP request - every chunk of client DATA becomes
       part of the request body. (For GET / simple requests the body is
       empty and we just fire the request immediately.)
    5. Once the request is fulfilled, we stream the response body back to
       server.py as WISP DATA packets, strip hop-by-hop headers, then
       send a CLOSE with REASON_VOLUNTARY (0x02) and release the pool slot.

API restrictions (enforced by the spec):
    * USE ONLY:  the native `fetch()` and `Request` from `cloudflare:fetch`
    * NEVER use: httpx, requests, urllib, aiohttp, socket-based HTTP, etc.
"""

import asyncio

# Cloudflare Python Workers exposes fetch and Request via the
# `cloudflare:fetch` module (colon syntax, same importer as cloudflare:sockets).
# Per the spec: "✅ USE ONLY: Native Cloudflare fetch() API".
from js import fetch, Request
# Uint8Array still comes from the `js` bridge (it's a JS typed-array primitive
# used for byte conversion; no cloudflare:* module exposes it).
from js import Uint8Array

# WISP close reason codes (re-imported from server.py for ergonomics).
try:
    from server import (
        REASON_NETWORK_ERROR,
        REASON_INVALID_INFO,
        REASON_THROTTLED,
        REASON_VOLUNTARY,
        REASON_UNSPECIFIED,
        js_to_bytes,
        bytes_to_js_uint8,
        INITIAL_BUFFER_SIZE,
    )
except ImportError:
    # Fallback values if imported in isolation.
    REASON_NETWORK_ERROR = 0x03
    REASON_INVALID_INFO = 0x41
    REASON_THROTTLED = 0x49
    REASON_VOLUNTARY = 0x02
    REASON_UNSPECIFIED = 0x01
    INITIAL_BUFFER_SIZE = 64

    def js_to_bytes(js_data) -> bytes:
        if isinstance(js_data, (bytes, bytearray)):
            return bytes(js_data)
        try:
            return bytes(js_data.to_py())
        except Exception:
            return bytes(js_data)

    def bytes_to_js_uint8(data: bytes):
        if not data:
            return Uint8Array.new(0)
        arr = Uint8Array.new(len(data))
        try:
            arr.assign(data)
        except Exception:
            for i, b in enumerate(data):
                arr[i] = b
        return arr


# ---------------------------------------------------------------------------
# Hop-by-hop headers
#
# These must NEVER be forwarded in either direction per RFC 7230 / RFC 2616.
# Cloudflare Workers handles some of these automatically, but we strip them
# ourselves to be defensive.
# ---------------------------------------------------------------------------

HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
})


def _is_hop_by_hop(name: str) -> bool:
    return name.lower() in HOP_BY_HOP_HEADERS


# ---------------------------------------------------------------------------
# HTTP connection pool (HTTP-only, NOT shared with TCP)
# ---------------------------------------------------------------------------

class ConnectionPool:
    """Asyncio-guarded counter for the 3-slot HTTP pool.

    Identical in semantics to the TCP pool but kept separate so that the
    two pools never borrow from each other.
    """

    def __init__(self, max_size: int = 3):
        self.max_size = max_size
        self.active = 0
        self._lock = asyncio.Lock()

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self.active >= self.max_size:
                return False
            self.active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self.active > 0:
                self.active -= 1

    @property
    def free_slots(self) -> int:
        return max(0, self.max_size - self.active)


# ---------------------------------------------------------------------------
# HTTP connection wrapper
# ---------------------------------------------------------------------------

class HTTPConnection:
    """Wraps a single outbound HTTP(S) request/response cycle.

    Unlike TCP, an HTTP "connection" is a single round-trip: we accept
    some optional request body from the client (DATA packets), construct a
    `Request`, fire it through `fetch()`, then stream the response body
    back to the client as DATA packets and close the stream.

    Because the WISP protocol is bidirectional, we model this as:

      * `write(data)` -> enqueues bytes onto `request_body_queue`
      * A background task `request_task` drains the queue and triggers
        the fetch once the queue is closed (via `flush_request_body()`).
      * A second background task `response_task` reads the response body
        chunk by chunk and forwards each chunk as DATA to server.py.
    """

    def __init__(self, hostname: str, port: int,
                 on_data, on_close, pool: ConnectionPool):
        self.hostname = hostname
        self.port = port
        self.on_data = on_data
        self.on_close = on_close
        self.pool = pool

        self.scheme = "https" if port == 443 else "http"
        self.url = f"{self.scheme}://{hostname}/"

        self.request_body_queue: "asyncio.Queue[bytes | None]" = asyncio.Queue()
        self.body_done = asyncio.Event()
        self.body_chunks: list = []  # accumulator of bytes for the request body

        self.write_task: "asyncio.Task | None" = None
        self.fetch_task: "asyncio.Task | None" = None
        self.closed = False
        self.closing_lock = asyncio.Lock()
        self.stream_id = None

    # -- request body ingestion ------------------------------------

    async def write(self, data: bytes) -> None:
        """Called by server.py when the client sends a DATA packet that
        should be appended to the request body."""
        if self.closed:
            return
        await self.request_body_queue.put(data)

    async def flush_request_body(self) -> None:
        """Signal that no more request body is coming.

        For WISP-over-HTTP, the client typically sends a CONNECT packet
        and immediately closes the stream after one DATA chunk (the
        HTTP request line / headers). server.py calls this once the
        client closes the stream voluntarily.
        """
        await self.request_body_queue.put(None)

    # -- the main fetch task ---------------------------------------

    async def _fetch_task(self) -> None:
        """Drain the request body, fire fetch(), then stream the response."""
        try:
            # 1. Wait for the (small) request body to be delivered by the
            # client. For WISP-over-HTTP, the client normally delivers the
            # entire HTTP request as a single DATA packet and then closes
            # the stream; we therefore drain until we see the sentinel.
            request_body = b""
            while True:
                chunk = await self.request_body_queue.get()
                if chunk is None:
                    break
                request_body += chunk
                # Defensive cap: a malicious / buggy client could try to
                # exhaust memory. 1 MB of request body is plenty for an
                # HTTP CONNECT proxy payload.
                if len(request_body) > 1 * 1024 * 1024:
                    await self._signal_close(REASON_NETWORK_ERROR)
                    return

            # 2. Parse the request out of the body if it looks like an
            # HTTP request; otherwise treat it as a GET to the URL.
            method, path, headers, body = self._parse_http_request(request_body)

            # 3. Build the absolute URL.
            full_url = f"{self.scheme}://{self.hostname}{path}"

            # 4. Strip hop-by-hop headers from the request.
            # Spec shows `headers={}` (a plain dict). The CF fetch API
            # accepts a Python dict directly for the `headers` kwarg.
            clean_headers = {}
            for name, value in headers:
                if _is_hop_by_hop(name):
                    continue
                clean_headers[name] = value

            # 5. Construct the Request object.
            # Spec: `Request(url, method='GET', headers={})`. The CF Python
            # runtime exposes `Request` from `cloudflare:fetch` as a callable
            # constructor (Pyodide auto-binds `.new()` for JS classes that
            # are re-exported through cloudflare:* modules).
            request_kwargs = {
                "method": method,
                "headers": clean_headers,
            }
            if body:
                request_kwargs["body"] = bytes_to_js_uint8(body)

            req = Request(full_url, **request_kwargs)

            # 6. Fire fetch(). Spec: `response = await fetch(req)`.
            # Default behaviour is to follow 3xx redirects; the spec permits
            # either "Follow HTTP 3xx status codes" OR "disable with
            # redirect: 'manual'" — we follow them (simpler, matches the
            # spec's primary example form).
            try:
                response = await fetch(req)
            except Exception as exc:
                msg = str(exc).lower()
                if "url" in msg or "invalid" in msg:
                    await self._signal_close(REASON_INVALID_INFO)
                else:
                    await self._signal_close(REASON_NETWORK_ERROR)
                return

            # 7. Format and forward the response as an HTTP/1.1 message.
            response_bytes = await self._format_response(response)
            if response_bytes:
                try:
                    await self.on_data(self.stream_id, response_bytes)
                except Exception:
                    await self._signal_close(REASON_NETWORK_ERROR)
                    return

            # 8. Done - voluntary closure.
            await self._signal_close(REASON_VOLUNTARY)

        except Exception:
            await self._signal_close(REASON_NETWORK_ERROR)

    async def _format_response(self, response) -> bytes:
        """Build a textual HTTP/1.1 response (status line + headers + body)
        to send back to the client as a single DATA packet."""
        try:
            status = int(response.status)
            status_text = str(response.statusText or "")
        except Exception:
            status = 502
            status_text = "Bad Gateway"

        # Collect response headers, skipping hop-by-hop ones.
        header_lines = []
        try:
            entries = response.headers.entries()
            while True:
                nxt = entries.next()
                if bool(getattr(nxt, "done", False)):
                    break
                pair = getattr(nxt, "value", None)
                if pair is None:
                    break
                # pair is a JS array-like [name, value].
                try:
                    name = pair[0]
                    value = pair[1]
                except Exception:
                    continue
                name = str(name)
                value = str(value)
                if _is_hop_by_hop(name):
                    continue
                header_lines.append(f"{name}: {value}")
        except Exception:
            # Some responses may not expose .entries() - fall back to
            # .forEach().
            try:
                def _push_header(entry, *_):
                    try:
                        name = str(entry[0])
                        value = str(entry[1])
                    except Exception:
                        return
                    if _is_hop_by_hop(name):
                        return
                    header_lines.append(f"{name}: {value}")
                response.headers.forEach(_push_header)
            except Exception:
                pass

        # Read the body. Cloudflare Workers auto-decompresses gzip/brotli
        # when the request was made via fetch(); we therefore get the
        # already-decompressed bytes back.
        body_bytes = b""
        try:
            buf = await response.arrayBuffer()
            body_bytes = js_to_bytes(buf)
        except Exception:
            # Fall back to text() - usually only succeeds for textual
            # responses.
            try:
                body_text = await response.text()
                if body_text:
                    body_bytes = body_text.encode("utf-8", errors="replace")
            except Exception:
                body_bytes = b""

        # Assemble the raw HTTP/1.1 response.
        lines = [f"HTTP/1.1 {status} {status_text}".rstrip()]
        lines.extend(header_lines)
        # Let the client know how many bytes to expect, unless the upstream
        # already provided one (in which case we kept it via header_lines).
        has_content_length = any(
            h.lower().startswith("content-length:") for h in header_lines
        )
        if not has_content_length:
            lines.append(f"Content-Length: {len(body_bytes)}")
        head = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n"
        return head + body_bytes

    def _parse_http_request(self, raw: bytes):
        """Best-effort parse of an HTTP/1.x request out of the client's
        DATA payload. Returns (method, path, headers, body)."""
        # Defaults: GET / with no body.
        if not raw:
            return "GET", "/", [], b""

        try:
            head_part, _, body_part = raw.partition(b"\r\n\r\n")
        except Exception:
            head_part = raw
            body_part = b""

        try:
            head_text = head_part.decode("latin-1")
        except Exception:
            head_text = head_part.decode("utf-8", errors="replace")

        lines = head_text.split("\r\n")
        if not lines or not lines[0]:
            return "GET", "/", [], body_part

        # Parse the request line.
        request_line = lines[0]
        parts = request_line.split(" ", 2)
        if len(parts) < 3:
            # Not a well-formed HTTP request line - treat as opaque body.
            return "GET", "/", [], raw

        method, target, _version = parts[0], parts[1], parts[2]
        method = method.upper()

        # CONNECT requests carry host:port as the "path".
        if method == "CONNECT":
            path = "/"
        elif target.startswith("http://") or target.startswith("https://"):
            # Absolute-URI form - extract path.
            try:
                scheme_sep = target.find("://")
                rest = target[scheme_sep + 3:]
                slash = rest.find("/")
                path = rest[slash:] if slash != -1 else "/"
            except Exception:
                path = "/"
        else:
            path = target or "/"

        # Parse headers.
        headers = []
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            headers.append((name.strip(), value.strip()))

        return method, path, headers, body_part

    # -- close / cleanup --------------------------------------------

    async def _signal_close(self, reason: int) -> None:
        """Tear down the connection and notify server.py exactly once."""
        async with self.closing_lock:
            if self.closed:
                return
            self.closed = True

        # Push sentinel so any blocked write() call returns.
        try:
            self.request_body_queue.put_nowait(None)
        except Exception:
            pass

        # Cancel any pending tasks.
        for task in (self.fetch_task,):
            if task is not None and not task.done():
                task.cancel()

        # Release the pool slot.
        if self.pool is not None:
            await self.pool.release()

        # Tell server.py.
        try:
            await self.on_close(self.stream_id, reason)
        except Exception:
            pass

    async def close(self) -> None:
        """Public close: voluntary closure from server.py."""
        # Tell the fetch task that the request body is complete.
        await self.flush_request_body()
        # The fetch task will eventually call _signal_close itself.
        # But just in case it's stuck, do a guarded signal.
        await self._signal_close(REASON_VOLUNTARY)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def establish(hostname: str, port: int, stream, pool: ConnectionPool,
                    on_data, on_close) -> "HTTPConnection | None":
    """Try to start an HTTP fetch for `stream`.

    On success, attaches the connection to `stream.outbound` and starts the
    background fetch task. On failure (pool full or invalid request), sends
    the appropriate CLOSE packet via `stream.send_close()` and returns None.
    """
    stream_id = stream.stream_id

    # Validate the port.
    if port not in (80, 443):
        await stream.send_close(REASON_INVALID_INFO)
        return None

    # 1. Try to grab a pool slot.
    acquired = await pool.try_acquire()
    if not acquired:
        await stream.send_close(REASON_THROTTLED)
        return None

    # 2. Construct the connection wrapper.
    conn = HTTPConnection(
        hostname=hostname,
        port=port,
        on_data=on_data,
        on_close=on_close,
        pool=pool,
    )
    conn.stream_id = stream_id

    # 3. Spin up the fetch task. It will block on request_body_queue until
    # the client sends a DATA packet (or closes the stream).
    conn.fetch_task = asyncio.create_task(conn._fetch_task())

    # 4. Wire it up to the stream.
    stream.outbound = conn

    # 5. Tell the client the stream is ready (initial CONTINUE).
    await stream.send_continue(INITIAL_BUFFER_SIZE)

    return conn


__all__ = [
    "ConnectionPool",
    "HTTPConnection",
    "establish",
    "HOP_BY_HOP_HEADERS",
]
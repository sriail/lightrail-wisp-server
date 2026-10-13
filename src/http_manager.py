"""
Light Rail WISP Server - HTTP connection manager
================================================

Handles HTTP/HTTPS outbound requests for WISP streams whose destination
port is 80 or 443. Uses ONLY the native Cloudflare Workers `fetch()` API -
no httpx, no requests, no urllib, no aiohttp, no socket-based HTTP.

Why not raw TCP for 80/443?
--------------------------
Cloudflare Workers blocks arbitrary TCP to ports 80 and 443; you must
use `fetch()`. This is both required AND optimal - fetch is significantly
faster and cheaper than raw TCP sockets on the Workers platform.

Architecture
------------
* `ConnectionPool`        - 3-slot concurrency limiter (independent of TCP pool).
* `HttpConnection`       - per-stream HTTP request parser + fetch() driver.
* `HttpManager`           - factory + pool wrapper used by server.py.

Per-stream flow
---------------
1. CONNECT for host:80 (or 443) arrives -> server.py creates a WispStream.
2. HttpManager.create_connection() acquires a pool slot and attaches an
   HttpConnection to the stream.
3. Client sends DATA packets containing raw HTTP/1.1 request bytes.
4. HttpConnection buffers them until it has a complete request
   (headers + Content-Length body), then constructs a Request and
   calls fetch().
5. The Response is serialized back to raw HTTP/1.1 bytes (status line +
   filtered headers + body) and pushed to the stream as DATA packets.
6. If the request was `Connection: close` (or HTTP/1.0 without keep-alive),
   the stream is closed. Otherwise the loop continues for the next
   pipelined request on the same stream (HTTP keep-alive).

Hop-by-hop headers (Connection, Keep-Alive, Proxy-Authenticate,
Proxy-Authorization, TE, Trailers, Transfer-Encoding, Upgrade) are
stripped from both the outgoing request and the returned response
per RFC 7230 §6.1.

Compatibility
-------------
* Supports both origin-form ("GET /path HTTP/1.1") and absolute-form
  ("GET http://host/path HTTP/1.1") request lines.
* Supports Content-Length and chunked request bodies.
* libcurl-compatible: handles standard HTTP/1.1 requests from libcurl
  and other HTTP client libraries.
* Epoxy-compatible: works correctly when the WISP client (like Epoxy)
  forwards HTTP requests through the tunnel.

API surface (Cloudflare Workers Python ONLY):
    from workers import fetch, Request
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from workers import fetch, Request


# ---------------------------------------------------------------------------
# Close reason codes (mirrored from server.py)
# ---------------------------------------------------------------------------
CLOSE_UNSPECIFIED = 0x01
CLOSE_VOLUNTARY = 0x02
CLOSE_NETWORK_ERROR = 0x03
CLOSE_INVALID_PAYLOAD = 0x41
CLOSE_THROTTLED = 0x49

# Pool sizing - per spec, 3 of the 6 total outbound connections are HTTP.
HTTP_POOL_MAX = 3

# Don't let a single fetch() eat the entire 10ms CPU budget. Most
# legitimate fetches return in 100-1000ms; we cap at 30s to protect the
# worker from a hung origin.
FETCH_TIMEOUT_SECONDS = 30.0

# Maximum inbound request size we'll buffer before declaring the
# request malformed. This protects the 128MB memory budget.
MAX_REQUEST_HEAD_BYTES = 64 * 1024  # 64 KiB headers
MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB body

# Hop-by-hop headers per RFC 7230 §6.1 - never forwarded.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------


class ConnectionPool:
    """Async-safe 3-slot concurrency limiter for HTTP streams."""

    __slots__ = ("max_size", "_count", "_lock")

    def __init__(self, max_size: int = HTTP_POOL_MAX):
        self.max_size = max_size
        self._count = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            if self._count >= self.max_size:
                return False
            self._count += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self._count > 0:
                self._count -= 1

    def is_full(self) -> bool:
        return self._count >= self.max_size


# ---------------------------------------------------------------------------
# Bytes coercion - robust handling of Pyodide JS proxies
# ---------------------------------------------------------------------------


def _coerce_bytes(value: Any) -> bytes:
    """Coerce a value to bytes, handling Pyodide JS proxies robustly."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, memoryview):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    try:
        return bytes(value)
    except Exception:
        pass
    try:
        converted = value.to_py()
        if isinstance(converted, (bytes, bytearray)):
            return bytes(converted)
        if isinstance(converted, memoryview):
            return bytes(converted)
        if isinstance(converted, str):
            return converted.encode("utf-8")
        return bytes(converted)
    except Exception:
        pass
    try:
        return bytes(int(x) for x in value)
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Minimal HTTP/1.1 request parser (no external deps)
# ---------------------------------------------------------------------------


def _parse_request_head(head_bytes: bytes) -> Optional[Tuple[str, str, str, Dict[str, str]]]:
    """Parse an HTTP/1.x request head into (method, path, version, headers).

    Returns None if the request line is malformed. Header values are
    decoded as latin-1 (which never throws) so even oddly encoded values
    survive.

    Supports both origin-form ("GET /path HTTP/1.1") and absolute-form
    ("GET http://host/path HTTP/1.1") request lines for proxy clients
    like libcurl.
    """
    text = head_bytes.decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None

    request_line = lines[0]
    parts = request_line.split(" ")
    if len(parts) != 3:
        return None
    method, path, version = parts
    if not method or not path or not version.startswith("HTTP/"):
        return None

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            return None
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            return None
        # Lowercase keys for case-insensitive lookup.
        headers[key.lower()] = value
    return method, path, version, headers


def _filter_request_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Drop hop-by-hop headers and the Host header (fetch() will set it)."""
    out: Dict[str, str] = {}
    for key, value in headers.items():
        if key in HOP_BY_HOP_HEADERS:
            continue
        if key == "host":
            continue  # fetch() sets Host from the URL
        out[key] = value
    return out


def _build_url(scheme: str, host: str, port: int, path: str) -> str:
    """Build the absolute URL for fetch().

    Handles both origin-form ("/path") and absolute-form
    ("http://host/path") request lines. For absolute-form, the path
    already contains the full URL and is used as-is. For origin-form,
    we construct the URL from the CONNECT destination (host:port).
    """
    if path.startswith("http://") or path.startswith("https://"):
        return path
    # Origin form: path is "/foo?bar". Default port omitted from URL.
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{netloc}{path}"


def _should_keep_alive(version: str, headers: Dict[str, str]) -> bool:
    """Decide whether the request wants keep-alive on the response side."""
    conn = headers.get("connection", "").lower()
    if "close" in conn:
        return False
    if version.upper() == "HTTP/1.1":
        return True
    if version.upper() == "HTTP/1.0":
        return "keep-alive" in conn
    # HTTP/2.0+ over WISP is unusual - default to closing.
    return False


# ---------------------------------------------------------------------------
# Chunked transfer-encoding parser for request bodies
# ---------------------------------------------------------------------------


def _parse_chunked_body(buffer: bytes, start: int) -> Tuple[Optional[bytes], int]:
    """Parse a chunked request body starting at `start` in `buffer`.

    Returns (body_bytes, total_bytes_consumed) if the complete body
    is available, or (None, 0) if more data is needed.

    Chunked format:
        <chunk-size-hex>\r\n
        <chunk-data>\r\n
        ...
        0\r\n
        \r\n
    """
    pos = start
    body_parts: List[bytes] = []
    total_consumed = 0

    while True:
        # Find the chunk size line
        line_end = buffer.find(b"\r\n", pos)
        if line_end == -1:
            return None, 0  # Need more data

        size_line = buffer[pos:line_end]
        try:
            # Chunk size is hex, may have extensions after ';'
            size_str = size_line.split(b";")[0].strip()
            chunk_size = int(size_str, 16)
        except ValueError:
            return None, 0  # Malformed

        pos = line_end + 2  # Skip past \r\n

        if chunk_size == 0:
            # Last chunk - expect trailing \r\n
            if pos + 2 > len(buffer):
                return None, 0  # Need more data
            if buffer[pos:pos + 2] != b"\r\n":
                return None, 0  # Malformed
            total_consumed = pos + 2 - start
            return b"".join(body_parts), total_consumed

        # Read chunk data
        if pos + chunk_size + 2 > len(buffer):
            return None, 0  # Need more data

        body_parts.append(buffer[pos:pos + chunk_size])
        pos += chunk_size

        # Expect trailing \r\n after chunk data
        if buffer[pos:pos + 2] != b"\r\n":
            return None, 0  # Malformed
        pos += 2


# ---------------------------------------------------------------------------
# HTTP connection (one per WISP stream on ports 80/443)
# ---------------------------------------------------------------------------


class HttpConnection:
    """Per-stream HTTP proxy: parse inbound HTTP, fetch(), serialize back.

    Supports HTTP/1.1 keep-alive - multiple requests can be pipelined on
    the same WISP stream until either the client requests
    `Connection: close` or the stream is closed by either side.

    libcurl compatibility: handles standard HTTP/1.1 requests including
    both Content-Length and chunked Transfer-Encoding bodies.
    """

    __slots__ = (
        "hostname",
        "port",
        "stream",
        "_pool",
        "_buffer",
        "_closed",
        "_lock",
        "_processing",
        "_pool_released",
        "_response_keep_alive",
    )

    def __init__(self, hostname: str, port: int, stream: Any, pool: ConnectionPool):
        self.hostname = hostname
        self.port = port
        self.stream = stream
        self._pool = pool
        self._buffer: bytearray = bytearray()
        self._closed = False
        self._lock = asyncio.Lock()
        # Serialize fetch() calls on this stream - one at a time.
        self._processing = asyncio.Lock()
        self._pool_released = False
        # Set by _serialize_response based on the response's Connection header
        self._response_keep_alive = True

    # ------------------------------------------------------------------
    # Inbound DATA from the client
    # ------------------------------------------------------------------

    async def write(self, data: bytes) -> None:
        """Called by server.py when a DATA packet arrives for this stream.

        Buffers the bytes and tries to extract complete HTTP requests
        from the buffer. Each complete request is fetched and the
        response is sent back as DATA packets.
        """
        if self._closed:
            return

        self._buffer.extend(data)
        if len(self._buffer) > MAX_REQUEST_HEAD_BYTES + MAX_REQUEST_BODY_BYTES:
            # Too large - reject to protect the memory budget.
            await self.stream.on_outbound_close(CLOSE_INVALID_PAYLOAD)
            await self._teardown()
            return

        # Drive the parser loop. One call may consume multiple pipelined
        # requests if they all fit in the buffer.
        await self._try_process_requests()

    # ------------------------------------------------------------------
    # Parser loop
    # ------------------------------------------------------------------

    async def _try_process_requests(self) -> None:
        async with self._processing:
            while not self._closed:
                # 1. Find end of headers.
                sep = self._buffer.find(b"\r\n\r\n")
                if sep == -1:
                    if len(self._buffer) > MAX_REQUEST_HEAD_BYTES:
                        await self.stream.on_outbound_close(CLOSE_INVALID_PAYLOAD)
                        await self._teardown()
                    return  # Need more DATA from the client.

                head_bytes = bytes(self._buffer[:sep])
                body_start = sep + 4

                # 2. Parse the head.
                parsed = _parse_request_head(head_bytes)
                if parsed is None:
                    await self.stream.on_outbound_close(CLOSE_INVALID_PAYLOAD)
                    await self._teardown()
                    return
                method, path, version, headers = parsed

                # 3. Figure out the body length.
                content_length_str = headers.get("content-length")
                is_chunked = headers.get("transfer-encoding", "").lower() == "chunked"

                body_bytes: bytes
                body_end: int

                if is_chunked:
                    # Parse chunked request body (libcurl may use this)
                    result = _parse_chunked_body(bytes(self._buffer), body_start)
                    if result[0] is None:
                        # Need more data
                        if len(self._buffer) > MAX_REQUEST_HEAD_BYTES + MAX_REQUEST_BODY_BYTES:
                            await self.stream.on_outbound_close(CLOSE_INVALID_PAYLOAD)
                            await self._teardown()
                            return
                        return
                    body_bytes = result[0]
                    body_end = body_start + result[1]
                elif content_length_str is not None:
                    try:
                        content_length = int(content_length_str)
                    except ValueError:
                        await self.stream.on_outbound_close(CLOSE_INVALID_PAYLOAD)
                        await self._teardown()
                        return
                    if content_length > MAX_REQUEST_BODY_BYTES:
                        await self.stream.on_outbound_close(CLOSE_INVALID_PAYLOAD)
                        await self._teardown()
                        return
                    body_end = body_start + content_length
                    if len(self._buffer) < body_end:
                        return  # Need more DATA.
                    body_bytes = bytes(self._buffer[body_start:body_end])
                else:
                    # No body for this request
                    content_length = 0
                    body_end = body_start
                    body_bytes = b""

                # Consume this request from the buffer.
                del self._buffer[:body_end]

                # 4. Decide keep-alive BEFORE we mutate headers.
                keep_alive = _should_keep_alive(version, headers)

                # 5. Build the fetch() Request.
                scheme = "https" if self.port == 443 else "http"
                url = _build_url(scheme, self.hostname, self.port, path)
                filtered_headers = _filter_request_headers(headers)

                # 6. Fetch and serialize the response.
                ok = await self._fetch_and_respond(
                    url, method, filtered_headers, body_bytes
                )
                if not ok:
                    return  # stream is already closed

                # 7. If the client asked for Connection: close, OR the
                # upstream response says Connection: close, tear down.
                # We check both: the request's keep-alive preference
                # and the response's Connection header (fetched in
                # _serialize_response).
                if not keep_alive:
                    await self.stream.on_outbound_close(CLOSE_VOLUNTARY)
                    await self._teardown()
                    return
                # The _fetch_and_respond method sets _response_keep_alive
                # based on the response's Connection header. If the
                # upstream says close, we also close the stream.
                if not getattr(self, "_response_keep_alive", True):
                    await self.stream.on_outbound_close(CLOSE_VOLUNTARY)
                    await self._teardown()
                    return
                # Otherwise loop to see if another request is already in
                # the buffer (HTTP pipelining).

    # ------------------------------------------------------------------
    # fetch() + response serialization
    # ------------------------------------------------------------------

    async def _fetch_and_respond(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> bool:
        """Issue the fetch and stream the serialized response back.

        Returns True on success, False if the stream should be torn down.

        NOTE: We do NOT use asyncio.wait_for() around fetch() because
        fetch() returns a JS Promise, and asyncio.wait_for may not
        properly integrate with JS Promises in all Pyodide versions.
        We await directly and rely on the Cloudflare runtime's own
        fetch timeout behavior.
        """
        try:
            # Build the Request. We pass redirect="manual" so the client
            # sees the actual 3xx response and can decide to follow it
            # itself by issuing a new CONNECT to the redirect target.
            kwargs: Dict[str, Any] = {
                "method": method.upper(),
                "headers": headers,
                "redirect": "manual",
            }
            if body and method.upper() not in ("GET", "HEAD"):
                # Cloudflare Workers Python Request accepts bytes for body.
                # Pyodide auto-converts Python bytes to Uint8Array when
                # passing to JS APIs.
                kwargs["body"] = body
            req = Request(url, **kwargs)
        except Exception:
            await self.stream.on_outbound_close(CLOSE_INVALID_PAYLOAD)
            await self._teardown()
            return False

        try:
            # Direct await on the JS Promise. Pyodide bridges JS Promises
            # to asyncio automatically.
            response = await fetch(req)
        except Exception:
            # fetch() failures are network-level errors from the
            # client's perspective. 4xx/5xx are NOT errors here - they
            # are valid responses that we forward verbatim.
            await self.stream.on_outbound_close(CLOSE_NETWORK_ERROR)
            await self._teardown()
            return False

        # Serialize the Response into raw HTTP/1.1 bytes.
        try:
            raw_response = await self._serialize_response(response, method.upper() == "HEAD")
        except Exception:
            await self.stream.on_outbound_close(CLOSE_NETWORK_ERROR)
            await self._teardown()
            return False

        # Push the bytes back through the stream as WISP DATA packets.
        # The WispStream's on_outbound_data() handles flow control:
        # it sends DATA immediately if the client has buffer space,
        # or queues it for later flushing on CONTINUE.
        if raw_response:
            # Chunk into reasonable sizes so flow control can kick in
            # per-chunk (each chunk = one WISP DATA packet).
            for chunk_start in range(0, len(raw_response), 16384):
                chunk = raw_response[chunk_start : chunk_start + 16384]
                await self.stream.on_outbound_data(chunk)
        return True

    async def _serialize_response(self, response: Any, head_only: bool) -> bytes:
        """Convert a fetch() Response into raw HTTP/1.1 response bytes.

        Also stores _response_keep_alive on the connection so the
        parser loop can decide whether to close the stream.
        """
        status = int(getattr(response, "status", 200))
        status_text = getattr(response, "statusText", "") or _default_reason(status)

        # Read the body. arrayBuffer() returns a JS Promise that resolves
        # to an ArrayBuffer. We await directly (no asyncio.wait_for).
        # For HEAD requests we still consume the body to free resources,
        # but don't send it.
        body_bytes = b""
        try:
            body_buf = await response.arrayBuffer()
            body_bytes = _coerce_bytes(body_buf)
        except Exception:
            body_bytes = b""

        # Collect filtered headers using robust iteration.
        header_lines: List[bytes] = [f"HTTP/1.1 {status} {status_text}\r\n".encode("latin-1")]
        have_content_length = False
        response_keep_alive = True

        # Iterate response headers - try multiple methods for robustness.
        header_pairs = _extract_header_pairs(response.headers)
        for key, value in header_pairs:
            key_str = str(key)
            key_lower = key_str.lower()
            if key_lower in HOP_BY_HOP_HEADERS:
                continue
            if key_lower == "content-length":
                have_content_length = True
            if key_lower == "connection" and "close" in str(value).lower():
                response_keep_alive = False
            header_lines.append(f"{key_str}: {value}\r\n".encode("latin-1"))

        # Store the response keep-alive decision so the parser loop
        # can close the stream if the upstream says Connection: close.
        self._response_keep_alive = response_keep_alive

        # Always set Content-Length so the client knows where the body
        # ends (we already stripped Transfer-Encoding).
        body_to_send = b"" if head_only else body_bytes
        if not have_content_length:
            header_lines.append(f"Content-Length: {len(body_to_send)}\r\n".encode("latin-1"))

        # Add Connection header to indicate keep-alive or close
        if response_keep_alive:
            header_lines.append(b"Connection: keep-alive\r\n")
        else:
            header_lines.append(b"Connection: close\r\n")

        header_lines.append(b"\r\n")
        return b"".join(header_lines) + body_to_send

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        await self._teardown()

    async def _teardown(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
        # Drop the buffer.
        try:
            self._buffer.clear()
        except Exception:
            pass
        # Always release the pool slot (exactly once).
        await self._release_pool_slot()

    async def _release_pool_slot(self) -> None:
        """Release the pool slot exactly once."""
        if self._pool_released:
            return
        self._pool_released = True
        try:
            await self._pool.release()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Header iteration - robust against different JS/Python proxy forms
# ---------------------------------------------------------------------------


def _extract_header_pairs(headers_obj: Any) -> List[Tuple[str, str]]:
    """Extract (key, value) pairs from a Headers object.

    The Cloudflare Workers Python `Headers` object can be iterated in
    multiple ways depending on the Pyodide version:
      - .items() -> dict-like
      - .entries() -> JS-style iterator yielding [key, value]
      - Direct iteration -> may yield keys or [key, value] tuples

    This function tries each method in order and returns a list of
    (key, value) string pairs.
    """
    if headers_obj is None:
        return []

    pairs: List[Tuple[str, str]] = []

    # Method 1: dict-like .items()
    try:
        items = headers_obj.items()
        for item in items:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                pairs.append((str(item[0]), str(item[1])))
            elif hasattr(item, "__getitem__"):
                try:
                    pairs.append((str(item[0]), str(item[1])))
                except Exception:
                    pass
        if pairs:
            return pairs
    except Exception:
        pass

    # Method 2: JS-style .entries() - returns an iterator
    try:
        entries = headers_obj.entries()
        # JS iterators have a .next() method
        if hasattr(entries, "next"):
            while True:
                try:
                    entry = entries.next()
                    # JS iterator result: {done: bool, value: [k, v]}
                    done_val = getattr(entry, "done", None)
                    if done_val is None and isinstance(entry, dict):
                        done_val = entry.get("done", False)
                    if done_val:
                        break
                    value = getattr(entry, "value", None)
                    if value is None and isinstance(entry, dict):
                        value = entry.get("value")
                    if value is not None:
                        if isinstance(value, (tuple, list)) and len(value) == 2:
                            pairs.append((str(value[0]), str(value[1])))
                        elif hasattr(value, "__getitem__"):
                            try:
                                pairs.append((str(value[0]), str(value[1])))
                            except Exception:
                                pass
                except StopIteration:
                    break
                except Exception:
                    break
        if pairs:
            return pairs
    except Exception:
        pass

    # Method 3: Direct iteration (may yield keys or [key, value] tuples)
    try:
        for entry in headers_obj:
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                pairs.append((str(entry[0]), str(entry[1])))
            elif isinstance(entry, str):
                # Iterating yields just keys - get values separately
                try:
                    val = headers_obj.get(entry)
                    if val is not None:
                        pairs.append((entry, str(val)))
                except Exception:
                    pass
            elif hasattr(entry, "__getitem__"):
                try:
                    pairs.append((str(entry[0]), str(entry[1])))
                except Exception:
                    pass
        if pairs:
            return pairs
    except Exception:
        pass

    # Method 4: Use .forEach() if available (JS-style callback)
    try:
        collected: List[Tuple[str, str]] = []

        # In Pyodide, we can use create_once_callable for callbacks,
        # but a simpler approach is to collect via forEach.
        # Since we can't easily use Python closures as JS callbacks,
        # we'll skip this method and fall through.
        pass
    except Exception:
        pass

    # Method 5: Convert to dict if possible (last resort)
    try:
        d = dict(headers_obj)
        for k, v in d.items():
            pairs.append((str(k), str(v)))
        return pairs
    except Exception:
        pass

    return pairs


# ---------------------------------------------------------------------------
# Default reason phrases for status codes without statusText
# ---------------------------------------------------------------------------


def _default_reason(status: int) -> str:
    return _REASON_PHRASES.get(status, "OK")


_REASON_PHRASES: Dict[int, str] = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    202: "Accepted",
    204: "No Content",
    206: "Partial Content",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    413: "Payload Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


# ---------------------------------------------------------------------------
# Manager (factory + pool)
# ---------------------------------------------------------------------------


class HttpManager:
    """Creates HttpConnection instances under a shared 3-slot pool."""

    __slots__ = ("pool",)

    def __init__(self):
        self.pool = ConnectionPool(max_size=HTTP_POOL_MAX)

    def is_full(self) -> bool:
        return self.pool.is_full()

    async def create_connection(
        self, hostname: str, port: int, stream: Any
    ) -> bool:
        """Try to attach an HttpConnection to `stream`.

        Returns True on success. On pool-exhaustion the stream has
        already been notified via on_outbound_close(0x49 THROTTLED).
        """
        acquired = await self.pool.acquire()
        if not acquired:
            try:
                await stream.on_outbound_close(CLOSE_THROTTLED)
            except Exception:
                pass
            return False

        conn = HttpConnection(hostname, port, stream, self.pool)
        # Attach so server.py can route DATA packets into it.
        stream.connection = conn
        return True


# Constants re-exported for server.py
HTTP_FULL = HTTP_POOL_MAX

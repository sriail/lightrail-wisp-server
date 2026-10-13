"""
Light Rail WISP Server - TCP connection manager
==============================================

Handles raw TCP outbound connections for WISP streams whose destination
port is *not* 80 or 443. Uses ONLY the Cloudflare Workers Python
`connect()` API - no CPython socket, no asyncio.open_connection, no
external libraries.

Architecture
------------
* `ConnectionPool`          - semaphore-style pool, hard cap of 3 sockets.
* `TcpConnection`           - one outbound TCP socket + read/write loops.
* `TcpManager`              - factory + pool wrapper used by server.py.

The pool is independent of the HTTP pool - each has its own 3-slot budget.
When the TCP pool is exhausted, `TcpManager.create_connection()` returns
`False` and the caller (server.py) sends a WISP CLOSE with reason 0x49
(THROTTLED).

API surface (Cloudflare Workers Python ONLY):
    from workers import connect
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional

from workers import connect


# ---------------------------------------------------------------------------
# Close reason codes (mirrored from server.py to avoid an import cycle)
# ---------------------------------------------------------------------------
CLOSE_UNSPECIFIED = 0x01
CLOSE_VOLUNTARY = 0x02
CLOSE_NETWORK_ERROR = 0x03
CLOSE_HOST_UNREACHABLE = 0x42
CLOSE_TIMEOUT = 0x43
CLOSE_REFUSED = 0x44
CLOSE_TCP_TIMEOUT = 0x47
CLOSE_THROTTLED = 0x49

# Pool sizing - per spec, 3 of the 6 total outbound connections are TCP.
TCP_POOL_MAX = 3

# How long to wait for the initial TCP handshake to complete before we
# declare a timeout. Cloudflare `connect()` is usually fast (1-6ms), but
# we set a sane ceiling to protect the 10ms CPU budget.
CONNECT_TIMEOUT_SECONDS = 10.0

# How long a read may block before we declare a TCP data-transfer timeout.
# This is wall-clock per-read, not cumulative.
READ_TIMEOUT_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------


class ConnectionPool:
    """Tiny async-safe connection counter. Slot-only - no socket reuse."""

    __slots__ = ("max_size", "_count", "_lock")

    def __init__(self, max_size: int = TCP_POOL_MAX):
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
    """Coerce a chunk read from the readable stream into bytes.

    Cloudflare Workers Python may return:
      - bytes / bytearray (native Python)
      - str (text frame - unlikely for TCP but handle anyway)
      - JS Uint8Array proxy (Pyodide JsProxy)
      - memoryview

    This function handles all cases robustly without calling non-existent
    methods like `to_bytes()`.
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
    # Pyodide JsProxy: try to_py() which converts JsProxy to Python type
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
    # Last resort: try iterating as integers
    try:
        return bytes(int(x) for x in value)
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Read result extraction - handles both dict and JS object forms
# ---------------------------------------------------------------------------


def _extract_read_result(result: Any) -> tuple[bool, Any]:
    """Extract (done, value) from a reader.read() result.

    The result can be:
      - A JS object with .done and .value properties (most common)
      - A Python dict with 'done' and 'value' keys
      - A tuple/list of (done, value)
    """
    # Try dict-style access first (some Pyodide versions return dicts)
    if isinstance(result, dict):
        return bool(result.get("done", False)), result.get("value")

    # Try attribute access (JS object proxy)
    done_val = getattr(result, "done", None)
    if done_val is not None:
        return bool(done_val), getattr(result, "value", None)

    # Try tuple/list access
    if isinstance(result, (tuple, list)) and len(result) >= 2:
        return bool(result[0]), result[1]

    # Try indexing (some JS proxies support __getitem__)
    try:
        done_val = result[0]
        value = result[1]
        return bool(done_val), value
    except Exception:
        pass

    # Unknown shape - treat as not-done with the result as value
    return False, result


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------


def _classify_error(error: BaseException) -> int:
    """Best-effort mapping from a TCP error to a WISP close reason code.

    The Cloudflare Workers Python runtime surfaces errors as JS exceptions
    proxied through Python. We can't rely on isinstance checks against
    well-known exception types, so we sniff the message text and type name.
    """
    # Get error message
    try:
        msg = str(error).lower()
    except Exception:
        msg = ""

    # Get error type name
    try:
        err_type = type(error).__name__.lower()
    except Exception:
        err_type = ""

    # DNS / hostname resolution failures
    if any(k in msg for k in ("dns", "resolve", "getaddrinfo", "enotfound", "ename")):
        return CLOSE_HOST_UNREACHABLE
    if "enotfound" in err_type:
        return CLOSE_HOST_UNREACHABLE

    # Connection refused
    if any(k in msg for k in ("refused", "econnrefused", "reset")):
        return CLOSE_REFUSED
    if "refused" in err_type:
        return CLOSE_REFUSED

    # Timeout
    if any(k in msg for k in ("timeout", "timed out", "etimedout")):
        return CLOSE_TCP_TIMEOUT
    if "timeout" in err_type:
        return CLOSE_TCP_TIMEOUT

    # Default: generic network error
    return CLOSE_NETWORK_ERROR


# ---------------------------------------------------------------------------
# TCP connection
# ---------------------------------------------------------------------------


class TcpConnection:
    """One outbound TCP socket bound to a WISP stream.

    The read loop forwards bytes back to the stream (which wraps them in
    WISP DATA packets); the write loop drains an asyncio.Queue of
    outbound payloads. Closing is idempotent and triggers pool release.
    """

    __slots__ = (
        "hostname",
        "port",
        "stream",
        "_pool",
        "_socket",
        "_reader",
        "_writer",
        "_write_queue",
        "_read_task",
        "_write_task",
        "_closed",
        "_lock",
        "_pool_released",
    )

    def __init__(self, hostname: str, port: int, stream: Any, pool: ConnectionPool):
        self.hostname = hostname
        self.port = port
        self.stream = stream
        self._pool = pool
        self._socket = None
        self._reader = None
        self._writer = None
        self._write_queue: asyncio.Queue = asyncio.Queue()
        self._read_task: Optional[asyncio.Task] = None
        self._write_task: Optional[asyncio.Task] = None
        self._closed = False
        self._lock = asyncio.Lock()
        self._pool_released = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def open(self) -> bool:
        """Establish the socket and start the read/write loops.

        Returns True on success. On failure, sends the appropriate WISP
        CLOSE packet to the client and returns False (pool slot is
        released).
        """
        try:
            # `connect()` from workers - may be sync or async depending
            # on the runtime version. Try sync first, then await.
            self._socket = connect({"hostname": self.hostname, "port": self.port})
            # If connect() returned a coroutine/promise, await it
            if hasattr(self._socket, "__await__"):
                self._socket = await self._socket

            # Get reader and writer from the socket's readable/writable streams
            self._reader = self._socket.readable.getReader()
            self._writer = self._socket.writable.getWriter()
        except Exception as exc:
            reason = _classify_error(exc)
            try:
                await self.stream.on_outbound_close(reason)
            except Exception:
                pass
            await self._release_pool_slot()
            self._closed = True
            return False

        # Spin up the background loops. They own the socket's lifetime.
        self._read_task = asyncio.create_task(self._read_loop())
        self._write_task = asyncio.create_task(self._write_loop())
        return True

    # ------------------------------------------------------------------
    # Read loop
    # ------------------------------------------------------------------

    async def _read_loop(self) -> None:
        """Continuously read from the socket and forward to the stream.

        NOTE: We do NOT use asyncio.wait_for() on the reader.read() call
        because reader.read() returns a JS Promise, and asyncio.wait_for
        may not properly integrate with JS Promises in all Pyodide
        versions. Instead, we await directly and use a separate watchdog
        task to enforce a read timeout.

        The watchdog sends CLOSE 0x47 (TCP data transfer timeout) if no
        data is received within READ_TIMEOUT_SECONDS.
        """
        # Use a mutable container to share the last-data-time between
        # the read loop and the watchdog task. Floats are immutable and
        # passed by value, so we use a 1-element list.
        last_data_time_box = [asyncio.get_event_loop().time()]
        watchdog_task = asyncio.create_task(
            self._read_watchdog(last_data_time_box)
        )
        try:
            while not self._closed:
                try:
                    # Direct await on the JS Promise. Pyodide bridges
                    # JS Promises to asyncio automatically.
                    result = await self._reader.read()
                except asyncio.CancelledError:
                    return
                except Exception as exc:
                    if self._closed:
                        return
                    reason = _classify_error(exc)
                    if not self._closed:
                        await self.stream.on_outbound_close(reason)
                        await self._teardown()
                    return

                # Update last data time for the watchdog (mutable box)
                last_data_time_box[0] = asyncio.get_event_loop().time()

                # Extract (done, value) from the result robustly.
                # Handles JS objects, dicts, and tuples.
                done, value = _extract_read_result(result)

                if done:
                    # Socket cleanly closed by peer.
                    if not self._closed:
                        await self.stream.on_outbound_close(CLOSE_VOLUNTARY)
                        await self._teardown()
                    return

                chunk = _coerce_bytes(value)
                if chunk:
                    await self.stream.on_outbound_data(chunk)
        except asyncio.CancelledError:
            # Normal shutdown path - just exit.
            pass
        except Exception as exc:
            if not self._closed:
                reason = _classify_error(exc)
                try:
                    await self.stream.on_outbound_close(reason)
                except Exception:
                    pass
                await self._teardown()
        finally:
            # Cancel the watchdog when the read loop exits
            if watchdog_task is not None and not watchdog_task.done():
                watchdog_task.cancel()

    async def _read_watchdog(self, last_data_time_box: list) -> None:
        """Watchdog task that enforces a read timeout.

        If no data is received within READ_TIMEOUT_SECONDS, sends
        CLOSE 0x47 (TCP data transfer timeout) and tears down.

        Uses a mutable list (last_data_time_box[0]) to share the
        last-data-time with the read loop.
        """
        try:
            while not self._closed:
                await asyncio.sleep(5.0)  # Check every 5 seconds
                if self._closed:
                    return
                elapsed = asyncio.get_event_loop().time() - last_data_time_box[0]
                if elapsed >= READ_TIMEOUT_SECONDS:
                    # No data for too long - signal TCP data-transfer timeout.
                    if not self._closed:
                        await self.stream.on_outbound_close(CLOSE_TCP_TIMEOUT)
                        await self._teardown()
                    return
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Write loop
    # ------------------------------------------------------------------

    async def _write_loop(self) -> None:
        """Drain the write queue and push bytes to the socket."""
        try:
            while not self._closed:
                data = await self._write_queue.get()
                if data is None:
                    # Sentinel - drain loop is being asked to stop.
                    break
                if not data:
                    continue
                try:
                    # Cloudflare Workers: writer.write() returns a Promise
                    # that resolves when the data has been written.
                    await self._writer.write(data)
                except asyncio.CancelledError:
                    return
                except Exception as exc:
                    if self._closed:
                        return
                    reason = _classify_error(exc)
                    await self.stream.on_outbound_close(reason)
                    await self._teardown()
                    return
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            if not self._closed:
                reason = _classify_error(exc)
                try:
                    await self.stream.on_outbound_close(reason)
                except Exception:
                    pass
                await self._teardown()

    # ------------------------------------------------------------------
    # Public API used by server.py
    # ------------------------------------------------------------------

    async def write(self, data: bytes) -> None:
        """Enqueue bytes for the upstream socket.

        This is called by the WispStream's drain loop after flow control
        has been applied. The write loop processes the queue in order.
        """
        if self._closed:
            return
        await self._write_queue.put(data)

    async def close(self) -> None:
        """Idempotent teardown. Always releases the pool slot."""
        await self._teardown()

    # ------------------------------------------------------------------
    # Internal teardown
    # ------------------------------------------------------------------

    async def _teardown(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True

        # Cancel background tasks first so they don't fight us for the
        # socket resources.
        for task in (self._read_task, self._write_task):
            if task is not None and not task.done():
                task.cancel()
        # Drain the write queue so any waiting producer doesn't hang.
        try:
            while not self._write_queue.empty():
                self._write_queue.get_nowait()
        except Exception:
            pass
        # Push a sentinel in case the write loop is blocked on get().
        try:
            self._write_queue.put_nowait(None)
        except Exception:
            pass

        # Close writer / release reader.
        try:
            if self._writer is not None:
                await self._writer.close()
        except Exception:
            pass
        try:
            if self._reader is not None:
                await self._reader.releaseLock()
        except Exception:
            pass

        # Always give the pool slot back (exactly once).
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
# Manager (factory + pool)
# ---------------------------------------------------------------------------


class TcpManager:
    """Creates TcpConnection instances under a shared 3-slot pool."""

    __slots__ = ("pool",)

    def __init__(self):
        self.pool = ConnectionPool(max_size=TCP_POOL_MAX)

    def is_full(self) -> bool:
        return self.pool.is_full()

    async def create_connection(
        self, hostname: str, port: int, stream: Any
    ) -> bool:
        """Try to open a TCP connection for `stream`.

        Returns True on success. On failure (pool full, connect error,
        timeout) the stream has already been notified via
        `on_outbound_close()` and the pool slot (if acquired) has been
        released.

        NOTE: We use asyncio.wait_for for the connect() phase only (not
        for read/write loops) because connect() is a one-shot operation.
        The conn.open() method itself handles the case where connect()
        returns a JS Promise vs a sync value.
        """
        acquired = await self.pool.acquire()
        if not acquired:
            try:
                await stream.on_outbound_close(CLOSE_THROTTLED)
            except Exception:
                pass
            return False

        conn = TcpConnection(hostname, port, stream, self.pool)

        # Wrap the connect+start sequence in a timeout so a hung
        # connect() doesn't eat the whole worker invocation.
        # asyncio.wait_for works here because conn.open() is a Python
        # async function (not a raw JS Promise).
        try:
            ok = await asyncio.wait_for(conn.open(), timeout=CONNECT_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            try:
                await stream.on_outbound_close(CLOSE_TIMEOUT)
            except Exception:
                pass
            # The pool slot was acquired in this scope; release it.
            await self.pool.release()
            return False
        except Exception as exc:
            reason = _classify_error(exc)
            try:
                await stream.on_outbound_close(reason)
            except Exception:
                pass
            await self.pool.release()
            return False

        if not ok:
            # conn.open() already released the slot and sent CLOSE.
            return False

        # Hand the connection to the stream so server.py can write to it.
        stream.connection = conn
        return True


# Constants re-exported for server.py
TCP_FULL = TCP_POOL_MAX

"""
WISP 1.2 - TCP outbound handler (cloudflare:sockets)

Handles raw TCP socket connections for non-HTTP traffic (i.e. ports other
than 80 and 443) using the Cloudflare Workers `cloudflare:sockets` API.

The flow is:

    1. server.py receives a CONNECT packet for a non-80/443 port.
    2. server.py calls `establish(...)` here.
    3. We acquire a slot from the TCP connection pool (max 3).
    4. We call `connect({"hostname": host, "port": port})` and grab the
       readable / writable stream readers.
    5. We spawn two asyncio tasks: a read loop that pumps bytes back into
       server.py as DATA packets, and a write loop that drains our write
       queue into the socket.
    6. On error / EOF / CLOSE we tear down both loops, release the pool
       slot, and notify server.py with the appropriate CLOSE reason.

API restrictions (enforced by the spec):
    * USE ONLY:  from js import connect
    * NEVER use: socket module, asyncio.open_connection, ssl, paramiko, etc.
"""

import asyncio
import struct

from js import connect

try:
    from server import (
        REASON_NETWORK_ERROR,
        REASON_HOST_UNREACHABLE,
        REASON_CONNECTION_TIMEOUT,
        REASON_CONNECTION_REFUSED,
        REASON_TCP_TIMEOUT,
        REASON_THROTTLED,
        REASON_VOLUNTARY,
        REASON_UNSPECIFIED,
        js_to_bytes,
        bytes_to_js_uint8,
    )
except ImportError:
    # Fallback definitions if tcp.py is imported in isolation (e.g. tests).
    REASON_NETWORK_ERROR = 0x03
    REASON_HOST_UNREACHABLE = 0x42
    REASON_CONNECTION_TIMEOUT = 0x43
    REASON_CONNECTION_REFUSED = 0x44
    REASON_TCP_TIMEOUT = 0x47
    REASON_THROTTLED = 0x49
    REASON_VOLUNTARY = 0x02
    REASON_UNSPECIFIED = 0x01

    def js_to_bytes(js_data) -> bytes:
        if isinstance(js_data, (bytes, bytearray)):
            return bytes(js_data)
        try:
            return bytes(js_data.to_py())
        except Exception:
            return bytes(js_data)

    def bytes_to_js_uint8(data: bytes):
        from js import Uint8Array
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
# Connection pool (TCP-only, NOT shared with HTTP)
# ---------------------------------------------------------------------------

class ConnectionPool:
    """Asyncio-guarded counter for the 3-slot TCP pool.

    `try_acquire()` returns False (non-blocking) when the pool is full so
    the caller can immediately send a CLOSE with reason 0x49 (THROTTLED)
    per the spec.
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
# TCP connection wrapper
# ---------------------------------------------------------------------------

class TCPConnection:
    """Wraps a single outbound TCP socket.

    Reads happen on a long-running asyncio task that pulls chunks from the
    readable side and forwards them to the supplied `on_data` callback.
    Writes are pushed onto an asyncio.Queue and drained by a separate
    writer task; this keeps `write()` non-blocking for the caller and
    naturally serialises outbound writes.
    """

    def __init__(self, hostname: str, port: int,
                 on_data, on_close, pool: ConnectionPool):
        self.hostname = hostname
        self.port = port
        self.on_data = on_data           # async def(stream_id, data: bytes) -> None
        self.on_close = on_close         # async def(stream_id, reason: int) -> None
        self.pool = pool

        self.socket = None              # cloudflare:sockets return value
        self.reader = None              # readable.getReader()
        self.writer = None             # writable.getWriter()

        self.write_queue: "asyncio.Queue[bytes]" = asyncio.Queue()
        self.read_task: "asyncio.Task | None" = None
        self.write_task: "asyncio.Task | None" = None
        self.closed = False
        self.closing_lock = asyncio.Lock()
        self.stream_id = None  # populated by establish()

    # -- connection establishment -----------------------------------

    async def connect(self) -> "int | None":
        """Open the TCP socket. Returns None on success, or a WISP CLOSE
        reason code on failure."""
        try:
            self.socket = connect({
                "hostname": self.hostname,
                "port": self.port,
            })
        except Exception as exc:
            return self._classify_connect_error(exc)

        try:
            # In the Cloudflare runtime, the socket object exposes
            # `readable` and `writable` properties that are WHATWG streams.
            self.reader = self.socket.readable.getReader()
            self.writer = self.socket.writable.getWriter()
        except Exception as exc:
            return self._classify_connect_error(exc)

        return None

    def _classify_connect_error(self, exc: Exception) -> int:
        """Map a connect() failure to a WISP CLOSE reason code."""
        msg = str(exc).lower()
        # DNS / hostname resolution failures.
        if any(s in msg for s in (
            "dns", "resolve", "resolv", "name resolution",
            "nodename", "no address"
        )):
            return REASON_HOST_UNREACHABLE
        # Connection refused by the remote peer.
        if any(s in msg for s in ("refused", "econnrefused", "reset")):
            return REASON_CONNECTION_REFUSED
        # Connection / handshake timeout.
        if any(s in msg for s in ("timeout", "timed out", "etimedout")):
            return REASON_CONNECTION_TIMEOUT
        # Fall back to a generic network error.
        return REASON_NETWORK_ERROR

    # -- read/write loops -------------------------------------------

    async def start_loops(self, stream_id: int) -> None:
        self.stream_id = stream_id
        self.read_task = asyncio.create_task(self._read_loop())
        self.write_task = asyncio.create_task(self._write_loop())

    async def _read_loop(self) -> None:
        """Continuously read from the socket and forward bytes to server.py."""
        try:
            while not self.closed:
                # `reader.read()` resolves to `{done: bool, value: Uint8Array}`
                # in the JS WHATWG stream API.
                result = await self.reader.read()
                if result is None:
                    break
                # Pyodide exposes the JS object as a dict-like.
                done = bool(getattr(result, "done", False)) \
                    if not isinstance(result, dict) else bool(result.get("done", False))
                if done:
                    break
                value = getattr(result, "value", None) \
                    if not isinstance(result, dict) else result.get("value")
                if value is None:
                    continue
                data = js_to_bytes(value)
                if not data:
                    continue
                try:
                    await self.on_data(self.stream_id, data)
                except Exception:
                    # If the client callback throws, the stream is in trouble;
                    # bail out with a network error.
                    await self._signal_close(REASON_NETWORK_ERROR)
                    return
        except Exception as exc:
            # Map read failures to close reasons. Most are generic.
            msg = str(exc).lower()
            if "timeout" in msg:
                await self._signal_close(REASON_TCP_TIMEOUT)
            else:
                await self._signal_close(REASON_NETWORK_ERROR)
            return
        # Clean EOF - voluntary closure.
        await self._signal_close(REASON_VOLUNTARY)

    async def _write_loop(self) -> None:
        """Drain the write queue into the socket's writable side."""
        try:
            while not self.closed:
                data = await self.write_queue.get()
                if data is None:
                    # Sentinel used by close() to unblock the loop.
                    break
                try:
                    js_payload = bytes_to_js_uint8(data)
                    await self.writer.write(js_payload)
                except Exception as exc:
                    msg = str(exc).lower()
                    if "timeout" in msg:
                        await self._signal_close(REASON_TCP_TIMEOUT)
                    else:
                        await self._signal_close(REASON_NETWORK_ERROR)
                    return
        except Exception:
            await self._signal_close(REASON_NETWORK_ERROR)

    # -- write interface --------------------------------------------

    async def write(self, data: bytes) -> None:
        """Enqueue bytes to be written to the socket."""
        if self.closed:
            return
        await self.write_queue.put(data)

    # -- close / cleanup --------------------------------------------

    async def _signal_close(self, reason: int) -> None:
        """Tear down the connection and notify server.py exactly once."""
        async with self.closing_lock:
            if self.closed:
                return
            self.closed = True

        # Cancel the partner task so we don't leave a dangling coroutine.
        for task in (self.read_task, self.write_task):
            if task is not None and not task.done():
                task.cancel()

        # Close the underlying socket.
        if self.writer is not None:
            try:
                await self.writer.close()
            except Exception:
                pass
        if self.socket is not None:
            # Some CF runtime versions expose a top-level close().
            close_fn = getattr(self.socket, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass

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
        # Push sentinel to unblock the write loop.
        try:
            self.write_queue.put_nowait(None)
        except Exception:
            pass
        await self._signal_close(REASON_VOLUNTARY)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def establish(hostname: str, port: int, stream, pool: ConnectionPool,
                    on_data, on_close) -> "TCPConnection | None":
    """Try to open a TCP connection for `stream`.

    On success, attaches the connection to `stream.outbound` and starts the
    read/write loops. On failure (pool full or connect error), sends the
    appropriate CLOSE packet via `stream.send_close()` and returns None.
    """
    stream_id = stream.stream_id

    # 1. Try to grab a pool slot.
    acquired = await pool.try_acquire()
    if not acquired:
        # Pool is full -> 0x49 THROTTLED.
        await stream.send_close(REASON_THROTTLED)
        return None

    # 2. Construct the connection wrapper.
    conn = TCPConnection(
        hostname=hostname,
        port=port,
        on_data=on_data,
        on_close=on_close,
        pool=pool,
    )
    conn.stream_id = stream_id

    # 3. Open the socket.
    failure_reason = await conn.connect()
    if failure_reason is not None:
        # Release the slot we just acquired and tell the client.
        await pool.release()
        await stream.send_close(failure_reason)
        return None

    # 4. Start the read / write loops.
    await conn.start_loops(stream_id)

    # 5. Wire it up to the stream.
    stream.outbound = conn

    # 6. Tell the client the stream is ready for DATA (initial CONTINUE).
    from server import INITIAL_BUFFER_SIZE
    await stream.send_continue(INITIAL_BUFFER_SIZE)

    return conn


__all__ = [
    "ConnectionPool",
    "TCPConnection",
    "establish",
    "connect",
]
"""Outbound TCP streams and optional HTTP fetch helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from js import Object, Response, console, eval as js_eval, fetch
from pyodide.ffi import to_js

from server.rates import (
    CONNECT_TIMEOUT_SECONDS,
    IDLE_TIMEOUT_SECONDS,
    MAX_BUFFERED_PACKETS,
    MAX_DATA_PAYLOAD_BYTES,
    MAX_QUEUED_BYTES_PER_STREAM,
)


async def load_tcp_module():
    """Load Cloudflare's built-in TCP socket module through Python FFI.

    Cloudflare exposes connect() from the `cloudflare:sockets` JavaScript module.
    Python Workers expose JavaScript/runtime APIs through Pyodide's FFI, so this
    lazy dynamic import keeps the module load inside the request/stream lifecycle.
    """
    return await js_eval("import('cloudflare:sockets')")


async def http_get(url: str, headers: dict[str, str] | None = None):
    """Fetch an HTTP resource with the Workers Fetch API.

    This helper is deliberately not used for Wisp TCP streams: Fetch is HTTP
    request/response oriented, whereas Wisp DATA requires a long-lived TCP socket.
    It is provided for ordinary HTTP content acquisition by callers that need it.
    """
    js_headers = to_js(headers or {}, dict_converter=Object.fromEntries)
    return await fetch(
        url,
        to_js(
            {
                "method": "GET",
                "headers": js_headers,
                "redirect": "follow",
            },
            dict_converter=Object.fromEntries,
        ),
    )


class TCPStream:
    """One client-visible Wisp stream backed by a Cloudflare TCP socket."""

    def __init__(
        self,
        *,
        stream_id: int,
        hostname: str,
        port: int,
        send_packet: Callable[[bytes], None],
        on_closed: Callable[[int], None],
    ):
        self.stream_id = stream_id
        self.hostname = hostname
        self.port = port
        self.send_packet = send_packet
        self.on_closed = on_closed

        self.max_buffered_packets = MAX_BUFFERED_PACKETS
        self.buffer_remaining = MAX_BUFFERED_PACKETS
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=MAX_BUFFERED_PACKETS)
        self.queued_bytes = 0

        self.socket = None
        self.writer = None
        self.reader = None
        self.writer_task: asyncio.Task | None = None
        self.reader_task: asyncio.Task | None = None
        self._ready = asyncio.Event()
        self._closed = False
        self._close_lock = asyncio.Lock()

    async def open(self, timeout: float = CONNECT_TIMEOUT_SECONDS) -> None:
        """Create the Cloudflare TCP socket and start bidirectional pumps."""
        if self._closed:
            return

        try:
            sockets = await load_tcp_module()
            address = to_js(
                {"hostname": self.hostname, "port": self.port},
                dict_converter=Object.fromEntries,
            )
            self.socket = sockets.connect(address)

            # `opened` resolves when the destination TCP connection is actually
            # established, and rejects on connection failure.
            await asyncio.wait_for(self.socket.opened, timeout=timeout)

            self.writer = self.socket.writable.getWriter()
            self.reader = self.socket.readable.getReader()
            self._ready.set()

            self.writer_task = asyncio.create_task(self._writer_loop())
            self.reader_task = asyncio.create_task(self._reader_loop())

        except asyncio.TimeoutError:
            await self.close(send_packet=True, reason=0x43)
        except Exception as exc:
            reason = self._classify_error(exc)
            console.log(
                f"[wisp] TCP connect failed stream={self.stream_id} "
                f"{self.hostname}:{self.port}: {exc}"
            )
            await self.close(send_packet=True, reason=reason)

    def enqueue(self, payload: bytes) -> bool:
        """Queue one client DATA packet without blocking the WebSocket handler."""
        if self._closed:
            return False
        if not payload:
            return True
        if len(payload) > MAX_DATA_PAYLOAD_BYTES:
            return False
        if self.queued_bytes + len(payload) > MAX_QUEUED_BYTES_PER_STREAM:
            return False
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            return False

        self.queued_bytes += len(payload)
        self.buffer_remaining = max(0, self.buffer_remaining - 1)
        return True

    async def _writer_loop(self) -> None:
        try:
            await self._ready.wait()
            while not self._closed:
                payload = await self.queue.get()
                try:
                    if self.writer is None:
                        return
                    await self.writer.write(to_js(payload))
                finally:
                    self.queued_bytes = max(0, self.queued_bytes - len(payload))
                    self.queue.task_done()

                # A slot has been consumed by the remote TCP writer, so tell the
                # client it can send another DATA packet. This is also a regular
                # CONTINUE refresh and avoids unnecessary head-of-line delay.
                if not self._closed:
                    self.buffer_remaining = min(
                        MAX_BUFFERED_PACKETS, self.buffer_remaining + 1
                    )
                    self.send_continue()

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            console.log(f"[wisp] TCP write failed stream={self.stream_id}: {exc}")
            await self.close(send_packet=True, reason=0x03)

    async def _reader_loop(self) -> None:
        try:
            if self.reader is None:
                return

            while not self._closed:
                if IDLE_TIMEOUT_SECONDS > 0:
                    result = await asyncio.wait_for(
                        self.reader.read(), timeout=IDLE_TIMEOUT_SECONDS
                    )
                else:
                    result = await self.reader.read()

                done = bool(result.done)
                value = result.value

                if done:
                    await self.close(send_packet=True, reason=0x02)
                    return
                if value is None:
                    continue

                data = self._js_bytes(value)
                if not data:
                    continue

                # Keep each Wisp DATA payload comfortably below the packet ceiling.
                for start in range(0, len(data), MAX_DATA_PAYLOAD_BYTES):
                    chunk = data[start : start + MAX_DATA_PAYLOAD_BYTES]
                    self.send_data(chunk)

        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            await self.close(send_packet=True, reason=0x47)
        except Exception as exc:
            console.log(f"[wisp] TCP read failed stream={self.stream_id}: {exc}")
            await self.close(send_packet=True, reason=0x03)

    @staticmethod
    def _js_bytes(value) -> bytes:
        try:
            return bytes(value.to_py())
        except AttributeError:
            return bytes(value)

    @staticmethod
    def _classify_error(exc: BaseException) -> int:
        message = str(exc).lower()
        if isinstance(exc, asyncio.TimeoutError) or "timeout" in message:
            return 0x43
        if "refused" in message or "econnrefused" in message:
            return 0x44
        if "resolve" in message or "not found" in message or "dns" in message:
            return 0x42
        if "disallowed" in message or "private" in message:
            return 0x48
        return 0x03

    def send_data(self, payload: bytes) -> None:
        from server.connection import DATA, build_packet

        self.send_packet(build_packet(DATA, self.stream_id, payload))

    def send_continue(self) -> None:
        from server.connection import CONTINUE, build_packet

        payload = int(self.buffer_remaining).to_bytes(4, "little")
        self.send_packet(build_packet(CONTINUE, self.stream_id, payload))

    async def close(self, *, send_packet: bool, reason: int = 0x02) -> None:
        """Close the TCP socket and optionally emit Wisp CLOSE."""
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._ready.set()

            current = asyncio.current_task()
            for task in (self.reader_task, self.writer_task):
                if task is not None and task is not current and not task.done():
                    task.cancel()

            if send_packet:
                from server.connection import CLOSE, build_packet

                self.send_packet(
                    build_packet(CLOSE, self.stream_id, bytes((reason & 0xFF,)))
                )

            if self.socket is not None:
                try:
                    await self.socket.close()
                except Exception:
                    pass

            self.on_closed(self.stream_id)

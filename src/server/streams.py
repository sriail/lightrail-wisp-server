"""
Fixed TCP stream handler with proper TLS configuration.

The issue: Using secureTransport="off" on port 443 confuses Cloudflare.
The solution: Automatically detect HTTPS ports and use secureTransport="on".
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from js import Object, console
from contextlib import contextmanager

from pyodide.ffi import create_proxy, to_js

from server.rates import (
    CONNECT_TIMEOUT_SECONDS,
    IDLE_TIMEOUT_SECONDS,
    MAX_DATA_PAYLOAD_BYTES,
    MAX_BUFFERED_PACKETS,
    MAX_QUEUED_BYTES_PER_STREAM,
)


def load_tcp_module():
    """Return Cloudflare's built-in sockets module."""
    from workers import import_from_javascript
    return import_from_javascript("cloudflare:sockets")


async def http_get(url: str, headers: dict[str, str] | None = None):
    """Fetch an ordinary HTTP URL through Workers Fetch."""
    from js import fetch
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


@contextmanager
def js_uint8array(data: bytes):
    """Expose Python bytes as a native JS Uint8Array without a large JS list."""
    proxy = create_proxy(data)
    buffer = proxy.getBuffer()
    try:
        yield buffer.data
    finally:
        buffer.release()
        proxy.destroy()


class TCPStream:
    """One Wisp stream backed by a Cloudflare outbound TCP socket."""

    # HTTPS ports that should use TLS
    HTTPS_PORTS = {443, 8443, 9443}

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
        self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=MAX_BUFFERED_PACKETS)
        self.queued_bytes = 0
        self.packets_sent = 0

        self.socket = None
        self.writer = None
        self.reader = None
        self.writer_task: asyncio.Task | None = None
        self.reader_task: asyncio.Task | None = None
        self._ready = asyncio.Event()
        self._closed = False
        self._close_lock = asyncio.Lock()

    @property
    def buffer_remaining(self) -> int:
        return max(0, self.queue.maxsize - self.queue.qsize())

    def _should_use_tls(self) -> bool:
        """
        Determine if TLS should be used based on port.
        
        Port 443 and other HTTPS ports should use TLS.
        The WISP protocol itself handles TLS at the application layer,
        but for the TCP socket to Cloudflare, we need to match the target's
        protocol expectations.
        """
        return self.port in self.HTTPS_PORTS

    async def open(self, timeout: float = CONNECT_TIMEOUT_SECONDS) -> None:
        if self._closed:
            return

        try:
            sockets = load_tcp_module()

            # Determine if we should use TLS based on port
            use_tls = self._should_use_tls()
            secure_transport = "on" if use_tls else "off"

            console.log(
                f"[wisp-tcp] Attempting connection to {self.hostname}:{self.port} "
                f"(stream_id={self.stream_id}, timeout={timeout}s, tls={use_tls})"
            )

            address = to_js(
                {"hostname": self.hostname, "port": self.port},
                dict_converter=Object.fromEntries,
            )

            # FIX: Use proper TLS setting based on port
            # - Port 443, 8443, 9443: use TLS (secureTransport="on")
            # - Other ports: no TLS (secureTransport="off")
            # 
            # IMPORTANT: WISP expects the proxy to NOT do TLS (it does TLS in WASM).
            # However, when connecting to HTTPS ports through Cloudflare's TCP socket API,
            # we must tell Cloudflare to establish a TLS connection to the target.
            # The encrypted data from the client (via Epoxy) will flow through this TLS tunnel.
            options = to_js(
                {
                    "secureTransport": secure_transport,
                    "allowHalfOpen": True,
                },
                dict_converter=Object.fromEntries,
            )

            console.log(
                f"[wisp-tcp] Socket options: secureTransport={secure_transport}, "
                f"allowHalfOpen=True"
            )

            self.socket = sockets.connect(address, options)

            await asyncio.wait_for(self.socket.opened, timeout=timeout)

            console.log(
                f"[wisp-tcp] Successfully established TCP connection to {self.hostname}:{self.port} "
                f"(stream_id={self.stream_id}, tls={use_tls})"
            )

            self.writer = self.socket.writable.getWriter()
            self.reader = self.socket.readable.getReader()
            self._ready.set()

            self.writer_task = asyncio.create_task(self._writer_loop())
            self.reader_task = asyncio.create_task(self._reader_loop())

        except asyncio.TimeoutError:
            console.log(f"[wisp-tcp] Connection timeout for {self.hostname}:{self.port}")
            await self.close(send_packet=True, reason=0x43)
        except Exception as exc:
            console.log(
                f"[wisp-tcp] TCP connect failed stream={self.stream_id} "
                f"{self.hostname}:{self.port}: {exc}"
            )
            await self.close(send_packet=True, reason=self._classify_error(exc))

    def enqueue(self, payload: bytes) -> bool:
        if self._closed:
            return False
        if len(payload) > MAX_DATA_PAYLOAD_BYTES:
            return False
        if self.queued_bytes + len(payload) > MAX_QUEUED_BYTES_PER_STREAM:
            return False
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            return False
        self.queued_bytes += len(payload)
        return True

    async def _writer_loop(self) -> None:
        try:
            await self._ready.wait()
            while not self._closed:
                payload = await self.queue.get()
                try:
                    if self.writer is None:
                        return
                    with js_uint8array(payload) as js_payload:
                        await self.writer.write(js_payload)
                    self.packets_sent += 1

                    if self.packets_sent % max(1, self.queue.maxsize // 4) == 0:
                        self.send_continue()
                finally:
                    self.queued_bytes = max(0, self.queued_bytes - len(payload))
                    self.queue.task_done()

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

                if bool(result.done):
                    await self.close(send_packet=True, reason=0x02)
                    return

                value = result.value
                if value is None:
                    continue

                data = self._js_bytes(value)
                if not data:
                    continue

                for start in range(0, len(data), MAX_DATA_PAYLOAD_BYTES):
                    self.send_data(data[start : start + MAX_DATA_PAYLOAD_BYTES])

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
        text = str(exc).lower()
        if isinstance(exc, asyncio.TimeoutError) or "timeout" in text:
            return 0x43
        if "refused" in text or "econnrefused" in text:
            return 0x44
        if "resolve" in text or "not found" in text or "dns" in text:
            return 0x42
        if "disallowed" in text or "private" in text or "proxy request failed" in text:
            return 0x48
        return 0x03

    def send_data(self, payload: bytes) -> None:
        from server.connection import DATA, build_packet

        self.send_packet(build_packet(DATA, self.stream_id, payload))

    def send_continue(self) -> None:
        from server.connection import CONTINUE, build_packet

        self.send_packet(
            build_packet(
                CONTINUE,
                self.stream_id,
                int(self.buffer_remaining).to_bytes(4, "little"),
            )
        )

    async def close(self, *, send_packet: bool, reason: int = 0x02) -> None:
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

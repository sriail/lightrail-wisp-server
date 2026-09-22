"""
WISP-Compatible HTTP Proxy using Cloudflare Workers Fetch API

Instead of raw TCP, we:
1. Accept WISP CONNECT packets requesting TCP streams
2. Use Fetch API to get HTTP/HTTPS content (Cloudflare-allowed)
3. Wrap HTTP responses in WISP DATA packets
4. Send back through WISP protocol to client

This bypasses Cloudflare's TCP restrictions while staying protocol-compliant.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from js import Object, fetch, console
from contextlib import contextmanager

from pyodide.ffi import create_proxy, to_js

from server.rates import (
    CONNECT_TIMEOUT_SECONDS,
    MAX_DATA_PAYLOAD_BYTES,
    MAX_BUFFERED_PACKETS,
    MAX_QUEUED_BYTES_PER_STREAM,
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


class HTTPFetchStream:
    """
    HTTP-based stream using Cloudflare Workers Fetch API.
    
    Accepts WISP CONNECT requests for TCP connections to HTTP/HTTPS servers,
    but fulfills them via Fetch API instead of raw TCP.
    
    This allows full WISP protocol support on Cloudflare Workers by:
    1. Client sends WISP CONNECT for example.com:443
    2. Worker receives HTTP/HTTPS request from client (through WISP)
    3. Worker uses Fetch to get content
    4. Worker wraps response in WISP DATA packets
    
    Limitation: This only works for HTTP requests, not arbitrary TCP protocols.
    """

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

        self._ready = asyncio.Event()
        self._closed = False
        self._close_lock = asyncio.Lock()
        
        # For HTTP request handling
        self.request_buffer = b""
        self.headers_complete = False
        self.content_length = 0
        self.body_received = 0

    @property
    def buffer_remaining(self) -> int:
        return max(0, self.queue.maxsize - self.queue.qsize())

    async def open(self, timeout: float = CONNECT_TIMEOUT_SECONDS) -> None:
        """
        For HTTP streams, 'opening' just validates the hostname is reachable.
        We don't actually establish a connection until an HTTP request arrives.
        """
        if self._closed:
            return

        try:
            console.log(
                f"[http-fetch] Stream {self.stream_id} ready for "
                f"{self.hostname}:{self.port} (HTTPS)" if self.port == 443 
                else f"(HTTP)"
            )
            
            # HTTP is connection-less, mark as ready immediately
            self._ready.set()

        except Exception as exc:
            console.log(
                f"[http-fetch] Stream {self.stream_id} setup failed: {exc}"
            )
            await self.close(send_packet=True, reason=self._classify_error(exc))

    def enqueue(self, payload: bytes) -> bool:
        """Queue HTTP request payload for forwarding."""
        if self._closed:
            return False
        if len(payload) > MAX_DATA_PAYLOAD_BYTES:
            return False
        
        try:
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            return False
        
        self.queued_bytes += len(payload)
        
        # Fire off async request handling
        asyncio.create_task(self._process_http_request())
        return True

    async def _process_http_request(self) -> None:
        """Process queued HTTP requests and forward via Fetch API."""
        try:
            # Accumulate payload until we have a complete HTTP request
            while not self._closed:
                try:
                    chunk = self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                
                self.request_buffer += chunk
                self.queued_bytes = max(0, self.queued_bytes - len(chunk))
                self.queue.task_done()
                
                # Check if we have a complete HTTP request (headers + body)
                if not self.headers_complete:
                    if b"\r\n\r\n" in self.request_buffer:
                        self.headers_complete = True
                        # Parse headers to get Content-Length
                        headers_part = self.request_buffer.split(b"\r\n\r\n")[0]
                        for line in headers_part.split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                try:
                                    self.content_length = int(line.split(b":")[1].strip())
                                except ValueError:
                                    pass
                
                # Check if we have the complete body
                if self.headers_complete:
                    body_start = self.request_buffer.find(b"\r\n\r\n") + 4
                    self.body_received = len(self.request_buffer) - body_start
                    
                    if self.content_length == 0 or self.body_received >= self.content_length:
                        # Complete request received, process it
                        await self._handle_http_request(self.request_buffer)
                        self.request_buffer = b""
                        self.headers_complete = False
                        self.content_length = 0
                        self.body_received = 0

        except Exception as exc:
            console.log(f"[http-fetch] Request processing error stream={self.stream_id}: {exc}")
            await self.close(send_packet=True, reason=self._classify_error(exc))

    async def _handle_http_request(self, request_data: bytes) -> None:
        """Forward HTTP request via Fetch API and send response through WISP."""
        try:
            from js import console
            
            # Parse HTTP request
            request_str = request_data.decode("utf-8", errors="ignore")
            lines = request_str.split("\r\n")
            
            if not lines:
                await self.close(send_packet=True, reason=0x41)  # CLOSE_INVALID
                return
            
            # Parse request line: "GET /path HTTP/1.1"
            try:
                parts = lines[0].split(" ", 2)
                if len(parts) < 2:
                    raise ValueError("Invalid request line")
                method, path = parts[0], parts[1]
            except (ValueError, IndexError):
                await self.close(send_packet=True, reason=0x41)
                return
            
            # Parse headers
            headers = {}
            body_start = 1
            for i, line in enumerate(lines[1:], 1):
                if not line:
                    body_start = i + 1
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            
            # Remove Host header to avoid conflicts
            headers.pop("Host", None)
            headers.pop("host", None)
            
            # Get request body
            body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else ""
            
            # Construct target URL
            # Use HTTPS for port 443, HTTP for others
            scheme = "https" if self.port == 443 else "http"
            target_url = f"{scheme}://{self.hostname}{path}"
            
            console.log(
                f"[http-fetch] stream={self.stream_id} {method} {target_url}"
            )
            
            # Forward via Fetch API
            response = await fetch(
                target_url,
                to_js(
                    {
                        "method": method,
                        "headers": headers,
                        "body": body if method not in ("GET", "HEAD", "DELETE") else None,
                        "redirect": "follow",
                    },
                    dict_converter=Object.fromEntries,
                ),
            )
            
            # Get response body
            response_body = await response.text()
            
            # Get response headers
            response_headers = {}
            for key, value in response.headers.items():
                response_headers[key] = value
            
            # Format as HTTP response
            status_line = f"HTTP/1.1 {response.status} OK\r\n"
            headers_str = "\r\n".join(
                f"{k}: {v}" for k, v in response_headers.items()
            )
            response_str = status_line + headers_str + "\r\n\r\n" + response_body
            response_bytes = response_str.encode("utf-8")
            
            console.log(
                f"[http-fetch] stream={self.stream_id} {response.status} "
                f"({len(response_bytes)} bytes)"
            )
            
            # Send response back through WISP in chunks
            for start in range(0, len(response_bytes), MAX_DATA_PAYLOAD_BYTES):
                chunk = response_bytes[start : start + MAX_DATA_PAYLOAD_BYTES]
                self.send_data(chunk)
            
            # After sending response, close the stream (HTTP is request-response)
            await self.close(send_packet=True, reason=0x02)
            
        except asyncio.TimeoutError:
            console.log(f"[http-fetch] Request timeout stream={self.stream_id}")
            await self.close(send_packet=True, reason=0x43)
        except Exception as exc:
            console.log(
                f"[http-fetch] Request failed stream={self.stream_id}: {exc}"
            )
            await self.close(send_packet=True, reason=self._classify_error(exc))

    @staticmethod
    def _classify_error(exc: BaseException) -> int:
        """Map exceptions to WISP close reason codes."""
        text = str(exc).lower()
        if isinstance(exc, asyncio.TimeoutError) or "timeout" in text:
            return 0x43  # CLOSE_TIMEOUT
        if "refused" in text or "econnrefused" in text:
            return 0x44  # CLOSE_REFUSED
        if "resolve" in text or "not found" in text or "dns" in text:
            return 0x42  # CLOSE_UNREACHABLE
        if "disallowed" in text or "private" in text:
            return 0x48  # CLOSE_BLOCKED
        return 0x03  # CLOSE_NETWORK_ERROR

    def send_data(self, payload: bytes) -> None:
        """Send HTTP response payload back through WISP."""
        from server.connection import DATA, build_packet

        self.send_packet(build_packet(DATA, self.stream_id, payload))

    def send_continue(self) -> None:
        """Send buffer availability notification to client."""
        from server.connection import CONTINUE, build_packet

        self.send_packet(
            build_packet(
                CONTINUE,
                self.stream_id,
                int(self.buffer_remaining).to_bytes(4, "little"),
            )
        )

    async def close(self, *, send_packet: bool, reason: int = 0x02) -> None:
        """Close this HTTP stream."""
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._ready.set()

            if send_packet:
                from server.connection import CLOSE, build_packet

                self.send_packet(
                    build_packet(CLOSE, self.stream_id, bytes((reason & 0xFF,)))
                )

            self.on_closed(self.stream_id)


# Export as TCPStream for compatibility with existing code
# The server will use HTTPFetchStream wherever it would use TCPStream
TCPStream = HTTPFetchStream

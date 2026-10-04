"""
HTTP request handling for WISP proxy.

Uses Cloudflare's fetch() API to forward HTTP requests to destinations.
"""
import asyncio
from typing import Dict, Optional, Tuple, Callable
import logging

logger = logging.getLogger(__name__)

# fetch() will be injected by worker.py from Cloudflare's global
fetch = None


class HTTPRequest:
    """
    Encapsulates an HTTP request parsed from raw bytes.
    
    Parses HTTP/1.0 and HTTP/1.1 request format:
    METHOD /path HTTP/1.1\r\n
    Header: value\r\n
    ...\r\n
    \r\n
    [body]
    """
    
    def __init__(self, stream_id: int, method: str = "GET", path: str = "/",
                 headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None):
        self.stream_id = stream_id
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body
        self.hostname = None
        self.port = 80
    
    def parse_from_raw(self, hostname: str, port: int, raw_data: bytes):
        """
        Parse raw HTTP request data.
        
        Args:
            hostname: Destination hostname
            port: Destination port
            raw_data: Raw HTTP request bytes
        """
        self.hostname = hostname
        self.port = port
        
        try:
            # Split headers and body
            if b'\r\n\r\n' in raw_data:
                headers_part, body_part = raw_data.split(b'\r\n\r\n', 1)
                self.body = body_part if body_part else None
            else:
                headers_part = raw_data
                self.body = None
            
            # Parse request line
            lines = headers_part.split(b'\r\n')
            if lines and lines[0]:
                try:
                    request_line = lines[0].decode('utf-8', errors='strict')
                    parts = request_line.split()
                    if len(parts) >= 2:
                        self.method = parts[0].upper()
                        self.path = parts[1]
                except Exception as e:
                    logger.warning(f"Error parsing request line: {e}")
            
            # Parse headers
            for line in lines[1:]:
                if b':' in line:
                    try:
                        key, val = line.split(b':', 1)
                        key_str = key.decode('utf-8', errors='ignore').strip()
                        val_str = val.decode('utf-8', errors='ignore').strip()
                        
                        # Skip hop-by-hop headers
                        if key_str.lower() not in ('connection', 'keep-alive', 'transfer-encoding', 'upgrade'):
                            self.headers[key_str] = val_str
                    except Exception as e:
                        logger.warning(f"Error parsing header: {e}")
        
        except Exception as e:
            logger.error(f"Error parsing HTTP request: {e}")


class HTTPConnection:
    """
    Manages a single HTTP request/response cycle.
    
    Accepts raw HTTP request bytes, parses them, forwards to destination
    via fetch(), and returns the complete HTTP response.
    """
    
    def __init__(self, stream_id: int, hostname: str, port: int):
        self.stream_id = stream_id
        self.hostname = hostname
        self.port = port
        self.closed = False
    
    async def handle_request(self, raw_data: bytes) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        Handle an HTTP request and return the response.
        
        Args:
            raw_data: Raw HTTP request bytes
        
        Returns:
            (success: bool, response_bytes: Optional[bytes], error_message: Optional[str])
        """
        try:
            if fetch is None:
                error_msg = "Fetch API not injected"
                logger.error(error_msg)
                return False, None, error_msg
            
            # Parse the raw HTTP request
            request = HTTPRequest(self.stream_id)
            request.parse_from_raw(self.hostname, self.port, raw_data)
            
            logger.debug(f"HTTP {request.method} {self.hostname}:{self.port}{request.path}")
            
            # Build URL
            scheme = "https" if self.port == 443 else "http"
            url = f"{scheme}://{self.hostname}{request.path}"
            
            # Prepare fetch options
            fetch_options = {
                "method": request.method,
            }
            
            # Copy headers
            if request.headers:
                fetch_options["headers"] = request.headers
            
            # Add body if present
            if request.body:
                fetch_options["body"] = request.body
            
            # Make the fetch request
            logger.debug(f"Fetching {url}")
            response = await fetch(url, fetch_options)
            
            # Read response body - use correct Python API
            response_body = await self._read_response_body(response)
            
            # Build HTTP response
            status_text = self._get_status_text(response.status)
            status_line = f"HTTP/1.1 {response.status} {status_text}\r\n"
            
            # Copy response headers (skip hop-by-hop)
            headers_lines = []
            try:
                headers_dict = response.headers or {}
                for header_name, header_value in headers_dict.items():
                    header_lower = header_name.lower()
                    # Skip hop-by-hop headers
                    if header_lower not in ('connection', 'keep-alive', 'transfer-encoding', 'upgrade'):
                        headers_lines.append(f"{header_name}: {header_value}\r\n")
            except Exception as e:
                logger.warning(f"Error reading response headers: {e}")
            
            headers_str = "".join(headers_lines) + "\r\n"
            
            # Combine status, headers, and body
            response_data = status_line.encode('utf-8') + headers_str.encode('utf-8') + response_body
            
            logger.debug(f"HTTP response {response.status} ({len(response_data)} bytes)")
            return True, response_data, None
        
        except Exception as e:
            error_msg = str(e)
            logger.error(f"HTTP request failed for stream {self.stream_id}: {error_msg}")
            
            # Return HTTP 502 error response
            status_text = self._get_status_text(502)
            error_response = f"HTTP/1.1 502 {status_text}\r\nContent-Type: text/plain\r\nContent-Length: {len(error_msg)}\r\n\r\n{error_msg}"
            return False, error_response.encode('utf-8'), error_msg
    
    @staticmethod
    async def _read_response_body(response) -> bytes:
        """
        Read response body using correct Cloudflare Python API.
        
        Try different methods that might be available on the response object.
        """
        try:
            # Try Python asyncio stream method
            if hasattr(response, 'read'):
                body = await response.read()
                return bytes(body) if body else b''
            
            # Try aiter/anext (async iterator)
            elif hasattr(response, '__aiter__'):
                chunks = []
                async for chunk in response:
                    chunks.append(chunk)
                return b''.join(chunks)
            
            # Try arrayBuffer (JavaScript-style, unlikely in Python but try)
            elif hasattr(response, 'arrayBuffer'):
                body = await response.arrayBuffer()
                return bytes(body) if body else b''
            
            # Try bytes() directly
            elif hasattr(response, 'body'):
                body = response.body
                if isinstance(body, bytes):
                    return body
                elif hasattr(body, 'read'):
                    return await body.read()
            
            # No method found, return empty
            logger.warning("Could not determine how to read response body")
            return b''
        
        except Exception as e:
            logger.error(f"Error reading response body: {e}")
            return b''
    
    @staticmethod
    def _get_status_text(status_code: int) -> str:
        """Get HTTP status text for a status code."""
        status_texts = {
            200: "OK",
            201: "Created",
            202: "Accepted",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return status_texts.get(status_code, "Unknown")


class HTTPConnectionPool:
    """
    Manages pool of concurrent HTTP requests with a configurable limit.
    
    HTTP requests are typically short-lived (complete before returning),
    so this limits simultaneous ongoing requests.
    
    Default limit: 3 concurrent requests per Worker.
    """
    
    MAX_CONNECTIONS = 3
    
    def __init__(self):
        self.active_requests: Dict[int, HTTPConnection] = {}
        self.active_count = 0
        self.pool_lock = asyncio.Lock()
    
    async def handle_request(self, stream_id: int, hostname: str, port: int,
                            data: bytes) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        Handle an HTTP request from a WISP stream.
        
        Args:
            stream_id: WISP stream identifier
            hostname: Destination hostname
            port: Destination port
            data: Raw HTTP request bytes
        
        Returns:
            (success: bool, response_bytes: Optional[bytes], error_message: Optional[str])
        """
        async with self.pool_lock:
            if self.active_count >= self.MAX_CONNECTIONS:
                error_msg = f"HTTP pool exhausted (max {self.MAX_CONNECTIONS} concurrent requests)"
                logger.warning(error_msg)
                return False, None, error_msg
            
            # Check for duplicate stream ID
            if stream_id in self.active_requests:
                error_msg = f"Stream {stream_id} already has pending request"
                logger.warning(error_msg)
                return False, None, error_msg
            
            self.active_count += 1
        
        # Create connection and handle request
        conn = HTTPConnection(stream_id, hostname, port)
        self.active_requests[stream_id] = conn
        
        try:
            success, response_data, error = await conn.handle_request(data)
            return success, response_data, error
        
        finally:
            async with self.pool_lock:
                self.active_requests.pop(stream_id, None)
                self.active_count = max(0, self.active_count - 1)
                logger.debug(f"HTTP pool: {self.active_count}/{self.MAX_CONNECTIONS} active")

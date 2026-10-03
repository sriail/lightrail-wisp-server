import asyncio
from typing import Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Fetch is available as a built-in in Cloudflare Workers Python runtime
# It should be in globals when we're running on Cloudflare
fetch = None

# Try to get fetch from different sources
try:
    # First try: check if it's already in globals
    import builtins
    if hasattr(builtins, 'fetch'):
        fetch = builtins.fetch
    else:
        # Second try: check the current globals
        fetch = globals().get('fetch')
except:
    pass

# If still not found, provide a fallback
if fetch is None:
    logger.warning("Built-in fetch not available - HTTP requests will fail")
    
    async def fetch(*args, **kwargs):
        raise RuntimeError(
            "Fetch API not available. "
            "Ensure you're running on Cloudflare Workers Python runtime."
        )

logger = logging.getLogger(__name__)

class HTTPRequest:
    """Encapsulates an HTTP request sent over a stream"""
    
    def __init__(self, stream_id: int, method: str = "GET", path: str = "/", 
                 headers: Optional[Dict] = None, body: Optional[bytes] = None):
        self.stream_id = stream_id
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body
        self.hostname = None
        self.port = 80
    
    def parse_from_raw(self, hostname: str, port: int, raw_data: bytes):
        """Parse raw HTTP request data (simplified)."""
        self.hostname = hostname
        self.port = port
        
        try:
            # Simple parsing: split headers and body
            if b'\r\n\r\n' in raw_data:
                headers_part, body_part = raw_data.split(b'\r\n\r\n', 1)
                self.body = body_part if body_part else None
            else:
                headers_part = raw_data
            
            # Parse first line for method and path
            lines = headers_part.split(b'\r\n')
            if lines:
                first_line = lines[0].decode('utf-8', errors='ignore')
                parts = first_line.split()
                if len(parts) >= 2:
                    self.method = parts[0]
                    self.path = parts[1]
            
            # Parse headers
            for line in lines[1:]:
                if b':' in line:
                    key, val = line.split(b':', 1)
                    self.headers[key.decode('utf-8', errors='ignore').strip()] = \
                        val.decode('utf-8', errors='ignore').strip()
        
        except Exception as e:
            logger.error(f"Error parsing HTTP request: {e}")


class HTTPConnection:
    """Manages HTTP requests for a stream"""
    
    def __init__(self, stream_id: int, hostname: str, port: int):
        self.stream_id = stream_id
        self.hostname = hostname
        self.port = port
        self.closed = False
    
    async def handle_request(self, raw_data: bytes) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        Handle an HTTP request.
        Returns: (success, response_data, error_message)
        """
        try:
            # Parse the raw HTTP request
            request = HTTPRequest(self.stream_id)
            request.parse_from_raw(self.hostname, self.port, raw_data)
            
            # Build URL
            scheme = "https" if self.port == 443 else "http"
            url = f"{scheme}://{self.hostname}{request.path}"
            
            # Prepare fetch options
            options = {
                "method": request.method,
                "headers": request.headers,
            }
            
            if request.body:
                options["body"] = request.body
            
            # Set appropriate Accept-Encoding for passthrough
            if "Accept-Encoding" not in options.get("headers", {}):
                options.setdefault("headers", {})["Accept-Encoding"] = "gzip, deflate"
            
            # Make the fetch request
            response = await fetch(url, options)
            
            # Read response body
            response_body = await response.arrayBuffer()
            
            # Build HTTP response
            status_line = f"HTTP/1.1 {response.status} {response.statusText}\r\n"
            
            # Copy response headers
            headers_lines = []
            for header_name, header_value in response.headers.items():
                headers_lines.append(f"{header_name}: {header_value}\r\n")
            
            headers_str = "".join(headers_lines) + "\r\n"
            
            response_data = status_line.encode() + headers_str.encode() + response_body
            
            return True, response_data, None
        
        except Exception as e:
            error_msg = str(e)
            logger.error(f"HTTP request failed for stream {self.stream_id}: {error_msg}")
            
            # Return HTTP error response
            error_response = f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n{error_msg}"
            return False, error_response.encode(), error_msg


class HTTPConnectionPool:
    """Manages pool of HTTP connections with limit of 3 concurrent requests"""
    
    MAX_CONNECTIONS = 3
    
    def __init__(self):
        self.active_requests: Dict[int, HTTPConnection] = {}
        self.active_count = 0
    
    async def handle_request(self, stream_id: int, hostname: str, port: int, 
                            data: bytes) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        Handle an HTTP request.
        Returns: (success, response_data, error_message)
        """
        if self.active_count >= self.MAX_CONNECTIONS:
            error_msg = "HTTP connection pool exhausted (max 3 concurrent)"
            return False, None, error_msg
        
        conn = HTTPConnection(stream_id, hostname, port)
        self.active_requests[stream_id] = conn
        self.active_count += 1
        
        try:
            success, response_data, error = await conn.handle_request(data)
            return success, response_data, error
        
        finally:
            self.active_requests.pop(stream_id, None)
            self.active_count = max(0, self.active_count - 1)

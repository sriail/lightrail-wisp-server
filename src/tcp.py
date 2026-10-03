import asyncio
from typing import Dict, Optional, Tuple
import logging

# Try to import from cloudflare workers runtime
try:
    from workers import connect
except ImportError:
    try:
        # Alternative import for cloudflare:sockets
        from cloudflare.sockets import connect
    except ImportError:
        # Fallback: define a placeholder that will raise an error
        async def connect(*args, **kwargs):
            raise RuntimeError(
                "TCP socket API not available. "
                "This requires Cloudflare Workers with TCP sockets enabled."
            )

logger = logging.getLogger(__name__)

class TCPConnection:
    """Manages a single TCP socket with bidirectional data transfer"""
    
    def __init__(self, stream_id: int, hostname: str, port: int):
        self.stream_id = stream_id
        self.hostname = hostname
        self.port = port
        self.socket = None
        self.reader_task = None
        self.write_queue = asyncio.Queue()
        self.error = None
        self.closed = False
    
    async def connect(self) -> bool:
        """Establish TCP connection. Returns True on success."""
        try:
            # Use Cloudflare's connect() API for TCP sockets
            self.socket = connect(
                {"hostname": self.hostname, "port": self.port},
                {"secureTransport": "off"}
            )
            
            # Wait for connection to establish
            await self.socket.opened
            logger.info(f"TCP connection established: {self.hostname}:{self.port} (stream {self.stream_id})")
            return True
            
        except Exception as e:
            self.error = str(e)
            logger.error(f"TCP connection failed for {self.hostname}:{self.port}: {e}")
            return False
    
    async def write_data(self, data: bytes) -> bool:
        """Queue data to write to TCP socket."""
        try:
            await self.write_queue.put(data)
            return True
        except Exception as e:
            logger.error(f"Error queuing write for stream {self.stream_id}: {e}")
            return False
    
    async def read_loop(self, on_data_callback, on_close_callback):
        """Continuously read from TCP socket and pass data to callback."""
        try:
            reader = self.socket.readable.getReader()
            
            while not self.closed:
                try:
                    chunk = await reader.read()
                    if not chunk or len(chunk) == 0:
                        # Connection closed by remote
                        break
                    
                    await on_data_callback(self.stream_id, bytes(chunk))
                    
                except Exception as e:
                    logger.error(f"Error reading from TCP socket (stream {self.stream_id}): {e}")
                    break
        
        finally:
            self.closed = True
            await on_close_callback(self.stream_id)
    
    async def write_loop(self):
        """Continuously write queued data to TCP socket."""
        try:
            writer = self.socket.writable.getWriter()
            
            while not self.closed:
                try:
                    data = await asyncio.wait_for(self.write_queue.get(), timeout=1.0)
                    await writer.write(data)
                    
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error writing to TCP socket (stream {self.stream_id}): {e}")
                    break
        
        finally:
            self.closed = True
    
    async def close(self):
        """Close TCP connection gracefully."""
        if self.socket:
            try:
                await self.socket.close()
            except:
                pass
        self.closed = True


class TCPConnectionPool:
    """Manages pool of TCP connections with limit of 3 concurrent connections"""
    
    MAX_CONNECTIONS = 3
    
    def __init__(self):
        self.connections: Dict[int, TCPConnection] = {}
        self.active_count = 0
    
    async def create_connection(self, stream_id: int, hostname: str, port: int) -> Tuple[bool, Optional[str]]:
        """
        Create a new TCP connection.
        Returns: (success, error_message)
        """
        if self.active_count >= self.MAX_CONNECTIONS:
            return False, "Connection pool exhausted (max 3 concurrent)"
        
        conn = TCPConnection(stream_id, hostname, port)
        
        if not await conn.connect():
            return False, conn.error
        
        self.connections[stream_id] = conn
        self.active_count += 1
        
        return True, None
    
    async def send_data(self, stream_id: int, data: bytes) -> Tuple[bool, Optional[str]]:
        """Send data to a TCP connection."""
        conn = self.connections.get(stream_id)
        if not conn:
            return False, "Stream not found"
        
        if conn.closed:
            return False, "Stream closed"
        
        if not await conn.write_data(data):
            return False, "Failed to queue data"
        
        return True, None
    
    async def close_connection(self, stream_id: int):
        """Close a TCP connection."""
        conn = self.connections.pop(stream_id, None)
        if conn:
            await conn.close()
            self.active_count = max(0, self.active_count - 1)
    
    def get_connection(self, stream_id: int) -> Optional[TCPConnection]:
        """Get a connection by stream ID."""
        return self.connections.get(stream_id)
    
    async def close_all(self):
        """Close all connections."""
        for conn in self.connections.values():
            await conn.close()
        self.connections.clear()
        self.active_count = 0

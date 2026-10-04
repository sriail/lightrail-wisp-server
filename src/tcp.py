"""
TCP socket handling for Cloudflare Workers Python runtime.

Uses Cloudflare's connect() global API for outbound TCP connections.
"""
import asyncio
from typing import Dict, Optional, Tuple, Callable
import logging

logger = logging.getLogger(__name__)

# connect() will be injected by worker.py from Cloudflare's global
connect = None

# Validation lists for security
BLOCKED_HOSTNAMES = [
    'localhost',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    '::',
]

BLOCKED_IP_RANGES = [
    # Private IP ranges (RFC 1918)
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    # Link-local
    ('169.254.0.0', '169.254.255.255'),
    # Loopback
    ('127.0.0.0', '127.255.255.255'),
    # Multicast
    ('224.0.0.0', '239.255.255.255'),
]


def _is_blocked_host(hostname: str) -> bool:
    """Check if a hostname is in the blocked list."""
    if hostname.lower() in BLOCKED_HOSTNAMES:
        return True
    
    # Check for private IPs (simplified - doesn't do full range checks)
    try:
        import ipaddress
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local:
                return True
        except ValueError:
            # Not an IP address, that's fine
            pass
    except Exception:
        pass
    
    return False


class TCPConnection:
    """
    Manages a single TCP socket with bidirectional data transfer.
    
    Uses Cloudflare's connect() API to establish outbound TCP connections.
    """
    
    def __init__(self, stream_id: int, hostname: str, port: int):
        self.stream_id = stream_id
        self.hostname = hostname
        self.port = port
        self.socket = None
        self.write_queue: asyncio.Queue = asyncio.Queue()
        self.error: Optional[str] = None
        self.closed = False
        self.closing_lock = asyncio.Lock()
    
    async def connect(self) -> bool:
        """
        Establish TCP connection to the specified hostname and port.
        Returns True on success, False otherwise.
        """
        try:
            if connect is None:
                self.error = "TCP socket API (connect) not injected - ensure worker.py sets it up"
                logger.error(self.error)
                return False
            
            # Validate destination
            if _is_blocked_host(self.hostname):
                self.error = f"Blocked host: {self.hostname}"
                logger.warning(self.error)
                return False
            
            if self.port < 1 or self.port > 65535:
                self.error = f"Invalid port: {self.port}"
                logger.error(self.error)
                return False
            
            logger.info(f"Connecting to {self.hostname}:{self.port} (stream {self.stream_id})")
            
            # Call Cloudflare's connect() API
            # The exact signature depends on Cloudflare's implementation
            # Expected: connect(hostname, port) or connect({"hostname": ..., "port": ...})
            try:
                # Try with positional args first
                self.socket = await connect(self.hostname, self.port)
            except TypeError:
                # Try with dict format
                self.socket = await connect({
                    "hostname": self.hostname,
                    "port": self.port
                })
            
            logger.info(f"TCP connection established: {self.hostname}:{self.port} (stream {self.stream_id})")
            return True
        
        except Exception as e:
            self.error = str(e)
            logger.error(f"TCP connection failed for {self.hostname}:{self.port}: {e}")
            return False
    
    async def write_data(self, data: bytes) -> bool:
        """
        Queue data to write to the TCP socket.
        Returns True on success.
        """
        try:
            if self.closed or self.socket is None:
                return False
            
            await asyncio.wait_for(self.write_queue.put(data), timeout=5.0)
            return True
        except Exception as e:
            logger.error(f"Error queuing write for stream {self.stream_id}: {e}")
            return False
    
    async def read_loop(self, on_data_callback: Callable, on_close_callback: Callable):
        """
        Continuously read from TCP socket and invoke callback with data.
        
        Args:
            on_data_callback: async function(stream_id, data)
            on_close_callback: async function(stream_id)
        """
        try:
            if self.socket is None:
                logger.error(f"Socket is None for stream {self.stream_id}")
                return
            
            # Read from socket - Cloudflare socket should support iteration or read method
            while not self.closed:
                try:
                    # Try different socket read APIs
                    chunk = None
                    
                    if hasattr(self.socket, 'read'):
                        # Standard asyncio-style read
                        chunk = await asyncio.wait_for(self.socket.read(4096), timeout=30.0)
                    elif hasattr(self.socket, 'recv'):
                        # Socket-style recv
                        chunk = await asyncio.wait_for(self.socket.recv(4096), timeout=30.0)
                    else:
                        logger.error(f"Socket has no read/recv method (stream {self.stream_id})")
                        break
                    
                    if not chunk:
                        # EOF - remote closed connection
                        logger.info(f"Remote closed connection (stream {self.stream_id})")
                        break
                    
                    # Invoke callback with received data
                    await on_data_callback(self.stream_id, bytes(chunk))
                
                except asyncio.TimeoutError:
                    logger.warning(f"Read timeout on stream {self.stream_id}")
                    break
                except Exception as e:
                    logger.error(f"Error reading from TCP socket (stream {self.stream_id}): {e}")
                    break
        
        finally:
            await self._mark_closed()
            # Notify server that stream is closed
            try:
                await on_close_callback(self.stream_id)
            except Exception as e:
                logger.error(f"Error in close callback: {e}")
    
    async def write_loop(self):
        """
        Continuously read from write queue and send to TCP socket.
        """
        try:
            if self.socket is None:
                logger.error(f"Socket is None for stream {self.stream_id}")
                return
            
            while not self.closed:
                try:
                    # Wait for data with timeout
                    data = await asyncio.wait_for(self.write_queue.get(), timeout=30.0)
                    
                    if not data:
                        continue
                    
                    # Write to socket
                    if hasattr(self.socket, 'write'):
                        await asyncio.wait_for(self.socket.write(data), timeout=30.0)
                    elif hasattr(self.socket, 'send'):
                        await asyncio.wait_for(self.socket.send(data), timeout=30.0)
                    else:
                        logger.error(f"Socket has no write/send method (stream {self.stream_id})")
                        break
                    
                    self.write_queue.task_done()
                
                except asyncio.TimeoutError:
                    # Timeout is OK, just keep waiting for data
                    continue
                except Exception as e:
                    logger.error(f"Error writing to TCP socket (stream {self.stream_id}): {e}")
                    break
        
        finally:
            await self._mark_closed()
    
    async def _mark_closed(self):
        """Mark connection as closed (thread-safe)."""
        async with self.closing_lock:
            self.closed = True
    
    async def close(self):
        """
        Close TCP connection gracefully.
        """
        async with self.closing_lock:
            if self.closed:
                return
            
            self.closed = True
            
            if self.socket:
                try:
                    if hasattr(self.socket, 'close'):
                        await self.socket.close()
                    elif hasattr(self.socket, 'shutdown'):
                        self.socket.shutdown()
                except Exception as e:
                    logger.warning(f"Error closing socket: {e}")


class TCPConnectionPool:
    """
    Manages pool of TCP connections with a configurable limit.
    
    Default limit: 3 concurrent connections per Worker.
    """
    
    MAX_CONNECTIONS = 3
    
    def __init__(self):
        self.connections: Dict[int, TCPConnection] = {}
        self.active_count = 0
        self.pool_lock = asyncio.Lock()
    
    async def create_connection(self, stream_id: int, hostname: str, port: int) -> Tuple[bool, Optional[str]]:
        """
        Create and establish a new TCP connection.
        
        Args:
            stream_id: WISP stream identifier
            hostname: Destination hostname
            port: Destination port
        
        Returns:
            (success: bool, error_message: Optional[str])
        """
        async with self.pool_lock:
            # Check pool limit
            if self.active_count >= self.MAX_CONNECTIONS:
                error_msg = f"Connection pool exhausted (max {self.MAX_CONNECTIONS} concurrent)"
                logger.warning(error_msg)
                return False, error_msg
            
            # Check for duplicate stream ID
            if stream_id in self.connections:
                error_msg = f"Stream {stream_id} already exists"
                logger.warning(error_msg)
                return False, error_msg
        
        # Create connection outside lock
        conn = TCPConnection(stream_id, hostname, port)
        
        if not await conn.connect():
            # Connection failed, don't add to pool
            return False, conn.error
        
        # Add to pool
        async with self.pool_lock:
            self.connections[stream_id] = conn
            self.active_count += 1
        
        logger.info(f"Connection added to pool (active: {self.active_count}/{self.MAX_CONNECTIONS})")
        return True, None
    
    async def send_data(self, stream_id: int, data: bytes) -> Tuple[bool, Optional[str]]:
        """
        Send data on an established connection.
        
        Args:
            stream_id: WISP stream identifier
            data: Data to send
        
        Returns:
            (success: bool, error_message: Optional[str])
        """
        conn = self.connections.get(stream_id)
        if not conn:
            return False, "Stream not found"
        
        if conn.closed:
            return False, "Stream is closed"
        
        if not await conn.write_data(data):
            return False, "Failed to queue data"
        
        return True, None
    
    async def close_connection(self, stream_id: int):
        """
        Close a connection and remove from pool.
        
        Args:
            stream_id: WISP stream identifier
        """
        async with self.pool_lock:
            conn = self.connections.pop(stream_id, None)
        
        if conn:
            await conn.close()
            async with self.pool_lock:
                self.active_count = max(0, self.active_count - 1)
            logger.info(f"Connection closed (active: {self.active_count}/{self.MAX_CONNECTIONS})")
    
    def get_connection(self, stream_id: int) -> Optional[TCPConnection]:
        """Get a connection by stream ID without removing it."""
        return self.connections.get(stream_id)
    
    async def close_all(self):
        """Close all connections in the pool."""
        async with self.pool_lock:
            connections = list(self.connections.values())
            self.connections.clear()
            self.active_count = 0
        
        for conn in connections:
            await conn.close()
        
        logger.info("All connections closed")

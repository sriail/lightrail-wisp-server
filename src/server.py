"""
WISP v1.2 Protocol Server

Implements the WISP (WebSocket-based) proxy protocol for multiplexing
TCP connections over a single WebSocket.

Protocol specification: multiple streams over one WebSocket connection,
with per-stream flow control and error reporting.
"""
import asyncio
import logging
from typing import Dict, Optional, Callable, Set
from wisp_protocol import WispPacket, PacketType, CloseReason
from tcp import TCPConnectionPool
from http import HTTPConnectionPool

logger = logging.getLogger(__name__)

# Buffer configuration
BUFFER_SIZE = 64  # Number of packets to buffer per stream
INITIAL_BUFFER_SIZE = 16  # Initial buffer size sent to client

class StreamBuffer:
    """Manages buffered packets for a stream"""
    
    def __init__(self, stream_id: int, max_size: int = BUFFER_SIZE):
        self.stream_id = stream_id
        self.max_size = max_size
        self.packets = asyncio.Queue(maxsize=max_size)
        self.remaining = max_size
    
    async def add_packet(self, packet: bytes) -> bool:
        """Add packet to buffer. Returns True on success."""
        try:
            await asyncio.wait_for(self.packets.put(packet), timeout=1.0)
            self.remaining = max(0, self.remaining - 1)
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Buffer full for stream {self.stream_id}")
            return False
    
    async def get_packet(self) -> Optional[bytes]:
        """Get packet from buffer."""
        try:
            return await asyncio.wait_for(self.packets.get(), timeout=1.0)
        except asyncio.TimeoutError:
            return None
    
    def refill(self):
        """Refill buffer (called when CONTINUE is received from client)."""
        self.remaining = self.max_size


class WispStream:
    """
    Manages state for a single WISP stream.
    
    A stream represents one logical connection through the proxy:
    - client initiates CONNECT to destination hostname:port
    - server establishes connection (TCP or HTTP)
    - data flows bidirectionally
    - either side can close the stream
    """
    
    def __init__(self, stream_id: int, hostname: str, port: int):
        self.stream_id = stream_id
        self.hostname = hostname
        self.port = port
        self.buffer = StreamBuffer(stream_id)
        self.closed = False
        self.close_lock = asyncio.Lock()
        
        # Determine transport based on port
        # HTTP: port 80/443 (use fetch())
        # TCP: everything else (use connect() sockets)
        self.is_http = port in (80, 443)
    
    async def send_to_tcp_connection(self, data: bytes) -> bool:
        """
        Queue data to be sent to TCP connection.
        
        Returns: True if queued successfully
        """
        if self.closed:
            return False
        
        if not await self.buffer.add_packet(data):
            logger.error(f"Failed to buffer data for stream {self.stream_id}")
            return False
        
        return True
    
    async def mark_closed(self):
        """Mark stream as closed (thread-safe)."""
        async with self.close_lock:
            self.closed = True


class WispServer:
    """
    WISP Protocol Server - multiplexes TCP connections over WebSocket.
    
    Manages:
    - Multiple concurrent streams over one WebSocket
    - TCP connection pooling (max 3 concurrent TCP connections)
    - HTTP request handling via fetch() (max 3 concurrent requests)
    - Per-stream flow control with CONTINUE packets
    - Proper cleanup when WebSocket closes
    """
    
    def __init__(self):
        self.streams: Dict[int, WispStream] = {}
        self.tcp_pool = TCPConnectionPool()
        self.http_pool = HTTPConnectionPool()
        self.client_buffers: Dict[int, int] = {}  # stream_id -> remaining buffer size
        self.websocket = None
        self.active_tasks: Set[asyncio.Task] = set()
        self.closing = False
        self.close_lock = asyncio.Lock()
    
    async def handle_connection(self, websocket):
        """
        Main handler for a WebSocket connection.
        
        This is called when a client connects via WebSocket.
        It manages the full lifecycle of the connection.
        
        Args:
            websocket: Cloudflare WebSocket server-side object
        """
        self.websocket = websocket
        logger.info("WebSocket connection accepted")
        
        try:
            # Send initial CONTINUE packet on stream 0 (protocol setup)
            init_packet = WispPacket.encode_continue(0, INITIAL_BUFFER_SIZE)
            await self.send_packet(init_packet)
            logger.info("Sent initial protocol CONTINUE packet")
            
            # Handle incoming messages from client
            await self._receive_messages()
        
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}", exc_info=True)
        
        finally:
            logger.info("WebSocket connection closing, cleaning up")
            await self.cleanup()
    
    async def _receive_messages(self):
        """
        Continuously receive and handle messages from the WebSocket.
        
        Tries different WebSocket APIs that might be available.
        """
        try:
            # Try async iterator pattern (Cloudflare Workers Python)
            if hasattr(self.websocket, '__aiter__'):
                logger.debug("Using async iterator for WebSocket messages")
                async for message in self.websocket:
                    if self.closing:
                        break
                    try:
                        # Message should be bytes for binary WISP packets
                        if isinstance(message, bytes):
                            await self.handle_packet(message)
                        else:
                            logger.warning(f"Received non-bytes message: {type(message)}")
                    except Exception as e:
                        logger.error(f"Error handling packet: {e}")
            
            # Try recv() method pattern (alternative API)
            elif hasattr(self.websocket, 'recv'):
                logger.debug("Using recv() for WebSocket messages")
                while not self.closing:
                    try:
                        message = await asyncio.wait_for(self.websocket.recv(), timeout=300.0)
                        if message is None:
                            logger.info("WebSocket recv returned None (connection closed)")
                            break
                        
                        if isinstance(message, bytes):
                            await self.handle_packet(message)
                        else:
                            logger.warning(f"Received non-bytes message: {type(message)}")
                    
                    except asyncio.TimeoutError:
                        logger.warning("WebSocket recv timeout")
                        break
                    except Exception as e:
                        if "closed" in str(e).lower():
                            logger.info("WebSocket closed")
                            break
                        logger.error(f"Error in recv: {e}")
                        break
            
            else:
                logger.error("WebSocket has neither __aiter__ nor recv method")
        
        except Exception as e:
            logger.error(f"Error in message receive loop: {e}", exc_info=True)
    
    async def handle_packet(self, data: bytes):
        """
        Decode and handle an incoming WISP packet.
        
        Args:
            data: Raw WISP packet bytes (binary)
        """
        try:
            if not data or len(data) < 5:
                logger.warning(f"Packet too short: {len(data) if data else 0} bytes")
                return
            
            packet_type, stream_id, payload = WispPacket.decode_packet(data)
            
            logger.debug(f"Packet type={packet_type}, stream_id={stream_id}, payload_len={len(payload)}")
            
            if packet_type == PacketType.CONNECT:
                await self.handle_connect(stream_id, payload)
            
            elif packet_type == PacketType.DATA:
                await self.handle_data(stream_id, payload)
            
            elif packet_type == PacketType.CONTINUE:
                await self.handle_continue(stream_id, payload)
            
            elif packet_type == PacketType.CLOSE:
                await self.handle_close(stream_id, payload)
            
            else:
                logger.warning(f"Unknown packet type: {packet_type}")
        
        except Exception as e:
            logger.error(f"Error decoding packet: {e}")
    
    def _create_task(self, coro):
        """
        Create and track an asyncio task.
        
        Tracks all tasks so they can be cancelled on shutdown.
        """
        task = asyncio.create_task(coro)
        self.active_tasks.add(task)
        task.add_done_callback(self.active_tasks.discard)
        return task
    
    async def handle_connect(self, stream_id: int, payload: bytes):
        """
        Handle CONNECT packet from client.
        
        CONNECT request: stream_id, port (2 bytes LE), hostname (UTF-8)
        
        Validates and initiates connection to destination.
        """
        try:
            port, hostname = WispPacket.decode_connect(payload)
            
            # Validate parameters
            if not hostname:
                logger.warning(f"CONNECT with empty hostname (stream {stream_id})")
                await self.send_close_packet(stream_id, CloseReason.INVALID_INFO)
                return
            
            if port < 1 or port > 65535:
                logger.warning(f"CONNECT with invalid port {port} (stream {stream_id})")
                await self.send_close_packet(stream_id, CloseReason.INVALID_INFO)
                return
            
            # Check for duplicate stream ID
            if stream_id in self.streams:
                logger.warning(f"Stream {stream_id} already exists")
                await self.send_close_packet(stream_id, CloseReason.INVALID_INFO)
                return
            
            # Create stream object
            stream = WispStream(stream_id, hostname, port)
            self.streams[stream_id] = stream
            self.client_buffers[stream_id] = INITIAL_BUFFER_SIZE
            
            logger.info(f"CONNECT {hostname}:{port} on stream {stream_id} (HTTP: {stream.is_http})")
            
            # Route to appropriate handler
            if stream.is_http:
                await self.handle_http_connection(stream_id, hostname, port)
            else:
                await self.handle_tcp_connection(stream_id, hostname, port)
        
        except ValueError as e:
            logger.error(f"Invalid CONNECT payload: {e}")
            await self.send_close_packet(stream_id, CloseReason.INVALID_INFO)
        except Exception as e:
            logger.error(f"Error handling CONNECT: {e}")
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
    
    async def handle_tcp_connection(self, stream_id: int, hostname: str, port: int):
        """
        Establish a TCP connection for a stream.
        
        Creates a connection and starts read/write tasks.
        """
        try:
            logger.debug(f"Creating TCP connection for stream {stream_id}")
            
            # Try to create connection
            success, error = await self.tcp_pool.create_connection(stream_id, hostname, port)
            
            if not success:
                logger.error(f"TCP connection failed: {error}")
                
                # Send appropriate close reason
                if "pool exhausted" in error:
                    close_reason = CloseReason.THROTTLED
                elif "blocked" in error.lower():
                    close_reason = CloseReason.BLOCKED_ADDRESS
                elif "refused" in error.lower():
                    close_reason = CloseReason.CONNECTION_REFUSED
                elif "timeout" in error.lower():
                    close_reason = CloseReason.CONNECTION_TIMEOUT
                else:
                    close_reason = CloseReason.UNREACHABLE_HOST
                
                await self.send_close_packet(stream_id, close_reason)
                self.streams.pop(stream_id, None)
                self.client_buffers.pop(stream_id, None)
                return
            
            # Send CONTINUE packet to indicate readiness
            await self.send_continue_packet(stream_id, INITIAL_BUFFER_SIZE)
            logger.info(f"TCP connection ready for stream {stream_id}")
            
            # Get the connection and start read/write loops
            tcp_conn = self.tcp_pool.get_connection(stream_id)
            if tcp_conn:
                # Create task for bidirectional I/O
                self._create_task(self._run_tcp_io_loop(stream_id, tcp_conn))
            else:
                logger.error(f"TCP connection not found for stream {stream_id}")
                await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
                await self.tcp_pool.close_connection(stream_id)
        
        except Exception as e:
            logger.error(f"Error setting up TCP connection: {e}")
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
            self.streams.pop(stream_id, None)
            self.client_buffers.pop(stream_id, None)
    
    async def _run_tcp_io_loop(self, stream_id: int, tcp_conn):
        """
        Run bidirectional I/O for a TCP connection.
        
        Manages both read and write loops, cleaning up when either completes.
        """
        try:
            logger.debug(f"Starting I/O loops for stream {stream_id}")
            
            # Create read and write tasks
            read_task = self._create_task(
                tcp_conn.read_loop(self.on_tcp_data, self.on_tcp_close)
            )
            write_task = self._create_task(tcp_conn.write_loop())
            
            # Wait for either task to complete
            done, pending = await asyncio.wait(
                [read_task, write_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            logger.debug(f"TCP I/O loop ended for stream {stream_id}")
            
            # Cancel any remaining tasks
            for task in pending:
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=1.0)
                except asyncio.CancelledError:
                    pass
                except asyncio.TimeoutError:
                    logger.warning(f"Task cancellation timeout for stream {stream_id}")
            
            # Ensure connection is closed
            await self.tcp_pool.close_connection(stream_id)
        
        except Exception as e:
            logger.error(f"Error in TCP I/O loop for stream {stream_id}: {e}")
            await self.tcp_pool.close_connection(stream_id)
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
    
    async def on_tcp_data(self, stream_id: int, data: bytes):
        """
        Callback invoked when data is received from TCP connection.
        
        Sends data back to client as WISP DATA packet.
        """
        try:
            if not data:
                return
            
            logger.debug(f"TCP data received on stream {stream_id}: {len(data)} bytes")
            
            packet = WispPacket.encode_data(stream_id, data)
            await self.send_packet(packet)
        
        except Exception as e:
            logger.error(f"Error sending TCP data packet: {e}")
    
    async def on_tcp_close(self, stream_id: int):
        """
        Callback invoked when TCP connection closes.
        
        Sends CLOSE packet to client and cleans up stream.
        """
        try:
            logger.info(f"TCP connection closed for stream {stream_id}")
            
            # Clean up connection
            await self.tcp_pool.close_connection(stream_id)
            
            # Clean up stream
            stream = self.streams.pop(stream_id, None)
            self.client_buffers.pop(stream_id, None)
            
            if stream and not stream.closed:
                # Send CLOSE to client
                await self.send_close_packet(stream_id, CloseReason.VOLUNTARY)
        
        except Exception as e:
            logger.error(f"Error in TCP close callback: {e}")
    
    async def handle_http_connection(self, stream_id: int, hostname: str, port: int):
        """
        Prepare HTTP stream to receive data.
        
        HTTP streams handle one request/response cycle then close.
        """
        try:
            logger.debug(f"HTTP stream {stream_id} ready")
            # Send CONTINUE to indicate readiness
            await self.send_continue_packet(stream_id, INITIAL_BUFFER_SIZE)
        except Exception as e:
            logger.error(f"Error setting up HTTP stream: {e}")
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
    
    async def handle_data(self, stream_id: int, payload: bytes):
        """
        Handle DATA packet from client.
        
        Routes data to appropriate connection (TCP or HTTP).
        Manages flow control with CONTINUE packets.
        """
        try:
            if not payload:
                return
            
            logger.debug(f"DATA packet on stream {stream_id}: {len(payload)} bytes")
            
            # Find stream
            stream = self.streams.get(stream_id)
            if not stream:
                logger.warning(f"DATA for unknown stream: {stream_id}")
                return
            
            if stream.closed:
                logger.warning(f"DATA on closed stream: {stream_id}")
                await self.send_close_packet(stream_id, CloseReason.VOLUNTARY)
                return
            
            # Decrement flow control buffer
            if stream_id in self.client_buffers:
                self.client_buffers[stream_id] = max(0, self.client_buffers[stream_id] - 1)
            
            # Handle HTTP vs TCP
            if stream.is_http:
                # HTTP: handle complete request and return response
                await self._handle_http_data(stream_id, stream, payload)
            else:
                # TCP: queue data for transmission
                await self._handle_tcp_data(stream_id, stream, payload)
            
            # Check if we need to send CONTINUE to refill client buffer
            if stream_id in self.client_buffers:
                remaining = self.client_buffers[stream_id]
                if remaining < BUFFER_SIZE // 2:
                    logger.debug(f"Buffer low ({remaining}/{BUFFER_SIZE}), sending CONTINUE")
                    await self.send_continue_packet(stream_id, BUFFER_SIZE)
                    self.client_buffers[stream_id] = BUFFER_SIZE
        
        except Exception as e:
            logger.error(f"Error handling DATA: {e}")
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
    
    async def _handle_http_data(self, stream_id: int, stream: WispStream, payload: bytes):
        """Handle DATA for HTTP connection."""
        try:
            logger.debug(f"HTTP request on stream {stream_id}")
            
            # Make HTTP request
            success, response_data, error = await self.http_pool.handle_request(
                stream_id, stream.hostname, stream.port, payload
            )
            
            if success and response_data:
                logger.debug(f"HTTP response {len(response_data)} bytes")
                # Send response back to client
                response_packet = WispPacket.encode_data(stream_id, response_data)
                await self.send_packet(response_packet)
            else:
                logger.error(f"HTTP request failed: {error}")
                await self.send_close_packet(stream_id, CloseReason.UNREACHABLE_HOST)
            
            # HTTP streams close after one request/response
            await stream.mark_closed()
            self.streams.pop(stream_id, None)
            self.client_buffers.pop(stream_id, None)
        
        except Exception as e:
            logger.error(f"Error handling HTTP data: {e}")
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
            self.streams.pop(stream_id, None)
            self.client_buffers.pop(stream_id, None)
    
    async def _handle_tcp_data(self, stream_id: int, stream: WispStream, payload: bytes):
        """Handle DATA for TCP connection."""
        try:
            # Queue data for TCP transmission
            success, error = await self.tcp_pool.send_data(stream_id, payload)
            if not success:
                logger.error(f"TCP send failed: {error}")
                await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
                await self.tcp_pool.close_connection(stream_id)
        
        except Exception as e:
            logger.error(f"Error sending TCP data: {e}")
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
    
    async def handle_continue(self, stream_id: int, payload: bytes):
        """
        Handle CONTINUE packet from client.
        
        CONTINUE replenishes the client's buffer (flow control).
        """
        try:
            buffer_remaining = WispPacket.decode_continue(payload)
            
            if stream_id in self.client_buffers:
                self.client_buffers[stream_id] = buffer_remaining
                logger.debug(f"CONTINUE stream {stream_id}: buffer={buffer_remaining}")
            else:
                logger.warning(f"CONTINUE for unknown stream: {stream_id}")
        
        except ValueError as e:
            logger.error(f"Invalid CONTINUE payload: {e}")
        except Exception as e:
            logger.error(f"Error handling CONTINUE: {e}")
    
    async def handle_close(self, stream_id: int, payload: bytes):
        """
        Handle CLOSE packet from client.
        
        Closes the stream and associated connection.
        """
        try:
            reason = WispPacket.decode_close(payload)
            logger.info(f"Client CLOSE stream {stream_id} (reason={reason})")
            
            # Close associated connection
            stream = self.streams.pop(stream_id, None)
            
            if stream:
                await stream.mark_closed()
                if not stream.is_http:
                    # Close TCP connection if it exists
                    await self.tcp_pool.close_connection(stream_id)
            
            # Clean up buffer tracking
            self.client_buffers.pop(stream_id, None)
        
        except ValueError as e:
            logger.error(f"Invalid CLOSE payload: {e}")
        except Exception as e:
            logger.error(f"Error handling CLOSE: {e}")
    
    async def send_packet(self, packet: bytes):
        """
        Send a WISP packet to the client over WebSocket.
        
        Args:
            packet: Raw WISP packet bytes (binary)
        """
        try:
            if not self.websocket:
                logger.warning("WebSocket not available for sending packet")
                return
            
            if self.closing:
                logger.debug("WebSocket closing, packet not sent")
                return
            
            # Send as binary frame
            if hasattr(self.websocket, 'send'):
                await asyncio.wait_for(self.websocket.send(packet), timeout=10.0)
            else:
                logger.error("WebSocket has no send method")
        
        except asyncio.TimeoutError:
            logger.error("WebSocket send timeout")
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
    
    async def send_continue_packet(self, stream_id: int, buffer_size: int):
        """Send CONTINUE packet to refill client buffer."""
        try:
            packet = WispPacket.encode_continue(stream_id, buffer_size)
            await self.send_packet(packet)
        except Exception as e:
            logger.error(f"Error sending CONTINUE: {e}")
    
    async def send_close_packet(self, stream_id: int, reason: int):
        """Send CLOSE packet to terminate stream."""
        try:
            packet = WispPacket.encode_close(stream_id, reason)
            await self.send_packet(packet)
        except Exception as e:
            logger.error(f"Error sending CLOSE: {e}")
    
    async def cleanup(self):
        """
        Cleanup all resources when connection closes.
        
        - Cancels all active tasks
        - Closes all TCP connections
        - Closes HTTP pool
        - Clears streams
        """
        async with self.close_lock:
            if self.closing:
                return
            self.closing = True
        
        logger.info("Cleaning up WISP connection")
        
        try:
            # Cancel all active tasks
            logger.debug(f"Cancelling {len(self.active_tasks)} active tasks")
            for task in list(self.active_tasks):
                task.cancel()
            
            # Wait for tasks to complete with timeout
            if self.active_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self.active_tasks, return_exceptions=True),
                        timeout=5.0
                    )
                except asyncio.TimeoutError:
                    logger.warning("Timeout waiting for tasks to complete")
            
            # Close all TCP connections
            await self.tcp_pool.close_all()
            
            # Clear streams
            self.streams.clear()
            self.client_buffers.clear()
            
            logger.info("Cleanup complete")
        
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

import asyncio
import logging
from typing import Dict, Optional, Set
from workers import WebSocket
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
    """Manages a single WISP stream"""
    
    def __init__(self, stream_id: int, hostname: str, port: int):
        self.stream_id = stream_id
        self.hostname = hostname
        self.port = port
        self.buffer = StreamBuffer(stream_id)
        self.closed = False
        self.is_http = port in (80, 443)
    
    async def send_to_tcp_connection(self, data: bytes):
        """Queue data to be sent to TCP connection"""
        if not await self.buffer.add_packet(data):
            logger.error(f"Failed to buffer data for stream {self.stream_id}")


class WispServer:
    """Main WISP protocol server"""
    
    def __init__(self):
        self.streams: Dict[int, WispStream] = {}
        self.tcp_pool = TCPConnectionPool()
        self.http_pool = HTTPConnectionPool()
        self.client_buffers: Dict[int, int] = {}  # stream_id -> remaining buffer
        self.websocket = None
    
    async def handle_connection(self, websocket: WebSocket):
        """Handle incoming WebSocket connection"""
        self.websocket = websocket
        
        try:
            # Send initial CONTINUE packet (stream 0 = protocol version)
            init_packet = WispPacket.encode_continue(0, INITIAL_BUFFER_SIZE)
            await self.send_packet(init_packet)
            
            logger.info("WISP connection established, sent initial CONTINUE packet")
            
            # Handle incoming messages
            async for message in websocket:
                try:
                    await self.handle_packet(message)
                except Exception as e:
                    logger.error(f"Error handling packet: {e}")
        
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
        
        finally:
            await self.cleanup()
    
    async def handle_packet(self, data: bytes):
        """Handle incoming WISP packet"""
        try:
            packet_type, stream_id, payload = WispPacket.decode_packet(data)
            
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
    
    async def handle_connect(self, stream_id: int, payload: bytes):
        """Handle CONNECT packet"""
        try:
            port, hostname = WispPacket.decode_connect(payload)
            
            # Validate
            if not hostname or port < 1 or port > 65535:
                await self.send_close_packet(stream_id, CloseReason.INVALID_INFO)
                return
            
            # Create stream
            stream = WispStream(stream_id, hostname, port)
            self.streams[stream_id] = stream
            self.client_buffers[stream_id] = INITIAL_BUFFER_SIZE
            
            logger.info(f"CONNECT: {hostname}:{port} (stream {stream_id}, is_http={stream.is_http})")
            
            # Route to TCP or HTTP
            if stream.is_http:
                await self.handle_http_connection(stream_id, hostname, port)
            else:
                await self.handle_tcp_connection(stream_id, hostname, port)
        
        except ValueError as e:
            logger.error(f"Invalid CONNECT payload: {e}")
            await self.send_close_packet(stream_id, CloseReason.INVALID_INFO)
    
    async def handle_tcp_connection(self, stream_id: int, hostname: str, port: int):
        """Establish TCP connection"""
        success, error = await self.tcp_pool.create_connection(stream_id, hostname, port)
        
        if not success:
            logger.error(f"TCP connection failed: {error}")
            
            if "pool exhausted" in error:
                await self.send_close_packet(stream_id, CloseReason.THROTTLED)
            else:
                await self.send_close_packet(stream_id, CloseReason.UNREACHABLE_HOST)
            
            self.streams.pop(stream_id, None)
            return
        
        # Send initial CONTINUE packet for this stream
        await self.send_continue_packet(stream_id, INITIAL_BUFFER_SIZE)
        
        # Start read/write loops for TCP connection
        tcp_conn = self.tcp_pool.get_connection(stream_id)
        if tcp_conn:
            asyncio.create_task(self.run_tcp_streams(stream_id, tcp_conn))
    
    async def run_tcp_streams(self, stream_id: int, tcp_conn):
        """Run read/write loops for TCP connection"""
        try:
            read_task = asyncio.create_task(
                tcp_conn.read_loop(self.on_tcp_data, self.on_tcp_close)
            )
            write_task = asyncio.create_task(tcp_conn.write_loop())
            
            # Wait for either to complete
            done, pending = await asyncio.wait(
                [read_task, write_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # Cancel remaining tasks
            for task in pending:
                task.cancel()
        
        except Exception as e:
            logger.error(f"Error in TCP streams for {stream_id}: {e}")
            await self.tcp_pool.close_connection(stream_id)
            await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
    
    async def on_tcp_data(self, stream_id: int, data: bytes):
        """Callback when TCP data is received"""
        try:
            packet = WispPacket.encode_data(stream_id, data)
            await self.send_packet(packet)
        except Exception as e:
            logger.error(f"Error sending TCP data packet: {e}")
    
    async def on_tcp_close(self, stream_id: int):
        """Callback when TCP connection closes"""
        logger.info(f"TCP connection closed: stream {stream_id}")
        await self.tcp_pool.close_connection(stream_id)
        await self.send_close_packet(stream_id, CloseReason.VOLUNTARY)
    
    async def handle_http_connection(self, stream_id: int, hostname: str, port: int):
        """Handle HTTP connection (will be handled when DATA arrives)"""
        # Send initial CONTINUE packet
        await self.send_continue_packet(stream_id, INITIAL_BUFFER_SIZE)
        logger.info(f"HTTP stream {stream_id} ready to receive data")
    
    async def handle_data(self, stream_id: int, payload: bytes):
        """Handle DATA packet"""
        stream = self.streams.get(stream_id)
        if not stream:
            logger.warning(f"DATA for unknown stream: {stream_id}")
            return
        
        if stream.closed:
            await self.send_close_packet(stream_id, CloseReason.VOLUNTARY)
            return
        
        # Decrement client buffer
        if stream_id in self.client_buffers:
            self.client_buffers[stream_id] -= 1
        
        # Route to TCP or HTTP
        if stream.is_http:
            # For HTTP, handle the complete request
            success, response_data, error = await self.http_pool.handle_request(
                stream_id, stream.hostname, stream.port, payload
            )
            
            if success and response_data:
                # Send response back to client
                response_packet = WispPacket.encode_data(stream_id, response_data)
                await self.send_packet(response_packet)
            else:
                await self.send_close_packet(stream_id, CloseReason.UNREACHABLE_HOST)
            
            # Close HTTP stream after response
            stream.closed = True
            self.streams.pop(stream_id, None)
        
        else:
            # For TCP, queue data to write
            success, error = await self.tcp_pool.send_data(stream_id, payload)
            if not success:
                logger.error(f"Failed to send TCP data: {error}")
                await self.send_close_packet(stream_id, CloseReason.NETWORK_ERROR)
        
        # Send CONTINUE if buffer is getting low
        if stream_id in self.client_buffers and self.client_buffers[stream_id] < BUFFER_SIZE // 2:
            await self.send_continue_packet(stream_id, BUFFER_SIZE)
    
    async def handle_continue(self, stream_id: int, payload: bytes):
        """Handle CONTINUE packet from client"""
        try:
            buffer_remaining = WispPacket.decode_continue(payload)
            self.client_buffers[stream_id] = buffer_remaining
            logger.debug(f"CONTINUE for stream {stream_id}: {buffer_remaining} packets")
        except ValueError as e:
            logger.error(f"Invalid CONTINUE payload: {e}")
    
    async def handle_close(self, stream_id: int, payload: bytes):
        """Handle CLOSE packet from client"""
        try:
            reason = WispPacket.decode_close(payload)
            logger.info(f"Client closed stream {stream_id} with reason: {reason}")
            
            # Close associated connection
            stream = self.streams.pop(stream_id, None)
            if stream and not stream.is_http:
                await self.tcp_pool.close_connection(stream_id)
            
            self.client_buffers.pop(stream_id, None)
        
        except ValueError as e:
            logger.error(f"Invalid CLOSE payload: {e}")
    
    async def send_packet(self, packet: bytes):
        """Send WISP packet to client"""
        try:
            if self.websocket:
                await self.websocket.send(packet)
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
    
    async def send_continue_packet(self, stream_id: int, buffer_size: int):
        """Send CONTINUE packet"""
        packet = WispPacket.encode_continue(stream_id, buffer_size)
        await self.send_packet(packet)
    
    async def send_close_packet(self, stream_id: int, reason: int):
        """Send CLOSE packet"""
        packet = WispPacket.encode_close(stream_id, reason)
        await self.send_packet(packet)
    
    async def cleanup(self):
        """Cleanup when connection closes"""
        logger.info("Cleaning up WISP connection")
        
        # Close all TCP connections
        await self.tcp_pool.close_all()
        
        # Close all streams
        self.streams.clear()
        self.client_buffers.clear()

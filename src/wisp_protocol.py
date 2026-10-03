import struct
from enum import IntEnum
from typing import Tuple, Optional

class PacketType(IntEnum):
    CONNECT = 0x01
    DATA = 0x02
    CONTINUE = 0x03
    CLOSE = 0x04

class CloseReason(IntEnum):
    # Client/Server
    UNSPECIFIED = 0x01
    VOLUNTARY = 0x02
    NETWORK_ERROR = 0x03
    # Server only
    INVALID_INFO = 0x41
    UNREACHABLE_HOST = 0x42
    CONNECTION_TIMEOUT = 0x43
    CONNECTION_REFUSED = 0x44
    DATA_TRANSFER_TIMEOUT = 0x47
    BLOCKED_ADDRESS = 0x48
    THROTTLED = 0x49
    # Client only
    CLIENT_ERROR = 0x81

class WispPacket:
    """Encode and decode WISP protocol packets (little-endian)"""
    
    @staticmethod
    def encode_connect(stream_id: int, port: int, hostname: str) -> bytes:
        """Encode CONNECT packet (0x01)"""
        packet_type = struct.pack('<B', PacketType.CONNECT)
        stream_id_bytes = struct.pack('<I', stream_id)
        port_bytes = struct.pack('<H', port)
        hostname_bytes = hostname.encode('utf-8')
        return packet_type + stream_id_bytes + port_bytes + hostname_bytes
    
    @staticmethod
    def encode_data(stream_id: int, data: bytes) -> bytes:
        """Encode DATA packet (0x02)"""
        packet_type = struct.pack('<B', PacketType.DATA)
        stream_id_bytes = struct.pack('<I', stream_id)
        return packet_type + stream_id_bytes + data
    
    @staticmethod
    def encode_continue(stream_id: int, buffer_remaining: int) -> bytes:
        """Encode CONTINUE packet (0x03)"""
        packet_type = struct.pack('<B', PacketType.CONTINUE)
        stream_id_bytes = struct.pack('<I', stream_id)
        buffer_remaining_bytes = struct.pack('<I', buffer_remaining)
        return packet_type + stream_id_bytes + buffer_remaining_bytes
    
    @staticmethod
    def encode_close(stream_id: int, reason: int) -> bytes:
        """Encode CLOSE packet (0x04)"""
        packet_type = struct.pack('<B', PacketType.CLOSE)
        stream_id_bytes = struct.pack('<I', stream_id)
        reason_bytes = struct.pack('<B', reason)
        return packet_type + stream_id_bytes + reason_bytes
    
    @staticmethod
    def decode_packet(data: bytes) -> Tuple[int, int, bytes]:
        """
        Decode packet header.
        Returns: (packet_type, stream_id, payload)
        """
        if len(data) < 5:
            raise ValueError(f"Packet too short: {len(data)} bytes")
        
        packet_type = data[0]
        stream_id = struct.unpack('<I', data[1:5])[0]
        payload = data[5:]
        
        return packet_type, stream_id, payload
    
    @staticmethod
    def decode_connect(payload: bytes) -> Tuple[int, str]:
        """Decode CONNECT payload. Returns: (port, hostname)"""
        if len(payload) < 2:
            raise ValueError("Invalid CONNECT payload")
        
        port = struct.unpack('<H', payload[0:2])[0]
        hostname = payload[2:].decode('utf-8')
        
        if not hostname:
            raise ValueError("Hostname cannot be empty")
        
        return port, hostname
    
    @staticmethod
    def decode_continue(payload: bytes) -> int:
        """Decode CONTINUE payload. Returns: buffer_remaining"""
        if len(payload) != 4:
            raise ValueError("Invalid CONTINUE payload")
        
        return struct.unpack('<I', payload)[0]
    
    @staticmethod
    def decode_close(payload: bytes) -> int:
        """Decode CLOSE payload. Returns: close_reason"""
        if len(payload) != 1:
            raise ValueError("Invalid CLOSE payload")
        
        return payload[0]

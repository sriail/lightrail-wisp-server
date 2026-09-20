import asyncio
import socket
import ipaddress
import aiohttp

# asyncudp import removed - not supported in Cloudflare
# from python_socks.async_.asyncio import Proxy

#various network utilities and wrappers

tcp_size = 64*1024
block_loopback = False
block_private = False
block_udp = False
block_tcp = False

proxy_url = None
proxy_dns = False

# NEW: Cloudflare tunnel backend URL
cloudflare_tunnel_url = None
aiohttp_session = None

def reuse_port_supported():
  # NEW: Always False in Cloudflare environment
  return False

def is_ip(addr_str):
  try:
    ipaddress.ip_address(addr_str)
    return True
  except:
    return False

def get_ip(host, port, stream_type):
  if stream_type == 0x01:
    proto = socket.IPPROTO_TCP
  else:
    proto = socket.IPPROTO_UDP
  info = socket.getaddrinfo(host, port, proto=proto)
  return info[0][4][0]

async def get_ip_async(host, port, stream_type):
  loop = asyncio.get_running_loop()
  return await loop.run_in_executor(None, get_ip, host, port, stream_type)

def validate_ip(addr_str):  
  ip_addr = ipaddress.ip_address(addr_str)
  if block_loopback and ip_addr.is_loopback:
    raise TypeError("Connection to loopback ip address blocked.")
  if block_private and ip_addr.is_private and not ip_addr.is_loopback:
    raise TypeError("Connection to private ip address blocked.")

async def validate_hostname(host, port, stream_type):
  if is_ip(host):
    validate_ip(host)
    return host
  elif proxy_url and proxy_dns:
    return None
  else:  
    addr_str = await get_ip_async(host, port, stream_type)
    validate_ip(addr_str)
    return addr_str

# NEW: Initialize aiohttp session
async def init_session():
  global aiohttp_session
  if aiohttp_session is None:
    aiohttp_session = aiohttp.ClientSession()

# NEW: Cleanup session
async def cleanup_session():
  global aiohttp_session
  if aiohttp_session:
    await aiohttp_session.close()
    aiohttp_session = None

class TCPConnection:
  def __init__(self, hostname, port):
    self.hostname = hostname
    self.port = port
    # NEW: Changed from tcp_reader/tcp_writer to connection_id
    self.connection_id = None
    self.recv_buffer = bytearray()
    self.connected = False
  
  async def connect(self):
    if block_tcp:
      raise TypeError("TCP connection blocked.")

    # NEW: Validate hostname (DNS resolution)
    addr_str = await validate_hostname(self.hostname, self.port, 0x01)
    
    # NEW: Initialize aiohttp session if needed
    await init_session()
    
    # NEW: Check if using Cloudflare tunnel or direct connection
    if cloudflare_tunnel_url:
      try:
        # NEW: Request connection through Cloudflare tunnel backend
        async with aiohttp_session.post(
          f"{cloudflare_tunnel_url}/connect",
          json={
            "host": self.hostname,
            "port": self.port,
            "type": "tcp"
          }
        ) as resp:
          if resp.status != 200:
            raise Exception(f"Tunnel connect failed: {resp.status}")
          data = await resp.json()
          self.connection_id = data.get("connection_id")
          self.connected = True
      except Exception as e:
        raise Exception(f"Failed to establish tunnel connection: {e}")
    else:
      raise Exception("cloudflare_tunnel_url not configured")
  
  # NEW: Receive data via fetch from tunnel backend
  async def recv(self):
    if not self.connected or not self.connection_id:
      return b""
    
    try:
      async with aiohttp_session.get(
        f"{cloudflare_tunnel_url}/recv",
        params={
          "connection_id": self.connection_id,
          "max_bytes": tcp_size
        }
      ) as resp:
        if resp.status == 200:
          return await resp.read()
        elif resp.status == 204:  # No data available
          return b""
        else:
          raise Exception(f"Recv failed: {resp.status}")
    except Exception as e:
      raise Exception(f"Failed to receive data: {e}")
  
  # NEW: Send data via fetch to tunnel backend
  async def send(self, data):
    if not self.connected or not self.connection_id:
      raise Exception("Connection not established")
    
    try:
      async with aiohttp_session.post(
        f"{cloudflare_tunnel_url}/send",
        params={"connection_id": self.connection_id},
        data=data
      ) as resp:
        if resp.status != 200:
          raise Exception(f"Send failed: {resp.status}")
    except Exception as e:
      raise Exception(f"Failed to send data: {e}")
  
  # NEW: Close connection via tunnel backend
  def close(self):
    if not self.connected or not self.connection_id:
      return
    
    # NEW: Async cleanup - store for later cleanup task
    # In production, you'd want to send a close request to the backend
    self.connected = False


# NEW: UDPConnection modified to use tunnel (or removed entirely)
class UDPConnection:
  def __init__(self, hostname, port):
    self.hostname = hostname
    self.port = port
    self.connection_id = None
    self.connected = False
  
  async def connect(self):
    if block_udp:
      raise TypeError("UDP connection blocked.")
    
    # NEW: UDP via tunnel backend (if supported)
    await init_session()
    
    if cloudflare_tunnel_url:
      try:
        async with aiohttp_session.post(
          f"{cloudflare_tunnel_url}/connect",
          json={
            "host": self.hostname,
            "port": self.port,
            "type": "udp"
          }
        ) as resp:
          if resp.status != 200:
            raise Exception(f"Tunnel connect failed: {resp.status}")
          data = await resp.json()
          self.connection_id = data.get("connection_id")
          self.connected = True
      except Exception as e:
        raise Exception(f"Failed to establish UDP tunnel: {e}")
    else:
      raise NotImplementedError("UDP not supported without tunnel backend")
  
  async def recv(self):
    if not self.connected or not self.connection_id:
      return b""
    
    try:
      async with aiohttp_session.get(
        f"{cloudflare_tunnel_url}/recv",
        params={
          "connection_id": self.connection_id,
          "max_bytes": tcp_size
        }
      ) as resp:
        if resp.status == 200:
          return await resp.read()
        elif resp.status == 204:
          return b""
        else:
          raise Exception(f"UDP recv failed: {resp.status}")
    except Exception as e:
      raise Exception(f"Failed to receive UDP data: {e}")
  
  async def send(self, data):
    if not self.connected or not self.connection_id:
      raise Exception("UDP connection not established")
    
    try:
      async with aiohttp_session.post(
        f"{cloudflare_tunnel_url}/send",
        params={"connection_id": self.connection_id},
        data=data
      ) as resp:
        if resp.status != 200:
          raise Exception(f"UDP send failed: {resp.status}")
    except Exception as e:
      raise Exception(f"Failed to send UDP data: {e}")
  
  def close(self):
    if not self.connected or not self.connection_id:
      return
    self.connected = False
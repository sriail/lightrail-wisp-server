import ipaddress


tcp_size = 64 * 1024

block_loopback = False
block_private = False
block_udp = False
block_tcp = False


def is_ip(addr_str):
    try:
        ipaddress.ip_address(addr_str)
        return True
    except ValueError:
        return False


def validate_ip(addr_str):
    ip_addr = ipaddress.ip_address(addr_str)

    if block_loopback and ip_addr.is_loopback:
        raise TypeError(
            "Connection to loopback ip address blocked."
        )

    if (
        block_private
        and ip_addr.is_private
        and not ip_addr.is_loopback
    ):
        raise TypeError(
            "Connection to private ip address blocked."
        )


def validate_hostname(host, port, stream_type):
    """
    Transport-level validation.

    DNS resolution is intentionally left to the underlying Cloudflare
    TCP socket rather than using Python socket.getaddrinfo().
    """
    if is_ip(host):
        validate_ip(host)

    if stream_type == 0x01 and block_tcp:
        raise TypeError("TCP connection blocked.")

    if stream_type == 0x02 and block_udp:
        raise TypeError("UDP connection blocked.")


def create_connection(stream_type, hostname, port):
    if stream_type == 0x01:
        return TCPConnection(hostname, port)

    if stream_type == 0x02:
        # Cloudflare Workers do not expose a UDP socket equivalent.
        raise NotImplementedError(
            "UDP streams are not supported by Cloudflare Workers."
        )

    raise ValueError("Invalid Wisp stream type.")


class TCPConnection:
    """
    Abstract TCP transport.

    The Cloudflare Worker implementation supplies the actual socket
    through its runtime transport adapter.

    The normal Python server can replace this implementation with its
    normal asyncio socket implementation.
    """

    def __init__(self, hostname, port, socket=None):
        self.hostname = hostname
        self.port = int(port)
        self.socket = socket
        self.connected = False

    async def connect(self):
        validate_hostname(
            self.hostname,
            self.port,
            0x01,
        )

        if self.socket is None:
            raise RuntimeError(
                "No TCP transport has been attached to this connection."
            )

        self.connected = True

    async def recv(self):
        if not self.connected:
            return b""

        if self.socket is None:
            return b""

        return await self.socket.recv()

    async def send(self, data):
        if not self.connected:
            raise RuntimeError(
                "Connection not established."
            )

        if self.socket is None:
            raise RuntimeError(
                "No TCP transport has been attached."
            )

        await self.socket.send(data)

    def close(self):
        self.connected = False

        if self.socket is not None:
            try:
                self.socket.close()
            except Exception:
                pass


class UDPConnection:
    """
    Retained as an explicit protocol-level transport failure.

    Cloudflare Workers do not provide the UDP socket transport required
    by Wisp UDP streams.
    """

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = int(port)

    async def connect(self):
        raise NotImplementedError(
            "UDP streams are not supported by Cloudflare Workers."
        )

    async def recv(self):
        raise NotImplementedError(
            "UDP streams are not supported by Cloudflare Workers."
        )

    async def send(self, data):
        raise NotImplementedError(
            "UDP streams are not supported by Cloudflare Workers."
        )

    def close(self):
        pass


def reuse_port_supported():
    # Cloudflare Workers do not expose SO_REUSEPORT.
    return False

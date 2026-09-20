import asyncio
import logging
import struct

from websockets.exceptions import ConnectionClosed

from wisp.server import net
from wisp.server import ratelimit


queue_size = 128

# Wisp packet format definitions.
# See https://docs.python.org/3/library/struct.html
packet_format = "<BI"
connect_format = "<BH"
continue_format = "<I"
close_format = "<B"


class WSProxyConnection:
    """
    Legacy direct WebSocket -> TCP proxy connection.

    This class is retained for the normal Python server. Cloudflare
    Workers use WispConnection directly through worker.py.
    """

    def __init__(self, ws, path, client_ip):
        self.ws = ws
        self.path = path
        self.client_ip = client_ip
        self.conn = None

    async def setup_connection(self):
        addr_str = self.path.split("/")[-1]

        try:
            self.tcp_host, self.tcp_port = addr_str.split(":", 1)
            self.tcp_port = int(self.tcp_port)
        except (ValueError, TypeError):
            await self.ws.close()
            return False

        try:
            self.conn = net.TCPConnection(
                self.tcp_host,
                self.tcp_port,
            )
            await self.conn.connect()
            return True
        except Exception as exc:
            logging.info(
                "Creating a WSProxy stream to %s:%s failed: %s",
                self.tcp_host,
                self.tcp_port,
                exc,
            )
            await self.ws.close()
            return False

    async def handle_ws(self):
        if self.conn is None:
            return

        try:
            while True:
                data = await self.ws.recv()

                if not isinstance(data, bytes):
                    continue

                await ratelimit.limit_client_bandwidth(
                    self.client_ip,
                    len(data),
                    "ws",
                )

                await self.conn.send(data)

        except ConnectionClosed:
            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logging.warning(
                "Failed to send WebSocket data: %s",
                exc,
            )
        finally:
            self.conn.close()

    async def handle_tcp(self):
        if self.conn is None:
            return

        try:
            while True:
                data = await self.conn.recv()

                if not data:
                    break

                await ratelimit.limit_client_bandwidth(
                    self.client_ip,
                    len(data),
                    "tcp",
                )

                await self.ws.send(data)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logging.warning(
                "Failed to receive TCP data: %s",
                exc,
            )
        finally:
            try:
                await self.ws.close()
            except Exception:
                pass

            self.conn.close()


class WispConnection:
    """
    Wisp protocol implementation.

    This class intentionally contains the Wisp framing/state machine,
    while network transport is delegated to wisp.server.net.
    """

    def __init__(self, ws, path, client_ip, id=None):
        self.ws = ws
        self.path = path
        self.active_streams = {}
        self.client_ip = client_ip
        self.id = id

    async def setup(self):
        continue_payload = struct.pack(
            continue_format,
            queue_size,
        )

        continue_packet = (
            struct.pack(packet_format, 0x03, 0)
            + continue_payload
        )

        await self.ws.send(continue_packet)

    async def new_stream(self, stream_id, payload):
        if len(payload) < 3:
            await self.send_close_packet(stream_id, 0x42)
            self.close_stream(stream_id)
            return

        stream_type, destination_port = struct.unpack(
            connect_format,
            payload[:3],
        )

        try:
            hostname = payload[3:].decode("utf-8")
        except UnicodeDecodeError:
            await self.send_close_packet(stream_id, 0x42)
            self.close_stream(stream_id)
            return

        if not hostname:
            await self.send_close_packet(stream_id, 0x42)
            self.close_stream(stream_id)
            return

        logging.debug(
            "(%s) Creating a new stream to %s:%s",
            self.id,
            hostname,
            destination_port,
        )

        stream_count = ratelimit.get_client_attr(
            self.client_ip,
            "streams",
        )

        if (
            ratelimit.enabled
            and stream_count >= ratelimit.connections_limit
        ):
            await self.send_close_packet(stream_id, 0x49)
            self.close_stream(stream_id)
            return

        try:
            connection = net.create_connection(
                stream_type,
                hostname,
                destination_port,
            )

            self.active_streams[stream_id]["conn"] = connection
            self.active_streams[stream_id]["type"] = stream_type

            await connection.connect()

        except Exception as exc:
            logging.warning(
                "(%s) Creating a new stream to %s:%s failed: %s",
                self.id,
                hostname,
                destination_port,
                exc,
            )

            await self.send_close_packet(stream_id, 0x42)
            self.close_stream(stream_id)
            return

        stream = self.active_streams.get(stream_id)

        if stream is None:
            connection.close()
            return

        stream["connect_task"] = None

        stream["ws_to_tcp_task"] = asyncio.create_task(
            self.stream_ws_to_tcp(stream_id)
        )

        stream["tcp_to_ws_task"] = asyncio.create_task(
            self.stream_tcp_to_ws(stream_id)
        )

        ratelimit.inc_client_attr(
            self.client_ip,
            "streams",
        )

    async def stream_ws_to_tcp(self, stream_id):
        stream = self.active_streams.get(stream_id)

        if stream is None:
            return

        try:
            while True:
                data = await stream["queue"].get()

                if data is None:
                    return

                await stream["conn"].send(data)

                remaining = (
                    stream["queue"].maxsize
                    - stream["queue"].qsize()
                )

                continue_payload = struct.pack(
                    continue_format,
                    remaining,
                )

                continue_packet = (
                    struct.pack(
                        packet_format,
                        0x03,
                        stream_id,
                    )
                    + continue_payload
                )

                await self.ws.send(continue_packet)

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            logging.warning(
                "(%s) Sending stream %s failed: %s",
                self.id,
                stream_id,
                exc,
            )

            if stream_id in self.active_streams:
                try:
                    await self.send_close_packet(
                        stream_id,
                        0x03,
                    )
                except Exception:
                    pass

        finally:
            if stream_id in self.active_streams:
                self.close_stream(stream_id)

    async def stream_tcp_to_ws(self, stream_id):
        stream = self.active_streams.get(stream_id)

        if stream is None:
            return

        try:
            while True:
                data = await stream["conn"].recv()

                if not data:
                    break

                data_packet = (
                    struct.pack(
                        packet_format,
                        0x02,
                        stream_id,
                    )
                    + data
                )

                await ratelimit.limit_client_bandwidth(
                    self.client_ip,
                    len(data_packet),
                    "tcp",
                )

                await self.ws.send(data_packet)

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            logging.warning(
                "(%s) Receiving stream %s failed: %s",
                self.id,
                stream_id,
                exc,
            )

            if stream_id in self.active_streams:
                try:
                    await self.send_close_packet(
                        stream_id,
                        0x03,
                    )
                except Exception:
                    pass

            return

        if stream_id in self.active_streams:
            try:
                await self.send_close_packet(
                    stream_id,
                    0x02,
                )
            except Exception:
                pass

            self.close_stream(stream_id)

    async def send_close_packet(self, stream_id, reason):
        if stream_id not in self.active_streams:
            return

        close_payload = struct.pack(
            close_format,
            reason,
        )

        close_packet = (
            struct.pack(
                packet_format,
                0x04,
                stream_id,
            )
            + close_payload
        )

        await self.ws.send(close_packet)

    def close_stream(self, stream_id):
        stream = self.active_streams.pop(
            stream_id,
            None,
        )

        if stream is None:
            return

        connection = stream.get("conn")

        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

        current_task = asyncio.current_task()

        for task_name in (
            "connect_task",
            "ws_to_tcp_task",
            "tcp_to_ws_task",
        ):
            task = stream.get(task_name)

            if (
                task is not None
                and task is not current_task
                and not task.done()
            ):
                task.cancel()

    async def handle_ws(self):
        try:
            while True:
                data = await self.ws.recv()

                if not isinstance(data, bytes):
                    continue

                # A Wisp packet has a 5-byte header.
                if len(data) < 5:
                    continue

                await ratelimit.limit_client_bandwidth(
                    self.client_ip,
                    len(data),
                    "ws",
                )

                packet_type, stream_id = struct.unpack(
                    packet_format,
                    data[:5],
                )

                payload = data[5:]

                if packet_type == 0x01:
                    # CONNECT
                    if stream_id in self.active_streams:
                        await self.send_close_packet(
                            stream_id,
                            0x42,
                        )
                        continue

                    connect_task = asyncio.create_task(
                        self.new_stream(
                            stream_id,
                            payload,
                        )
                    )

                    self.active_streams[stream_id] = {
                        "conn": None,
                        "type": None,
                        "queue": asyncio.Queue(queue_size),
                        "connect_task": connect_task,
                        "ws_to_tcp_task": None,
                        "tcp_to_ws_task": None,
                    }

                elif packet_type == 0x02:
                    # DATA
                    stream = self.active_streams.get(stream_id)

                    if stream is None:
                        continue

                    await stream["queue"].put(payload)

                elif packet_type == 0x04:
                    # CLOSE
                    if len(payload) < 1:
                        continue

                    self.close_stream(stream_id)

                # 0x03 is generated by the server and is not an
                # incoming stream command.

        except ConnectionClosed:
            pass

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            logging.warning(
                "(%s) Receiving data from WebSocket failed: %s",
                self.id,
                exc,
            )

        finally:
            for stream_id in list(self.active_streams):
                self.close_stream(stream_id)

import logging

from wisp.server import ratelimit


class CloudflareWebSocket:
    """
    Small adapter around a Cloudflare WebSocket.

    The concrete WebSocket object is supplied by the Cloudflare
    Python runtime.
    """

    def __init__(self, websocket):
        self.websocket = websocket

    async def send(self, data):
        await self.websocket.send(data)

    async def recv(self):
        return await self.websocket.recv()

    async def close(self):
        await self.websocket.close()


async def handle_websocket(websocket, client_ip):
    """
    Run the existing Wisp protocol implementation against the
    Cloudflare WebSocket transport.
    """

    from wisp.server.connection import WispConnection

    ws = CloudflareWebSocket(websocket)

    connection = WispConnection(
        ws,
        "/",
        client_ip,
    )

    await connection.setup()
    await connection.handle_ws()


class Default:
    """
    Cloudflare Worker entrypoint.

    The WebSocketPair/runtime-specific construction belongs here,
    rather than in the Wisp protocol implementation.
    """

    async def fetch(self, request, env=None):
        upgrade = request.headers.get(
            "Upgrade",
            "",
        )

        if upgrade.lower() != "websocket":
            return {
                "status": 200,
                "headers": {
                    "content-type": (
                        "text/plain; charset=utf-8"
                    ),
                },
                "body": (
                    "Lightrail Wisp Server\n"
                    "WebSocket endpoint available.\n"
                ),
            }

        # The Cloudflare Python runtime's WebSocketPair must be
        # instantiated through the runtime's JS FFI.
        #
        # Keep this logic isolated here. Nothing inside
        # connection.py should know about Cloudflare APIs.
        #
        # This intentionally raises until the runtime-specific
        # WebSocketPair adapter is installed.
        raise RuntimeError(
            "Cloudflare WebSocketPair adapter is not configured."
        )

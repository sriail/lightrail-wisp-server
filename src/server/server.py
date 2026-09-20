"""HTTP/WebSocket binder for the Wisp server."""

from __future__ import annotations

from js import console
from workers import Response

from page import html_response
from server.connection import WispConnection
from server.rates import WEBSOCKET_PATH_MUST_END_WITH_SLASH


class WispServer:
    """Route ordinary HTTP requests and Wisp WebSocket upgrades."""

    def __init__(self, _env=None):
        self.env = _env

    async def handle(self, request):
        path = self._path(request.url)
        upgrade = (request.headers.get("Upgrade") or "").lower()

        if request.method != "GET":
            return Response("GET is required.", status=405, headers={"Allow": "GET"})

        if upgrade == "websocket":
            if WEBSOCKET_PATH_MUST_END_WITH_SLASH and not path.endswith("/"):
                return Response("Wisp WebSocket endpoint must end with '/'.", status=400)
            return self.upgrade(request)

        # Ordinary browser/user visits receive the static placeholder page.
        return html_response()

    @staticmethod
    def _path(url: str) -> str:
        try:
            return url.split("?", 1)[0].split("#", 1)[0]
        except Exception:
            return "/"

    @staticmethod
    def upgrade(request):
        pair = WebSocketPair.new().object_values()
        client, server = pair
        connection = WispConnection(server)
        connection.start()
        console.log("[wisp] HTTP Upgrade -> WebSocket complete")
        return Response(None, status=101, web_socket=client)

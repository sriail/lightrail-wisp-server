"""HTTP/WebSocket binder for the Wisp server."""

from __future__ import annotations

from js import Response as JSResponse, WebSocketPair, console
from page import html_response
from server.connection import WispConnection
from server.rates import WEBSOCKET_PATH_MUST_END_WITH_SLASH


class WispServer:
    """Route normal HTTP requests and Wisp WebSocket upgrades."""

    def __init__(self, _env=None):
        self.env = _env

    async def handle(self, request):
        path = self._path(request.url)

        if request.method != "GET":
            return JSResponse.new(
                "GET is required.",
                status=405,
                headers={"Allow": "GET"},
            )

        upgrade = (request.headers.get("Upgrade") or "").strip().lower()

        if upgrade == "websocket":
            if WEBSOCKET_PATH_MUST_END_WITH_SLASH and not path.endswith("/"):
                return JSResponse.new(
                    "Wisp WebSocket endpoint must end with '/'.",
                    status=400,
                    headers={"Content-Type": "text/plain; charset=utf-8"},
                )

            return self._upgrade(request)

        return html_response()

    @staticmethod
    def _path(url: str) -> str:
        try:
            return url.split("?", 1)[0].split("#", 1)[0]
        except Exception:
            return "/"

    @staticmethod
    def _upgrade(request):
        # Match Cloudflare's documented Python WebSocket pattern:
        # create a pair, accept the server side, then return a native JS
        # 101 Response containing the client side.
        upgrade = (request.headers.get("Upgrade") or "").strip().lower()
        if upgrade != "websocket":
            return JSResponse.new(
                "Expected Upgrade: websocket",
                status=426,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )

        client, server = WebSocketPair.new().object_values()

        # Binary Wisp packets must arrive as ArrayBuffer rather than Blob.
        server.binaryType = "arraybuffer"
        server.accept()

        # Keep the Wisp connection object alive through its JS callback proxies.
        connection = WispConnection(server)
        connection.install_after_accept()

        console.log("[wisp] WebSocket 101 upgrade accepted")

        return JSResponse.new(None, status=101, webSocket=client)

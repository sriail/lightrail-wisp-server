from workers import WorkerEntrypoint, Response
from page import html_response


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        upgrade = (request.headers.get("Upgrade") or "").lower()

        # Normal browser request.
        if upgrade != "websocket":
            return html_response()

        # Only load the Wisp/WebSocket implementation when it is actually needed.
        from server.server import WispServer

        return await WispServer(self.env).handle(request)

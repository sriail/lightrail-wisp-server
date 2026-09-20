"""Cloudflare Python Worker entry point."""

from workers import Response, WorkerEntrypoint

from page import html_response
from server.server import WispServer


class Default(WorkerEntrypoint):
    """Bridge between Cloudflare's fetch handler and the Wisp server."""

    async def fetch(self, request):
        return await WispServer(self.env).handle(request)

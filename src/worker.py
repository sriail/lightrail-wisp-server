"""Cloudflare Python Worker entry point."""

from workers import Response, WorkerEntrypoint

from page import html_response
from server.server import WispServer


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        return await WispServer(self.env).handle(request)

import logging
from workers import WorkerEntrypoint, Response
from server import WispServer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WispWorkerEndpoint(WorkerEntrypoint):
    """
    Cloudflare Worker entrypoint for WISP proxy server
    
    Deployment:
    - Deploy to Cloudflare Workers
    - Routes should point to /:path* or /wisp/*
    - Supports WebSocket upgrade for WISP protocol
    """
    
    def __init__(self, env):
        super().__init__(env)
        self.server = None
    
    async def on_request(self, request):
        """Handle HTTP requests"""
        # Check if this is a WebSocket upgrade request
        if request.headers.get("Upgrade") == "websocket":
            return await self.handle_websocket(request)
        
        # Otherwise return a simple status page
        return Response(
            "WISP Server Ready\n"
            "WISP 1.2 Protocol Implementation\n"
            "Connect via WebSocket to upgrade",
            status=200,
            headers={
                "Content-Type": "text/plain",
                "Connection": "close"
            }
        )
    
    async def handle_websocket(self, request):
        """Handle WebSocket upgrade and WISP protocol"""
        try:
            # Get the WebSocket from the request
            # Note: This depends on the Cloudflare Workers Python runtime
            # The exact API may vary
            
            if not hasattr(request, "websocket"):
                return Response(
                    "WebSocket upgrade not supported",
                    status=400
                )
            
            websocket = await request.websocket()
            
            # Create and run WISP server
            server = WispServer()
            await server.handle_connection(websocket)
            
            return None  # WebSocket connection handled
        
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            return Response(
                f"WebSocket error: {str(e)}",
                status=500
            )

# Export the worker
default_export = WispWorkerEndpoint

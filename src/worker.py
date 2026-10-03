import logging
from workers import Request, Response
from server import WispServer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def on_request(request: Request) -> Response:
    """
    Main handler for Cloudflare Worker
    
    Deployment:
    - Deploy to Cloudflare Workers
    - Routes should point to /:path* or /wisp/*
    - Supports WebSocket upgrade for WISP protocol
    """
    
    # Check if this is a WebSocket upgrade request
    upgrade = request.headers.get("Upgrade")
    
    if upgrade and upgrade.lower() == "websocket":
        try:
            # Get WebSocket from request context
            websocket = request.context.get("websocket")
            
            if not websocket:
                # Try using WebSocketPair for upgrade
                try:
                    from workers import WebSocketPair
                    
                    # Accept the WebSocket
                    pair = WebSocketPair()
                    server_ws = pair.server
                    client_ws = pair.client
                    
                    # Create and run WISP server
                    server = WispServer()
                    
                    # Run server in background
                    import asyncio
                    asyncio.create_task(server.handle_connection(server_ws))
                    
                    # Return response that upgrades the connection
                    return Response(None, status=101, headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                    })
                
                except ImportError:
                    logger.warning("WebSocketPair not available, using alternative method")
                    return Response(
                        "WebSocket upgrade not supported on this runtime",
                        status=400,
                        headers={"Content-Type": "text/plain"}
                    )
            
            # Create and run WISP server
            server = WispServer()
            await server.handle_connection(websocket)
            
            return Response("Connection closed", status=200)
        
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            return Response(
                f"WebSocket error: {str(e)}\n",
                status=500,
                headers={"Content-Type": "text/plain"}
            )
    
    # Return status page for non-WebSocket requests
    return Response(
        "WISP 1.2 Server Ready\n"
        "Cloudflare Workers Python Implementation\n"
        "Connect via WebSocket to /wisp/ to use the proxy\n\n"
        "GitHub: https://github.com/ading2210/wisp\n",
        status=200,
        headers={"Content-Type": "text/plain"}
    )


# Export handler as default (Cloudflare Workers pattern)
async def fetch(request: Request) -> Response:
    """Standard fetch handler"""
    return await on_request(request)


# Support both patterns
export = fetch

"""
Cloudflare Python Worker - WISP 1.2 Proxy Server

Entry point for Cloudflare Workers Python runtime.
"""
import logging
import sys
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Inject Cloudflare globals into tcp and http modules
def _setup_cloudflare_apis():
    """
    Inject Cloudflare's global fetch and connect into module namespaces.
    Cloudflare Workers Python runtime provides these as globals.
    """
    try:
        # Get globals from current context
        fetch_fn = globals().get('fetch')
        connect_fn = globals().get('connect')
        
        # Inject into tcp module if available
        try:
            import tcp as tcp_module
            if connect_fn:
                tcp_module.connect = connect_fn
                logger.info("Injected connect() into tcp module")
        except ImportError:
            logger.warning("tcp module not found for injection")
        
        # Inject into http module if available
        try:
            import http as http_module
            if fetch_fn:
                http_module.fetch = fetch_fn
                logger.info("Injected fetch() into http module")
        except ImportError:
            logger.warning("http module not found for injection")
    
    except Exception as e:
        logger.error(f"Error setting up Cloudflare APIs: {e}")

# Setup before importing server
_setup_cloudflare_apis()

# Now import server which will need tcp and http
try:
    from server import WispServer
except Exception as e:
    logger.error(f"Failed to import WispServer: {e}", exc_info=True)


async def fetch(request):
    """
    Main Cloudflare Worker fetch handler (required entry point).
    
    This function MUST be named 'fetch' for Cloudflare Workers Python runtime
    to recognize it as a valid event handler.
    
    Args:
        request: Cloudflare Request object
    
    Returns:
        Cloudflare Response object
    """
    try:
        logger.info(f"Request: {request.method} {request.url}")
        
        # Check for WebSocket upgrade request
        upgrade_header = request.headers.get('upgrade', '').lower()
        
        if upgrade_header == 'websocket':
            logger.info("WebSocket upgrade requested")
            return await _handle_websocket_upgrade(request)
        
        # Return HTTP status page
        return await _handle_http_request(request)
    
    except Exception as e:
        logger.error(f"Error in fetch handler: {e}", exc_info=True)
        return _create_response(
            status=500,
            body=f"Internal Server Error: {str(e)}\n"
        )


async def _handle_websocket_upgrade(request) -> 'Response':
    """
    Handle WebSocket upgrade request.
    
    Uses Cloudflare's WebSocketPair to create a server-side WebSocket
    that will be passed to the WISP server.
    """
    try:
        # Import WebSocketPair from cloudflare module
        from cloudflare import WebSocketPair
        
        # Create a WebSocket pair (one for client, one for server)
        client_ws, server_ws = WebSocketPair()
        
        logger.info("WebSocket pair created, upgrading connection")
        
        # Start WISP server with the server-side socket
        # Run in background - the handler must return immediately
        import asyncio
        asyncio.create_task(_run_wisp_server(server_ws))
        
        # Return upgrade response with client socket
        return _create_websocket_response(client_ws)
    
    except ImportError as e:
        logger.error(f"WebSocketPair not available: {e}")
        return _create_response(
            status=400,
            body="WebSocket not available\n"
        )
    except Exception as e:
        logger.error(f"WebSocket upgrade failed: {e}", exc_info=True)
        return _create_response(
            status=500,
            body=f"WebSocket error: {str(e)}\n"
        )


async def _run_wisp_server(server_ws):
    """
    Run the WISP server on the server-side WebSocket.
    
    This runs in a background task and handles the WISP protocol
    over the WebSocket connection.
    """
    try:
        if 'WispServer' not in globals():
            logger.error("WispServer not available")
            return
        
        server = WispServer()
        logger.info("WISP server starting")
        await server.handle_connection(server_ws)
        logger.info("WISP connection closed")
    
    except Exception as e:
        logger.error(f"WISP server error: {e}", exc_info=True)


async def _handle_http_request(request) -> 'Response':
    """
    Handle regular HTTP requests (non-WebSocket).
    Return a status page.
    """
    status_text = (
        "WISP 1.2 Proxy Server\n"
        "Cloudflare Workers Python Implementation\n"
        "========================================\n"
        "\n"
        "WebSocket endpoint ready.\n"
        "Status: Running ✓\n"
    )
    
    return _create_response(status=200, body=status_text)


def _create_response(status: int = 200, body: str = "", headers: Optional[dict] = None) -> 'Response':
    """
    Create a Cloudflare Response object.
    
    Args:
        status: HTTP status code
        body: Response body (string)
        headers: Optional headers dict
    
    Returns:
        Response object
    """
    try:
        from cloudflare import Response
        
        default_headers = {
            'Content-Type': 'text/plain',
            'Content-Length': str(len(body.encode('utf-8')))
        }
        
        if headers:
            default_headers.update(headers)
        
        return Response(
            body=body,
            status=status,
            headers=default_headers
        )
    except Exception as e:
        logger.error(f"Error creating response: {e}")
        # Fallback: try basic dict response
        return {
            "body": body,
            "status": status,
            "headers": headers or {}
        }


def _create_websocket_response(websocket) -> 'Response':
    """
    Create a WebSocket upgrade Response.
    
    Args:
        websocket: The WebSocket client object from WebSocketPair
    
    Returns:
        Response object with WebSocket
    """
    try:
        from cloudflare import Response
        
        # Return the client WebSocket in the response
        # Cloudflare Workers will handle the upgrade
        return Response(
            body=None,
            status=101,
            headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade'
            },
            websocket=websocket
        )
    except Exception as e:
        logger.error(f"Error creating WebSocket response: {e}")
        return {
            "status": 101,
            "headers": {
                'Upgrade': 'websocket',
                'Connection': 'Upgrade'
            },
            "websocket": websocket
        }

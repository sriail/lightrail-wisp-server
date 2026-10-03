import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def handle(request):
    """
    Main handler for Cloudflare Worker (Python runtime)
    
    This is the entry point when disable_python_external_sdk = true.
    The request object and response handling are provided by Cloudflare's runtime.
    """
    
    try:
        # Get request method and path
        method = getattr(request, 'method', 'GET')
        url = getattr(request, 'url', '')
        
        logger.info(f"Request: {method} {url}")
        
        # Check for WebSocket upgrade
        headers = getattr(request, 'headers', {})
        
        # Handle WebSocket upgrade
        if headers.get('Upgrade') == 'websocket' or headers.get('upgrade') == 'websocket':
            logger.info("WebSocket upgrade requested")
            
            try:
                # Try to import and handle WISP protocol
                from server import WispServer
                import asyncio
                
                # Get WebSocket from request (Cloudflare provides this)
                websocket = getattr(request, 'websocket', None)
                
                if websocket:
                    logger.info("WebSocket object found, starting WISP server")
                    server = WispServer()
                    await server.handle_connection(websocket)
                    logger.info("WebSocket connection closed")
                    return None  # Connection handled
                else:
                    logger.warning("WebSocket upgrade requested but no websocket object available")
                    return {
                        "status": 400,
                        "statusText": "Bad Request",
                        "headers": {"Content-Type": "text/plain"},
                        "body": "WebSocket not available\n"
                    }
            
            except ImportError as e:
                logger.error(f"Failed to import server: {e}")
                return {
                    "status": 500,
                    "statusText": "Internal Server Error",
                    "headers": {"Content-Type": "text/plain"},
                    "body": f"Server error: {e}\n"
                }
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                return {
                    "status": 500,
                    "statusText": "Internal Server Error",
                    "headers": {"Content-Type": "text/plain"},
                    "body": f"WebSocket error: {e}\n"
                }
        
        # Return status page for HTTP requests
        status_text = (
            "WISP 1.2 Server\n"
            "Cloudflare Workers Python Implementation\n"
            "=====================================\n"
            "Connect via WebSocket to use the proxy.\n"
            "URL: wss://your-domain.com/wisp/\n"
            "\n"
            "Status: Ready ✓\n"
        )
        
        # Return response as dict (Cloudflare's built-in runtime will convert this)
        return {
            "status": 200,
            "statusText": "OK",
            "headers": {"Content-Type": "text/plain"},
            "body": status_text
        }
    
    except Exception as e:
        logger.error(f"Error in handler: {e}", exc_info=True)
        error_text = f"Error: {str(e)}\n"
        
        return {
            "status": 500,
            "statusText": "Internal Server Error",
            "headers": {"Content-Type": "text/plain"},
            "body": error_text
        }


# Support multiple entry point names
fetch = handle
on_request = handle
main = handle

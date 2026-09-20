import asyncio
import logging
import json
import os
import sys

# Configure logging for Cloudflare
class CloudflareHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            print(f"[{record.levelname}] {msg}")
        except Exception:
            self.handleError(record)

logger = logging.getLogger("wisp")
handler = CloudflareHandler()
formatter = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Import wisp server modules
try:
    from wisp.server import http, net, ratelimit
except ImportError as e:
    logger.error(f"Failed to import wisp modules: {e}")
    sys.exit(1)


class Args:
    """Mimic CLI args for http.main()"""
    def __init__(self, env: dict):
        self.host = "127.0.0.1"
        self.port = 6001
        self.static = env.get("STATIC")
        self.limits = env.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
        self.bandwidth = float(env.get("RATE_LIMIT_BANDWIDTH", "1000"))
        self.connections = int(env.get("RATE_LIMIT_CONNECTIONS", "30"))
        self.window = float(env.get("RATE_LIMIT_WINDOW", "60"))
        self.allow_loopback = env.get("ALLOW_LOOPBACK", "false").lower() == "true"
        self.allow_private = env.get("ALLOW_PRIVATE", "false").lower() == "true"
        self.log_level = env.get("LOG_LEVEL", "info").lower()
        self.proxy = None
        self.block_udp = env.get("BLOCK_UDP", "false").lower() == "true"
        self.block_tcp = env.get("BLOCK_TCP", "false").lower() == "true"


def get_client_ip(request: dict) -> str:
    """Extract client IP from Cloudflare headers"""
    headers = request.get("headers", {})
    return (
        headers.get("cf-connecting-ip") or
        headers.get("x-forwarded-for", "").split(",")[0].strip() or
        "unknown"
    )


async def setup_network_and_ratelimit(args: Args):
    """Configure network and rate limiting from args"""
    net.block_loopback = not args.allow_loopback
    net.block_private = not args.allow_private
    net.block_udp = args.block_udp
    net.block_tcp = args.block_tcp
    
    if args.limits:
        ratelimit.enabled = True
        ratelimit.connections_limit = args.connections
        ratelimit.bandwidth_limit = args.bandwidth
        ratelimit.window_size = args.window


async def handle_request(request: dict, env: dict) -> dict:
    """Main request handler - delegates to http.main()"""
    args = Args(env)
    
    # Setup logging
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Configure network settings
    await setup_network_and_ratelimit(args)
    
    client_ip = get_client_ip(request)
    method = request.get("method", "GET")
    path = request.get("url", "/").split("?")[0]
    
    logger.info(f"{method} {path} from {client_ip}")
    
    # Check for WebSocket upgrade
    headers = request.get("headers", {})
    upgrade_header = headers.get("upgrade", "").lower()
    connection_header = headers.get("connection", "").lower()
    
    if upgrade_header == "websocket" or "upgrade" in connection_header:
        logger.debug(f"WebSocket upgrade from {client_ip}")
        # Cloudflare handles WebSocket protocol upgrade
        # Return 101 Switching Protocols
        return {
            "status": 101,
            "statusText": "Switching Protocols",
            "headers": {
                "upgrade": "websocket",
                "connection": "upgrade",
                "sec-websocket-accept": headers.get("sec-websocket-key", ""),
            },
            "body": None
        }
    
    # Regular HTTP - serve landing page
    try:
        import wisp
        version = getattr(wisp, 'version', '0.0.0')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>lightrail-wisp-server v{version}</title>
    <style>
      html {{ color-scheme: light dark; }}
      body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        line-height: 1.6;
      }}
      h1 {{ color: #0051ba; }}
      code {{ 
        background: #f0f0f0;
        padding: 2px 6px;
        border-radius: 3px;
        font-family: monospace;
      }}
      .info {{
        background: #f0f7ff;
        border-left: 4px solid #0051ba;
        padding: 12px;
        margin: 12px 0;
      }}
    </style>
  </head>
  <body>
    <h1>lightrail-wisp-server</h1>
    <p>Wisp protocol server v{version} running on Cloudflare Workers</p>
    
    <div class="info">
      <strong>Async Event Loop</strong>
      <p>Single-threaded async event loop handles all concurrent WebSocket and TCP connections efficiently.</p>
    </div>
    
    <h2>Connection Info</h2>
    <ul>
      <li><strong>WebSocket Endpoint:</strong> <code>ws://this-worker-url/</code></li>
      <li><strong>Protocol:</strong> <a href="https://github.com/MercuryWorkshop/wisp-protocol">Wisp Protocol</a></li>
      <li><strong>License:</strong> GNU AGPL v3</li>
    </ul>
    
    <h2>Features</h2>
    <ul>
      <li>WebSocket proxy (all streams)</li>
      <li>TCP tunneling</li>
      <li>Concurrent connections (async)</li>
      <li>Rate limiting (configurable)</li>
    </ul>
  </body>
</html>
"""
        
        return {
            "status": 200,
            "statusText": "OK",
            "headers": {"content-type": "text/html; charset=utf-8"},
            "body": html
        }
        
    except Exception as e:
        logger.error(f"Error handling HTTP request: {e}")
        return {
            "status": 500,
            "statusText": "Internal Server Error",
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }


async def fetch(request: dict, env: dict) -> dict:
    """
    Cloudflare Worker fetch handler.
    Processes all HTTP requests and WebSocket upgrades.
    
    Args:
        request: HTTP request object
        env: Environment variables from wrangler.toml
    
    Returns:
        HTTP response object
    """
    try:
        return await handle_request(request, env)
    except Exception as e:
        logger.error(f"Fatal error in fetch handler: {e}", exc_info=True)
        return {
            "status": 500,
            "statusText": "Internal Server Error",
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "Internal server error"})
        }


# For local CLI testing
if __name__ == "__main__":
    """Run as a normal Python server for local testing"""
    from wisp.server import cli
    cli.main()

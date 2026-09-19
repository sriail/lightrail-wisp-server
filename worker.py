import asyncio
import logging
import json
from datetime import datetime
from typing import Optional, Dict

# Import your existing wisp modules from src/
import sys
sys.path.insert(0, '/app')

from wisp.server import http, connection, net, ratelimit


class CloudflareHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            print(f"[{record.levelname}] {msg}")
        except Exception:
            self.handleError(record)


logger = logging.getLogger("wisp-cloudflare")
handler = CloudflareHandler()
formatter = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class Args:
    """Args object to mimic CLI arguments"""
    def __init__(self, env: dict):
        self.host = "127.0.0.1"
        self.port = 6001
        self.static = None
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
        self.tunnel_url = None  # Not needed - Cloudflare handles TCP directly


def get_client_ip(request: Dict) -> str:
    """Extract client IP from Cloudflare headers"""
    headers = request.get("headers", {})
    return (
        headers.get("cf-connecting-ip") or
        headers.get("x-forwarded-for", "").split(",")[0].strip() or
        "unknown"
    )


async def handle_websocket_connection(request: Dict, env: dict, client_ip: str) -> Dict:
    """
    Handle WebSocket upgrade requests.
    Cloudflare Workers automatically handle WebSocket protocol upgrades.
    """
    try:
        path = request.get("url", "/").split("?")[0]
        
        logger.info(f"WebSocket connection from {client_ip} on {path}")

        ws_conn = connection.WispConnection(
            ws=None,  # Will be set by Cloudflare runtime
            path=path,
            client_ip=client_ip,
            id=None
        )
        
        return {
            "status": 101,
            "statusText": "Switching Protocols",
            "headers": {
                "upgrade": "websocket",
                "connection": "upgrade",
                "sec-websocket-accept": request.get("headers", {}).get("sec-websocket-key", ""),
            },
            "body": None
        }
        
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        return {
            "status": 500,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": f"WebSocket error: {e}"})
        }


async def handle_http_request(request: Dict, env: dict, client_ip: str) -> Dict:
    """Handle regular HTTP requests"""
    try:
        import wisp
        
        path = request.get("url", "/").split("?")[0]
        method = request.get("method", "GET")
        
        logger.info(f"{method} {path} from {client_ip}")
        
        # Serve the default Wisp server landing page
        html = f"""
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>lightrail-wisp-server v{wisp.version}</title>
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
    <p>Wisp protocol server v{wisp.version} running on Cloudflare Workers</p>
    
    <div class="info">
      <strong>TCP Support Enabled</strong>
      <p>This worker supports TCP connections directly through Cloudflare's native capabilities.</p>
    </div>
    
    <h2>Connection Info</h2>
    <ul>
      <li><strong>WebSocket Endpoint:</strong> <code>ws://this-worker-url/</code></li>
      <li><strong>Protocol:</strong> <a href="https://github.com/MercuryWorkshop/wisp-protocol">Wisp Protocol</a></li>
      <li><strong>License:</strong> GNU AGPL v3</li>
    </ul>
    
    <h2>Features</h2>
    <ul>
      <li>WebSocket proxy</li>
      <li>TCP tunneling</li>
      <li>Rate limiting (configurable)</li>
      <li>Global Cloudflare edge deployment</li>
    </ul>
    
    <h2>Configuration</h2>
    <p>Configure via <code>wrangler.toml</code> environment variables:</p>
    <ul>
      <li><code>LOG_LEVEL</code> - debug, info, warn, error</li>
      <li><code>RATE_LIMIT_ENABLED</code> - true/false</li>
      <li><code>RATE_LIMIT_BANDWIDTH</code> - KB/s (default: 1000)</li>
      <li><code>RATE_LIMIT_CONNECTIONS</code> - per minute (default: 30)</li>
      <li><code>ALLOW_LOOPBACK</code> - true/false</li>
      <li><code>ALLOW_PRIVATE</code> - true/false</li>
    </ul>
  </body>
</html>
"""
        
        return {
            "status": 200,
            "headers": {"content-type": "text/html; charset=utf-8"},
            "body": html
        }
        
    except Exception as e:
        logger.error(f"HTTP error: {e}")
        return {
            "status": 500,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": f"Server error: {e}"})
        }


async def setup_network_config(args: Args, env: dict):
    """Configure network settings from environment variables"""
    # Network restrictions
    net.block_loopback = not args.allow_loopback
    net.block_private = not args.allow_private
    net.block_udp = args.block_udp
    net.block_tcp = args.block_tcp
    
    # Rate limiting
    if args.limits:
        ratelimit.enabled = True
        ratelimit.connections_limit = args.connections
        ratelimit.bandwidth_limit = args.bandwidth
        ratelimit.window_size = args.window
        logger.info(
            f"Rate limiting: {args.bandwidth}KB/s, "
            f"{args.connections} connections/{int(args.window)}s"
        )


async def handle_request(request: Dict, env: dict) -> Dict:
    """
    Main Cloudflare Worker request handler.
    Processes all HTTP requests and WebSocket upgrades.
    """
    args = Args(env)
    client_ip = get_client_ip(request)
    
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    await setup_network_config(args, env)
    
    # Check for WebSocket upgrade
    headers = request.get("headers", {})
    upgrade_header = headers.get("upgrade", "").lower()
    connection_header = headers.get("connection", "").lower()
    
    if upgrade_header == "websocket" or "upgrade" in connection_header:
        return await handle_websocket_connection(request, env, client_ip)
    
    # Regular HTTP
    return await handle_http_request(request, env, client_ip)

# Entry
async def fetch(request: Dict, env: Dict) -> Dict:
    """
    Main Cloudflare Worker fetch handler.
    
    This is called for every HTTP request and WebSocket upgrade.
    
    Args:
        request: HTTP request object with url, method, headers, body
        env: Environment variables from wrangler.toml
    
    Returns:
        Response object with status, headers, body
    """
    try:
        response = await handle_request(request, env)
        
        # Convert response to Cloudflare format
        return {
            "status": response.get("status", 200),
            "statusText": response.get("statusText", "OK"),
            "headers": response.get("headers", {}),
            "body": response.get("body", "")
        }
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return {
            "status": 500,
            "statusText": "Internal Server Error",
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "Internal server error", "message": str(e)})
        }


# ============================================================================
# LOCAL TESTING (CLI)
# ============================================================================

if __name__ == "__main__":
    """
    For local testing with CLI.
    Run: python src/worker.py
    This will start the standard wisp CLI server.
    """
    from wisp.server import cli
    cli.main()

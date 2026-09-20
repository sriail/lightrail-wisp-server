from workers import WorkerEntrypoint, Response
import asyncio
import logging
import pathlib
import mimetypes

from wisp.server import connection
from wisp.server import ratelimit
from wisp.server import net

# Configure logging
logging.basicConfig(
    format="[%(levelname)-8s] %(message)s",
    level=logging.INFO
)

# Static path configuration
static_path = None
default_html = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>lightrail-wisp-server</title>
    <style>
      html {
        color-scheme: light dark;
      }
      h1, p {
        font-family: sans-serif;
      }
      body {
        max-width: 600px;
        margin-left: auto;
        margin-right: auto;
      }
      pre {
        white-space: pre-wrap
      }
    </style>
  </head>
  <body>
    <h1>Lightrail wisp server</h1>
    <p>This is a <a href="https://github.com/MercuryWorkshop/wisp-protocol">Wisp protocol</a> server running a version of
     <a href="https://github.com/MercuryWorkshop/wisp-server-python">wisp-server-python</a> on Cloudflare Workers.</p>
    <p>This program is licensed under the <a href="https://github.com/MercuryWorkshop/wisp-server-python/blob/main/LICENSE">GNU AGPL v3</a>.</p>
    <pre>
wisp-server-python: a Wisp server implementation written in Python
Copyright (C) 2025 Mercury Workshop

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see &lt;https://www.gnu.org/licenses/&gt;.
</pre>
  </body>
</html>
""".strip()


async def connection_handler(websocket, path):
    """Handle WebSocket connections for Wisp protocol"""
    client_ip = websocket.remote_address[0] if hasattr(websocket, 'remote_address') else "127.0.0.1"
    
    # Check for real IP in headers (Cloudflare provides this)
    if hasattr(websocket, 'request_headers') and "X-Forwarded-For" in websocket.request_headers:
        client_ip = websocket.request_headers["X-Forwarded-For"].split(",")[0].strip()
    
    origin = ""
    if hasattr(websocket, 'request_headers'):
        origin = websocket.request_headers.get("Origin", "")

    import random
    conn_id = "".join(random.choices("1234567890abcdef", k=8))
    logging.info(f"({conn_id}) incoming connection on {path} from {client_ip} (origin: {origin})")
    ratelimit.inc_client_attr(client_ip, "streams")

    if path.endswith("/"):
        wisp_conn = connection.WispConnection(websocket, path, client_ip, conn_id)
        await wisp_conn.setup()
        ws_handler = asyncio.create_task(wisp_conn.handle_ws())
        await asyncio.gather(ws_handler)
    else:
        stream_count = ratelimit.get_client_attr(client_ip, "streams")
        if ratelimit.enabled and stream_count > ratelimit.connections_limit:
            return
        wsproxy_conn = connection.WSProxyConnection(websocket, path, client_ip)
        await wsproxy_conn.setup_connection()
        ws_handler = asyncio.create_task(wsproxy_conn.handle_ws())
        tcp_handler = asyncio.create_task(wsproxy_conn.handle_tcp())
        await asyncio.gather(ws_handler, tcp_handler)


async def request_handler(path, request_headers):
    """Handle HTTP requests (non-WebSocket)"""
    if "Upgrade" in request_headers:
        return

    if not static_path:
        if path.endswith("/") or path.endswith("/index.html"):
            return 200, [("Content-Type", "text/html")], default_html.encode()
        else:
            return 404, [], "404 not found".encode()

    response_headers = []
    target_path = static_path / path[1:]

    if target_path.is_dir():
        target_path = target_path / "index.html"
    if not target_path.is_relative_to(static_path):
        return 403, response_headers, "403 forbidden".encode()
    if not target_path.exists():
        return 404, response_headers, "404 not found".encode()

    mimetype = mimetypes.guess_type(target_path.name)[0]
    response_headers.append(("Content-Type", mimetype))

    static_data = await asyncio.to_thread(target_path.read_bytes)
    return 200, response_headers, static_data


class Default(WorkerEntrypoint):
    """Cloudflare Worker entry point for wisp-server-python"""

    async def fetch(self, request):
        """Main handler for incoming requests"""
        # This is the primary handler that Cloudflare Workers calls
        # For WebSocket upgrades, the Workers runtime will handle the upgrade
        # and pass the connection to connection_handler

        # For HTTP requests
        path = request.url.split("localhost")[1] if "localhost" in request.url else request.url
        
        if request.method == "GET":
            # Check if this is likely a static file request
            if path == "/" or path == "/index.html":
                return Response(default_html, status=200, headers={"Content-Type": "text/html"})
            else:
                return Response("404 not found", status=404)

        return Response("Method not allowed", status=405)
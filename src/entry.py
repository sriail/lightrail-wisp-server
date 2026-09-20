from workers import WorkerEntrypoint, Response
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

default_html = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width">
    <title>wisp-server-python</title>
    <style>
      html { color-scheme: light dark; }
      h1, p { font-family: sans-serif; }
      body { max-width: 600px; margin-left: auto; margin-right: auto; }
      pre { white-space: pre-wrap }
    </style>
  </head>
  <body>
    <h1>wisp-server-python</h1>
    <p>This is a <a href="https://github.com/MercuryWorkshop/wisp-protocol">Wisp protocol</a> server running on Cloudflare Workers.</p>
    <p>This program is licensed under the <a href="https://github.com/MercuryWorkshop/wisp-server-python/blob/main/LICENSE">GNU AGPL v3</a>.</p>
  </body>
</html>
""".strip()


class Default(WorkerEntrypoint):
    """Cloudflare Worker entry point for wisp-server-python"""

    async def fetch(self, request):
        """Main handler for incoming requests"""
        try:
            # Parse URL path
            url = request.url
            path = url.split('/')[-1] if '/' in url else '/'
            
            # Handle HTTP requests
            if request.method == "GET":
                if path == "" or path == "/" or path == "index.html":
                    return Response(default_html, status=200, headers={"Content-Type": "text/html"})
                else:
                    return Response("404 not found", status=404)
            
            return Response("Method not allowed", status=405)
        except Exception as e:
            logging.error(f"Error in fetch handler: {e}")
            return Response(f"Internal Server Error: {str(e)}", status=500)

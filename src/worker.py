"""
Cloudflare Python Worker - WISP 1.2 Proxy Server

Entry point for the Cloudflare Workers Python runtime.

Python Workers require handlers to be methods on a class named `Default`
that extends `WorkerEntrypoint` (imported from the `workers` module).
This class is the Python equivalent of the JS default export:

    export default {
        async fetch(request, env, ctx) { ... },
    };
"""

import asyncio
import builtins
import logging

from js import Object, Response
from pyodide.ffi import to_js
from workers import WorkerEntrypoint

try:
    from js import WebSocketPair
except ImportError:
    WebSocketPair = None  # runtime without WebSocket support

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Cloudflare API bridging (JS interop)
# --------------------------------------------------------------------------- #

def _cf_global(name: str):
    """
    Resolve a Cloudflare/JS global wherever this runtime exposes it:
    injected module globals, Python builtins, or the Pyodide `js` module
    (which proxies the JavaScript globalThis).
    """
    candidate = globals().get(name)
    if candidate is None:
        candidate = getattr(builtins, name, None)
    if candidate is None:
        try:
            import js
            candidate = getattr(js, name, None)
        except ImportError:
            candidate = None
    return candidate


def _tcp_connect():
    """Return the Workers TCP `connect()` API, if this runtime has one."""
    connect = _cf_global("connect")
    if connect is not None:
        return connect
    # Some runtimes expose TCP sockets on the `cloudflare` JS namespace.
    try:
        import js
        sockets = getattr(getattr(js, "cloudflare", None), "sockets", None)
        if sockets is not None:
            return sockets.connect
    except ImportError:
        pass
    return None


def _setup_cloudflare_apis() -> None:
    """Give our `tcp` / `http` helper modules the Workers fetch()/connect() APIs."""
    fetch_fn = _cf_global("fetch")
    connect_fn = _tcp_connect()

    try:
        import tcp as tcp_module
        if connect_fn is not None:
            tcp_module.connect = connect_fn
            logger.info("Injected connect() into tcp module")
        else:
            logger.warning("TCP connect() not found; outbound sockets unavailable")
    except ImportError:
        logger.warning("tcp module not found for injection")

    try:
        import http as http_module
        if fetch_fn is not None:
            http_module.fetch = fetch_fn
            logger.info("Injected fetch() into http module")
        else:
            logger.warning("Workers fetch() not found")
    except ImportError:
        logger.warning("http module not found for injection")


# Inject APIs *before* importing the server, in case server.py does
# `from tcp import connect` (which binds the attribute at import time).
_setup_cloudflare_apis()

try:
    from server import WispServer as _WispServer
except Exception:
    _WispServer = None
    logger.exception("Failed to import WispServer")


def _make_response(body=None, status: int = 200, web_socket=None):
    """
    Build a Cloudflare Response via JS interop.

    JS equivalent: new Response(body, { status: ..., webSocket: ... })
    """
    init = {}
    if status != 200:
        init["status"] = status
    if web_socket is not None:
        init["webSocket"] = web_socket
    return Response.new(body, to_js(init, dict_converter=Object.fromEntries))


# --------------------------------------------------------------------------- #
# Worker entry point
# --------------------------------------------------------------------------- #

class Default(WorkerEntrypoint):
    """
    Required entry point for Python Workers.

    The runtime looks for a class named `Default` extending
    `WorkerEntrypoint` and dispatches events to its handler methods.
    A module-level `fetch()` function is NOT recognized.
    """

    async def fetch(self, request, env=None, ctx=None):
        """
        Fetch handler — invoked for every incoming HTTP request.

        `env` (bindings) and `ctx` (execution context) mirror the JS
        signature; defaults keep this compatible with runtimes that
        only pass the request.
        """
        try:
            logger.info(f"Request: {request.method} {request.url}")

            upgrade = (request.headers.get("upgrade") or "").lower()
            if upgrade == "websocket":
                logger.info("WebSocket upgrade requested")
                return self._websocket_upgrade(request, ctx)

            return self._http_index()

        except Exception as e:
            logger.exception("Error in fetch handler")
            return _make_response(f"Internal Server Error: {e}\n", status=500)

    # -- WebSocket (WISP transport) ------------------------------------- #

    def _websocket_upgrade(self, request, ctx):
        """
        Accept the WebSocket upgrade:
          1. Create a WebSocketPair (client side + server side).
          2. Accept the server side so it can send/receive immediately.
          3. Return a 101 Response carrying the client socket.
          4. Run the WISP protocol on the server socket in the background.
        """
        if WebSocketPair is None:
            logger.error("WebSocketPair is not available in this runtime")
            return _make_response("WebSocket not available\n", status=500)

        if _WispServer is None:
            return _make_response("WISP server unavailable\n", status=503)

        try:
            pair = WebSocketPair.new()
            values = Object.values(pair)
            client_ws, server_ws = values[0], values[1]

            server_ws.accept()
            logger.info("WebSocket pair created, upgrading connection")

            # Background task: the upgrade response must return immediately.
            task = asyncio.ensure_future(self._run_wisp_server(server_ws))
            if ctx is not None:
                try:
                    ctx.waitUntil(task)
                except Exception:
                    # Not all runtimes accept a Python Task here; the open
                    # WebSocket keeps the isolate alive regardless.
                    pass

            # JS equivalent:
            #   return new Response(null, { status: 101, webSocket: client });
            return _make_response(None, status=101, web_socket=client_ws)

        except Exception as e:
            logger.exception("WebSocket upgrade failed")
            return _make_response(f"WebSocket error: {e}\n", status=500)

    async def _run_wisp_server(self, server_ws):
        """Run the WISP protocol handler over the server-side WebSocket."""
        try:
            server = _WispServer()
            logger.info("WISP server starting")
            await server.handle_connection(server_ws)
            logger.info("WISP connection closed")

        except Exception:
            logger.exception("WISP server error")
            try:
                server_ws.close(1011, "Internal error")
            except Exception:
                pass

    # -- Plain HTTP ------------------------------------------------------ #

    def _http_index(self):
        return _make_response(
“                                   .:-=====:..\n”
“                            :+%@@@@@@@@@@@@@@@@@@@@%+:\n”
“                        =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=\n”
“                    .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*\n
“                  *@@@@@@@@@@@@*                  +@@@@@@@@@@@@=\n”
“                %@@@@@@@@@@@@@@+  =#%%%.  .%%%#=  +@@@@@@@@@@@@@@#\n”
“              %@@@@@@@@@@@@@@@@@@@@@@@@:  -@@@@@@@@@@@@@@@@@@@@@@@@#\n”
“            =@@@@@@@@@@@@@%*                          +%@@@@@@@@@@@@@-\n”
“           %@@@@@@@@@@@#           ..........            .#@@@@@@@@@@@#\n”
“         .%@@@@@@@@@@@@          %@@@@@@@@@@@@@@%          @@@@@@@@@@@@%\n”
“        :@@@@@@@@@@@@@@                                    @@@@@@@@@@@@@@.\n”
“        %@@@@@@@@@@@@@@                                    @@@@@@@@@@@@@@%\n”
“       @@@@@@@@@@@@@@@@   =@@@@@@@@@@@@@@@@@@@@@@@@@@@@=   @@@@@@@@@@@@@@@%\n”
“      *@@@@@@@@@@@@@@@@   *@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   @@@@@@@@@@@@@@@@+\n”
“      @@@@@@@@@@@@@@@@@   +@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   @@@@@@@@@@@@@@@@%\n”
“     +@@@@@@@@@@@@@@@@@   +@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   @@@@@@@@@@@@@@@@@:\n”
“     @@@@@@@@@@@@@@@@@@   +@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   @@@@@@@@@@@@@@@@@#\n”
“     @@@@@@@@@@@@@@@@@@   +@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   @@@@@@@@@@@@@@@@@@\n”
“     @@@@@@@@@@@@@@@@@@   *@@@@@@@@@@@@@@@@@@@@@@@@@@@@+   @@@@@@@@@@@@@@@@@@\n”
“     @@@@@@@@@@@@@@@@@@   *@@@@@@@@@@@@@@@@@@@@@@@@@@@@*   @@@@@@@@@@@@@@@@@@\n”
“     %@@@@@@@@@@@@@@@@@    %@@@@@@@@@@@@@@@@@@@@@@@@@@%    @@@@@@@@@@@@@@@@@%\n”
“     =@@@@@@@@@@@@@@@@@                                    @@@@@@@@@@@@@@@@@=\n”
“      %@@@@@@@@@@@@@@@@    .*-                      ++     @@@@@@@@@@@@@@@@%\n”
“      +@@@@@@@@@@@@@@@@   +@@@%                   .@@@@=   @@@@@@@@@@@@@@@@+\n”
“       %@@@@@@@@@@@@@@@    #%%=                    +%%*    @@@@@@@@@@@@@@@%\n”
“        %@@@@@@@@@@@@@@                                    @@@@@@@@@@@@@@%\n”
“        :@@@@@@@@@@@@@@+                                  +@@@@@@@@@@@@@@:\n”
“         :@@@@@@@@@@@@@@*                                *@@@@@@@@@@@@@%.\n”
“           %@@@@@@@@@@@@@@@%                          %@@@@@@@@@@@@@@@#\n”
“            *@@@@@@@@@@@@@@+                          *@@@@@@@@@@@@@@=\n”
“              %@@@@@@@@@@@@   %@@@@@@@@@@@@@@@@@@@@%   @@@@@@@@@@@@%\n”
“                %@@@@@@@@@%%#%@@@@@@@@@@@@@@@@@@@@@@%#%%@@@@@@@@@#\n”
“                  *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+\n”
“                    :#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*\n”
“                        +%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=\n”
“                            :*%@@@@@@@@@@@@@@@@@@@@%*:\n”
“                                   ..-=====-:.\n”

            "WISP 1.2 Proxy Server\n"
            "Cloudflare Workers Python Implementation\n"
            "========================================\n"
            "\n"
            "WebSocket endpoint ready.\n"
            "Status: Running ✓\n",
            status=200,
        )

# Wisp Python Worker

Small Wisp v1 TCP-over-WebSocket proxy for Cloudflare Python Workers.

## Layout

```text
wrangler.toml
pyproject.toml
src/
├── worker.py
├── page.py
└── server/
    ├── server.py
    ├── connection.py
    ├── rates.py
    ├── udp.py
    ├── net.py
    └── streams.py
```

## Behavior

- WebSocket endpoint must use a trailing `/`, as required by the Wisp URL guidance.
- The server sends the initial `CONTINUE` immediately after the WebSocket is accepted, on stream ID `0`.
- Wisp packets use the 1-byte type + 4-byte little-endian stream ID + payload layout.
- TCP CONNECT creates a Cloudflare outbound TCP socket with `cloudflare:sockets`.
- DATA is queued per TCP stream with a fixed packet-count buffer.
- CONTINUE is refreshed as queued DATA is written to the TCP socket.
- CLOSE immediately tears down the associated stream.
- UDP (`stream type 0x02`) is silently ignored and only logged server-side; no Wisp response tells the client that UDP is disabled.
- Literal loopback/private/reserved IP destinations and obvious local-only hostnames are blocked.

## Local development

Current Cloudflare Python Worker tooling uses PyWrangler. A typical setup is:

```bash
uv sync
uv run pywrangler dev
```

Then open the development URL in a browser to see the placeholder page, or connect a Wisp client to the WebSocket URL ending in `/`.

## Deploy

```bash
uv run pywrangler deploy
```

This project intentionally does not add a JavaScript worker shim. The Python Worker uses Pyodide FFI to access `WebSocketPair` and lazily imports Cloudflare's `cloudflare:sockets` runtime module for outbound TCP.

## Important Cloudflare note

`fetch()` is used for ordinary HTTP content acquisition, but it cannot substitute for a full-duplex arbitrary TCP socket. Wisp DATA streams therefore use the Workers TCP socket runtime API. This is what preserves actual Wisp TCP proxy semantics.

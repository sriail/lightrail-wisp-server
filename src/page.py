"""Static page shown for ordinary HTTP visits."""

from workers import Response


_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Wisp Python Worker</title>
</head>
<body>
  <h1>Wisp Python Worker</h1>
  <p>This endpoint accepts Wisp v1 WebSocket connections.</p>
  <p>Use the trailing-slash WebSocket endpoint, for example <code>wss://example.com/</code>.</p>
</body>
</html>
"""


def html_response(status: int = 200):
    return Response(
        _HTML,
        status=status,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )

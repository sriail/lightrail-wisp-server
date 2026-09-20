"""Limits used by the small Wisp server.

These are intentionally simple in-memory limits. Cloudflare Workers isolates are
short-lived and independent, so these values are per Wisp WebSocket/isolate rather
than a durable, global quota.
"""

# Wisp packet/header limits.
MAX_PACKET_BYTES = 64 * 1024
MAX_DATA_PAYLOAD_BYTES = MAX_PACKET_BYTES - 5
MAX_HOSTNAME_BYTES = 253

# Per-WebSocket stream limits.
MAX_STREAMS = 32
MAX_BUFFERED_PACKETS = 128
MAX_CONNECTION_ATTEMPTS_PER_MINUTE = 60

# TCP connection behavior.
CONNECT_TIMEOUT_SECONDS = 10.0
IDLE_TIMEOUT_SECONDS = 0  # 0 disables an application-level idle timeout.

# A hard cap is useful for simple deployments so one client cannot consume an
# unlimited amount of memory even when the remote peer is fast.
MAX_QUEUED_BYTES_PER_STREAM = MAX_BUFFERED_PACKETS * MAX_DATA_PAYLOAD_BYTES

# WebSocket policy.
WEBSOCKET_PATH_MUST_END_WITH_SLASH = True

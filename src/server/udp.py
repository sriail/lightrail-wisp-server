"""UDP policy for Cloudflare Python Workers.

UDP support is intentionally disabled for this Worker. The requested behavior is
silent rejection/ignoring of UDP CONNECT packets, rather than sending a Wisp CLOSE
packet to the client saying that UDP is unavailable.
"""

from js import console

UDP_ENABLED = False
UDP_STREAM_TYPE = 0x02


def is_udp_stream(stream_type: int) -> bool:
    return stream_type == UDP_STREAM_TYPE


def note_udp_attempt(stream_id: int, hostname: str, port: int) -> None:
    # This is a server-side log only. Nothing is sent to the Wisp peer.
    console.log(
        f"[wisp] UDP stream ignored stream={stream_id} destination={hostname}:{port}"
    )

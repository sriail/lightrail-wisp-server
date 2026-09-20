"""In-memory stream table and queue ownership for one Wisp client."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from server.streams import TCPStream


class StreamTable:
    """Hold all TCP streams belonging to one Wisp WebSocket."""

    def __init__(self, max_streams: int):
        self.max_streams = max_streams
        self.max_buffered_packets = 16
        self._streams: dict[int, TCPStream] = {}

    @property
    def count(self) -> int:
        return len(self._streams)

    def contains(self, stream_id: int) -> bool:
        return stream_id in self._streams

    def get(self, stream_id: int):
        return self._streams.get(stream_id)

    def add(self, stream: TCPStream) -> None:
        if self.count >= self.max_streams:
            raise RuntimeError("maximum stream count reached")
        if stream.stream_id in self._streams:
            raise RuntimeError("stream id already exists")
        self._streams[stream.stream_id] = stream

    def remove(self, stream_id: int) -> None:
        self._streams.pop(stream_id, None)

    async def close_all(self) -> None:
        streams = list(self._streams.values())
        self._streams.clear()
        if streams:
            await asyncio.gather(
                *(stream.close(send_packet=False) for stream in streams),
                return_exceptions=True,
            )

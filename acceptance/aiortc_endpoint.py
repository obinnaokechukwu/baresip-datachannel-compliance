from __future__ import annotations

import asyncio
from typing import Any

from aiortc import RTCDataChannel, RTCPeerConnection, RTCSessionDescription


class AiortcEndpoint:
    def __init__(self) -> None:
        self.pc = RTCPeerConnection()
        self.channels: dict[str, RTCDataChannel] = {}
        self.events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

        @self.pc.on("datachannel")
        def on_datachannel(channel: RTCDataChannel) -> None:
            self._register(channel)

        @self.pc.on("connectionstatechange")
        async def on_connectionstatechange() -> None:
            await self.events.put(
                {
                    "name": "ready",
                    "body": {"connectionState": self.pc.connectionState},
                }
            )

    def _register(self, channel: RTCDataChannel) -> None:
        self.channels[channel.label] = channel

        @channel.on("open")
        async def on_open() -> None:
            await self.events.put(
                {
                    "name": "channel",
                    "body": {
                        "label": channel.label,
                        "id": channel.id,
                        "state": channel.readyState,
                    },
                }
            )

        @channel.on("close")
        async def on_close() -> None:
            await self.events.put(
                {
                    "name": "channel",
                    "body": {
                        "label": channel.label,
                        "id": channel.id,
                        "state": channel.readyState,
                    },
                }
            )

        @channel.on("message")
        async def on_message(message: str | bytes) -> None:
            if isinstance(message, str):
                message_type = "text"
                payload = message.encode()
            else:
                message_type = "binary"
                payload = bytes(message)
            await self.events.put(
                {
                    "name": "message",
                    "body": {
                        "label": channel.label,
                        "type": message_type,
                        "payloadHex": payload.hex(),
                    },
                }
            )

    async def answer(self, offer: dict[str, str]) -> dict[str, str]:
        await self.pc.setRemoteDescription(
            RTCSessionDescription(sdp=offer["sdp"], type=offer["type"])
        )
        await self.pc.setLocalDescription(await self.pc.createAnswer())
        await self._wait_ice_complete()
        assert self.pc.localDescription is not None
        return {
            "type": self.pc.localDescription.type,
            "sdp": self.pc.localDescription.sdp,
        }

    async def _wait_ice_complete(self, timeout: float = 15.0) -> None:
        async def wait() -> None:
            while self.pc.iceGatheringState != "complete":
                await asyncio.sleep(0.05)

        await asyncio.wait_for(wait(), timeout)

    async def wait_channel_open(self, label: str, timeout: float = 15.0) -> None:
        async def wait() -> None:
            while (
                label not in self.channels
                or self.channels[label].readyState != "open"
            ):
                await asyncio.sleep(0.05)

        await asyncio.wait_for(wait(), timeout)

    async def send(self, label: str, message_type: str, payload: bytes) -> None:
        channel = self.channels[label]
        channel.send(payload.decode() if message_type == "text" else payload)

    async def send_raw(
        self, stream_id: int, ppid: int, payload: bytes
    ) -> None:
        if self.pc.sctp is None or self.pc.sctp.state != "connected":
            raise RuntimeError("SCTP association is not connected")
        await self.pc.sctp._send(stream_id, ppid, payload)

    async def drain_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while not self.events.empty():
            events.append(self.events.get_nowait())
        return events

    async def stats(self) -> dict[str, Any]:
        report = await self.pc.getStats()
        rows = []
        for value in report.values():
            rows.append(
                {
                    key: item
                    for key, item in vars(value).items()
                    if isinstance(item, (str, int, float, bool, type(None)))
                }
            )
        return {
            "connectionState": self.pc.connectionState,
            "iceConnectionState": self.pc.iceConnectionState,
            "signalingState": self.pc.signalingState,
            "sctpState": self.pc.sctp.state if self.pc.sctp else None,
            "dtlsState": (
                self.pc.sctp.transport.state if self.pc.sctp else None
            ),
            "rows": rows,
        }

    async def close(self) -> None:
        await self.pc.close()

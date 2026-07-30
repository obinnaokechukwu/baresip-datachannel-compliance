from __future__ import annotations

import asyncio
from typing import Any

from aiortc import (
    AudioStreamTrack,
    RTCDataChannel,
    RTCPeerConnection,
    RTCSessionDescription,
    VideoStreamTrack,
)


def expand_bundle_transport_attributes(sdp: str) -> str:
    """Work around aiortc requiring DTLS attributes on every BUNDLE member."""
    newline = "\r\n" if "\r\n" in sdp else "\n"
    lines = sdp.replace("\r\n", "\n").splitlines()
    bundle: list[str] = []
    sections: list[list[str]] = []
    session: list[str] = []

    for line in lines:
        if line.startswith("a=group:BUNDLE "):
            bundle = line.removeprefix("a=group:BUNDLE ").split()
        if line.startswith("m="):
            sections.append([line])
        elif sections:
            sections[-1].append(line)
        else:
            session.append(line)

    if not bundle:
        return sdp

    by_mid = {
        mid: section
        for section in sections
        if (
            mid := next(
                (
                    line.removeprefix("a=mid:")
                    for line in section
                    if line.startswith("a=mid:")
                ),
                "",
            )
        )
    }
    tag = by_mid.get(bundle[0])
    if not tag:
        return sdp

    attributes = [
        line
        for line in tag
        if line.startswith(("a=setup:", "a=fingerprint:"))
    ]
    for mid in bundle[1:]:
        section = by_mid.get(mid)
        if not section:
            continue
        names = {line.partition(":")[0] for line in section}
        insertion = next(
            (
                index + 1
                for index, line in enumerate(section)
                if line.startswith("a=mid:")
            ),
            1,
        )
        additions = [
            line for line in attributes if line.partition(":")[0] not in names
        ]
        section[insertion:insertion] = additions

    rendered = newline.join(
        [*session, *(line for section in sections for line in section)]
    )
    if sdp.endswith(("\r\n", "\n")):
        rendered += newline
    return rendered


def copy_application_attributes(
    source: str, target: str, names: tuple[str, ...]
) -> str:
    """Copy endpoint-app SDP attributes that aiortc does not model."""
    prefixes = tuple(f"a={name}:" for name in names)

    def application_attributes(sdp: str) -> list[str]:
        result: list[str] = []
        in_application = False
        for line in sdp.replace("\r\n", "\n").splitlines():
            if line.startswith("m="):
                in_application = line.startswith("m=application ")
            elif in_application and line.startswith(prefixes):
                result.append(line)
        return result

    attributes = application_attributes(source)
    if not attributes:
        return target
    newline = "\r\n" if "\r\n" in target else "\n"
    lines = target.replace("\r\n", "\n").splitlines()
    insertion = len(lines)
    in_application = False
    for index, line in enumerate(lines):
        if line.startswith("m="):
            if in_application:
                insertion = index
                break
            in_application = line.startswith("m=application ")
    if not in_application:
        return target
    existing = set(application_attributes(target))
    lines[insertion:insertion] = [
        line for line in attributes if line not in existing
    ]
    rendered = newline.join(lines)
    if target.endswith(("\r\n", "\n")):
        rendered += newline
    return rendered


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

    async def answer(
        self,
        offer: dict[str, str],
        *,
        media: bool = False,
        audio_only: bool = False,
    ) -> dict[str, str]:
        remote_sdp = expand_bundle_transport_attributes(offer["sdp"])
        await self.pc.setRemoteDescription(
            RTCSessionDescription(sdp=remote_sdp, type=offer["type"])
        )
        if media:
            self.pc.addTrack(AudioStreamTrack())
            if not audio_only:
                self.pc.addTrack(VideoStreamTrack())
        await self.pc.setLocalDescription(await self.pc.createAnswer())
        await self._wait_ice_complete()
        assert self.pc.localDescription is not None
        return {
            "type": self.pc.localDescription.type,
            "sdp": self.pc.localDescription.sdp,
        }

    def add_media(self, *, audio_only: bool = False) -> None:
        self.pc.addTrack(AudioStreamTrack())
        if not audio_only:
            self.pc.addTrack(VideoStreamTrack())

    async def set_remote_description(
        self, description: dict[str, str]
    ) -> None:
        await self.pc.setRemoteDescription(
            RTCSessionDescription(
                sdp=expand_bundle_transport_attributes(description["sdp"]),
                type=description["type"],
            )
        )

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

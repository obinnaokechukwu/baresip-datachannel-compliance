from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aiortc.rtcsctptransport import (
    DataChunk,
    ForwardTsnChunk,
    parse_packet,
    serialize_packet,
)

from .aiortc_endpoint import AiortcEndpoint, copy_application_attributes
from .baresip_endpoint import BaresipEndpoint
from .chromium import ChromiumEndpoint, FirefoxEndpoint
from .evidence import prepare_evidence_dir, versions, write_json
from .model import MessageRecord, Verdict, compare_ordered, compare_unordered
from .oracle import calibrate


@dataclass(frozen=True)
class ProductScenario:
    name: str
    peer: str
    media: bool
    malformed: bool = False
    baresip_offerer: bool = False
    late_local_open: bool = False
    audio_only: bool = False
    simultaneous_open: bool = False
    ordered: bool = True
    max_retransmits: int | None = None
    max_packet_lifetime: int | None = None
    negotiated: bool = False


PRODUCT_SCENARIOS = (
    ProductScenario("baresip-aiortc-data-only", "aiortc", False),
    ProductScenario(
        "baresip-aiortc-unordered-reliable",
        "aiortc",
        False,
        ordered=False,
    ),
    ProductScenario(
        "baresip-aiortc-retransmit-limited",
        "aiortc",
        False,
        ordered=False,
        max_retransmits=2,
    ),
    ProductScenario(
        "baresip-aiortc-lifetime-limited",
        "aiortc",
        False,
        ordered=False,
        max_packet_lifetime=1000,
    ),
    ProductScenario(
        "baresip-aiortc-audiodata",
        "aiortc",
        True,
        audio_only=True,
    ),
    ProductScenario(
        "baresip-offerer-aiortc-data-only",
        "aiortc",
        False,
        baresip_offerer=True,
    ),
    ProductScenario(
        "baresip-offerer-aiortc-rfc8864",
        "aiortc",
        False,
        baresip_offerer=True,
        negotiated=True,
    ),
    ProductScenario(
        "baresip-offerer-aiortc-avdata",
        "aiortc",
        True,
        baresip_offerer=True,
    ),
    ProductScenario(
        "baresip-late-open-aiortc-data-only",
        "aiortc",
        False,
        late_local_open=True,
    ),
    ProductScenario(
        "baresip-aiortc-simultaneous-open",
        "aiortc",
        False,
        simultaneous_open=True,
    ),
    ProductScenario(
        "baresip-aiortc-malformed-input", "aiortc", False, True
    ),
    ProductScenario("baresip-chromium-avdata", "chromium", True),
    ProductScenario("baresip-firefox-data-only", "firefox", False),
    ProductScenario(
        "baresip-firefox-audiodata",
        "firefox",
        True,
        audio_only=True,
    ),
    ProductScenario("baresip-firefox-avdata", "firefox", True),
)


def payloads() -> tuple[tuple[str, bytes], ...]:
    return (
        ("text", b""),
        ("binary", b""),
        ("text", b"a"),
        ("binary", b"\x00"),
        ("text", b"baresip-real-peer"),
        ("binary", bytes(range(256))),
        ("binary", bytes(index % 251 for index in range(1199))),
        ("binary", bytes(index % 251 for index in range(1200))),
        ("binary", bytes(index % 251 for index in range(1201))),
        ("text", b"x" * 4095),
        ("text", b"x" * 4096),
        ("text", b"x" * 4097),
        ("binary", bytes(index % 251 for index in range(8191))),
        ("binary", bytes(index % 251 for index in range(8192))),
        ("binary", bytes(index % 251 for index in range(8193))),
        ("text", b"x" * 16383),
        ("text", b"x" * 16384),
        ("binary", bytes(index % 251 for index in range(16384))),
    )


def records(
    scenario: ProductScenario,
    channel: str,
    values: list[tuple[str, bytes]],
    association: str = "baresip",
) -> list[MessageRecord]:
    return [
        MessageRecord.from_payload(
            run=scenario.name,
            association=association,
            channel=channel,
            direction=f"{scenario.peer}-baresip-echo",
            sequence=sequence,
            message_type=message_type,
            payload=payload,
        )
        for sequence, (message_type, payload) in enumerate(values, 1)
    ]


def received_values(
    events: list[dict[str, Any]], label: str | None = None
) -> list[tuple[str, bytes]]:
    return [
        (event["body"]["type"], bytes.fromhex(event["body"]["payloadHex"]))
        for event in events
        if event["name"] == "message"
        and (label is None or event["body"].get("label") == label)
    ]


def unexpected_message_failures(
    peer: int, events: list[dict[str, Any]]
) -> list[str]:
    unexpected = received_values(events)
    return (
        [f"peer {peer} received {len(unexpected)} unexpected extra messages"]
        if unexpected
        else []
    )


def parallel_payloads(
    peer: int, values: list[tuple[str, bytes]]
) -> list[tuple[str, bytes]]:
    prefix = peer.to_bytes(2, "big")
    return [
        (message_type, prefix + payload)
        for message_type, payload in values
    ]


def expected_media_kinds(scenario: ProductScenario) -> set[str]:
    if not scenario.media:
        return set()
    return {"audio"} if scenario.audio_only else {"audio", "video"}


def exception_verdict(error: Exception, negotiated: bool) -> Verdict:
    if negotiated and isinstance(error, TimeoutError):
        return Verdict.FAIL
    return Verdict.INFRA_ERROR


def verified_dtls_count(log: str) -> int:
    """Count the production DTLS fingerprint-verification evidence line."""
    return sum(
        line == "dtls_srtp: verified sha-256 fingerprint OK "
        "(committed identity)"
        for line in log.splitlines()
    )


def initialize_scenario_evidence(
    destination: Path,
    scenario: ProductScenario,
    command: str,
    baresip: Path,
    libre: Path,
) -> None:
    (destination / "command.txt").write_text(command + "\n")
    write_json(destination / "scenario.json", scenario.__dict__)
    write_json(destination / "versions.json", versions(baresip, libre))


def primary_host_ip() -> str:
    route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        route.connect(("192.0.2.1", 9))
        return str(route.getsockname()[0])
    finally:
        route.close()


def primary_host_sdp(sdp: str, host_ip: str) -> str:
    """Constrain local same-host tests to the routed IPv4 ICE candidate."""
    newline = "\r\n" if "\r\n" in sdp else "\n"
    lines = sdp.replace("\r\n", "\n").splitlines()
    filtered: list[str] = []
    kept = 0
    for line in lines:
        if not line.startswith("a=candidate:"):
            filtered.append(line)
            continue
        fields = line.split()
        if len(fields) >= 8 and fields[4] == host_ip and fields[7] == "host":
            filtered.append(line)
            kept += 1
    if not kept:
        raise RuntimeError(f"SDP has no host ICE candidate for {host_ip}")
    rendered = newline.join(filtered)
    if sdp.endswith(("\r\n", "\n")):
        rendered += newline
    return rendered


def send_turn_mtu_probe(address: str, mtu: int) -> int:
    host, port_text = address.rsplit(":", 1)
    size = mtu + 1
    payload_len = size - 4
    frame = struct.pack("!HH", 0x4001, payload_len) + bytes(payload_len)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return probe.sendto(frame, (host, int(port_text)))
    finally:
        probe.close()


def constrain_description_to_primary_host(
    description: dict[str, str], host_ip: str
) -> dict[str, str]:
    return {
        **description,
        "sdp": primary_host_sdp(description["sdp"], host_ip),
    }


async def terminate_and_reap(
    process: asyncio.subprocess.Process, timeout: float = 5.0
) -> tuple[bytes, bytes]:
    if process.returncode is None:
        try:
            if pid := getattr(process, "pid", None):
                os.killpg(pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            pass
    try:
        return await asyncio.wait_for(process.communicate(), timeout)
    except TimeoutError:
        try:
            if pid := getattr(process, "pid", None):
                os.killpg(pid, signal.SIGKILL)
            elif process.returncode is None:
                process.kill()
        except ProcessLookupError:
            pass
        return await asyncio.wait_for(process.communicate(), timeout)


def relay_candidate_failures(result: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if result.get("localCandidateType") != "relay":
        failures.append("Pion selected local candidate is not relay")
    if result.get("remoteCandidateType") != "relay":
        failures.append("baresip selected remote candidate is not relay")
    return failures


def pion_process_failures(
    returncode: int | None, result: dict[str, Any]
) -> list[str]:
    failures = list(result.get("failures") or [])
    if returncode:
        failures.append(f"Pion endpoint exited with status {returncode}")
    if result.get("verdict") != Verdict.PASS:
        verdict = str(result.get("verdict"))
        failures.append(
            f"Pion endpoint verdict was {verdict!r}"
        )
    return failures


def impairment_failures(
    metrics: dict[str, Any], mtu_probe_bytes: int
) -> list[str]:
    failures: list[str] = []
    for metric in (
        "dataDropped",
        "dataDelayed",
        "dataJittered",
        "dataBandwidthDelayed",
        "dataReordered",
        "dataDuplicated",
        "dataMtuDropped",
    ):
        if metrics.get(metric, 0) <= 0:
            failures.append(f"TURN data traffic did not exercise {metric}")
    if metrics.get("bandwidthBitsPerSecond") != 2_000_000:
        failures.append("TURN bandwidth limit was not active")
    if metrics.get("mtu") != 1400:
        failures.append("TURN MTU limit was not active")
    if mtu_probe_bytes != 1401:
        failures.append("TURN MTU probe was not transmitted")
    if metrics.get("maxDatagramSize", 0) <= 1400:
        failures.append("TURN MTU ceiling did not observe probe")
    if metrics.get("minAppliedDelayMillis", 0) >= metrics.get(
        "maxAppliedDelayMillis", 0
    ):
        failures.append(
            "TURN deterministic jitter produced no delay variation"
        )
    return failures


def rejected_message_failures(
    events: list[dict[str, Any]], label: str
) -> list[str]:
    if received_values(events):
        return [f"{label} reached the application"]
    return []


async def wait_for_messages(
    drain: Any,
    count: int,
    label: str | None = None,
    timeout: float = 15.0,
) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]]]:
    events: list[dict[str, Any]] = []

    async def wait() -> list[tuple[str, bytes]]:
        while True:
            events.extend(await drain())
            values = received_values(events, label)
            if len(values) >= count:
                return values
            await asyncio.sleep(0.05)

    values = await asyncio.wait_for(wait(), timeout)
    return events, values


def dcep_open(label: bytes, protocol: bytes = b"") -> bytes:
    return (
        struct.pack("!BBHLHH", 3, 0, 256, 0, len(label), len(protocol))
        + label
        + protocol
    )


async def exercise_malformed_inputs(
    peer: AiortcEndpoint, channel: str
) -> tuple[
    list[dict[str, Any]],
    str,
    list[tuple[str, bytes]],
    list[str],
]:
    failures: list[str] = []
    events: list[dict[str, Any]] = []
    control = peer.channels[channel]
    if control.id is None:
        return events, channel, [], ["control channel has no stream ID"]

    async def require_closed(
        candidate: Any, description: str, timeout: float = 5.0
    ) -> None:
        try:
            async def wait() -> None:
                while candidate.readyState != "closed":
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(wait(), timeout)
        except TimeoutError:
            failures.append(f"{description} did not reset its SCTP stream")

    parity = control.id & 1
    first_id = 101 if parity else 100
    malformed = (
        ("embedded-nul", first_id, dcep_open(b"bad\x00label")),
        ("invalid-dcep-utf8", first_id + 2, dcep_open(b"\xc0\x80")),
    )
    for label, stream_id, payload in malformed:
        malformed_channel = peer.pc.createDataChannel(
            label, negotiated=True, id=stream_id
        )
        peer._register(malformed_channel)
        await peer.wait_channel_open(label)
        await peer.send_raw(stream_id, 50, payload)
        await require_closed(malformed_channel, label)
        if peer.pc.connectionState != "connected":
            failures.append(f"{label} damaged the peer connection")
        if malformed_channel.readyState != "closed":
            malformed_channel.close()
        events.extend(await peer.drain_events())

    await peer.send_raw(control.id, 51, b"\xc0\x80")
    await require_closed(control, "invalid UTF-8 text")
    events.extend(await peer.drain_events())
    failures.extend(rejected_message_failures(events, "invalid UTF-8 text"))

    oversized = peer.pc.createDataChannel("oversized")
    peer._register(oversized)
    await peer.wait_channel_open("oversized")
    oversized.send(bytes(16385))
    await asyncio.sleep(0.5)
    events.extend(await peer.drain_events())
    if any(
        event["name"] == "message"
        and event["body"].get("label") == "oversized"
        for event in events
    ):
        failures.append("oversized message reached the application")
    await require_closed(oversized, "oversized message")
    if oversized.readyState != "closed":
        oversized.close()

    recovery_label = "valid-after-malformed-input"
    recovery = peer.pc.createDataChannel(recovery_label)
    peer._register(recovery)
    await peer.wait_channel_open(recovery_label)
    expected = [("binary", b"valid-after-invalid-input")]
    await peer.send(recovery_label, *expected[0])
    more_events, actual = await wait_for_messages(
        peer.drain_events, 1, recovery_label
    )
    events.extend(more_events)

    if peer.pc.connectionState != "connected":
        failures.append("malformed input damaged the peer connection")
    return events, recovery_label, actual, failures


class PartialReliabilityDropper:
    """Drop one channel's inbound DATA while observing FORWARD-TSN."""

    def __init__(self, peer: AiortcEndpoint, stream_id: int, payload: bytes):
        if peer.pc.sctp is None:
            raise RuntimeError("SCTP transport is unavailable")
        self._sctp = peer.pc.sctp
        self._original = self._sctp._handle_data
        self._stream_id = stream_id
        self._payload = payload
        self.forwarded = asyncio.Event()
        self.dropped = 0

    async def _handle_data(self, data: bytes) -> None:
        try:
            source_port, destination_port, verification_tag, chunks = (
                parse_packet(data)
            )
        except ValueError:
            await self._original(data)
            return
        if any(isinstance(chunk, ForwardTsnChunk) for chunk in chunks):
            self.forwarded.set()
        dropped = [
            chunk
            for chunk in chunks
            if (
                isinstance(chunk, DataChunk)
                and chunk.stream_id == self._stream_id
                and chunk.user_data == self._payload
            )
        ]
        if dropped:
            self.dropped += len(dropped)
            for chunk in chunks:
                if chunk in dropped:
                    continue
                await self._original(
                    serialize_packet(
                        source_port,
                        destination_port,
                        verification_tag,
                        chunk,
                    )
                )
            return
        await self._original(data)

    def start(self) -> None:
        self._sctp._handle_data = self._handle_data

    def stop(self) -> None:
        self._sctp._handle_data = self._original


def partial_reliability_failures(
    dropped: int, forward_tsn: bool, delivered: bool
) -> list[str]:
    failures: list[str] = []
    if dropped <= 0:
        failures.append("partial-reliability probe did not drop DATA")
    if not forward_tsn:
        failures.append(
            "partial-reliability probe saw no FORWARD-TSN; "
            "the channel behaved as reliable"
        )
    if delivered:
        failures.append("abandoned partial-reliability message was delivered")
    return failures


async def exercise_partial_reliability(
    peer: AiortcEndpoint, channel: str
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    candidate = peer.channels[channel]
    if candidate.id is None:
        return (
            [],
            ["partial-reliability channel has no stream ID"],
            {"streamId": None},
        )
    marker = b"partial-reliability-must-be-abandoned"
    recovery = b"partial-reliability-recovery"
    dropper = PartialReliabilityDropper(peer, candidate.id, marker)
    events: list[dict[str, Any]] = []
    delivered = False
    dropper.start()
    try:
        await peer.send(channel, "binary", marker)
        try:
            await asyncio.wait_for(dropper.forwarded.wait(), 15.0)
        except TimeoutError:
            pass
        events.extend(await peer.drain_events())
        delivered = ("binary", marker) in received_values(events, channel)
    finally:
        dropper.stop()

    failures = partial_reliability_failures(
        dropper.dropped, dropper.forwarded.is_set(), delivered
    )
    await peer.send(channel, "binary", recovery)
    recovery_events, recovery_values = await wait_for_messages(
        peer.drain_events, 1, channel, 15.0
    )
    events.extend(recovery_events)
    if recovery_values != [("binary", recovery)]:
        failures.append("partial-reliability channel did not recover")
    return (
        events,
        failures,
        {
            "streamId": candidate.id,
            "droppedDataChunks": dropper.dropped,
            "forwardTsnObserved": dropper.forwarded.is_set(),
            "abandonedMessageDelivered": delivered,
            "recoveryDelivered": recovery_values == [("binary", recovery)],
        },
    )


def check_sdp(scenario: ProductScenario, offer: str, answer: str) -> list[str]:
    failures: list[str] = []
    for description, name in ((offer, "offer"), (answer, "answer")):
        if "m=application " not in description:
            failures.append(f"{name} lacks m=application")
        if "a=sctp-port:5000" not in description:
            failures.append(f"{name} lacks a=sctp-port:5000")
        if "a=max-message-size:" not in description:
            failures.append(f"{name} lacks a=max-message-size")
        if "a=fingerprint:" not in description:
            failures.append(f"{name} lacks media-level fingerprint")
        if scenario.negotiated:
            expected = (
                'a=dcmap:1 subprotocol="sdp-test";'
                'label="baresip-acceptance"'
            )
            if expected not in description:
                failures.append(f"{name} lacks negotiated dcmap")
    if scenario.media:
        mids = [
            line.removeprefix("a=mid:")
            for line in offer.replace("\r", "").splitlines()
            if line.startswith("a=mid:")
        ]
        groups = [
            line.removeprefix("a=group:BUNDLE ").split()
            for line in offer.replace("\r", "").splitlines()
            if line.startswith("a=group:BUNDLE ")
        ]
        bundle = groups[0] if groups else []
        expected_mids = len(expected_media_kinds(scenario)) + 1
        if len(mids) < expected_mids or set(mids) - set(bundle):
            failures.append(
                f"offer does not bundle all media: mids={mids} bundle={bundle}"
            )
    return failures


async def run_product_scenario(
    scenario: ProductScenario,
    evidence_root: Path,
    executable: Path,
    baresip: Path,
    libre: Path,
    library_paths: tuple[Path, ...],
    command: str,
) -> Verdict:
    destination = evidence_root / scenario.name
    prepare_evidence_dir(destination)
    initialize_scenario_evidence(destination, scenario, command, baresip, libre)
    endpoint = BaresipEndpoint(
        executable, baresip, library_paths, destination / "baresip.log"
    )
    failures: list[str] = []
    events: list[dict[str, Any]] = []
    stats: dict[str, Any] = {}
    offer: dict[str, str] | None = None
    answer: dict[str, str] | None = None
    negotiated = False
    expected_values = (
        [("binary", b"valid-after-invalid-input")]
        if scenario.malformed
        else list(payloads())
    )
    expected_by_channel: dict[str, list[tuple[str, bytes]]] = {}
    actual_by_channel: dict[str, list[tuple[str, bytes]]] = {}
    probe_stats: dict[str, Any] | None = None
    verdict = Verdict.INFRA_ERROR
    result_payload: dict[str, Any] = {
        "verdict": verdict,
        "failures": ["scenario did not complete"],
    }
    channel = (
        "baresip-acceptance"
        if scenario.baresip_offerer
        else f"{scenario.peer}-acceptance"
    )
    peer: AiortcEndpoint | ChromiumEndpoint | FirefoxEndpoint
    host_ip = primary_host_ip()

    if scenario.peer == "aiortc":
        peer = AiortcEndpoint(host_ip)
    elif scenario.peer == "firefox":
        peer = FirefoxEndpoint(destination / "firefox-profile")
    else:
        peer = ChromiumEndpoint(destination / "chrome-profile")

    try:
        await endpoint.start()
        if isinstance(peer, AiortcEndpoint):
            if scenario.baresip_offerer:
                offer = await endpoint.offer(
                    media=scenario.media,
                    audio_only=scenario.audio_only,
                    negotiated=scenario.negotiated,
                )
                offer = constrain_description_to_primary_host(offer, host_ip)
                if scenario.negotiated:
                    negotiated_channel = peer.pc.createDataChannel(
                        channel,
                        protocol="sdp-test",
                        negotiated=True,
                        id=1,
                    )
                    peer._register(negotiated_channel)
                answer = await peer.answer(
                    offer,
                    media=scenario.media,
                    audio_only=scenario.audio_only,
                )
                answer = constrain_description_to_primary_host(answer, host_ip)
                if scenario.negotiated:
                    answer["sdp"] = copy_application_attributes(
                        offer["sdp"], answer["sdp"], ("dcmap", "dcsa")
                    )
                await endpoint.set_answer(answer)
                negotiated = True
            else:
                if scenario.media:
                    peer.add_media(audio_only=scenario.audio_only)
                data_channel = peer.pc.createDataChannel(
                    channel,
                    protocol="baresip-acceptance-v1",
                    ordered=scenario.ordered,
                    maxRetransmits=scenario.max_retransmits,
                    maxPacketLifeTime=scenario.max_packet_lifetime,
                )
                peer._register(data_channel)
                peer.constrain_ice()
                await peer.pc.setLocalDescription(await peer.pc.createOffer())
                await peer._wait_ice_complete()
                assert peer.pc.localDescription is not None
                offer = {
                    "type": peer.pc.localDescription.type,
                    "sdp": primary_host_sdp(
                        peer.pc.localDescription.sdp, host_ip
                    ),
                }
                answer = await endpoint.answer(
                    offer,
                    media=scenario.media,
                    audio_only=scenario.audio_only,
                )
                answer = constrain_description_to_primary_host(answer, host_ip)
                await peer.set_remote_description(answer)
                negotiated = True
            await peer.wait_channel_open(channel, 30.0)
            if scenario.late_local_open:
                channel = "baresip-late-open"
                await endpoint.create_datachannel(channel)
                await peer.wait_channel_open(channel, 30.0)
            channels = [channel]
            if scenario.simultaneous_open:
                remote_label = "aiortc-simultaneous"
                local_label = "baresip-simultaneous"
                create_local = asyncio.create_task(
                    endpoint.create_datachannel(local_label)
                )
                remote_channel = peer.pc.createDataChannel(remote_label)
                peer._register(remote_channel)
                await create_local
                await asyncio.gather(
                    peer.wait_channel_open(remote_label, 30.0),
                    peer.wait_channel_open(local_label, 30.0),
                )
                channels.extend((remote_label, local_label))
            if scenario.malformed:
                (
                    events,
                    recovery_channel,
                    actual_values,
                    malformed_failures,
                ) = (
                    await exercise_malformed_inputs(peer, channel)
                )
                failures.extend(malformed_failures)
                expected_by_channel[recovery_channel] = expected_values
                actual_by_channel[recovery_channel] = actual_values
            else:
                for active_channel in channels:
                    expected_by_channel[active_channel] = expected_values
                    for message_type, payload in expected_values:
                        await peer.send(
                            active_channel, message_type, payload
                        )
                    more_events, actual_values = await wait_for_messages(
                        peer.drain_events,
                        len(expected_values),
                        active_channel,
                    )
                    events.extend(more_events)
                    actual_by_channel[active_channel] = actual_values
                if (
                    scenario.max_retransmits is not None
                    or scenario.max_packet_lifetime is not None
                ):
                    probe_events, probe_failures, probe_stats = (
                        await exercise_partial_reliability(peer, channel)
                    )
                    events.extend(probe_events)
                    failures.extend(probe_failures)
            stats = await peer.stats()
            if probe_stats is not None:
                stats["partialReliabilityProbe"] = probe_stats
            if scenario.negotiated:
                stats["rfc8864SignalingAdapter"] = (
                    "controller preserves dcmap/dcsa because aiortc does not "
                    "model them; aiortc owns negotiated SCTP stream 1"
                )
            if stats.get("dtlsState") != "connected":
                failures.append("aiortc DTLS is not connected")
            if stats.get("sctpState") != "connected":
                failures.append("aiortc SCTP is not connected")
            if scenario.media:
                received_kinds = {
                    row.get("kind")
                    for row in stats.get("rows", [])
                    if row.get("type") == "inbound-rtp"
                    and row.get("packetsReceived", 0) > 0
                }
                expected_kinds = expected_media_kinds(scenario)
                if received_kinds != expected_kinds:
                    failures.append(
                        "aiortc lacks received audio/video: "
                        f"{received_kinds}"
                    )
        else:
            await peer.start(
                media=scenario.media,
                audio_only=scenario.audio_only,
            )
            await peer.create_channel(channel)
            offer = await peer.create_offer()
            answer = await endpoint.answer(
                offer,
                media=scenario.media,
                audio_only=scenario.audio_only,
            )
            await peer.set_remote_description(answer)
            negotiated = True
            await peer.wait_channel_open(channel, 30.0)
            for message_type, payload in expected_values:
                await peer.send(channel, message_type, payload)
            events, actual_values = await wait_for_messages(
                peer.events, len(expected_values), channel
            )
            expected_by_channel[channel] = expected_values
            actual_by_channel[channel] = actual_values
            await asyncio.sleep(1.0)
            stats = await peer.stats()
            if stats.get("connectionState") != "connected":
                failures.append(
                    f"{scenario.peer} peer connection is not connected"
                )
            if scenario.media:
                received_kinds = {
                    row.get("kind")
                    for row in stats.get("rows", [])
                    if row.get("type") == "inbound-rtp"
                    and row.get("packetsReceived", 0) > 0
                }
                expected_kinds = expected_media_kinds(scenario)
                if received_kinds != expected_kinds:
                    failures.append(
                        f"{scenario.peer} lacks received media: "
                        f"{received_kinds}"
                    )

        sent = [
            record
            for active_channel, values in expected_by_channel.items()
            for record in records(
                scenario, active_channel, values
            )
        ]
        received = [
            record
            for active_channel, values in actual_by_channel.items()
            for record in records(
                scenario, active_channel, values
            )
        ]
        compare = compare_ordered if scenario.ordered else compare_unordered
        failures.extend(compare(sent, received).failures)
        assert offer is not None and answer is not None
        failures.extend(check_sdp(scenario, offer["sdp"], answer["sdp"]))

        await endpoint.delete_session()
        await endpoint.close()
        log = (destination / "baresip.log").read_text(errors="replace")
        if "connectivity check is complete" not in log:
            failures.append("baresip log lacks completed ICE evidence")
        if not verified_dtls_count(log):
            failures.append("baresip log lacks verified DTLS evidence")
        if scenario.media:
            for kind in expected_media_kinds(scenario):
                if f"rtp established ({kind})" not in log:
                    failures.append(
                        f"baresip log lacks established {kind} RTP"
                    )

        (destination / "command.txt").write_text(command + "\n")
        (destination / "offer.sdp").write_text(offer["sdp"])
        (destination / "answer.sdp").write_text(answer["sdp"])
        write_json(destination / "scenario.json", scenario.__dict__)
        version_data = versions(baresip, libre)
        if stats.get("browserUserAgent"):
            version_data[scenario.peer] = stats["browserUserAgent"]
        write_json(destination / "versions.json", version_data)
        write_json(destination / "peer-stats.json", stats)
        write_json(destination / "sent-manifest.json", [x.json() for x in sent])
        write_json(
            destination / "received-manifest.json",
            [x.json() for x in received],
        )
        (destination / "events.ndjson").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        )
        verdict = Verdict.FAIL if failures else Verdict.PASS
        result_payload = {"verdict": verdict, "failures": failures}
    except Exception as error:
        verdict = exception_verdict(error, negotiated)
        result_payload = {
            "verdict": verdict,
            "failures": [f"{type(error).__name__}: {error}"],
        }
    finally:
        await peer.close()
        await endpoint.close()
        write_json(destination / "result.json", result_payload)
    return verdict


def inbound_packet_counts(stats: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in stats.get("rows", []):
        if row.get("type") != "inbound-rtp":
            continue
        kind = row.get("kind")
        if kind not in {"audio", "video"}:
            continue
        counts[kind] = counts.get(kind, 0) + int(
            row.get("packetsReceived", 0)
        )
    return counts


async def wait_browser_media(
    peer: ChromiumEndpoint,
    timeout: float = 15.0,
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        stats = await peer.stats()
        if (
            stats.get("connectionState") == "connected"
            and set(inbound_packet_counts(stats)) == {"audio", "video"}
        ):
            return
        await asyncio.sleep(0.1)
    raise TimeoutError("Chromium media did not become active")


async def run_media_regression(
    evidence_root: Path,
    executable: Path,
    baresip: Path,
    libre: Path,
    library_paths: tuple[Path, ...],
    command: str,
) -> Verdict:
    destination = evidence_root / "baresip-chromium-media-regression"
    prepare_evidence_dir(destination)
    evidence_scenario = ProductScenario(
        "baresip-chromium-media-regression", "chromium", True
    )
    initialize_scenario_evidence(
        destination, evidence_scenario, command, baresip, libre
    )
    failures: list[str] = []
    duration = 5.0
    minimum_ratio = 0.8
    burst_size = 16
    runs: dict[str, Any] = {}
    negotiated = False

    async def run_case(loaded: bool) -> None:
        nonlocal negotiated
        negotiated = False
        name = "saturated-data" if loaded else "media-only"
        case = destination / name
        case.mkdir(parents=True, exist_ok=True)
        endpoint = BaresipEndpoint(
            executable, baresip, library_paths, case / "baresip.log"
        )
        peer = ChromiumEndpoint(case / "chrome-profile")
        offer: dict[str, str] | None = None
        answer: dict[str, str] | None = None
        messages = 0
        received_bytes = 0
        try:
            await endpoint.start()
            await peer.start(media=True)
            if loaded:
                await peer.create_channel("media-load")
            offer = await peer.create_offer()
            answer = await endpoint.answer(
                offer, media=True, data=loaded
            )
            await peer.set_remote_description(answer)
            negotiated = True
            if loaded:
                await peer.wait_channel_open("media-load", 30.0)
            await wait_browser_media(peer)
            before = await peer.stats()
            started = time.monotonic()
            payload_body = bytes(
                index % 251 for index in range(16384 - 8)
            )
            while time.monotonic() - started < duration:
                if loaded:
                    expected = []
                    for _ in range(burst_size):
                        payload = (
                            messages.to_bytes(8, "big") + payload_body
                        )
                        expected.append(("binary", payload))
                        await peer.send(
                            "media-load", "binary", payload
                        )
                        messages += 1
                        received_bytes += len(payload)
                    _, actual = await wait_for_messages(
                        peer.events, burst_size, "media-load", 5.0
                    )
                    if actual != expected:
                        failures.append(
                            "saturated data transcript mismatch"
                        )
                        break
                else:
                    await asyncio.sleep(0.05)
            elapsed = time.monotonic() - started
            after = await peer.stats()
            before_counts = inbound_packet_counts(before)
            after_counts = inbound_packet_counts(after)
            deltas = {
                kind: after_counts.get(kind, 0)
                - before_counts.get(kind, 0)
                for kind in ("audio", "video")
            }
            runs[name] = {
                "elapsedSeconds": elapsed,
                "packetsReceivedBefore": before_counts,
                "packetsReceivedAfter": after_counts,
                "packetDeltas": deltas,
                "dataMessages": messages,
                "dataBytes": received_bytes,
            }
            if any(value <= 0 for value in deltas.values()):
                failures.append(f"{name} did not receive continuous media")
            if loaded and messages < 10:
                failures.append(
                    "saturated run exchanged fewer than 10 full-size messages"
                )

            await endpoint.delete_session()
            await endpoint.close()
            log = (case / "baresip.log").read_text(errors="replace")
            for kind in ("audio", "video"):
                if f"rtp established ({kind})" not in log:
                    failures.append(
                        f"{name} lacks established {kind} RTP evidence"
                    )
            assert offer is not None and answer is not None
            (case / "offer.sdp").write_text(offer["sdp"])
            (case / "answer.sdp").write_text(answer["sdp"])
            write_json(case / "stats-before.json", before)
            write_json(case / "stats-after.json", after)
        finally:
            await peer.close()
            await endpoint.close()

    try:
        await run_case(False)
        await run_case(True)
        baseline = runs["media-only"]["packetDeltas"]
        loaded = runs["saturated-data"]["packetDeltas"]
        ratios = {
            kind: loaded[kind] / baseline[kind]
            if baseline[kind] > 0
            else 0.0
            for kind in ("audio", "video")
        }
        runs["loadedToBaselineRatios"] = ratios
        for kind, ratio in ratios.items():
            if ratio < minimum_ratio:
                failures.append(
                    f"{kind} packet rate under load was "
                    f"{ratio:.1%}, below {minimum_ratio:.0%}"
                )
        write_json(
            destination / "budgets.json",
            {
                "measurementSeconds": duration,
                "minimumLoadedToBaselinePacketRatio": minimum_ratio,
                "minimumFullSizeMessages": 10,
                "fullSizeMessageBurst": burst_size,
            },
        )
        write_json(destination / "measurements.json", runs)
        write_json(destination / "versions.json", versions(baresip, libre))
        (destination / "command.txt").write_text(command + "\n")
        verdict = Verdict.FAIL if failures else Verdict.PASS
        write_json(
            destination / "result.json",
            {"verdict": verdict, "failures": failures},
        )
        return verdict
    except Exception as error:
        verdict = exception_verdict(error, negotiated)
        write_json(
            destination / "result.json",
            {
                "verdict": verdict,
                "failures": [f"{type(error).__name__}: {error}"],
            },
        )
        return verdict


async def run_parallel_sessions(
    evidence_root: Path,
    executable: Path,
    baresip: Path,
    libre: Path,
    library_paths: tuple[Path, ...],
    command: str,
    count: int = 4,
) -> Verdict:
    scenario = ProductScenario(
        "baresip-aiortc-parallel-sessions", "aiortc", False
    )
    destination = evidence_root / scenario.name
    prepare_evidence_dir(destination)
    initialize_scenario_evidence(destination, scenario, command, baresip, libre)
    endpoint = BaresipEndpoint(
        executable, baresip, library_paths, destination / "baresip.log"
    )
    host_ip = primary_host_ip()
    peers = [AiortcEndpoint(host_ip) for _ in range(count)]
    session_ids: list[str] = []
    failures: list[str] = []
    sent: list[MessageRecord] = []
    received: list[MessageRecord] = []
    all_events: list[dict[str, Any]] = []
    all_stats: list[dict[str, Any]] = []
    base_values = list(payloads()[:4])
    values_by_peer = [
        parallel_payloads(index, base_values) for index in range(count)
    ]
    negotiated = False
    verdict = Verdict.INFRA_ERROR
    result_payload: dict[str, Any] = {
        "verdict": verdict,
        "failures": ["scenario did not complete"],
    }

    try:
        await endpoint.start()
        offers: list[dict[str, str]] = []
        for index, peer in enumerate(peers):
            label = f"parallel-{index}"
            channel = peer.pc.createDataChannel(label)
            peer._register(channel)
            peer.constrain_ice()
            await peer.pc.setLocalDescription(await peer.pc.createOffer())
            offers.append({})

        await asyncio.gather(*(peer._wait_ice_complete() for peer in peers))
        for index, peer in enumerate(peers):
            assert peer.pc.localDescription is not None
            offers[index] = {
                "type": peer.pc.localDescription.type,
                "sdp": primary_host_sdp(
                    peer.pc.localDescription.sdp, host_ip
                ),
            }

        sessions = await asyncio.gather(
            *(
                endpoint.answer_session(offer, media=False)
                for offer in offers
            )
        )
        sessions = [
            (
                session_id,
                constrain_description_to_primary_host(answer, host_ip),
            )
            for session_id, answer in sessions
        ]
        session_ids.extend(session_id for session_id, _ in sessions)
        await asyncio.gather(
            *(
                peer.set_remote_description(answer)
                for peer, (_, answer) in zip(peers, sessions, strict=True)
            )
        )
        negotiated = True
        await asyncio.gather(
            *(
                    peer.wait_channel_open(f"parallel-{index}", 30.0)
                for index, peer in enumerate(peers)
            )
        )

        for index, peer in enumerate(peers):
            label = f"parallel-{index}"
            for message_type, payload in values_by_peer[index]:
                await peer.send(label, message_type, payload)

        results = await asyncio.gather(
            *(
                wait_for_messages(
                    peer.drain_events,
                    len(values_by_peer[index]),
                    f"parallel-{index}",
                    30.0,
                )
                for index, peer in enumerate(peers)
            )
        )
        await asyncio.sleep(0.25)
        for index, (peer, (events, actual)) in enumerate(
            zip(peers, results, strict=True)
        ):
            label = f"parallel-{index}"
            association = f"baresip-{index}"
            extras = await peer.drain_events()
            events.extend(extras)
            failures.extend(unexpected_message_failures(index, extras))
            all_events.extend(
                {"peer": index, **event} for event in events
            )
            sent.extend(
                records(
                    scenario, label, values_by_peer[index], association
                )
            )
            received.extend(
                records(scenario, label, actual, association)
            )
            stats = await peer.stats()
            all_stats.append({"peer": index, **stats})
            if stats.get("dtlsState") != "connected":
                failures.append(f"peer {index} DTLS is not connected")
            if stats.get("sctpState") != "connected":
                failures.append(f"peer {index} SCTP is not connected")

        failures.extend(compare_ordered(sent, received).failures)
        await asyncio.gather(
            *(endpoint.delete_session_id(value) for value in session_ids)
        )
        session_ids.clear()
        await endpoint.close()

        log = (destination / "baresip.log").read_text(errors="replace")
        if log.count("connectivity check is complete") < count:
            failures.append("baresip log lacks parallel ICE completions")
        if verified_dtls_count(log) < count:
            failures.append("baresip log lacks parallel DTLS verification")

        (destination / "command.txt").write_text(command + "\n")
        write_json(destination / "scenario.json", scenario.__dict__)
        write_json(destination / "versions.json", versions(baresip, libre))
        write_json(destination / "peer-stats.json", all_stats)
        write_json(destination / "sent-manifest.json", [x.json() for x in sent])
        write_json(
            destination / "received-manifest.json",
            [x.json() for x in received],
        )
        (destination / "events.ndjson").write_text(
            "".join(
                json.dumps(event, sort_keys=True) + "\n"
                for event in all_events
            )
        )
        verdict = Verdict.FAIL if failures else Verdict.PASS
        result_payload = {"verdict": verdict, "failures": failures}
    except Exception as error:
        verdict = exception_verdict(error, negotiated)
        result_payload = {
            "verdict": verdict,
            "failures": [f"{type(error).__name__}: {error}"],
        }
    finally:
        for session_id in session_ids:
            try:
                await endpoint.delete_session_id(session_id, missing_ok=True)
            except Exception:
                pass
        await asyncio.gather(
            *(peer.close() for peer in peers), return_exceptions=True
        )
        await endpoint.close()
        write_json(destination / "result.json", result_payload)
    return verdict


async def run_pion_scenario(
    evidence_root: Path,
    executable: Path,
    pion_endpoint: Path,
    baresip: Path,
    libre: Path,
    library_paths: tuple[Path, ...],
    command: str,
    turn_server: Path | None = None,
    forced_relay: bool = False,
    impairment: bool = False,
) -> Verdict:
    scenario = ProductScenario(
        (
            "baresip-pion-turn-impairment"
            if impairment
            else "baresip-pion-forced-turn"
            if forced_relay
            else "baresip-pion-data-only"
        ),
        "pion",
        False,
    )
    destination = evidence_root / scenario.name
    prepare_evidence_dir(destination)
    initialize_scenario_evidence(destination, scenario, command, baresip, libre)
    endpoint: BaresipEndpoint | None = None
    pion_process: asyncio.subprocess.Process | None = None
    turn_process: asyncio.subprocess.Process | None = None
    pion_stdout = b""
    pion_stderr = b""
    failures: list[str] = []
    values = list(payloads())
    label = "pion-acceptance"
    turn_url = ""
    turn_username = "baresip"
    turn_password = "acceptance"
    mtu_probe_bytes = 0
    verdict = Verdict.INFRA_ERROR
    result_payload: dict[str, Any] = {
        "verdict": verdict,
        "failures": ["scenario did not complete"],
    }

    try:
        host_ip = primary_host_ip()
        if forced_relay:
            if turn_server is None:
                raise RuntimeError("forced relay requires a TURN server")
            turn_arguments = [
                str(turn_server),
                "-public-ip",
                host_ip,
                "-username",
                turn_username,
                "-password",
                turn_password,
            ]
            if impairment:
                turn_arguments.extend(
                    (
                        "-drop-every",
                        "29",
                        "-reorder-every",
                        "31",
                        "-duplicate-every",
                        "37",
                        "-delay",
                        "2ms",
                        "-jitter",
                        "2ms",
                        "-bandwidth",
                        "2000000",
                        "-mtu",
                        "1400",
                    )
                )
            turn_process = await asyncio.create_subprocess_exec(
                *turn_arguments,
                start_new_session=True,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert turn_process.stdout is not None
            ready_line = await asyncio.wait_for(
                turn_process.stdout.readline(), 10.0
            )
            ready = json.loads(ready_line)
            if not ready.get("ready"):
                raise RuntimeError("TURN server did not become ready")
            turn_url = f"turn:{ready['address']}?transport=udp"
            if impairment:
                mtu_probe_bytes = await asyncio.to_thread(
                    send_turn_mtu_probe, ready["address"], 1400
                )

        endpoint = BaresipEndpoint(
            executable,
            baresip,
            library_paths,
            destination / "baresip.log",
            ice_server=turn_url or None,
            ice_username=turn_username if forced_relay else None,
            ice_password=turn_password if forced_relay else None,
            ice_relay_only=forced_relay,
        )
        await endpoint.start()
        pion_process = await asyncio.create_subprocess_exec(
            str(pion_endpoint),
            start_new_session=True,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        request = {
            "baseUrl": "http://127.0.0.1:9000",
            "label": label,
            "messages": [
                {"type": message_type, "payloadHex": payload.hex()}
                for message_type, payload in values
            ],
            "turnUrl": turn_url,
            "turnUsername": turn_username,
            "turnCredential": turn_password,
            "forceRelay": forced_relay,
            "hostIp": host_ip,
        }
        stdout, stderr = await asyncio.wait_for(
            pion_process.communicate(json.dumps(request).encode()), 75.0
        )
        pion_stdout = stdout
        (destination / "pion.stdout").write_bytes(pion_stdout)
        pion_stderr += stderr
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Pion endpoint returned invalid JSON: {error}"
            ) from error
        failures.extend(pion_process_failures(pion_process.returncode, result))

        actual = [
            (item["type"], bytes.fromhex(item["payloadHex"]))
            for item in (result.get("messages") or [])
        ]
        sent = records(scenario, label, values)
        received = records(scenario, label, actual)
        failures.extend(compare_ordered(sent, received).failures)
        if result.get("connectionState") != "connected":
            failures.append("Pion peer connection is not connected")
        if result.get("iceState") not in {"connected", "completed"}:
            failures.append("Pion ICE is not connected")
        if result.get("channelState") != "open":
            failures.append("Pion data channel is not open")
        if forced_relay:
            failures.extend(relay_candidate_failures(result))
            candidates = [
                line
                for line in result.get("offer", "").splitlines()
                if line.startswith("a=candidate:")
            ]
            if not candidates or any(
                " typ relay " not in f" {line} " for line in candidates
            ):
                failures.append("Pion offer was not relay-only")
        if impairment:
            assert turn_process is not None
            assert turn_process.stdout is not None
            turn_process.send_signal(signal.SIGUSR1)
            metrics_line = await asyncio.wait_for(
                turn_process.stdout.readline(), 10.0
            )
            metrics = json.loads(metrics_line)
            write_json(destination / "turn-metrics.json", metrics)
            failures.extend(
                impairment_failures(metrics, mtu_probe_bytes)
            )

        await endpoint.close()
        log = (destination / "baresip.log").read_text(errors="replace")
        if "connectivity check is complete" not in log:
            failures.append("baresip log lacks completed ICE evidence")
        if not verified_dtls_count(log):
            failures.append("baresip log lacks verified DTLS evidence")

        (destination / "command.txt").write_text(command + "\n")
        (destination / "offer.sdp").write_text(result.get("offer", ""))
        (destination / "answer.sdp").write_text(result.get("answer", ""))
        write_json(destination / "scenario.json", scenario.__dict__)
        version_data = versions(baresip, libre)
        version_data["pion"] = result.get("pionVersion", "unknown")
        write_json(destination / "versions.json", version_data)
        write_json(
            destination / "peer-stats.json",
            {
                key: result.get(key)
                for key in (
                    "connectionState",
                    "iceState",
                    "channelState",
                    "localCandidateType",
                    "remoteCandidateType",
                    "selectedPair",
                )
            },
        )
        write_json(destination / "sent-manifest.json", [x.json() for x in sent])
        write_json(
            destination / "received-manifest.json",
            [x.json() for x in received],
        )
        verdict = Verdict.FAIL if failures else Verdict.PASS
        result_payload = {"verdict": verdict, "failures": failures}
    except Exception as error:
        verdict = Verdict.INFRA_ERROR
        result_payload = {
            "verdict": verdict,
            "failures": [f"{type(error).__name__}: {error}"],
        }
    finally:
        if endpoint is not None:
            await endpoint.close()
        if pion_process is not None:
            _, remaining_stderr = await terminate_and_reap(pion_process)
            pion_stderr += remaining_stderr
        (destination / "pion.stdout").write_bytes(pion_stdout)
        (destination / "pion.log").write_bytes(pion_stderr)
        if turn_process is not None:
            _, turn_stderr = await terminate_and_reap(turn_process)
            (destination / "turn-server.log").write_bytes(turn_stderr)
        write_json(destination / "result.json", result_payload)
    return verdict


def analyze_resources(
    baseline: dict[str, int],
    samples: list[dict[str, Any]],
) -> dict[str, dict[str, float | int]]:
    metrics = ("rssBytes", "fileDescriptors", "threads")
    cycles = [sample for sample in samples if sample["cycle"] >= 0]
    count = len(cycles)
    x_mean = (count - 1) / 2 if count else 0.0
    denominator = sum((index - x_mean) ** 2 for index in range(count))
    analysis: dict[str, dict[str, float | int]] = {}
    for metric in metrics:
        values = [int(sample[metric]) for sample in cycles]
        slope = (
            sum(
                (index - x_mean) * (value - sum(values) / count)
                for index, value in enumerate(values)
            )
            / denominator
            if count > 1 and denominator
            else 0.0
        )
        analysis[metric] = {
            "baseline": baseline[metric],
            "final": values[-1] if values else baseline[metric],
            "peak": max(values, default=baseline[metric]),
            "peakGrowth": max(
                0, max(values, default=baseline[metric]) - baseline[metric]
            ),
            "slopePerCycle": slope,
            "projectedGrowth": max(0.0, slope * count),
        }
    return analysis


async def run_lifecycle_campaign(
    evidence_root: Path,
    executable: Path,
    baresip: Path,
    libre: Path,
    library_paths: tuple[Path, ...],
    command: str,
    cycles: int,
) -> Verdict:
    scenario = ProductScenario(
        "baresip-aiortc-lifecycle-campaign", "aiortc", False
    )
    destination = evidence_root / scenario.name
    prepare_evidence_dir(destination)
    initialize_scenario_evidence(destination, scenario, command, baresip, libre)
    endpoint = BaresipEndpoint(
        executable, baresip, library_paths, destination / "baresip.log"
    )
    failures: list[str] = []
    sent: list[MessageRecord] = []
    received: list[MessageRecord] = []
    samples: list[dict[str, Any]] = []
    teardown_budget = 15.0
    rss_growth_budget = 32 * 1024 * 1024
    fd_growth_budget = 4
    thread_growth_budget = 2
    negotiated = False
    host_ip = primary_host_ip()
    verdict = Verdict.INFRA_ERROR
    result_payload: dict[str, Any] = {
        "verdict": verdict,
        "failures": ["scenario did not complete"],
    }

    try:
        if cycles <= 0:
            raise ValueError("lifecycle cycles must be positive")
        await endpoint.start()
        baseline = endpoint.resource_snapshot()
        samples.append({"cycle": -1, **baseline})
        for cycle in range(cycles):
            negotiated = False
            peer = AiortcEndpoint(host_ip)
            session_id: str | None = None
            label = f"lifecycle-{cycle}"
            payload = cycle.to_bytes(4, "big")
            values = [("binary", payload)]
            started = time.monotonic()
            remote_close_observed = False
            cleanup_session_existed: bool | None = None
            try:
                channel = peer.pc.createDataChannel(label)
                peer._register(channel)
                peer.constrain_ice()
                await peer.pc.setLocalDescription(await peer.pc.createOffer())
                await peer._wait_ice_complete()
                assert peer.pc.localDescription is not None
                offer = {
                    "type": peer.pc.localDescription.type,
                    "sdp": primary_host_sdp(
                        peer.pc.localDescription.sdp, host_ip
                    ),
                }
                session_id, answer = await endpoint.answer_session(
                    offer, media=False
                )
                answer = constrain_description_to_primary_host(answer, host_ip)
                await peer.set_remote_description(answer)
                negotiated = True
                await peer.wait_channel_open(label, 30.0)
                await peer.send(label, "binary", payload)
                _, actual = await wait_for_messages(
                    peer.drain_events, 1, label, 15.0
                )
                association = f"baresip-{cycle}"
                sent.extend(records(scenario, label, values, association))
                received.extend(
                    records(scenario, label, actual, association)
                )

                teardown_started = time.monotonic()
                if cycle % 2 == 0:
                    closed_id = channel.id
                    if closed_id is None:
                        failures.append(
                            f"cycle {cycle} channel had no assigned SID"
                        )
                    channel.close()

                    async def wait_closed() -> None:
                        while channel.readyState != "closed":
                            await asyncio.sleep(0.01)

                    await asyncio.wait_for(wait_closed(), teardown_budget)
                    try:
                        replacement_label = f"{label}-replacement"
                        replacement = peer.pc.createDataChannel(
                            replacement_label
                        )
                        peer._register(replacement)
                        await peer.wait_channel_open(
                            replacement_label, teardown_budget
                        )
                        if replacement.id != closed_id:
                            failures.append(
                                f"cycle {cycle} replacement SID "
                                f"{replacement.id} did not reuse {closed_id}"
                            )
                        await peer.send(
                            replacement_label, "binary", payload
                        )
                        _, replacement_actual = await wait_for_messages(
                            peer.drain_events,
                            1,
                            replacement_label,
                            teardown_budget,
                        )
                        sent.extend(
                            records(
                                scenario,
                                replacement_label,
                                values,
                                association,
                            )
                        )
                        received.extend(
                            records(
                                scenario,
                                replacement_label,
                                replacement_actual,
                                association,
                            )
                        )
                        remote_close_observed = True
                    except (TimeoutError, OSError) as error:
                        failures.append(
                            f"cycle {cycle} could not open a replacement "
                            "channel after remote channel close: "
                            f"{type(error).__name__}: {error}"
                        )
                    cleanup_session_existed = (
                        await endpoint.delete_session_id(session_id)
                    )
                else:
                    await peer.close()
                    try:
                        await endpoint.wait_session_missing(
                            session_id,
                            teardown_budget,
                        )
                        remote_close_observed = True
                    except TimeoutError:
                        failures.append(
                            f"cycle {cycle} did not propagate remote "
                            "peer close to baresip"
                        )
                    cleanup_session_existed = (
                        await endpoint.delete_session_id(
                            session_id, missing_ok=True
                        )
                    )
                    if remote_close_observed and cleanup_session_existed:
                        failures.append(
                            f"cycle {cycle} retained an autonomously "
                            "closed session"
                        )
                session_id = None
                teardown_elapsed = time.monotonic() - teardown_started
                if teardown_elapsed > teardown_budget:
                    failures.append(
                        f"cycle {cycle} teardown exceeded "
                        f"{teardown_budget:.0f} seconds"
                    )
            finally:
                if session_id is not None:
                    try:
                        await endpoint.delete_session_id(
                            session_id, missing_ok=True
                        )
                    except Exception:
                        pass
                await peer.close()

            elapsed = time.monotonic() - started
            if elapsed > 45.0:
                failures.append(
                    f"cycle {cycle} exceeded 45-second total budget"
                )
            snapshot = endpoint.resource_snapshot()
            samples.append(
                {
                    "cycle": cycle,
                    "totalSeconds": elapsed,
                    "teardownSeconds": teardown_elapsed,
                    "remoteCloseObserved": remote_close_observed,
                    "cleanupSessionExisted": cleanup_session_existed,
                    **snapshot,
                }
            )

        failures.extend(compare_ordered(sent, received).failures)
        resource_analysis = analyze_resources(baseline, samples)
        budgets = {
            "rssBytes": rss_growth_budget,
            "fileDescriptors": fd_growth_budget,
            "threads": thread_growth_budget,
        }
        for metric, budget in budgets.items():
            metric_analysis = resource_analysis[metric]
            if metric_analysis["peakGrowth"] > budget:
                failures.append(
                    f"Baresip peak {metric} growth exceeded {budget}"
                )
            if metric_analysis["projectedGrowth"] > budget:
                failures.append(
                    f"Baresip {metric} trend exceeded {budget} "
                    "over the campaign"
                )

        await endpoint.close()
        log = (destination / "baresip.log").read_text(errors="replace")
        if log.count("connectivity check is complete") < cycles:
            failures.append("lifecycle log lacks ICE completions")
        if verified_dtls_count(log) < cycles:
            failures.append("lifecycle log lacks DTLS verifications")

        (destination / "command.txt").write_text(command + "\n")
        write_json(destination / "scenario.json", scenario.__dict__)
        write_json(destination / "versions.json", versions(baresip, libre))
        write_json(
            destination / "budgets.json",
            {
                "cycles": cycles,
                "teardownSeconds": teardown_budget,
                "rssGrowthBytes": rss_growth_budget,
                "fileDescriptorGrowth": fd_growth_budget,
                "threadGrowth": thread_growth_budget,
            },
        )
        write_json(destination / "resource-samples.json", samples)
        write_json(
            destination / "resource-analysis.json", resource_analysis
        )
        write_json(destination / "sent-manifest.json", [x.json() for x in sent])
        write_json(
            destination / "received-manifest.json",
            [x.json() for x in received],
        )
        verdict = Verdict.FAIL if failures else Verdict.PASS
        result_payload = {"verdict": verdict, "failures": failures}
    except Exception as error:
        verdict = exception_verdict(error, negotiated)
        result_payload = {
            "verdict": verdict,
            "failures": [f"{type(error).__name__}: {error}"],
        }
    finally:
        await endpoint.close()
        write_json(destination / "result.json", result_payload)
    return verdict


async def run_abrupt_peer_death(
    evidence_root: Path,
    executable: Path,
    pion_endpoint: Path,
    baresip: Path,
    libre: Path,
    library_paths: tuple[Path, ...],
    command: str,
) -> Verdict:
    scenario = ProductScenario(
        "baresip-pion-abrupt-peer-death", "pion", False
    )
    destination = evidence_root / scenario.name
    prepare_evidence_dir(destination)
    initialize_scenario_evidence(destination, scenario, command, baresip, libre)
    endpoint = BaresipEndpoint(
        executable, baresip, library_paths, destination / "baresip.log"
    )
    failures: list[str] = []
    teardown_budget = 45.0
    rss_growth_budget = 8 * 1024 * 1024
    fd_growth_budget = 1
    thread_growth_budget = 1
    result: dict[str, Any] = {}
    returncode: int | None = None
    pion_process: asyncio.subprocess.Process | None = None
    pion_stdout = b""
    pion_stderr = b""
    session_id: str | None = None
    autonomous_close_observed = False
    autonomous_close_seconds: float | None = None
    cleanup_session_existed: bool | None = None
    verdict = Verdict.INFRA_ERROR
    result_payload: dict[str, Any] = {
        "verdict": verdict,
        "failures": ["scenario did not complete"],
    }

    try:
        await endpoint.start()
        baseline = endpoint.resource_snapshot()
        pion_process = await asyncio.create_subprocess_exec(
            str(pion_endpoint),
            start_new_session=True,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        request = {
            "baseUrl": "http://127.0.0.1:9000",
            "label": "abrupt-peer-death",
            "messages": [{"type": "binary", "payloadHex": "00"}],
            "abortAfterOpen": True,
            "hostIp": primary_host_ip(),
        }
        stdout, stderr = await asyncio.wait_for(
            pion_process.communicate(json.dumps(request).encode()), 75.0
        )
        pion_stdout = stdout
        (destination / "pion.stdout").write_bytes(pion_stdout)
        returncode = pion_process.returncode
        pion_stderr += stderr
        result = json.loads(stdout)
        if result.get("verdict") != Verdict.PASS:
            failures.extend(result.get("failures") or [])
            failures.append(
                f"Pion endpoint verdict was {str(result.get('verdict'))!r}"
            )
        if returncode != -signal.SIGKILL:
            failures.append("Pion endpoint did not terminate by SIGKILL")
        if result.get("connectionState") != "connected":
            failures.append("Pion was not connected before abrupt death")
        if result.get("iceState") not in {"connected", "completed"}:
            failures.append("Pion ICE was not connected before abrupt death")
        if result.get("channelState") != "open":
            failures.append("Pion channel was not open before abrupt death")
        actual = [
            (item["type"], bytes.fromhex(item["payloadHex"]))
            for item in (result.get("messages") or [])
        ]
        if actual != [("binary", b"\x00")]:
            failures.append("pre-death data-channel echo did not complete")
        session_id = result.get("sessionId")
        if not session_id:
            failures.append("Pion did not report the active session ID")
        elif (
            returncode == -signal.SIGKILL
            and result.get("verdict") == Verdict.PASS
        ):
            try:
                autonomous_close_seconds = await endpoint.wait_session_missing(
                    session_id, teardown_budget
                )
                autonomous_close_observed = True
            except TimeoutError:
                failures.append(
                    "baresip did not autonomously close the session "
                    "after abrupt peer death"
                )

        final = endpoint.resource_snapshot()
        if final["rssBytes"] - baseline["rssBytes"] > rss_growth_budget:
            failures.append("abrupt-death RSS growth exceeded 8 MiB")
        if (
            final["fileDescriptors"] - baseline["fileDescriptors"]
            > fd_growth_budget
        ):
            failures.append(
                "abrupt-death file-descriptor growth exceeded 1"
            )
        if final["threads"] - baseline["threads"] > thread_growth_budget:
            failures.append("abrupt-death thread growth exceeded 1")

        if session_id:
            cleanup_session_existed = await endpoint.delete_session_id(
                session_id, missing_ok=True
            )
            if autonomous_close_observed and cleanup_session_existed:
                failures.append(
                    "baresip reported autonomous close but retained the session"
                )
            session_id = None

        await endpoint.close()
        log = (destination / "baresip.log").read_text(errors="replace")
        if "connectivity check is complete" not in log:
            failures.append("baresip log lacks completed ICE evidence")
        if not verified_dtls_count(log):
            failures.append("baresip log lacks verified DTLS evidence")

        (destination / "command.txt").write_text(command + "\n")
        (destination / "offer.sdp").write_text(result.get("offer", ""))
        (destination / "answer.sdp").write_text(result.get("answer", ""))
        write_json(destination / "scenario.json", scenario.__dict__)
        version_data = versions(baresip, libre)
        version_data["pion"] = result.get("pionVersion", "unknown")
        write_json(destination / "versions.json", version_data)
        write_json(
            destination / "process.json",
            {
                "expectedSignal": signal.SIGKILL,
                "returncode": returncode,
                "sessionId": result.get("sessionId"),
                "preDeathEcho": actual == [("binary", b"\x00")],
                "autonomousCloseObserved": autonomous_close_observed,
                "autonomousCloseSeconds": autonomous_close_seconds,
                "cleanupSessionExisted": cleanup_session_existed,
            },
        )
        write_json(
            destination / "resources.json",
            {"baseline": baseline, "final": final},
        )
        verdict = Verdict.FAIL if failures else Verdict.PASS
        result_payload = {"verdict": verdict, "failures": failures}
    except Exception as error:
        verdict = Verdict.INFRA_ERROR
        result_payload = {
            "verdict": verdict,
            "failures": [f"{type(error).__name__}: {error}"],
        }
    finally:
        if session_id:
            try:
                await endpoint.delete_session_id(session_id, missing_ok=True)
            except Exception:
                pass
        await endpoint.close()
        if pion_process is not None:
            _, remaining_stderr = await terminate_and_reap(pion_process)
            pion_stderr += remaining_stderr
        (destination / "pion.stdout").write_bytes(pion_stdout)
        (destination / "pion.log").write_bytes(pion_stderr)
        write_json(destination / "result.json", result_payload)
    return verdict


def calibrate_product_oracle() -> dict[str, str]:
    scenario = PRODUCT_SCENARIOS[0]
    values = list(payloads()[:3])
    sent = records(scenario, "calibration", values)
    results = calibrate(sent)
    calibration = {name: result.verdict for name, result in results.items()}
    calibration["malformed-known-good"] = (
        Verdict.FAIL
        if rejected_message_failures([], "invalid UTF-8 text")
        else Verdict.PASS
    )
    injected = [
        {
            "name": "message",
            "body": {
                "label": "calibration",
                "type": "text",
                "payloadHex": "ff",
            },
        }
    ]
    calibration["malformed-delivery"] = (
        Verdict.FAIL
        if rejected_message_failures(injected, "invalid UTF-8 text")
        else Verdict.PASS
    )
    return calibration

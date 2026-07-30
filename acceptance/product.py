from __future__ import annotations

import asyncio
import json
import signal
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .aiortc_endpoint import AiortcEndpoint
from .baresip_endpoint import BaresipEndpoint
from .chromium import ChromiumEndpoint
from .evidence import versions, write_json
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


def expected_media_kinds(scenario: ProductScenario) -> set[str]:
    if not scenario.media:
        return set()
    return {"audio"} if scenario.audio_only else {"audio", "video"}


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
) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]], list[str]]:
    failures: list[str] = []
    events: list[dict[str, Any]] = []
    control = peer.channels[channel]
    if control.id is None:
        return events, [], ["control channel has no stream ID"]

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
        await asyncio.sleep(0.25)
        if peer.pc.connectionState != "connected":
            failures.append(f"{label} damaged the peer connection")
        malformed_channel.close()
        events.extend(await peer.drain_events())

    await peer.send_raw(control.id, 51, b"\xc0\x80")
    await asyncio.sleep(0.5)
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
    if oversized.readyState != "closed":
        oversized.close()

    expected = [("binary", b"valid-after-invalid-input")]
    await peer.send(channel, *expected[0])
    more_events, actual = await wait_for_messages(peer.drain_events, 1)
    events.extend(more_events)

    if peer.pc.connectionState != "connected":
        failures.append("malformed input damaged the peer connection")
    return events, actual, failures


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
    destination.mkdir(parents=True, exist_ok=True)
    endpoint = BaresipEndpoint(
        executable, baresip, library_paths, destination / "baresip.log"
    )
    failures: list[str] = []
    events: list[dict[str, Any]] = []
    stats: dict[str, Any] = {}
    offer: dict[str, str] | None = None
    answer: dict[str, str] | None = None
    expected_values = (
        [("binary", b"valid-after-invalid-input")]
        if scenario.malformed
        else list(payloads())
    )
    expected_by_channel: dict[str, list[tuple[str, bytes]]] = {}
    actual_by_channel: dict[str, list[tuple[str, bytes]]] = {}
    channel = (
        "baresip-acceptance"
        if scenario.baresip_offerer
        else f"{scenario.peer}-acceptance"
    )
    peer: AiortcEndpoint | ChromiumEndpoint

    if scenario.peer == "aiortc":
        peer = AiortcEndpoint()
    else:
        peer = ChromiumEndpoint(destination / "chrome-profile")

    try:
        await endpoint.start()
        if isinstance(peer, AiortcEndpoint):
            if scenario.baresip_offerer:
                offer = await endpoint.offer(
                    media=scenario.media,
                    audio_only=scenario.audio_only,
                )
                answer = await peer.answer(
                    offer,
                    media=scenario.media,
                    audio_only=scenario.audio_only,
                )
                await endpoint.set_answer(answer)
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
                await peer.pc.setLocalDescription(await peer.pc.createOffer())
                await peer._wait_ice_complete()
                assert peer.pc.localDescription is not None
                offer = {
                    "type": peer.pc.localDescription.type,
                    "sdp": peer.pc.localDescription.sdp,
                }
                answer = await endpoint.answer(
                    offer,
                    media=scenario.media,
                    audio_only=scenario.audio_only,
                )
                await peer.set_remote_description(answer)
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
                events, actual_values, malformed_failures = (
                    await exercise_malformed_inputs(peer, channel)
                )
                failures.extend(malformed_failures)
                expected_by_channel[channel] = expected_values
                actual_by_channel[channel] = actual_values
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
            stats = await peer.stats()
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
            await peer.start(media=True)
            await peer.create_channel(channel)
            offer = await peer.create_offer()
            answer = await endpoint.answer(offer, media=True)
            await peer.set_remote_description(answer)
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
                failures.append("Chromium peer connection is not connected")
            received_kinds = {
                row.get("kind")
                for row in stats.get("rows", [])
                if row.get("type") == "inbound-rtp"
                and row.get("packetsReceived", 0) > 0
            }
            if received_kinds != {"audio", "video"}:
                failures.append(
                    f"Chromium lacks received audio/video: {received_kinds}"
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
        if "verified sha-256 fingerprint OK" not in log:
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
        write_json(destination / "versions.json", versions(baresip, libre))
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
        write_json(
            destination / "result.json",
            {"verdict": verdict, "failures": failures},
        )
        return verdict
    except Exception as error:
        write_json(
            destination / "result.json",
            {
                "verdict": Verdict.INFRA_ERROR,
                "failures": [f"{type(error).__name__}: {error}"],
            },
        )
        return Verdict.INFRA_ERROR
    finally:
        await peer.close()
        await endpoint.close()


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
    destination.mkdir(parents=True, exist_ok=True)
    endpoint = BaresipEndpoint(
        executable, baresip, library_paths, destination / "baresip.log"
    )
    peers = [AiortcEndpoint() for _ in range(count)]
    session_ids: list[str] = []
    failures: list[str] = []
    sent: list[MessageRecord] = []
    received: list[MessageRecord] = []
    all_events: list[dict[str, Any]] = []
    all_stats: list[dict[str, Any]] = []
    values = list(payloads()[:4])

    try:
        await endpoint.start()
        offers: list[dict[str, str]] = []
        for index, peer in enumerate(peers):
            label = f"parallel-{index}"
            channel = peer.pc.createDataChannel(label)
            peer._register(channel)
            await peer.pc.setLocalDescription(await peer.pc.createOffer())
            offers.append({})

        await asyncio.gather(*(peer._wait_ice_complete() for peer in peers))
        for index, peer in enumerate(peers):
            assert peer.pc.localDescription is not None
            offers[index] = {
                "type": peer.pc.localDescription.type,
                "sdp": peer.pc.localDescription.sdp,
            }

        sessions = await asyncio.gather(
            *(
                endpoint.answer_session(offer, media=False)
                for offer in offers
            )
        )
        session_ids.extend(session_id for session_id, _ in sessions)
        await asyncio.gather(
            *(
                peer.set_remote_description(answer)
                for peer, (_, answer) in zip(peers, sessions, strict=True)
            )
        )
        await asyncio.gather(
            *(
                peer.wait_channel_open(f"parallel-{index}", 30.0)
                for index, peer in enumerate(peers)
            )
        )

        for index, peer in enumerate(peers):
            label = f"parallel-{index}"
            association = f"baresip-{index}"
            for message_type, payload in values:
                await peer.send(label, message_type, payload)
            events, actual = await wait_for_messages(
                peer.drain_events, len(values), label, 30.0
            )
            all_events.extend(
                {"peer": index, **event} for event in events
            )
            sent.extend(records(scenario, label, values, association))
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
        if log.count("verified sha-256 fingerprint OK") < count:
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
        write_json(
            destination / "result.json",
            {"verdict": verdict, "failures": failures},
        )
        return verdict
    except Exception as error:
        write_json(
            destination / "result.json",
            {
                "verdict": Verdict.INFRA_ERROR,
                "failures": [f"{type(error).__name__}: {error}"],
            },
        )
        return Verdict.INFRA_ERROR
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
    destination.mkdir(parents=True, exist_ok=True)
    endpoint: BaresipEndpoint | None = None
    turn_process: asyncio.subprocess.Process | None = None
    failures: list[str] = []
    values = list(payloads())
    label = "pion-acceptance"
    turn_url = ""
    turn_username = "baresip"
    turn_password = "acceptance"

    try:
        if forced_relay:
            if turn_server is None:
                raise RuntimeError("forced relay requires a TURN server")
            route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                route.connect(("192.0.2.1", 9))
                relay_ip = route.getsockname()[0]
            finally:
                route.close()
            turn_arguments = [
                str(turn_server),
                "-public-ip",
                relay_ip,
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

        endpoint = BaresipEndpoint(
            executable,
            baresip,
            library_paths,
            destination / "baresip.log",
            ice_server=turn_url or None,
            ice_username=turn_username if forced_relay else None,
            ice_password=turn_password if forced_relay else None,
        )
        await endpoint.start()
        process = await asyncio.create_subprocess_exec(
            str(pion_endpoint),
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
        }
        stdout, stderr = await asyncio.wait_for(
            process.communicate(json.dumps(request).encode()), 75.0
        )
        (destination / "pion.log").write_bytes(stderr)
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"Pion endpoint returned invalid JSON: {error}"
            ) from error
        if process.returncode or result.get("verdict") != Verdict.PASS:
            failures.extend(result.get("failures") or [])

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
            if result.get("localCandidateType") != "relay":
                failures.append("Pion selected local candidate is not relay")
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
            for metric in ("dropped", "delayed", "reordered", "duplicated"):
                if metrics.get(metric, 0) <= 0:
                    failures.append(
                        f"TURN impairment did not exercise {metric}"
                    )
            if metrics.get("bandwidthBitsPerSecond") != 2_000_000:
                failures.append("TURN bandwidth limit was not active")
            if metrics.get("mtu") != 1400:
                failures.append("TURN MTU limit was not active")

        await endpoint.close()
        log = (destination / "baresip.log").read_text(errors="replace")
        if "connectivity check is complete" not in log:
            failures.append("baresip log lacks completed ICE evidence")
        if "verified sha-256 fingerprint OK" not in log:
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
        write_json(
            destination / "result.json",
            {"verdict": verdict, "failures": failures},
        )
        return verdict
    except Exception as error:
        write_json(
            destination / "result.json",
            {
                "verdict": Verdict.INFRA_ERROR,
                "failures": [f"{type(error).__name__}: {error}"],
            },
        )
        return Verdict.INFRA_ERROR
    finally:
        if endpoint is not None:
            await endpoint.close()
        if turn_process is not None:
            if turn_process.returncode is None:
                turn_process.terminate()
            _, turn_stderr = await turn_process.communicate()
            (destination / "turn-server.log").write_bytes(turn_stderr)


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
    destination.mkdir(parents=True, exist_ok=True)
    endpoint = BaresipEndpoint(
        executable, baresip, library_paths, destination / "baresip.log"
    )
    failures: list[str] = []
    sent: list[MessageRecord] = []
    received: list[MessageRecord] = []
    samples: list[dict[str, Any]] = []
    teardown_budget = 5.0
    rss_growth_budget = 32 * 1024 * 1024
    fd_growth_budget = 4
    thread_growth_budget = 2

    try:
        if cycles <= 0:
            raise ValueError("lifecycle cycles must be positive")
        await endpoint.start()
        baseline = endpoint.resource_snapshot()
        samples.append({"cycle": -1, **baseline})
        for cycle in range(cycles):
            peer = AiortcEndpoint()
            session_id: str | None = None
            label = f"lifecycle-{cycle}"
            payload = cycle.to_bytes(4, "big")
            values = [("binary", payload)]
            started = time.monotonic()
            try:
                channel = peer.pc.createDataChannel(label)
                peer._register(channel)
                await peer.pc.setLocalDescription(await peer.pc.createOffer())
                await peer._wait_ice_complete()
                assert peer.pc.localDescription is not None
                offer = {
                    "type": peer.pc.localDescription.type,
                    "sdp": peer.pc.localDescription.sdp,
                }
                session_id, answer = await endpoint.answer_session(
                    offer, media=False
                )
                await peer.set_remote_description(answer)
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
                    channel.close()

                    async def wait_closed() -> None:
                        while channel.readyState != "closed":
                            await asyncio.sleep(0.01)

                    await asyncio.wait_for(wait_closed(), teardown_budget)
                else:
                    await peer.close()
                await endpoint.delete_session_id(
                    session_id, missing_ok=cycle % 2 != 0
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
                    **snapshot,
                }
            )

        failures.extend(compare_ordered(sent, received).failures)
        final = samples[-1]
        if final["rssBytes"] - baseline["rssBytes"] > rss_growth_budget:
            failures.append("Baresip RSS growth exceeded 32 MiB")
        if (
            final["fileDescriptors"] - baseline["fileDescriptors"]
            > fd_growth_budget
        ):
            failures.append("Baresip file-descriptor growth exceeded 4")
        if final["threads"] - baseline["threads"] > thread_growth_budget:
            failures.append("Baresip thread growth exceeded 2")

        await endpoint.close()
        log = (destination / "baresip.log").read_text(errors="replace")
        if log.count("connectivity check is complete") < cycles:
            failures.append("lifecycle log lacks ICE completions")
        if log.count("verified sha-256 fingerprint OK") < cycles:
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
        write_json(destination / "sent-manifest.json", [x.json() for x in sent])
        write_json(
            destination / "received-manifest.json",
            [x.json() for x in received],
        )
        verdict = Verdict.FAIL if failures else Verdict.PASS
        write_json(
            destination / "result.json",
            {"verdict": verdict, "failures": failures},
        )
        return verdict
    except Exception as error:
        write_json(
            destination / "result.json",
            {
                "verdict": Verdict.INFRA_ERROR,
                "failures": [f"{type(error).__name__}: {error}"],
            },
        )
        return Verdict.INFRA_ERROR
    finally:
        await endpoint.close()


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

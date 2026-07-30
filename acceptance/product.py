from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aiortc import RTCSessionDescription

from .aiortc_endpoint import AiortcEndpoint
from .baresip_endpoint import BaresipEndpoint
from .chromium import ChromiumEndpoint
from .evidence import versions, write_json
from .model import MessageRecord, Verdict, compare_ordered
from .oracle import calibrate


@dataclass(frozen=True)
class ProductScenario:
    name: str
    peer: str
    media: bool


PRODUCT_SCENARIOS = (
    ProductScenario("baresip-aiortc-data-only", "aiortc", False),
    ProductScenario("baresip-chromium-avdata", "chromium", True),
)


def payloads() -> tuple[tuple[str, bytes], ...]:
    return (
        ("text", b""),
        ("binary", b""),
        ("text", b"baresip-real-peer"),
        ("binary", bytes(range(256))),
        ("text", b"x" * 16384),
        ("binary", bytes(index % 251 for index in range(16384))),
    )


def records(
    scenario: ProductScenario,
    channel: str,
    values: list[tuple[str, bytes]],
) -> list[MessageRecord]:
    return [
        MessageRecord.from_payload(
            run=scenario.name,
            association="baresip",
            channel=channel,
            direction=f"{scenario.peer}-baresip-echo",
            sequence=sequence,
            message_type=message_type,
            payload=payload,
        )
        for sequence, (message_type, payload) in enumerate(values, 1)
    ]


def received_values(events: list[dict[str, Any]]) -> list[tuple[str, bytes]]:
    return [
        (event["body"]["type"], bytes.fromhex(event["body"]["payloadHex"]))
        for event in events
        if event["name"] == "message"
    ]


async def wait_for_messages(
    drain: Any, count: int, timeout: float = 15.0
) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]]]:
    events: list[dict[str, Any]] = []

    async def wait() -> list[tuple[str, bytes]]:
        while True:
            events.extend(await drain())
            values = received_values(events)
            if len(values) >= count:
                return values
            await asyncio.sleep(0.05)

    values = await asyncio.wait_for(wait(), timeout)
    return events, values


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
        if len(mids) < 3 or set(mids) - set(bundle):
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
    expected_values = list(payloads())
    channel = f"{scenario.peer}-acceptance"
    peer: AiortcEndpoint | ChromiumEndpoint

    if scenario.peer == "aiortc":
        peer = AiortcEndpoint()
    else:
        peer = ChromiumEndpoint(destination / "chrome-profile")

    try:
        await endpoint.start()
        if isinstance(peer, AiortcEndpoint):
            data_channel = peer.pc.createDataChannel(
                channel, protocol="baresip-acceptance-v1"
            )
            peer._register(data_channel)
            await peer.pc.setLocalDescription(await peer.pc.createOffer())
            await peer._wait_ice_complete()
            assert peer.pc.localDescription is not None
            offer = {
                "type": peer.pc.localDescription.type,
                "sdp": peer.pc.localDescription.sdp,
            }
            answer = await endpoint.answer(offer, media=False)
            await peer.pc.setRemoteDescription(
                RTCSessionDescription(
                    sdp=answer["sdp"], type=answer["type"]
                )
            )
            await peer.wait_channel_open(channel, 30.0)
            for message_type, payload in expected_values:
                await peer.send(channel, message_type, payload)
            events, actual_values = await wait_for_messages(
                peer.drain_events, len(expected_values)
            )
            stats = await peer.stats()
            if stats.get("dtlsState") != "connected":
                failures.append("aiortc DTLS is not connected")
            if stats.get("sctpState") != "connected":
                failures.append("aiortc SCTP is not connected")
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
                peer.events, len(expected_values)
            )
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

        sent = records(scenario, channel, expected_values)
        received = records(scenario, channel, actual_values)
        failures.extend(compare_ordered(sent, received).failures)
        assert offer is not None and answer is not None
        failures.extend(check_sdp(scenario, offer["sdp"], answer["sdp"]))

        await endpoint.delete_session()
        log = (destination / "baresip.log").read_text(errors="replace")
        if "connectivity check is complete" not in log:
            failures.append("baresip log lacks completed ICE evidence")
        if "verified sha-256 fingerprint OK" not in log:
            failures.append("baresip log lacks verified DTLS evidence")
        if scenario.media:
            for kind in ("audio", "video"):
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
    except (TimeoutError, asyncio.TimeoutError, RuntimeError) as error:
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


def calibrate_product_oracle() -> dict[str, str]:
    scenario = PRODUCT_SCENARIOS[0]
    values = list(payloads()[:3])
    sent = records(scenario, "calibration", values)
    results = calibrate(sent)
    return {name: result.verdict for name, result in results.items()}

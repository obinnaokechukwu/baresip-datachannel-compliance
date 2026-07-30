from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .aiortc_endpoint import AiortcEndpoint
from .chromium import ChromiumEndpoint
from .evidence import versions, write_json
from .model import MessageRecord, Verdict, compare_ordered
from .oracle import check_media_bundle, check_required_evidence, check_transport
from .protocol import Envelope


@dataclass(frozen=True)
class FoundationScenario:
    name: str
    media: bool


SCENARIOS = (
    FoundationScenario("data-only", False),
    FoundationScenario("audio-video-data-bundle", True),
)


def deterministic_payload(
    scenario: str, direction: str, sequence: int, message_type: str
) -> bytes:
    prefix = f"{scenario}:{direction}:{sequence}:{message_type}:".encode()
    if message_type == "text":
        return prefix + (
            f"{sequence:02d}" * 32
        ).encode()
    return prefix + bytes(
        ((sequence * 31 + index) % 251) for index in range(64)
    )


def sdp_mids(sdp: str) -> tuple[list[str], list[str]]:
    bundle: list[str] = []
    media: list[str] = []
    for line in sdp.replace("\r", "").split("\n"):
        if line.startswith("a=group:BUNDLE "):
            bundle = line.removeprefix("a=group:BUNDLE ").split()
        elif line.startswith("a=mid:"):
            media.append(line.removeprefix("a=mid:"))
    return bundle, media


async def run_foundation_scenario(
    scenario: FoundationScenario,
    evidence_root: Path,
    baresip: Path,
    libre: Path,
    command: str,
) -> Verdict:
    destination = evidence_root / scenario.name
    destination.mkdir(parents=True, exist_ok=True)
    chrome = ChromiumEndpoint(destination / "chrome-profile")
    aiortc = AiortcEndpoint()
    sent: list[MessageRecord] = []
    received: list[MessageRecord] = []
    events: list[dict[str, Any]] = []
    failures: list[str] = []
    event_seq = 1

    def record_command(name: str, body: dict[str, Any]) -> None:
        nonlocal event_seq
        envelope = Envelope(
            kind="command",
            seq=event_seq,
            name=name,
            body=body,
        )
        events.append(envelope.json())
        event_seq += 1

    def record_event(endpoint: str, event: dict[str, Any]) -> None:
        nonlocal event_seq
        envelope = Envelope(
            kind="event",
            seq=event_seq,
            name=event["name"],
            body={"endpoint": endpoint, **event.get("body", {})},
        )
        events.append(envelope.json())
        event_seq += 1

    try:
        record_command("start", {"endpoint": "chromium", "media": scenario.media})
        await chrome.start(media=scenario.media)
        record_command(
            "create_channel",
            {"endpoint": "chromium", "label": "foundation", "ordered": True},
        )
        await chrome.create_channel("foundation")
        record_command("create_offer", {"endpoint": "chromium"})
        offer = await chrome.create_offer()
        record_command(
            "set_remote_description",
            {"endpoint": "aiortc", "type": offer["type"]},
        )
        answer = await aiortc.answer(offer)
        record_command(
            "set_remote_description",
            {"endpoint": "chromium", "type": answer["type"]},
        )
        await chrome.set_remote_description(answer)
        await asyncio.gather(
            chrome.wait_channel_open("foundation"),
            aiortc.wait_channel_open("foundation"),
        )

        for sequence, message_type in enumerate(
            ("text", "binary", "text", "binary"), start=1
        ):
            for direction in ("chromium-to-aiortc", "aiortc-to-chromium"):
                payload = deterministic_payload(
                    scenario.name, direction, sequence, message_type
                )
                record = MessageRecord.from_payload(
                    run=scenario.name,
                    association="foundation",
                    channel="foundation",
                    direction=direction,
                    sequence=sequence,
                    message_type=message_type,
                    payload=payload,
                )
                sent.append(record)
                if direction == "chromium-to-aiortc":
                    record_command(
                        "send",
                        {
                            "endpoint": "chromium",
                            "label": "foundation",
                            "type": message_type,
                            "sequence": sequence,
                        },
                    )
                    await chrome.send("foundation", message_type, payload)
                else:
                    record_command(
                        "send",
                        {
                            "endpoint": "aiortc",
                            "label": "foundation",
                            "type": message_type,
                            "sequence": sequence,
                        },
                    )
                    await aiortc.send("foundation", message_type, payload)

        await asyncio.sleep(0.5)
        chrome_events = await chrome.events()
        aiortc_events = await aiortc.drain_events()
        for endpoint, endpoint_events in (
            ("chromium", chrome_events),
            ("aiortc", aiortc_events),
        ):
            for event in endpoint_events:
                record_event(endpoint, event)
                if event["name"] != "message":
                    continue
                body = event["body"]
                direction = (
                    "aiortc-to-chromium"
                    if endpoint == "chromium"
                    else "chromium-to-aiortc"
                )
                sequence = (
                    sum(
                        1
                        for item in received
                        if item.direction == direction
                    )
                    + 1
                )
                payload = bytes.fromhex(body["payloadHex"])
                received.append(
                    MessageRecord.from_payload(
                        run=scenario.name,
                        association="foundation",
                        channel=body["label"],
                        direction=direction,
                        sequence=sequence,
                        message_type=body["type"],
                        payload=payload,
                    )
                )

        sent.sort(key=lambda item: (item.sequence, item.direction))
        received.sort(key=lambda item: (item.sequence, item.direction))
        oracle = compare_ordered(sent, received)
        failures.extend(oracle.failures)

        bundle, mids = sdp_mids(offer["sdp"])
        if scenario.media:
            if len(mids) < 3 or set(mids) - set(bundle):
                failures.append(
                    f"offer does not bundle all audio/video/data mids: "
                    f"bundle={bundle} mids={mids}"
                )
            for token in ("m=audio", "m=video", "m=application"):
                if token not in offer["sdp"]:
                    failures.append(f"offer lacks {token}")
        else:
            if "m=application" not in offer["sdp"]:
                failures.append("data-only offer lacks m=application")
            if "m=audio" in offer["sdp"] or "m=video" in offer["sdp"]:
                failures.append("data-only offer unexpectedly contains RTP media")

        record_command("stats", {"endpoint": "chromium"})
        browser_stats = await chrome.stats()
        record_command("stats", {"endpoint": "aiortc"})
        aiortc_stats = await aiortc.stats()
        failures.extend(check_transport(browser_stats, aiortc_stats).failures)
        if scenario.media:
            failures.extend(
                check_media_bundle(offer["sdp"], aiortc_stats).failures
            )
        write_json(destination / "scenario.json", scenario.__dict__)
        (destination / "command.txt").write_text(command + "\n")
        (destination / "offer.sdp").write_text(offer["sdp"])
        (destination / "answer.sdp").write_text(answer["sdp"])
        write_json(destination / "versions.json", versions(baresip, libre))
        write_json(
            destination / "sent-manifest.json",
            [record.json() for record in sent],
        )
        write_json(
            destination / "received-manifest.json",
            [record.json() for record in received],
        )
        write_json(destination / "browser-stats.json", browser_stats)
        write_json(destination / "aiortc-stats.json", aiortc_stats)
        (destination / "events.ndjson").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        )
        failures.extend(check_required_evidence(destination).failures)
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
        await aiortc.close()
        await chrome.close()

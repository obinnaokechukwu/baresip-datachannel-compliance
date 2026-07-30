from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from .model import MessageRecord, OracleResult, Verdict, compare_ordered


INJECTIONS = ("corrupt", "omit", "duplicate", "reorder")


def inject(
    records: list[MessageRecord], violation: str
) -> list[MessageRecord]:
    if violation not in INJECTIONS:
        raise ValueError(f"unknown violation {violation!r}")
    if len(records) < 2:
        raise ValueError("at least two records are required for calibration")

    result = list(records)
    if violation == "corrupt":
        result[0] = replace(result[0], sha256="0" * 64)
    elif violation == "omit":
        result.pop()
    elif violation == "duplicate":
        result.append(result[-1])
    elif violation == "reorder":
        result[0], result[1] = result[1], result[0]
    return result


def calibrate(records: list[MessageRecord]) -> dict[str, OracleResult]:
    results = {"known-good": compare_ordered(records, list(records))}
    for violation in INJECTIONS:
        result = compare_ordered(records, inject(records, violation))
        if result.verdict is Verdict.PASS:
            raise AssertionError(f"{violation} injection escaped the oracle")
        results[violation] = result
    return results


def check_transport(
    browser_stats: dict[str, Any], aiortc_stats: dict[str, Any]
) -> OracleResult:
    failures: list[str] = []
    if browser_stats.get("connectionState") != "connected":
        failures.append("Chromium connection state is not connected")
    if aiortc_stats.get("dtlsState") != "connected":
        failures.append("aiortc DTLS state is not connected")
    if aiortc_stats.get("sctpState") != "connected":
        failures.append("aiortc SCTP state is not connected")
    selected = [
        row
        for row in browser_stats.get("rows", [])
        if row.get("type") == "candidate-pair"
        and row.get("nominated")
        and row.get("state") == "succeeded"
    ]
    if len(selected) != 1:
        failures.append(
            f"expected one nominated succeeded ICE pair, found {len(selected)}"
        )
    channels = [
        row
        for row in browser_stats.get("rows", [])
        if row.get("type") == "data-channel"
        and row.get("state") == "open"
    ]
    if len(channels) != 1:
        failures.append(
            f"expected one open browser data channel, found {len(channels)}"
        )
    return OracleResult(
        Verdict.FAIL if failures else Verdict.PASS, tuple(failures)
    )


def check_media_bundle(
    offer_sdp: str, aiortc_stats: dict[str, Any]
) -> OracleResult:
    failures: list[str] = []
    bundle: list[str] = []
    mids: list[str] = []
    for line in offer_sdp.replace("\r", "").split("\n"):
        if line.startswith("a=group:BUNDLE "):
            bundle = line.removeprefix("a=group:BUNDLE ").split()
        elif line.startswith("a=mid:"):
            mids.append(line.removeprefix("a=mid:"))
    if len(mids) < 3 or set(mids) - set(bundle):
        failures.append(
            f"audio/video/data mids are not in one BUNDLE group: "
            f"bundle={bundle} mids={mids}"
        )
    inbound = [
        row
        for row in aiortc_stats.get("rows", [])
        if row.get("type") == "inbound-rtp"
        and row.get("kind") in {"audio", "video"}
        and row.get("packetsReceived", 0) > 0
    ]
    kinds = {row["kind"] for row in inbound}
    if kinds != {"audio", "video"}:
        failures.append(
            f"missing received bundled media packets: kinds={sorted(kinds)}"
        )
    if len({row.get("transportId") for row in inbound}) != 1:
        failures.append("audio and video did not use one transport")
    return OracleResult(
        Verdict.FAIL if failures else Verdict.PASS, tuple(failures)
    )


def check_required_evidence(directory: Path) -> OracleResult:
    required = {
        "scenario.json",
        "command.txt",
        "versions.json",
        "events.ndjson",
        "offer.sdp",
        "answer.sdp",
        "sent-manifest.json",
        "received-manifest.json",
        "browser-stats.json",
        "aiortc-stats.json",
    }
    missing = sorted(name for name in required if not (directory / name).is_file())
    failures = tuple(f"missing required evidence: {name}" for name in missing)
    return OracleResult(
        Verdict.FAIL if failures else Verdict.PASS, failures
    )

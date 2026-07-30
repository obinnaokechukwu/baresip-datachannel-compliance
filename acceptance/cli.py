from __future__ import annotations

import argparse
import asyncio
import json
import copy
import sys
from pathlib import Path

from .baresip_probe import baseline
from .evidence import write_json
from .model import MessageRecord, Verdict
from .oracle import (
    calibrate,
    check_media_bundle,
    check_required_evidence,
    check_transport,
)
from .scenario import SCENARIOS, deterministic_payload, run_foundation_scenario
from .supervision import classify_process


async def run(args: argparse.Namespace) -> int:
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    command = " ".join(sys.orig_argv)

    scenario_verdicts = {}
    for scenario in SCENARIOS:
        scenario_verdicts[scenario.name] = await run_foundation_scenario(
            scenario,
            evidence,
            args.baresip.resolve(),
            args.libre.resolve(),
            command,
        )

    records = [
        MessageRecord.from_payload(
            run="oracle-calibration",
            association="foundation",
            channel="foundation",
            direction="chromium-to-aiortc",
            sequence=sequence,
            message_type="binary",
            payload=deterministic_payload(
                "oracle-calibration",
                "chromium-to-aiortc",
                sequence,
                "binary",
            ),
        )
        for sequence in range(1, 4)
    ]
    calibration = calibrate(records)
    calibration_json = {
        name: {
            "verdict": result.verdict,
            "failures": result.failures,
        }
        for name, result in calibration.items()
    }
    write_json(evidence / "oracle-calibration.json", calibration_json)

    bundle_evidence = evidence / "audio-video-data-bundle"
    offer_sdp = (bundle_evidence / "offer.sdp").read_text()
    browser_stats = json.loads(
        (bundle_evidence / "browser-stats.json").read_text()
    )
    aiortc_stats = json.loads(
        (bundle_evidence / "aiortc-stats.json").read_text()
    )
    broken_transport = copy.deepcopy(aiortc_stats)
    broken_transport["sctpState"] = "closed"
    broken_media = copy.deepcopy(aiortc_stats)
    for row in broken_media["rows"]:
        if row.get("type") == "inbound-rtp":
            row["packetsReceived"] = 0
    nontranscript_calibration = {
        "transport-known-good": check_transport(browser_stats, aiortc_stats),
        "transport-injected-closed": check_transport(
            browser_stats, broken_transport
        ),
        "bundle-known-good": check_media_bundle(offer_sdp, aiortc_stats),
        "bundle-injected-missing-group": check_media_bundle(
            offer_sdp.replace("a=group:BUNDLE", "a=x-group:BUNDLE"),
            aiortc_stats,
        ),
        "media-injected-no-packets": check_media_bundle(
            offer_sdp, broken_media
        ),
        "evidence-known-good": check_required_evidence(bundle_evidence),
        "evidence-injected-missing": check_required_evidence(
            evidence / "deliberately-missing"
        ),
    }
    write_json(
        evidence / "nontranscript-oracle-calibration.json",
        {
            name: {
                "verdict": result.verdict,
                "failures": result.failures,
            }
            for name, result in nontranscript_calibration.items()
        },
    )

    supervision = {
        mode: await classify_process(mode) for mode in ("success", "crash", "hang")
    }
    write_json(evidence / "supervision-calibration.json", supervision)

    baresip_result = baseline(args.baresip.resolve())
    write_json(evidence / "baresip-baseline.json", baresip_result)

    passed = (
        all(verdict is Verdict.PASS for verdict in scenario_verdicts.values())
        and calibration["known-good"].verdict is Verdict.PASS
        and all(
            calibration[name].verdict is Verdict.FAIL
            for name in ("corrupt", "omit", "duplicate", "reorder")
        )
        and supervision["success"] is Verdict.PASS
        and supervision["crash"] is Verdict.INFRA_ERROR
        and supervision["hang"] is Verdict.INFRA_ERROR
        and baresip_result["verdict"] is Verdict.UNSUPPORTED
        and all(
            result.verdict
            is (Verdict.PASS if name.endswith("known-good") else Verdict.FAIL)
            for name, result in nontranscript_calibration.items()
        )
    )
    summary = {
        "verdict": Verdict.PASS if passed else Verdict.FAIL,
        "scenarios": scenario_verdicts,
        "oracle_calibration": {
            name: result.verdict for name, result in calibration.items()
        },
        "supervision_calibration": supervision,
        "nontranscript_oracle_calibration": {
            name: result.verdict
            for name, result in nontranscript_calibration.items()
        },
        "baresip_baseline": baresip_result["verdict"],
    }
    write_json(evidence / "foundation-summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--baresip", type=Path, required=True)
    result.add_argument("--libre", type=Path, required=True)
    result.add_argument("--evidence", type=Path, required=True)
    return result


def main() -> None:
    raise SystemExit(asyncio.run(run(parser().parse_args())))


if __name__ == "__main__":
    main()

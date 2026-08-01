from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .evidence import (
    prepare_evidence_dir,
    load_build_manifest,
    reproduction_command,
    verify_build_manifest,
    write_json,
)
from .model import Verdict
from .product import (
    PRODUCT_SCENARIOS,
    run_abrupt_peer_death,
    calibrate_product_oracle,
    run_media_regression,
    run_parallel_sessions,
    run_pion_scenario,
    run_lifecycle_campaign,
    run_product_scenario,
)


async def run(args: argparse.Namespace) -> int:
    evidence = args.evidence.resolve()
    prepare_evidence_dir(evidence)
    argv = list(sys.orig_argv)
    command = reproduction_command(argv)
    library_paths = tuple(path.resolve() for path in args.library_path)
    harness = Path(__file__).parents[1]
    extras = (args.pion_endpoint.resolve(), args.turn_server.resolve())
    module_paths = tuple(path.resolve() for path in args.module_path)
    write_json(evidence / "argv.json", argv)
    (evidence / "command.txt").write_text(command + "\n")
    try:
        manifest = load_build_manifest(args.build_manifest)
        verified = verify_build_manifest(
            args.build_manifest,
            args.executable,
            args.baresip,
            args.libre,
            harness,
            library_paths,
            extras,
            module_paths,
        )
    except Exception as error:
        write_json(
            evidence / "product-summary.json",
            {
                "verdict": Verdict.INFRA_ERROR,
                "scenarios": {},
                "failures": [f"build binding verification failed: {error}"],
            },
        )
        return 1
    write_json(
        evidence / "provenance.json",
        {"manifest": manifest, "verifiedAtStart": verified},
    )

    provenance_checks: list[dict[str, str]] = []
    provenance_failures: list[str] = []

    def verify_artifacts(stage: str) -> None:
        current = verify_build_manifest(
            args.build_manifest,
            args.executable,
            args.baresip,
            args.libre,
            harness,
            library_paths,
            extras,
            module_paths,
        )
        provenance_checks.append(
            {"stage": stage, "bindingSha256": current["bindingSha256"]}
        )

    async def checked(name: str, operation) -> Verdict:
        try:
            verify_artifacts(f"before:{name}")
        except Exception as error:
            provenance_failures.append(f"before {name}: {error}")
            write_json(evidence / "provenance-checks.json", {
                "checks": provenance_checks,
                "failures": provenance_failures,
            })
            return Verdict.INFRA_ERROR
        verdict = await operation()
        try:
            verify_artifacts(f"after:{name}")
        except Exception as error:
            provenance_failures.append(f"after {name}: {error}")
            verdict = Verdict.INFRA_ERROR
        write_json(evidence / "provenance-checks.json", {
            "checks": provenance_checks,
            "failures": provenance_failures,
        })
        return verdict

    verdicts = {}
    for scenario in PRODUCT_SCENARIOS:
        verdicts[scenario.name] = await checked(
            scenario.name,
            lambda scenario=scenario: run_product_scenario(
                scenario,
                evidence,
                args.executable.resolve(),
                args.baresip.resolve(),
                args.libre.resolve(),
                library_paths,
                command,
            ),
        )
    verdicts["baresip-aiortc-parallel-sessions"] = (
        await checked(
            "baresip-aiortc-parallel-sessions",
            lambda: run_parallel_sessions(
                evidence,
                args.executable.resolve(),
                args.baresip.resolve(),
                args.libre.resolve(),
                library_paths,
                command,
            ),
        )
    )
    verdicts["baresip-chromium-media-regression"] = (
        await checked(
            "baresip-chromium-media-regression",
            lambda: run_media_regression(
                evidence,
                args.executable.resolve(),
                args.baresip.resolve(),
                args.libre.resolve(),
                library_paths,
                command,
            ),
        )
    )
    verdicts["baresip-pion-data-only"] = await checked(
        "baresip-pion-data-only",
        lambda: run_pion_scenario(
            evidence,
            args.executable.resolve(),
            args.pion_endpoint.resolve(),
            args.baresip.resolve(),
            args.libre.resolve(),
            library_paths,
            command,
        ),
    )
    verdicts["baresip-pion-forced-turn"] = await checked(
        "baresip-pion-forced-turn",
        lambda: run_pion_scenario(
            evidence,
            args.executable.resolve(),
            args.pion_endpoint.resolve(),
            args.baresip.resolve(),
            args.libre.resolve(),
            library_paths,
            command,
            turn_server=args.turn_server.resolve(),
            forced_relay=True,
        ),
    )
    verdicts["baresip-pion-turn-impairment"] = await checked(
        "baresip-pion-turn-impairment",
        lambda: run_pion_scenario(
            evidence,
            args.executable.resolve(),
            args.pion_endpoint.resolve(),
            args.baresip.resolve(),
            args.libre.resolve(),
            library_paths,
            command,
            turn_server=args.turn_server.resolve(),
            forced_relay=True,
            impairment=True,
        ),
    )
    verdicts["baresip-pion-abrupt-peer-death"] = (
        await checked(
            "baresip-pion-abrupt-peer-death",
            lambda: run_abrupt_peer_death(
                evidence,
                args.executable.resolve(),
                args.pion_endpoint.resolve(),
                args.baresip.resolve(),
                args.libre.resolve(),
                library_paths,
                command,
            ),
        )
    )
    verdicts["baresip-aiortc-lifecycle-campaign"] = (
        await checked(
            "baresip-aiortc-lifecycle-campaign",
            lambda: run_lifecycle_campaign(
                evidence,
                args.executable.resolve(),
                args.baresip.resolve(),
                args.libre.resolve(),
                library_paths,
                command,
                args.lifecycle_cycles,
            ),
        )
    )
    calibration = calibrate_product_oracle()
    write_json(evidence / "oracle-calibration.json", calibration)
    calibrated = (
        calibration["known-good"] == Verdict.PASS
        and calibration["malformed-known-good"] == Verdict.PASS
        and all(
            calibration[name] == Verdict.FAIL
            for name in (
                "corrupt",
                "omit",
                "duplicate",
                "reorder",
                "malformed-delivery",
            )
        )
    )
    passed = not provenance_failures and calibrated and all(
        verdict is Verdict.PASS for verdict in verdicts.values()
    )
    summary = {
        "verdict": Verdict.PASS if passed else Verdict.FAIL,
        "scenarios": verdicts,
        "oracle_calibration": calibration,
        "provenance_failures": provenance_failures,
    }
    write_json(evidence / "product-summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--executable", type=Path, required=True)
    result.add_argument("--baresip", type=Path, required=True)
    result.add_argument("--libre", type=Path, required=True)
    result.add_argument(
        "--pion-endpoint",
        type=Path,
        default=Path(".work/pion-endpoint"),
    )
    result.add_argument(
        "--turn-server",
        type=Path,
        default=Path(".work/turn-server"),
    )
    result.add_argument("--lifecycle-cycles", type=int, default=20)
    result.add_argument("--build-manifest", type=Path, required=True)
    result.add_argument(
        "--module-path", type=Path, action="append", required=True
    )
    result.add_argument("--library-path", type=Path, action="append", default=[])
    result.add_argument("--evidence", type=Path, required=True)
    return result


def main() -> None:
    raise SystemExit(asyncio.run(run(parser().parse_args())))


if __name__ == "__main__":
    main()

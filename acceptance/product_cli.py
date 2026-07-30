from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .evidence import write_json
from .model import Verdict
from .product import (
    PRODUCT_SCENARIOS,
    calibrate_product_oracle,
    run_product_scenario,
)


async def run(args: argparse.Namespace) -> int:
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    command = " ".join(sys.orig_argv)
    library_paths = tuple(path.resolve() for path in args.library_path)
    verdicts = {}
    for scenario in PRODUCT_SCENARIOS:
        verdicts[scenario.name] = await run_product_scenario(
            scenario,
            evidence,
            args.executable.resolve(),
            args.baresip.resolve(),
            args.libre.resolve(),
            library_paths,
            command,
        )
    calibration = calibrate_product_oracle()
    write_json(evidence / "oracle-calibration.json", calibration)
    calibrated = (
        calibration["known-good"] == Verdict.PASS
        and all(
            calibration[name] == Verdict.FAIL
            for name in ("corrupt", "omit", "duplicate", "reorder")
        )
    )
    passed = calibrated and all(
        verdict is Verdict.PASS for verdict in verdicts.values()
    )
    summary = {
        "verdict": Verdict.PASS if passed else Verdict.FAIL,
        "scenarios": verdicts,
        "oracle_calibration": calibration,
    }
    write_json(evidence / "product-summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--executable", type=Path, required=True)
    result.add_argument("--baresip", type=Path, required=True)
    result.add_argument("--libre", type=Path, required=True)
    result.add_argument("--library-path", type=Path, action="append", default=[])
    result.add_argument("--evidence", type=Path, required=True)
    return result


def main() -> None:
    raise SystemExit(asyncio.run(run(parser().parse_args())))


if __name__ == "__main__":
    main()

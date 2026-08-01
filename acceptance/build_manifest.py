from __future__ import annotations

import argparse
from pathlib import Path

from .evidence import build_manifest, write_json


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--executable", type=Path, required=True)
    result.add_argument("--baresip", type=Path, required=True)
    result.add_argument("--libre", type=Path, required=True)
    result.add_argument("--pion-endpoint", type=Path, required=True)
    result.add_argument("--turn-server", type=Path, required=True)
    result.add_argument("--library-path", type=Path, action="append", default=[])
    result.add_argument(
        "--module-path", type=Path, action="append", required=True
    )
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> None:
    args = parser().parse_args()
    harness = Path(__file__).parents[1]
    manifest = build_manifest(
        args.executable.resolve(),
        args.baresip.resolve(),
        args.libre.resolve(),
        harness,
        tuple(path.resolve() for path in args.library_path),
        (args.pion_endpoint.resolve(), args.turn_server.resolve()),
        tuple(path.resolve() for path in args.module_path),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, manifest)


if __name__ == "__main__":
    main()

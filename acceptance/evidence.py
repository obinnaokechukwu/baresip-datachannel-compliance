from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

import aiortc


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def git_revision(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def chrome_version() -> str:
    executable = (
        os.environ.get("CHROMIUM")
        or next(
            (
                value
                for value in (
                    "/usr/bin/google-chrome",
                    "/usr/bin/chromium",
                )
                if Path(value).exists()
            ),
            "",
        )
    )
    if not executable:
        return "unavailable"
    result = subprocess.run(
        [executable, "--version"],
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() or result.stderr.strip()


def versions(baresip: Path, libre: Path) -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": sys.version,
        "chrome": chrome_version(),
        "aiortc": aiortc.__version__,
        "baresip_revision": git_revision(baresip),
        "libre_revision": git_revision(libre),
        "harness_revision": git_revision(Path(__file__).parents[1]),
    }

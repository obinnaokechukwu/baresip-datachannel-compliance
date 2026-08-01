from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .model import Verdict


REQUIRED_PUBLIC_SYMBOLS = (
    "peerconnection_create_datachannel",
    "peerconnection_set_datachannel_handler",
    "datachannel_send",
)


def baseline(baresip: Path) -> dict[str, Any]:
    header = (baresip / "include" / "baresip.h").read_text()
    missing = [
        symbol
        for symbol in REQUIRED_PUBLIC_SYMBOLS
        if re.search(rf"\b{re.escape(symbol)}\s*\(", header) is None
    ]
    if missing:
        return {
            "capability_status": Verdict.UNSUPPORTED,
            "capability": "webrtc-datachannel",
            "missing_public_api": missing,
            "media_baseline": "covered by upstream peerconnection regression",
        }
    return {
        "capability_status": "AVAILABLE_NOT_TESTED",
        "capability": "webrtc-datachannel",
        "missing_public_api": [],
        "reason": (
            "public API exists; product acceptance is outside harness "
            "calibration scope"
        ),
    }

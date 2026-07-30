from __future__ import annotations

import asyncio
import sys

from .model import Verdict


async def classify_process(mode: str, timeout: float = 0.25) -> Verdict:
    if mode == "crash":
        command = [sys.executable, "-c", "raise SystemExit(23)"]
    elif mode == "hang":
        command = [sys.executable, "-c", "import time; time.sleep(60)"]
    else:
        command = [sys.executable, "-c", "raise SystemExit(0)"]

    process = await asyncio.create_subprocess_exec(*command)
    try:
        returncode = await asyncio.wait_for(process.wait(), timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return Verdict.INFRA_ERROR
    return Verdict.PASS if returncode == 0 else Verdict.INFRA_ERROR

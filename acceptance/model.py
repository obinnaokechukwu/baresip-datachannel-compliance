from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNSUPPORTED = "UNSUPPORTED"
    INFRA_ERROR = "INFRA_ERROR"


@dataclass(frozen=True)
class MessageRecord:
    run: str
    association: str
    channel: str
    direction: str
    sequence: int
    message_type: str
    length: int
    sha256: str
    payload_hex: str

    @classmethod
    def from_payload(
        cls,
        *,
        run: str,
        association: str,
        channel: str,
        direction: str,
        sequence: int,
        message_type: str,
        payload: bytes,
    ) -> MessageRecord:
        return cls(
            run=run,
            association=association,
            channel=channel,
            direction=direction,
            sequence=sequence,
            message_type=message_type,
            length=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            payload_hex=payload.hex(),
        )

    def json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OracleResult:
    verdict: Verdict
    failures: tuple[str, ...]


def compare_ordered(
    sent: list[MessageRecord], received: list[MessageRecord]
) -> OracleResult:
    failures: list[str] = []
    if len(sent) != len(received):
        failures.append(
            f"manifest length differs: sent={len(sent)} received={len(received)}"
        )
    for index, (expected, actual) in enumerate(zip(sent, received, strict=False)):
        if expected != actual:
            failures.append(
                f"record {index} differs: expected={expected.json()} "
                f"actual={actual.json()}"
            )
    return OracleResult(
        Verdict.FAIL if failures else Verdict.PASS, tuple(failures)
    )


def compare_unordered(
    sent: list[MessageRecord], received: list[MessageRecord]
) -> OracleResult:
    def key(record: MessageRecord) -> tuple[Any, ...]:
        return (
            record.run,
            record.association,
            record.channel,
            record.direction,
            record.message_type,
            record.length,
            record.sha256,
            record.payload_hex,
        )

    expected = Counter(key(record) for record in sent)
    actual = Counter(key(record) for record in received)
    failures = (
        []
        if expected == actual
        else [
            "unordered manifest differs: "
            f"missing={list((expected - actual).elements())} "
            f"unexpected={list((actual - expected).elements())}"
        ]
    )
    return OracleResult(
        Verdict.FAIL if failures else Verdict.PASS, tuple(failures)
    )

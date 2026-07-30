from acceptance.model import (
    MessageRecord,
    Verdict,
    compare_ordered,
    compare_unordered,
)
from acceptance.oracle import INJECTIONS, inject


def records() -> list[MessageRecord]:
    return [
        MessageRecord.from_payload(
            run="test",
            association="a",
            channel="c",
            direction="send",
            sequence=sequence,
            message_type="binary",
            payload=f"payload-{sequence}".encode(),
        )
        for sequence in range(1, 4)
    ]


def test_known_good_passes() -> None:
    values = records()
    assert compare_ordered(values, list(values)).verdict is Verdict.PASS


def test_each_injected_violation_fails() -> None:
    values = records()
    for violation in INJECTIONS:
        assert (
            compare_ordered(values, inject(values, violation)).verdict
            is Verdict.FAIL
        )


def test_unordered_oracle_accepts_only_reordering() -> None:
    values = records()

    assert (
        compare_unordered(values, inject(values, "reorder")).verdict
        is Verdict.PASS
    )
    for violation in ("corrupt", "omit", "duplicate"):
        assert (
            compare_unordered(values, inject(values, violation)).verdict
            is Verdict.FAIL
        )

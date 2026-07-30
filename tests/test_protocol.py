import pytest

from acceptance.protocol import Envelope


def test_valid_envelope() -> None:
    Envelope(kind="command", seq=1, name="start", body={}).validate()


@pytest.mark.parametrize(
    "envelope",
    (
        Envelope(kind="command", seq=0, name="start", body={}),
        Envelope(kind="command", seq=1, name="unknown", body={}),
        Envelope(kind="event", seq=1, name="start", body={}),
    ),
)
def test_invalid_envelope(envelope: Envelope) -> None:
    with pytest.raises(ValueError):
        envelope.validate()

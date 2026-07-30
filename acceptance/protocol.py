from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


PROTOCOL_VERSION = 1
COMMANDS = frozenset(
    {
        "start",
        "create_channel",
        "create_offer",
        "set_remote_description",
        "send",
        "stats",
        "close",
    }
)
EVENTS = frozenset(
    {
        "ready",
        "local_description",
        "channel",
        "message",
        "stats",
        "closed",
        "error",
    }
)


@dataclass(frozen=True)
class Envelope:
    kind: Literal["command", "event"]
    seq: int
    name: str
    body: dict[str, Any]
    version: int = PROTOCOL_VERSION

    def validate(self) -> None:
        if self.version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version {self.version}")
        if self.seq < 1:
            raise ValueError("sequence must be positive")
        allowed = COMMANDS if self.kind == "command" else EVENTS
        if self.name not in allowed:
            raise ValueError(f"unknown {self.kind} {self.name!r}")
        if not isinstance(self.body, dict):
            raise ValueError("body must be an object")

    def json(self) -> dict[str, Any]:
        self.validate()
        return {
            "version": self.version,
            "kind": self.kind,
            "seq": self.seq,
            "name": self.name,
            "body": self.body,
        }

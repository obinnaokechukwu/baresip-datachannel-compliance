# Evidence bundle schema v1

Each scenario directory is immutable after its `result.json` is written and
contains:

- `scenario.json`: exact activated scenario and oracle requirements.
- `command.txt`: exact reproduction command.
- `versions.json`: OS, browser, aiortc, Python, and source revisions.
- `events.ndjson`: versioned endpoint command/event transcript.
- `offer.sdp` and `answer.sdp`: negotiated descriptions.
- `sent-manifest.json` and `received-manifest.json`: deterministic complete
  message records.
- `browser-stats.json` and `aiortc-stats.json`: endpoint transport and media
  statistics.
- `result.json`: one of `PASS`, `FAIL`, `UNSUPPORTED`, or `INFRA_ERROR`, with
  every oracle outcome and missing-evidence item.

Release scenarios additionally require packet captures and network-controller
evidence. Foundation scenarios do not claim route or impairment coverage.

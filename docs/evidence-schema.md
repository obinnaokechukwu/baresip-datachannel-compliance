# Evidence bundle schema v1

Each scenario directory is immutable after its `result.json` is written and
contains:

- `scenario.json`: exact activated scenario and oracle requirements.
- `command.txt`: exact reproduction command.
- `versions.json`: OS, browser, aiortc, Python, and dirty-aware source state.
- `events.ndjson`: versioned endpoint command/event transcript.
- `offer.sdp` and `answer.sdp`: negotiated descriptions.
- `sent-manifest.json` and `received-manifest.json`: deterministic complete
  message records.
- `browser-stats.json` and `aiortc-stats.json`: endpoint transport and media
  statistics.
- `result.json`: one of `PASS`, `FAIL`, `UNSUPPORTED`, or `INFRA_ERROR`, with
  every oracle outcome and missing-evidence item.

A product run also has root `argv.json` and shell-escaped `command.txt`
reproducers. `provenance.json` contains the cryptographic build binding between
source states and exact executable/runtime hashes, including every `.so` below
each required module root and each module's resolved dynamic dependencies.
`provenance-checks.json` records verification immediately before and after
every scenario. The evidence directory is recreated at invocation start, and
scenario identity, command, versions, logs, and result are retained even for
`FAIL` or `INFRA_ERROR`.

Harness calibration does not claim product acceptance, route, or impairment
coverage. Its summary carries `scope: HARNESS_CALIBRATION_ONLY` and
`product_acceptance: NOT_RUN`.

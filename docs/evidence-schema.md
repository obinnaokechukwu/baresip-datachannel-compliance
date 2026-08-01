# Evidence bundle schema v1

The evidence bundle supports cross-implementation compatibility claims. It
identifies which browser or independent language stack communicated with
baresip, what each peer negotiated, what messages and media crossed the wire,
and which exact source and runtime artifacts produced the result. This lets a
reviewer distinguish a repeatable Chrome/Chromium, Firefox, aiortc, or Pion
interoperability result from an in-process loopback or an unrepeatable local
test pass.

Each scenario directory is immutable after its `result.json` is written and
contains:

- `scenario.json`: exact activated scenario and oracle requirements.
- `command.txt`: exact reproduction command.
- `versions.json`: OS and runtime details, the applicable browser, aiortc, or
  Pion version, and dirty-aware source state.
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

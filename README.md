# baresip data-channel compliance

This repository is the external compliance and acceptance harness for baresip
WebRTC data channels. It deliberately lives outside the baresip and libre Git
trees.

The former foundation gate is retained only as a harness calibration command.
It uses stable Chrome and aiortc to prove that transcript, transport, media,
and supervision oracles distinguish known-good behavior from injected
failures. Its summary is explicitly scoped `HARNESS_CALIBRATION_ONLY` and
records `product_acceptance: NOT_RUN`; a calibration `PASS` is not a baresip
product verdict.

## Reproduce harness calibration

```sh
./scripts/foundation-gate \
  --baresip /path/to/baresip \
  --libre /path/to/re
```

Generated virtual environments, browser profiles, builds, logs, and evidence
are written beneath `.work/` or `evidence/` in this repository. The legacy
script name emits a retirement notice. The command fails unless every
known-good calibration is `PASS`, every injected violation is `FAIL`, and
crash and hang calibration are `INFRA_ERROR`.

The four verdicts are:

- `PASS`: all scenario oracles and required evidence passed.
- `FAIL`: endpoints ran, but product behavior violated an oracle.
- `UNSUPPORTED`: an endpoint explicitly lacks the requested capability.
- `INFRA_ERROR`: the harness could not establish product behavior.

Only `PASS` satisfies an acceptance gate.

## Pion interoperability endpoint

The independent Pion endpoint is built outside the Python environment:

```sh
./scripts/build-pion-endpoint
```

After all production and harness builds are final, bind the dirty source states
to the exact runtime artifacts. Keep the manifest outside all three source
trees so creating it does not change a bound working tree:

```sh
dc-build-manifest \
  --executable /path/to/baresip-webrtc \
  --baresip /path/to/baresip \
  --libre /path/to/re \
  --pion-endpoint .work/pion-endpoint \
  --turn-server .work/turn-server \
  --library-path /path/to/baresip/lib \
  --library-path /path/to/re/lib \
  --module-path /path/to/baresip/lib/baresip/modules \
  --output /tmp/datachannel-build-manifest.json

dc-product-acceptance \
  --build-manifest /tmp/datachannel-build-manifest.json \
  --executable /path/to/baresip-webrtc \
  --baresip /path/to/baresip \
  --libre /path/to/re \
  --pion-endpoint .work/pion-endpoint \
  --turn-server .work/turn-server \
  --library-path /path/to/baresip/lib \
  --library-path /path/to/re/lib \
  --module-path /path/to/baresip/lib/baresip/modules \
  --evidence /tmp/datachannel-product-evidence
```

Acceptance verifies the manifest before and after every scenario. A source,
executable, helper, or resolved runtime-library change is an infrastructure
error and cannot produce a product pass.

`dc-product-acceptance` uses `.work/pion-endpoint` and `.work/turn-server` by
default. It records the resolved Pion module version and includes a relay-only
TURN/UDP scenario that enables the baresip demo's `-R` policy and requires both
selected candidates to be `relay`. A second
relay run applies measured deterministic loss, delay, jitter, reordering,
duplication, bandwidth limiting, and a 1400-byte datagram ceiling entirely
inside the harness TURN server.

Product evidence includes the verified source-to-artifact binding, dirty-aware
source snapshots, SHA-256 hashes, and ELF build IDs for the executable, every
recursively discovered baresip module, and every executable/module dynamic
dependency. Each invocation recreates its evidence tree so artifacts from a
prior run cannot be mistaken for current results.

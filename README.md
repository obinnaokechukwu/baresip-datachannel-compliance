# baresip data-channel acceptance

This repository is the external acceptance harness for baresip WebRTC data
channels. It deliberately lives outside the baresip and libre Git trees.

The foundation gate uses stable Chrome and aiortc through one versioned
command/event contract. It proves that the transcript oracle distinguishes
working data-only and audio/video/data BUNDLE sessions from corruption,
omission, duplication, ordering violations, endpoint crashes, and hangs. It
also records the current baresip data-channel capability as `UNSUPPORTED`
until the public API is available.

## Reproduce the foundation gate

```sh
./scripts/foundation-gate \
  --baresip /path/to/baresip \
  --libre /path/to/re
```

Generated virtual environments, browser profiles, builds, logs, and evidence
are written beneath `.work/` or `evidence/` in this repository. The command
fails unless every known-good scenario is `PASS`, every injected transcript
violation is `FAIL`, crash and hang calibration are `INFRA_ERROR`, and the
baresip baseline is explicitly `UNSUPPORTED`.

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

`dc-product-acceptance` uses `.work/pion-endpoint` by default and records the
resolved Pion module version in each Pion scenario's evidence bundle.

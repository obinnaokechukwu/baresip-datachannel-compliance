# baresip data-channel compliance

This repository is a cross-implementation compatibility and acceptance suite
for baresip WebRTC data channels. Its primary purpose is to prove that baresip
can negotiate and communicate with WebRTC implementations that already exist
outside the baresip/libre ecosystem:

- Chrome/Chromium and Firefox, representing widely deployed browser WebRTC
  implementations;
- [aiortc](https://github.com/aiortc/aiortc), an independent Python WebRTC
  stack; and
- [Pion](https://github.com/pion/webrtc), an independent Go WebRTC stack.

Unit and loopback tests inside libre or baresip can validate internal
contracts, but they cannot establish compatibility with these independent
implementations. This suite exercises baresip as a black-box peer through its
public signaling surface and the real ICE, DTLS, SCTP, DCEP, SDP, BUNDLE, RTP,
and TURN protocols. It checks both data-only communication and data channels
coexisting with audio and video.

The suite deliberately lives outside the baresip and libre Git trees so it
does not share their private APIs, test-only hooks, fixtures, or build state.
Here, **external** describes that independent test boundary. **Reproducible**
means each run records the exact source states, runtime artifacts, dependency
and peer versions, commands, SDP, message manifests, statistics, and logs
needed to repeat or diagnose the compatibility result. These are separate
properties: independent peers establish interoperability, while retained
provenance and evidence make that result reproducible.

The former foundation gate is retained only as a harness calibration command.
It connects Chrome/Chromium to aiortc to prove that transcript, transport,
media, and supervision oracles distinguish known-good behavior from injected
failures before those oracles judge baresip. Its summary is explicitly scoped
`HARNESS_CALIBRATION_ONLY` and records `product_acceptance: NOT_RUN`; a
calibration `PASS` is not a baresip product verdict.

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

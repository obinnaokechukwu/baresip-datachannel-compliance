# Libre data-channel boundary decision

The approved placement is the optional `libre::datachannel` companion target.
The goal explicitly prefers this placement, and no maintainer rejection exists.
Contacting external maintainers is outside the authorized execution scope, so
the implementation proceeds in libre while keeping the companion ABI separate
from `libre::re`.

The component owns one SCTP association, DCEP, PPID mapping, stream allocation,
complete-message delivery, channel state, and bounded buffering. It accepts
decrypted SCTP packets and emits SCTP packets synchronously through callbacks.
It does not own UDP, ICE, DTLS, SDP, BUNDLE, SIP, or baresip policy. No public
type exposes usrsctp.

## Fixed ownership contract

- `dc_transport_alloc()` creates an unstarted association and copies its
  configuration.
- `dc_transport_start()` is one-shot and receives the established local DTLS
  role. It may emit packets synchronously.
- `dc_transport_input()` borrows and synchronously consumes one decrypted SCTP
  packet. Consumed peer-invalid input returns zero; nonzero errors describe
  caller misuse or local resource exhaustion.
- The packet callback borrows one outbound SCTP packet and returns the DTLS
  write result. No component lock is held across the callback.
- Every operation and callback runs on one libre event-loop context.
- Callback-time destruction defers finalization until the callback stack
  unwinds. No callback runs after final destruction.
- A channel retains its transport. A transport terminal error closes every
  channel with the same positive POSIX error.
- Accepted sends are copied into bounded memory. `EAGAIN` reports pressure and
  `EMSGSIZE` reports the negotiated or implementation message limit.

## Build contract

`USE_DATACHANNEL=ON` creates and installs a companion shared/static library and
`re_datachannel.h`. The target requires an externally supplied pristine
usrsctp package at configuration time, links `libre::re`, and has its own
SOVERSION. The base libre target, headers, dependency set, and ABI remain
unchanged when the option is off.

This boundary is fixed for Phases 2–4. Experience may refine private data
structures, but changing packet ownership, callback synchronization, public
state semantics, or repository ownership requires revisiting the approved
design.

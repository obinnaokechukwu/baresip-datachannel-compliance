# Endpoint control contract v1

Every endpoint adapter accepts commands and emits events with the same
envelope:

```json
{"version":1,"kind":"command","seq":1,"name":"create_offer","body":{}}
{"version":1,"kind":"event","seq":1,"name":"local_description","body":{}}
```

`version`, `kind`, `seq`, `name`, and `body` are required. Sequence numbers
are positive and strictly increasing per direction. Unknown commands produce
an `error` event; they are never ignored.

Foundation commands are `start`, `create_channel`, `create_offer`,
`set_remote_description`, `send`, `stats`, and `close`. Foundation events are
`ready`, `local_description`, `channel`, `message`, `stats`, `closed`, and
`error`.

Payload events identify association, channel, direction, sequence, type,
length, and SHA-256 digest. Payload bytes are stored in the evidence manifest,
not silently truncated in endpoint logs.

The controller owns deadlines, endpoint process supervision, signaling,
cleanup, verdicts, and evidence. An adapter cannot declare a scenario
`PASS`.

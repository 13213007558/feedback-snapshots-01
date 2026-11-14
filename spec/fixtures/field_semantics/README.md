# Field-semantics corpus

`cases.json` is a deterministic corpus of 123 MQTT packet cases. Each entry
keeps the logical fields (`args`, hex encoded) separate from the bytes on the
wire (`wire_hex`), so an encoder and a decoder can be compared against the same
field independently.

Categories:

- `publish-topic` — PUBLISH Topic Name. Wildcards, U+0000, ill-formed UTF-8 and
  65535/65536-byte boundaries.
- `publish-payload` — PUBLISH payload. Opaque binary bytes must survive
  byte-for-byte and must never be validated or transcoded as text.
- `topic-filter` — SUBSCRIBE / UNSUBSCRIBE Topic Filters. Legal wildcard
  placements (for example `#`, `a/#`, `sport/tennis/+`) must remain legal,
  while misplaced wildcards are rejected.
- `connect-identity` — CONNECT ClientId, User Name, Will Topic (UTF-8 text),
  plus Password and Will Message (binary). Includes clean-session and
  MQTT 3.1.0 identifier-length rules.

Each entry has `expect.encode` and `expect.parse` values of `accept`, `reject`,
or `n/a` (when the value cannot be represented on that side, such as a string
longer than the two-byte length prefix).

Boundary lengths (65535/65536 bytes and MQTT 3.1.0's 23-byte ClientId limit)
are asserted directly in `spec/mqtt_field_semantics_spec.rb` rather than
serialized into this corpus, so the corpus stays small and reviewable.

The `wire_hex` field is the minimal input that reproduces a rejection, produced
by the independent builder in `spec/support/field_semantics_builder.rb`, not by
`MQTT::Packet`. Replay one case directly:

```sh
bundle exec ruby spec/support/replay_field_semantics_case.rb publish-topic-invalid-utf8-ff
bundle exec ruby spec/support/replay_field_semantics_case.rb --failed
bundle exec ruby spec/support/replay_field_semantics_case.rb --list
```

Encoder misuse (bad local field values) raises `ArgumentError`; malformed
bytes received from the network raise `MQTT::ProtocolException`. The two are
kept apart so a caller can distinguish its own bad input from a peer's. The
same field validators back both paths, which is what makes the acceptance rules
identical.

Regenerate the corpus after changing field semantics:

```sh
bundle exec ruby spec/support/generate_field_semantics_corpus.rb
```

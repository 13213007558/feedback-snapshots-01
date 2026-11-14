# MQTT::Forensics — offline session analysis

Offline, reassembly-tolerant analysis of captured MQTT 3.1.1 byte streams.
It never opens a network connection: it consumes raw fragments captured from
the two directions of one transport connection (client→broker and
broker→client), decodes them with the gem's own `MQTT::Packet`, correlates the
events into a timeline, and reports deviations from the protocol ordering.

## Why it is conservative

A capture is not the session. Fragments may be split arbitrarily, truncated, or
the recording may start halfway through a conversation. Every conclusion is
therefore assigned a status:

| Severity   | Meaning                                                                 | Status            |
|------------|-------------------------------------------------------------------------|-------------------|
| `violation`| Contradicts the MQTT 3.1.1 state machine *using bytes that are present* | `proven`          |
| `evidence` | Abnormal, but an absent packet in the capture could explain it          | `unproven`        |
| `gap`      | The capture is incomplete; this is never reported as an attack          | `unproven`        |

A missing response is recorded as a **gap**, not an attack. A response with no
visible request is **unsolicited but unproven**, because the request may lie in
a missing fragment. Only duplicated acknowledgements and ordering contradictions
that are fully visible in the captured bytes are raised as proven violations.

The `username` field in CONNECT is a *client declaration*. It is reported as
`declared_only` and is never treated as an authenticated identity; the broker's
CONNACK return code is the only acceptance signal available in the capture.

## What it detects

- Connection: multiple CONNECT/CONNACK, CONNACK without a visible CONNECT,
  rejected connections, and a missing CONNECT (mid-session start).
- Subscriptions: SUBSCRIBE/SUBACK and UNSUBSCRIBE/UNSUBACK pairing, duplicate
  and unsolicited acknowledgements, `0x80` failure codes, missing responses.
- Publishing: QoS 0/1/2 flows, packet-id reuse, DUP retransmissions, and the
  full QoS 2 `PUBLISH → PUBREC → PUBREL → PUBCOMP` handshake.
- Acknowledgements: duplicated PUBACK/PUBREC/PUBREL/PUBCOMP/SUBACK/UNSUBACK
  (proven) versus acknowledgements whose request is absent (unproven).
- Keep-alive: unmatched PINGREQ/PINGRESP.
- Capture defects: truncated or undecodable frames are surfaced as MALFORMED
  evidence with the parse error, never silently dropped.

Three comparison tables are always emitted: **duplicate acknowledgements**,
**unsolicited responses**, and **capture gaps**.

## Traceability

Every timeline event carries a frame reference such as `CF0029`
(client stream, byte offset 29) or `BF0009` (broker stream, offset 9), plus a
provenance list naming the exact source fragment, start and length of every
byte that formed the frame. A finding's `evidence_refs` point back at those
same frames, so each definite event is reproducible from the raw fragments.

## Input format

A JSON document or JSON Lines file listing fragments in arrival order:

```json
{
  "fragments": [
    {"direction": "client", "encoding": "hex",    "data": "10..", "source": "c0"},
    {"direction": "broker", "encoding": "hex",    "data": "20..", "source": "b0"},
    {"direction": "client", "encoding": "binary", "data": "..",   "captured_at": 1700.5}
  ]
}
```

- `direction`: `client`/`broker` (aliases `c`/`b`, `in`/`out`, `server`).
- `encoding`: `hex` (default), `binary`, or `base64` (needs the base64 gem).
- `source`: any label used for provenance; `captured_at` is optional.

No packet-boundary alignment is assumed. A packet may span many fragments and
a fragment may contain many packets.

## Usage

CLI:

```sh
ruby bin/mqtt-forensics --demo                 # built-in synthetic capture
ruby bin/mqtt-forensics session.json session2.jsonl
ruby bin/mqtt-forensics --format json session.json
```

Library:

```ruby
require 'mqtt'                       # MQTT::Forensics is autoloaded
report = MQTT::Forensics.analyze([
  [:client, raw_bytes, nil, 'c0'],
  [:broker, raw_bytes, nil, 'b0']
])
puts report.to_text
report.to_h   # structured data, including provenance and the three tables
```

## Ordering honesty

Each direction is always presented in exact byte-stream order. Without a
synchronised, trusted cross-direction clock the two streams are interleaved for
readability only; the report states that the interleaving is not a proven
global ordering. Ordering *violations* are decided from same-direction byte
offsets and from per-packet-id handshake state, never from the visual merge.

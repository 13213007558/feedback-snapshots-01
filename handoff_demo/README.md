# External review hand-off

A workflow for sending `detect-secrets` findings to an outside reviewer without
the matched marker values ever leaving the machine that ran the scan, and for
folding the returned decisions back onto the exact findings.

## Why a separate projection

`detect-secrets audit --report` re-opens the scanned source files and embeds
both the plaintext marker value (`secrets`) and the full source line (`lines`)
in its output. It also aggregates by `(hashed_secret, filename)`. Neither is
safe or precise enough for external sharing:

- the plaintext value and the source line are local material that must not be
  exported;
- two different plugin categories can flag the same line and the same value,
  so they share a `hashed_secret` but are distinct findings that need separate
  decisions.

The hand-off projection in `detect_secrets/audit/handoff.py` solves both.

## The one projection, used at every stage

Export, re-open and merge all call the same `assert_shareable` guard and use
the same finding identity, so a finding means the same thing across the whole
round trip.

A shared finding contains only:

| field | purpose |
| --- | --- |
| `filename` | locates the file |
| `line_number` | locates the line |
| `type` | the plugin category that flagged it |
| `hashed_secret` | one-way fingerprint for the reviewer's reference |
| `is_verified` | automated verification status (boolean) |

A returned review may additionally carry `is_secret` (the human triage
decision: `true`, `false`, or `null`). Any other field — notably
`secret_value` or a source `line` — makes `assert_shareable` raise
`LeakageError`, so local marker values can never be emitted.

## Identity: composite key, never the fingerprint

Findings are keyed by the composite tuple

```
(filename, line_number, type)
```

The fingerprint is deliberately **not** part of the join key. Two findings at
the same location that share a fingerprint but differ in `type` therefore keep
independent decisions; one verdict can never be copied onto the other just
because the outgoing hash matched.

## CLI

```bash
# 1. Project a local baseline into the shareable document.
python -m detect_secrets.audit.handoff export .secrets.baseline -o handoff.json

# 2. (Optional) Emit a blank review form the vendor fills in.
python -m detect_secrets.audit.handoff template handoff.json -o review.json

# 3. Re-open a shared document without touching any source file.
python -m detect_secrets.audit.handoff reopen handoff.json

# 4. Merge the returned decisions back onto the local baseline.
python -m detect_secrets.audit.handoff merge .secrets.baseline review.json \
    -o reviewed.baseline.json
```

The `merge` report lists every decision that landed (`applied`) and any review
entry that matched no finding (`unmatched`).

## End-to-end demo and tests

```bash
python handoff_demo/run_demo.py
python -m pytest tests/audit/handoff_test.py
```

The demo builds two fully synthetic scan baselines (obviously fake literals,
no production source), where `app.py:1` is flagged by both `AWS Access Key`
and `Secret Keyword` with an identical fingerprint. It then exports, re-opens,
applies opposite decisions to those two categories, merges them back, and
asserts at every shared stage that no local marker value is present.

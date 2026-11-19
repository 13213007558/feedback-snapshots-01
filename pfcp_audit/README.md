# PFCP endpoint-allocation evidence checker

A small, deliberately limited audit layer built on pycrate's
`pycrate_mobile.TS29244_PFCP`.  It answers one narrow question without ever
equating "the bytes parse" with "the GTP-U tunnel is installed":

> For every F-TEID referenced by a PDR under a given F-SEID, what evidence do
> the captured request and response actually provide?

## Endpoint states

Each F-TEID reference ends in exactly one of these states:

- `specified` — CH is clear in the request and TEID/address(es) are carried on
  the wire;
- `allocation_requested` — CH is set, optionally with CHID/CHOOSE_ID, and no
  address is present (a missing address under CH is never treated as zero);
- `allocation_confirmed` — a CreatedPDR/UpdatedPDR in an accepted response for
  the *same F-SEID and PDR id* clears CH and returns TEID/address(es);
- `inconclusive` — the layout is invalid, the response kept CH set, or the
  response F-TEID has no matching request PDR.

## What is preserved as evidence

- The full IE nesting path (`CreatePDR/PDI/FTEID`, `CreatedPDR/FTEID`, ...),
  message sequence number and absolute byte offset/length of every IE.
- Strict conditional layout of F-TEID: truncation, trailing bytes, zero
  addresses, address-presence bits set under CH, and CHID without CH on the
  request side.
- Selection groups keyed by `(F-SEID, CHOOSE_ID-or-anonymous-CH)`: shared
  allocations, group-internal conflicts, reused PDR ids, and missing/partial
  responses.
- Response `Cause`: an explicit rejection or a partial acceptance never turns
  an allocation request into a confirmed endpoint.
- F-SEID isolation: a successful allocation in one session can never satisfy a
  same-numbered CHOOSE_ID group in another session.

## Layout

- `fteid.py` — raw F-TEID byte walker with a pycrate cross-check.
- `evidence.py` — immutable evidence records and IE paths.
- `audit.py` — `EndpointAuditor`, message correlation and verdicts.
- `transcript.py` — labelled raw-byte transcript loader.
- `scenarios.py` — two interleaved sessions (same CHOOSE_ID value) producing
  the legal, conflict and incomplete transcripts.
- `mutation.py` — single-bit F-TEID flag mutators used by the tests.
- `artifacts.py` / `samples/endpoint_evidence.json` — self-contained JSON
  evidence artifact.
- `tools/pfcp_endpoint_audit_demo.py` — CLI that writes the artifact.

## Usage

```python
from pfcp_audit import audit_messages

result = audit_messages(list_of_raw_pfcp_messages)
for (seid, pdr_id), verdicts in result.all_verdicts().items():
    print(seid, pdr_id, [v.value for v in verdicts])
```

Generate the full evidence artifact:

```sh
PYTHONPATH=. .venv/bin/python tools/pfcp_endpoint_audit_demo.py \
    pfcp_audit/samples/endpoint_evidence.json
```

Tests live in `test/test_pfcp_audit.py` and include byte-level mutations that
flip one presence/CH bit, proving the following field is never misread as an
address and that no cross-session result is borrowed.

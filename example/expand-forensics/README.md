# Expand forensics: shareable evidence reports

This example produces a partner-safe forensics report from an OpenFGA Expand
response. The raw Expand tree contains internal account ids, so it must never
be forwarded as-is. The forensics package keeps the dependency structure and
the source tuple evidence, but replaces every internal subject reference with
a stable public id.

## What the scenario covers

`local_fga_stub.py` is an in-memory stand-in for the OpenFGA API (no network,
no server). For `document:deal-memo#viewer` it returns:

- **Chain A — direct viewer memberships.** Direct `viewer` tuples, including
  an internal account (`alice`) that also appears through the editor chain and
  a group membership, plus two *different* subjects that share the display
  name "Jordan Lee".
- **Chain B — editor chain.** A computed userset (`viewer includes editor`)
  whose evidence tuples share the `alice` node with chain A.
- **Unconfirmed branch.** A `temp_contractor` leaf whose backing tuple was
  never written, so the report flags it as unconfirmed instead of asserting it.

The stub can return the same tree with sibling children in `forward` or
`reversed` order.

## Identity rules

- Identity is always keyed on the full OpenFGA reference `<type>:<id>`.
  Display names are never used to merge subjects.
- One reference maps to one public id (`subj_xxxxx`) reused at every position
  where that subject appears, so repeated occurrences can be correlated inside
  one report.
- Two subjects with the same display name stay separate and are listed under
  `display_name_collisions`.
- Public ids are derived deterministically (`sha256(salt + ref)`), so two
  exports of the same data compare equal regardless of response ordering.

## Run it

```sh
.venv/bin/python example/expand-forensics/demo.py
```

Outputs are written to `example/expand-forensics/out/`:

- `report_forward.json`, `report_reversed.json` — shareable, public-safe
  reports. They are identical apart from `generated_at`; the demo asserts this.
- `internal_forward.json`, `internal_reversed.json` — internal-only bundle with
  the untouched Expand tree, raw evidence triples and the
  `public id -> internal reference` mapping for re-identification. Never share
  these.

## Report fields

- `request` / `authorization_model` — the request, model id and model schema
  the report answers to.
- `relations_read` — which object relations were read to gather evidence.
- `tree` — canonical userset tree; every node carries a stable `node_id`,
  evidence links and a confirmed/unconfirmed leaf status.
- `evidence` — observed tuples as public triples with stable `evidence_id` and
  observation timestamp.
- `subjects` — public subject directory with object type and display names.
- `unconfirmed_branches` — branches with no backing evidence, with the expected
  relation that could not be substantiated.
- `redaction` — the redaction rule and public id algorithm.
- `summary` — counts for quick review.

A final guard scans the serialized public report and refuses to export it if
any internal-type reference survives.

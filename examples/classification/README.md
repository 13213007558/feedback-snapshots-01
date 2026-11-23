# Order classification example

Two order shapes share field names, but which definitions apply depends on
validation: a retail order takes the `then` branch and a wholesale order
takes the `else` branch.  Each branch resolves its own nested shipment and
parcel definitions through `$ref`, so the effective levels differ even
though the instance paths look alike.

Samples:

- `retail-order.json` — takes `then`; its nested parcels use
  `retailParcel` (contents `internal`).
- `wholesale-order.json` — takes `else`; its nested parcels use
  `freightParcel` (contents `restricted`).
- `conflict-schema.json` + `conflict-order.json` — the base schema says
  `delivery.notes` is `restricted`, while the taken branch's definition
  says `internal`; the strictest level wins and the conflict is listed.
- `invalid-order.json` — fails validation, so the classification is
  withheld and no approved fields are emitted.

Generate the compliance documents:

```sh
python examples/classification/report.py
```

Outputs land in `examples/classification/reports/`.  Each document has:

- `validation` — the ordinary validation result and errors;
- `classification` — `status`, policy, approved `fields`, `conflicts`,
  and a `summary`;
- `diagnostics` — rejected-branch observations, never mixed into the
  approved fields.

To consume a field, read its `instance_path` (JSON Pointer) or
`json_path`, its `level`, and `known` (`false` means explicitly
`unknown`).  Every source records where the level came from, including
the `$ref` and resolved URI when a reference supplied it.

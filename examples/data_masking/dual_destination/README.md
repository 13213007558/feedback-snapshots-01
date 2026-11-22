# Dual-destination data masking

This example shows how to derive two destinations from one event:

- **Audit** gets a recoverable copy of the whole event, encrypted with a key that only the
  audit role can use.
- **Public metrics** gets an irreversible projection of non-personal fields and never receives
  ciphertext, a key reference, or a decrypt-capable provider.

The point is not just to mask fields. It is to make the split enforceable: the public branch
never holds material it could recover, and a replay cannot silently publish the event twice.

## Interface boundaries in the current utility

These are the behaviours this example relies on. Verify them against your installed version
before adapting the pattern.

| Capability | Current contract | Consequence for this design |
| --- | --- | --- |
| `erase(data, fields=[...])` | Field-level JSONPath; replaces matched values with `*****` | Use it for the public projection |
| `encrypt(data)` / `decrypt(data)` | Whole payload only; `fields` is not supported | Audit encrypts the whole two-layer event |
| `raise_on_missing_field` | `True` (default) raises `DataMaskingFieldNotFoundError`; `False` only warns | Keep the default on the public path |
| `BaseProvider` | `encrypt`/`decrypt` raise `NotImplementedError` unless implemented | An erase-only provider cannot decrypt, even if given ciphertext |
| `AWSEncryptionSDKProvider` | KMS key ARN and exact context required on decrypt | Store `key_ref` and `encryption_context` beside the ciphertext |

`erase` with a path to an object replaces the object itself with `*****`. Point at scalar
leaves when the public projection needs sibling fields, as `PUBLIC_ERASE_FIELDS` does for
`address`.

## Production shape

```text
raw event
   |-- audit branch ---- DataMasking(AWSEncryptionSDKProvider([AUDIT_KEY]))
   |                        encrypt(whole event, **context) -> ciphertext
   |                        -> audit store (KMS decrypt allowed only for the audit role)
   |
   `-- public branch --- DataMasking(erase-only provider)
                            erase(raw event, fields=PII paths)
                            -> allowlist projection -> metrics store (no ciphertext, no key ref)
```

Keep the two branches in separate execution roles when they run in separate functions:

1. The audit role needs `kms:GenerateDataKey` and `kms:Decrypt` on the audit key, and write
   access to the audit store.
2. The public role needs neither the audit key ARN nor `kms:Decrypt`. Give it write access only
   to the metrics store.
3. The public function must not receive the raw event through a channel that also carries the
   audit ciphertext. Fan out from the raw event; do not derive one destination from the other.
4. Pin the schema version and the PII path list together. A new personal field is a change to
   both the erasure list and the allowlist review.

The example's `FakeAuditKmsProvider` is a deterministic test double with a keystream, an
integrity tag, key allowlisting, and exact encryption-context matching. It is **not**
cryptography and must not leave tests. Production uses `AWSEncryptionSDKProvider`.

## Run the acceptance suite

From the repository root:

```bash
.venv/bin/python -m pytest -q examples/data_masking/dual_destination/test_dual_destination.py
```

The suite exercises `DataMasking`, `BaseProvider`, and the documented exceptions through the
example pipeline. It includes two synthetic events under `events/`: one EventBridge envelope with
the domain event in `detail`, and a second event with a different ID and values.

## What each destination actually receives

Audit record, from `checkout_event.json`:

```json
{
  "event_id": "evt-0001",
  "schema_version": "1.0",
  "tenant_id": "tenant-42",
  "key_ref": "arn:aws:kms:sa-east-1:111122223333:key/audit",
  "encryption_context": {
    "purpose": "audit",
    "event_id": "evt-0001",
    "tenant_id": "tenant-42",
    "schema_version": "1.0"
  },
  "ciphertext": "<base64 envelope>"
}
```

The ciphertext payload is opaque: the test decodes the envelope and asserts that no identifier
from either layer (`evt-0001`, `ord-9001`, `cus-7788`, names, email, document, address, card
data) appears in the encrypted bytes. An auditor holding the audit key decrypts and gets the
input event back as an equal Python object, including both the EventBridge envelope and the
domain event.

Public metrics record:

```json
{
  "event_type": "checkout.completed",
  "source": "checkout.service",
  "tenant_id": "tenant-42",
  "plan": "business",
  "currency": "BRL",
  "amount": 129.9,
  "item_count": 2,
  "payment_method": "credit_card",
  "checkout_duration_ms": 1840,
  "payment_attempts": 1,
  "event_date": "2026-11-19"
}
```

It contains no event ID, order ID, customer ID, name, email, document, street, postcode, card
number, card holder, ciphertext, or key reference. `assert_no_personal_data` fails closed on an
unknown field or a known canary value.

Note that `tenant_id` is a non-personal routing dimension in this synthetic example. Decide
per tenant whether it is safe for your public metrics; if not, remove it or bucket it.

## Acceptance: decrypt failure

The tests assert the exception type and that a failed read does not modify either destination.

| Scenario | Expected | What to assert |
| --- | --- | --- |
| Provider is not permitted to use the envelope key | `DataMaskingDecryptKeyError` | Audit record unchanged; no public fallback |
| Ciphertext payload is tampered with | `DataMaskingDecryptValueError` | Integrity failure is explicit |
| Ciphertext is not valid base64 | `DataMaskingDecryptValueError` | Not a raw `binascii` or `ValueError` |
| Ciphertext lacks the expected envelope header | `DataMaskingDecryptValueError` | Header check happens before deserialization |
| Envelope JSON is malformed | `DataMaskingDecryptValueError` | Failure is normalized to the documented type |
| Encryption context differs | `DataMaskingContextMismatchError` | Context is compared exactly, including `tenant_id` |

With `AWSEncryptionSDKProvider`, the documented mapping is:

- invalid key or KMS environment → `DataMaskingDecryptKeyError`;
- bad, tampered, or truncated ciphertext → `DataMaskingDecryptValueError`;
- context mismatch → `DataMaskingContextMismatchError`;
- non-string context values → `DataMaskingUnsupportedTypeError`.

The test double mirrors that mapping so the acceptance suite can run offline.

Acceptance decision: a decrypt failure is **a failed read, not a reason to widen access**.
Alert on the failure, keep the audit record immutable, and never fall back to the public copy
or to a different key.

## Acceptance: field not found

`DataMasking(raise_on_missing_field=True)` on the public path raises
`DataMaskingFieldNotFoundError`. The pipeline runs the public projection before encryption, so
the event is rejected before any KMS call or destination write.

The test removes `address.street` and asserts:

- `DataMaskingFieldNotFoundError` is raised;
- audit and metrics sinks are empty;
- the completion ledger has no entry;
- the audit provider has zero `encrypt` calls.

Do not "fix" this by setting `raise_on_missing_field=False`: the lenient mode only warns and
leaves the value in place. The test documents that behaviour explicitly, and the allowlist gate
would then be the last line of defence rather than the first.

Acceptance decision: a missing declared PII path is a **schema regression**. Fail the event,
route it to a dead-letter queue, and fix the path list. Do not let it reach either destination.

## Acceptance: the same event processed twice

The pipeline keys both sinks and a completion ledger by `event_id` and also records a
keyed content hash of the full event (HMAC-SHA256, never the raw payload).

| Scenario | Result | Destination effect |
| --- | --- | --- |
| Same `event_id`, byte-identical event, after completion | `DeliveryStatus.DUPLICATE` | No write to either sink; no new encrypt or erase calls |
| Same `event_id`, different content | `EventIdConflictError` | Neither sink is updated; the first record stays |
| Partial fan-out (audit only) | `DELIVERED`, `audit_written=False`, `metrics_written=True` | Only the missing destination is filled; ciphertext is reused, so `encrypt_calls` stays at 1 |
| Different `event_id`, different content | `DELIVERED` | Both sinks get a second record |

Acceptance decision: duplicate delivery is expected in at-least-once systems, so **duplicates
must be no-ops**, not errors. The same ID with different content is a producer bug or an
attack: reject it and alert. Partial fan-out must converge without re-encrypting or silently
overwriting a committed destination.

The in-memory sinks stand in for conditional writes. In production, implement `put_if_absent`
with a conditional write (for example, DynamoDB `attribute_not_exists` on the destination
primary key) and keep the content hash in the same item.

## Test output

```text
20 passed
```

The fake provider and in-memory sinks make the suite hermetic: no KMS, DynamoDB, or other
network dependency is involved.

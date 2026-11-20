# Transparency Log Deactivation

Sigstore transparency logs can be decommissioned and replaced by a successor
log. New artifacts must then be signed against the current log, while bundles
published to the retired log before its deactivation point still need to be
verifiable. `sigstore-python` expresses this transition with an explicit
**log deactivation policy** that is safe to use fully offline and during the
old/new log coexistence phase.

## Policy expression

A `LogDeactivation` names one retired log by its raw key ID, its fixed
`deactivated_at` point, and an optional `historical_window_start`. A
`LogDeactivationPolicy` collects these and evaluates them against a fixed,
caller-supplied `reference_time` (the trusted "now"):

* entries on a log that is not deactivated **as of the reference time** are
  accepted as **current log** material — this also covers the coexistence
  phase, where the reference time is still before the deactivation point;
* entries on a retired log are accepted only as **historical** material when
  their authenticated entry time is inside
  `[historical_window_start, deactivated_at)`;
* an entry at or after the deactivation point, or before the approved window,
  fails verification. New materials are therefore never accepted off a log
  that was supposed to be shut down.

The entry time comes from the materials themselves, never from the local
clock: Rekor v1 entries use the log's integrated time, while Rekor v2 entries
use a verified RFC 3161 timestamp.

## Offline verification with a receipt

Pass the policy to the `Verifier` and use the receipt-returning APIs. The
returned `VerificationReceipt` states which material was actually accepted.

```python
from datetime import UTC, datetime

from sigstore.models import Bundle
from sigstore.verify import (
    LogDeactivation,
    LogDeactivationPolicy,
    Verifier,
)

retired_log_id = bytes.fromhex("...")  # 32-byte key ID of the retired Rekor v1 log

log_policy = LogDeactivationPolicy(
    deactivated_logs=[
        LogDeactivation(
            log_id=retired_log_id,
            deactivated_at=datetime(2026, 1, 1, tzinfo=UTC),
            historical_window_start=datetime(2024, 1, 1, tzinfo=UTC),
        )
    ],
    # Pin a fixed trusted time instead of relying on the local clock.
    reference_time=datetime(2026, 11, 20, tzinfo=UTC),
)

verifier = Verifier(
    trusted_root=trusted_root,
    log_policy=log_policy,
)

bundle = Bundle.from_json(open("foo.txt.sigstore.json", "rb").read())
receipt = verifier.verify_artifact_with_receipt(
    open("foo.txt", "rb").read(),
    bundle,
    identity_policy,
)

# `current_log` for a current Rekor log, `retired_log_historical` otherwise.
print(receipt.accepted_material.value)
print(receipt.describe())
```

The same policy can instead be supplied per call with
`verify_artifact_with_receipt(..., log_policy=log_policy)`, and
`verify_dsse_with_receipt` provides the equivalent for DSSE bundles. Without a
policy, `verify_artifact` and `verify_dsse` keep their original behavior and
the receipt-returning APIs return `None`.

A policy that names a log absent from the trusted root is rejected when the
`Verifier` is constructed, so a misconfigured sunset fails closed rather than
silently accepting or denying entries.

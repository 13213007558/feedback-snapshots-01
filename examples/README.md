# Approval-pinned botocore client (offline two-account demo)

`account_pinned_client_demo.py` proves that a **shared** botocore client keeps
using one approved account across endpoint resolution, signing, and retries,
even while temporary credentials and the on-duty identity rotate underneath it.

## Run

```sh
.venv/bin/python examples/account_pinned_client_demo.py
```

No AWS account, credentials, or network access is required. The HTTP layer is
short-circuited by a `before-send` event handler, and the STS/identity broker
is an in-memory fake driven by a controllable clock.

## What it demonstrates

- **Account-scoped endpoint** — `s3control.GetAccessGrantsInstance` renders
  `https://{AccountId}.s3-control.us-east-1.amazonaws.com/...` from the
  approved account via botocore's real endpoint ruleset.
- **Pinning across rotation** — after the first transmission returns 500, the
  duty roster rotates to the second account, but the in-flight call retries
  with freshly rotated credentials for the *original* account (V1 -> V2).
- **Three-way evidence per attempt** — every attempt records and asserts:
  rendered endpoint account == signer credential account == approval account,
  plus the duty roster row active at that timestamp.
- **Explicit expiry policy between calls** — an expired approval either
  rebuilds safely for the on-duty account (`REBUILD`, with an allowlist) or
  hard-stops (`STOP`); there is no silent account switch.
- **Regional endpoints stay ordinary** — `sts.GetCallerIdentity` keeps using
  `https://sts.us-east-1.amazonaws.com/`; account-level endpoints remain
  opt-in per service rather than applying to every request.

## Layout

- `FakeIdentityBroker` / `DutyEntry` — in-memory STS stand-in and duty log.
- `ApprovalContext` / `ApprovalManager` — per-call account binding and the
  rebuild-vs-stop expiry policy.
- `PinnedCredentialProvider` — a `RefreshableCredentials` whose refresh
  callback can only mint for the pinned approval's account.
- `OfflineTransport` — scripted 500-then-200 responses and the signing double
  that snapshots the frozen SigV4 identity of each attempt.
- `AuditTrail` — per-attempt records and the cross-check assertions.

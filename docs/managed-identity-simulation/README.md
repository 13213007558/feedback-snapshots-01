# Managed Identity Source Pinning — Failure-Recovery Simulation

This is the recorded, runnable evidence for the fail-closed managed-identity
behavior. A worker that exposes several managed-identity entry points is given
one **approved source** and one **approved user-assigned identity**. MSAL must
keep that choice through failure recovery and must never silently complete a
call with the machine's broader, shared identity.

## How to run

From the repository root (no network and no local sockets are needed — both
"platforms" are in-process fakes behind a recording HTTP client):

```sh
.venv/bin/python -m tests.managed_identity_source_simulation
```

It regenerates two artifacts in this folder:

- `request-log.json` — the structured step results and the full chronological
  request log.
- `request-records.md` — a human-readable record of every GET, its endpoint,
  its identity selector, and whether it carried the local-key `Authorization`.

## The two simulated platforms

| Platform | Endpoint | Identity it serves | Role |
|---|---|---|---|
| Approved | `http://approved-platform.example/...` | echoes the requested user-assigned id `approved-user-assigned-client-id` | the pinned, approved Azure-Arc-style source |
| Broader | `http://broad-platform.example/...` | always returns `machine-shared-system-assigned-id` | used only to pre-warm a broad token; never an approved target |

The client is constructed with `managed_identity_source=AZURE_ARC` and
`transient_failure_retries=2`, so the approved source is pinned and only
transient transport failures on that same source are retried.

## What the recorded sequence shows

`request-records.md` contains eight GETs, in order:

1. **Requests 1–2 — broad platform (warm-up only).** A system-assigned token is
   acquired from the broader platform and placed into the process token cache,
   then re-keyed under the approved identity's cache slot and marked *aging* so
   the next call is forced to refresh on the network. This is the "broad
   identity already warm in the cache" precondition.
2. **Requests 3–4 — first approved attempt.** The pinned client calls only the
   approved endpoint (challenge, then the authenticated token GET). Request 4
   fails with a transient `ConnectionError`.
3. **Requests 5–6 — same-source retry and recovery.** The retry restarts the
   Arc challenge/token pair against the **same approved endpoint**, which now
   succeeds and echoes `approved-user-assigned-client-id`. The returned token is
   attributed to the approved identity (`token_source=identity_provider`).
4. **Requests 7–8 — fail-closed run.** A second client points at a rogue
   approved endpoint that answers with the broad identity. MSAL raises
   `ManagedIdentityMismatchError`; nothing is cached and the broad endpoint is
   never contacted.

## Why the warm, broad identity never changes either result's attribution

Three independent guarantees, each visible in the records:

- **Source pinning.** Every request carrying the approved `client_id` goes to
  `approved-platform.example`. The flag
  `approved_client_ever_used_broad_endpoint` is `false`, and the recording
  router raises if asked for a route that was not approved. A retry therefore
  cannot move the call to the broader platform — failure recovery re-issues the
  same request to the same source rather than hunting for another entry point.
- **Fail-closed identity confirmation.** The approved endpoint must echo the
  exact requested identity. When it instead returns
  `machine-shared-system-assigned-id`, the response is rejected with
  `ManagedIdentityMismatchError` before a token is cached or returned. The
  `rogue_token_cached` flag stays `false`.
- **Cache isolation.** The broad token is keyed by its identity (`client_id`),
  resource, environment and realm, and a mismatch error bypasses the normal
  cached-token fallback. So even though the broad token is already resident in
  the process cache, the mismatch path raises instead of handing it back, and
  the successful path overwrites the slot only with a token the approved
  endpoint actually confirmed (request 6). The later step-3 read is then served
  from that approved-identity cache entry with zero new network calls.

The net effect: the first acquisition fails transiently and is retried on the
original source, the later acquisition succeeds on that same source, and in
neither case does the pre-warmed broad identity influence which identity the
returned token belongs to.

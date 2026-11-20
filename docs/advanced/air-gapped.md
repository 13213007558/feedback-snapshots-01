# Air-gapped deployment

This page is a deployment runbook for running `sigstore verify` on machines with
no outbound network access. It assumes a split workflow:

* a **connected staging host** periodically fetches trust material; and
* an **isolated verification host** receives that material as files and runs
  every verification with `--offline`.

The rules below are derived from this client's behavior, not from general
Sigstore guidance. Where a rule is enforced by code, the enforcing module is
named so it can be re-checked after an upgrade.

Most of this page is executable: `tools/offline_readiness.py` inspects a root or
bundle, blocks every socket, and reports what can and cannot be verified locally.

```console
$ python tools/offline_readiness.py --help
```

## What `--offline` actually changes

`sigstore verify --offline` touches two independent switches:

1. **TUF refresh is skipped.** `TrustUpdater` is constructed with
   `offline=True`, so `Updater.refresh()` never runs and no metadata is fetched.
   The client reads `trusted_root.json` and `signing_config.v0.2.json` straight
   from the target cache directory, *without TUF verification*
   (`sigstore/_internal/tuf.py`, `get_trusted_root_path` /
   `get_signing_config_path`).
2. **Transparency-log lookup is skipped.** Detached `.crt`/`.sig` inputs look up
   their log entry online; `--offline` rejects that combination outright
   (`--offline cannot be used with --certificate or --signature`). Bundles carry
   their own log entry, so they need no lookup.

Everything else — certificate chain building, SCT verification, inclusion
proof/checkpoint, inclusion promise, timestamp verification, signature and log
body consistency — is performed locally against the bundle and the trusted root.

!!! warning "Offline means unverified trust material"
    Because the cache is read without TUF verification, an attacker who can
    write to the target cache can substitute the trust root. Treat the cache
    directory as security-sensitive and populate it only from material that
    arrived over an authenticated channel.

## Cache layout

The two directories come from `platformdirs`, keyed by the URL-quoted TUF
repository URL:

| Purpose | Path |
| --- | --- |
| TUF metadata | `$XDG_DATA_HOME/sigstore-python/tuf/<quoted-url>/` |
| Targets | `$XDG_CACHE_HOME/sigstore-python/tuf/<quoted-url>/` |

On macOS these expand to `~/Library/Application Support/...` and
`~/Library/Caches/...`; on Linux, `~/.local/share/...` and `~/.cache/...`.

Only two files in the **targets** directory matter for offline verification:

```
<targets>/trusted_root.json
<targets>/signing_config.v0.2.json
```

`root.json` in the metadata directory is *not consulted at all* in offline
mode. It only matters when the client later runs an online refresh.

## Three states, three responses

### State 1 — the host already has a usable root

Use the root that is present. In priority order:

1. `--trust-config FILE` — a complete `ClientTrustConfig` JSON document. This
   bypasses TUF and the cache entirely and is the most reproducible option.
2. `--instance URL` with a populated target cache (see above).
3. `--staging` / default production with the target cache, or the roots baked
   into the installed package (`sigstore/_store/`) when the cache is empty.

Verify with `--offline` and confirm the report shows the root you expect.

### State 2 — the cached root is stale or expired

Two different expiries exist and they behave differently:

**TUF metadata expiry (`root.json` / `timestamp.json` / `targets.json`
`expires`).** Enforced only during an online refresh. With `--offline` it is
never checked, so an expired `root.json` does not by itself break verification.
The risk is that new root keys or revocations issued after your snapshot will be
missed. Fix by delivering a fresh metadata snapshot from the connected host.

**Trusted-root content expiry (`validFor` on CAs and TSAs).** Checked during
verification, but narrowly:

* A TSA outside its `validFor` window yields no verified time. If the bundle
  has no other time source, verification fails with
  `not enough sources of verified time`.
* The Fulcio `validFor` window is **not** consulted when building the
  certificate chain: `get_fulcio_certs()` uses `allow_expired=True` and chain
  validation uses the bundle's signed time. A CA window that has closed
  therefore does not invalidate bundles that were timestamped inside it.
  Likewise, a CA whose window has not started yet is not rejected on that
  basis, so rotation is a policy decision rather than an enforced boundary.
* TLOG and CT log entries carry no `validFor` in the v0.1 trusted root.

The practical rule: if bundles still verify, the root is adequate for them; do
not rotate purely because a CA window closed. Rotate when a bundle fails to
chain, or when the connected host reports a newer root version.

### State 3 — the bundle is missing a class of proof

The bundle must be repaired at the signing side; no amount of trust material
will substitute. Which classes are load-bearing, measured against
`test/assets/` with sockets blocked:

| Removed from bundle | Result | Why |
| --- | --- | --- |
| signing certificate | rejected at load | bundle must carry exactly one verification key |
| log entry | rejected at load | bundle must carry exactly one entry |
| inclusion proof | rejected at load | proof is mandatory for every supported bundle version |
| inclusion proof checkpoint | rejected at load | proof without a signed checkpoint is useless |
| inclusion promise | fails at verify (`not enough sources of verified time`) | it was the only time source |
| signed timestamps | **still verifies** | the promise supplied the time instead |

Notes that prevent false alarms:

* A missing **inclusion promise** is only fatal when nothing else supplies
  time. Rekor v2 bundles legitimately omit it and carry RFC3161 timestamps.
* A missing **signed timestamp** is only fatal when the promise is also absent.
* `sigstore plumbing fix-bundle` can repair a proof that is present but lacks
  a checkpoint. It always contacts Rekor, so it must run on the connected host.

## Checklist

Run from the repository root on the isolated host. Set `PY` to the interpreter
that has `sigstore` installed.

1. **Confirm the package and its baked-in roots.**
   ```console
   $PY -m sigstore --version
   $PY -c "from sigstore._utils import read_embedded; \
           print(len(read_embedded('trusted_root.json', 'https://tuf-repo-cdn.sigstore.dev')))"
   ```

2. **Inventory what the host can already verify, with sockets blocked.**
   ```console
   $PY tools/offline_readiness.py --embedded \
       --bundle dist/foo.whl.sigstore.json
   ```
   `[verified]` means no network is needed for that bundle. A categorized
   failure (`bundle-missing-proof`, `root-missing-tsa`, ...) names which side
   must supply input.

3. **Check the cache, if the deployment uses `--instance`.**
   ```console
   $PY tools/offline_readiness.py \
       --tuf-url https://sigstore.example.com \
       --bundle dist/foo.whl.sigstore.json
   ```
   The report prints both cache directories, the files present, and whether
   `root.json` is expired.

4. **Prove the refresh path works before shipping material.** This exercises
   the real `ClientTrustConfig.from_tuf` refresh using a fake downloader and
   blocks all sockets:
   ```console
   $PY tools/offline_readiness.py --selftest \
       --selftest-targets /path/to/staged/targets
   ```
   `network_requests: 0` plus a non-zero `refreshed_tlogs` is the pass
   condition.

5. **Run the acceptance verification.**
   ```console
   $PY -m sigstore verify identity \
       --offline \
       --cert-identity 'builder@example.com' \
       --cert-oidc-issuer 'https://issuer.example.com' \
       dist/foo.whl \
       --bundle dist/foo.whl.sigstore.json
   ```
   Success prints `OK: dist/foo.whl`.

6. **Record the inputs that must flow back to the staging host.** Any
   `bundle-missing-*` verdict means the artifact must be re-signed. Any
   `root-missing-*` verdict means the staging host must deliver a newer
   `trusted_root.json`.

## What must cross the air gap

| Input | Needed when | Produced by |
| --- | --- | --- |
| `trusted_root.json` | always, unless `--trust-config` is used | TUF refresh on staging host |
| `signing_config.v0.2.json` | only for `--instance` cache mode | TUF refresh on staging host |
| `root.json` | only for a later online refresh | TUF refresh on staging host |
| `ClientTrustConfig` JSON | preferred when using `--trust-config` | assembled on staging host |
| `*.sigstore.json` bundle | per artifact | the signer |
| re-signed bundle | when a proof class is missing | the signer, on the connected host |

Nothing else is required. In particular, no verification step opens a socket
when a bundle and a trusted root are present.

## Failure messages and their owners

| Message | Owner | Action |
| --- | --- | --- |
| `--offline cannot be used with --certificate or --signature` | deployment | switch to bundle inputs |
| `FileNotFoundError: .../trusted_root.json` (custom instance) | staging host | deliver `trusted_root.json` |
| `bundle must contain an inclusion promise or signed timestamp(s)` | signer | re-sign with a time source |
| `entry must contain inclusion proof, with checkpoint` | signer | re-sign, or `fix-bundle` online |
| `no Timestamp Authorities have been provided ...` | staging host | deliver a root containing the TSA |
| `failed to build timestamp certificate chain` | deployment | wrong instance/root for this bundle |
| `not enough sources of verified time` | signer or staging host | add a time source or a valid TSA |

## Known limitation in the test fixtures

`test/assets/staging-tuf/` declares `signing_config.v0.2.json` as 1022 bytes
while the file on disk is 1021 bytes, so a TUF refresh driven from those
fixtures fails with `Observed length 1021 does not match expected length 1022`.
This is pre-existing and unrelated to air-gapped operation; use `--selftest`
with a freshly built local repository, or real `sigstore.dev` material,
instead of the staging fixtures.

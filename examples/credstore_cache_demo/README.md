# Credential-list cache over decrypted CTAP Info fields

A scoped example showing how an authenticator-management backend may reuse a
resident-credential inventory keyed on the values python-fido2 decrypts from
two CTAP 2.1 `authenticatorGetInfo` fields, **without** treating decryptable
bytes as an authenticated device identity.

## What the two Info fields are

Both fields are returned by `fido2.ctap2.base.Info` and decrypted with the
*persistent* PIN/UV auth token (PUAT):

| CBOR key | `Info` attribute | Decryptor | Purpose |
| --- | --- | --- | --- |
| `0x38` | `enc_identifier` | `Info.get_identifier(token)` | Opaque encrypted device identifier |
| `0x3B` | `enc_cred_store_state` | `Info.get_cred_store_state(token)` | Opaque credential-store state |

Construction (identical in the library and in this example, see
`pinuv2.py`):

```
key = HKDF-SHA-256(ikm = persistent PUAT,
                   salt = 32 zero bytes,
                   info = b"encIdentifier" | b"encCredStoreState",
                   L = 16)          # AES-128
plaintext = AES-128-CBC-decrypt(key, iv = blob[:16], ciphertext = blob[16:])
```

The two `info` strings give the two fields **purpose-separated keys** derived
from the same token; a key for one field cannot be used for the other.

### What decryption does and does not guarantee

This construction is AES-CBC with **no embedded authentication tag**.
Consequences, all demonstrated by `demo.py`:

- A wrong key still produces output of exactly the plaintext's length
  (`len(ciphertext) - 16`). "It decrypted" only means the block framing held.
- Padding usually fails under the wrong key, but with probability ~1/256 the
  final byte is a valid `0x01`, so strict PKCS#7 validation can succeed on
  garbage. The demo searches for such a key and prints the bogus identifier.
- Therefore the decrypted bytes are **decoded-only**: usable as opaque cache
  keys, never as proof of which device is attached.

We deliberately do **not** add a MAC to the existing CBC blobs. The on-wire
format has no tag field, so a locally computed tag could only be verified by
the party that invented it - it would add a *claim* of verifiability without
any authenticator to verify against. Authenticity must come from the
authenticated CTAP session instead (below).

## Where trust actually comes from

| Conclusion | Source | Label |
| --- | --- | --- |
| Which physical device / transport this is | Caller-confirmed connection (open transport, successful `getInfo`) | upper-layer trusted fact |
| The token is valid and has `persCredentialMgmt` | pinUvAuth v2 ECDH + user verification + authenticator HMAC checks on each command | upper-layer trusted fact |
| Token generation | Backend bookkeeping, incremented on every (re)issuance | upper-layer trusted fact |
| Decrypted identifier / store-state bytes | AES-CBC decryption only | `DECODED_ONLY` |
| Cached credential list contents | Enumeration via HMAC-authenticated credential-management commands | `SESSION_AUTHENTICATED` |

The pinUvAuthProtocol v2 channel itself uses purpose-separated HKDF outputs
from the ECDH shared secret `Z`: `b"CTAP2 HMAC key"` (32B) for the HMAC that
authenticates commands, and `b"CTAP2 AES key"` (32B) for wrapping the token.
The PUAT used to derive the Info-field keys is a separate 32-byte value.

## Persistent token lifecycle and cache invalidation

The composite cache key (`cred_cache.CacheKey`) binds **all** of:
connection id, token generation, decoded identifier, decoded store state.
Refresh (re-enumerate over the authenticated channel) is required on:

- **Factory reset** - the device regenerates the identifier secret, store
  state and PUAT together; every prior value is meaningless.
- **Token replacement / rotation** - token generation changes; the old
  session is closed and its cache entry dropped.
- **Credential store change** - add/delete/update rotates
  `encCredStoreState`, so the key no longer matches and the entry is stale.
- **New connection handle** - even with a persistent PUAT that survives
  reconnect, the connection id is a new upper-layer fact; the entry is
  invalidated and re-enumerated rather than silently inherited.

A non-persistent token would not survive a power cycle, so cross-reconnect
reuse is only considered at all because the backend explicitly requested the
persistent credential-management permission (`0x40`).

The cache is in-memory, holds one entry per connection, and is never written
to disk: a cache is an optimisation inside one trusted process, not a store
of device identities.

## Three distinct failure classes

- `MissingFieldError` - the Info object omits the field (older/smaller
  authenticator). A negotiation outcome, not a security error; fall back to a
  fresh enumeration.
- `UnparseableFieldError` - field present but framing/padding invalid
  (truncated blob, non-block-length ciphertext, bad PKCS#7).
- `AuthenticityError` - the upper-layer binding cannot be made or no longer
  matches (foreign connection id, stale token generation). Decryption may
  still succeed; the value is rejected anyway.

## Files

- `trust.py` - error taxonomy, `TrustLabel`, `TrustedBinding`, `DecodedValue`.
- `pinuv2.py` - ECDH, purpose-separated HKDF, CBC/HMAC, strict Info decoding.
- `software_device.py` - in-process CTAP authenticator (persistent PUAT,
  reconnect, rotation, reset, store mutations) on top of the real `Info`.
- `cred_cache.py` - composite-key cache and `get_or_refresh`.
- `manager.py` - upper-layer orchestration that owns the trusted session.
- `demo.py` - the seven required scenarios.
- `test_credstore_cache.py` - pytest coverage.

## Running

```
python -m examples.credstore_cache_demo.demo
python -m pytest examples/credstore_cache_demo
```

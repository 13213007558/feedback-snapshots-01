# WebAuthn registration attestation audit: field-level privacy plan

This plan is based on what `webauthn-ruby` 3.5.1 actually parses and returns for
`WebAuthn::Credential.from_create`, not on fields that a browser might expose.
The goal is an audit record that can explain an admission decision after the raw
attestation has been deleted, while keeping the verification path on the full
original material.

## 1. What the library actually returns

`PublicKeyCredentialWithAttestation` exposes the following after
`from_create` and `verify`.

| Field | Source | Actual type | Notes |
| --- | --- | --- | --- |
| `id` | top-level JSON `id` | String, base64url | Same bytes as `rawId`, text encoding only |
| `raw_id` | top-level JSON `rawId` | binary String | Decoded by the configured encoder |
| `type` | top-level JSON `type` | String | Always `public-key` |
| `authenticator_attachment` | client JSON | String or nil | Client-declared hint, not proof |
| `client_extension_outputs` | client JSON | Hash or nil | Client extension output |
| `response.attestation_type` | set during successful verification | String or `false` | `None`, `Self`, `Basic`, `AttCA`, `Basic_or_AttCA`, `AnonCA` |
| `response.attestation_trust_path` | set during verification | Array of `OpenSSL::X509::Certificate` or nil | The `x5c` certificates only; the root is not included |
| `response.transports` | client JSON | Array or nil | Client hint; nil if omitted |
| `response.aaguid` | `authData` attested credential data | UUID String or nil | nil when the raw AAGUID is all zero |
| `response.attestation_certificate_key_id` | leaf certificate SKI | Hex String or nil, or raises | Raises `NoMethodError` when there is no attestation certificate |
| `response.authenticator_data` | `authData` | `WebAuthn::AuthenticatorData` | Includes flags, sign count, RP ID hash |
| `response.credential` | `authData` | Struct with `id`, `public_key`, `algorithm` | No user handle |
| `response.client_data` | `clientDataJSON` | `WebAuthn::ClientData` | `type`, `challenge`, `origin`, `cross_origin`, `top_origin`, `hash` |
| `response.attestation_statement` | `attStmt` | Format object | Includes `alg`, `sig`, `x5c` or format-specific fields |
| `public_key` | credential public key | COSE bytes, re-encoded | The only long-term signing material needed |

Important boundaries confirmed against the local fixtures:

- Registration does not contain a user handle. `userHandle` exists only in the
  assertion response, via `PublicKeyCredentialWithAssertion#raw_user_handle`.
  The registration user ID is something the RP generated and sent in the
  creation options, not something returned in the attestation response.
- `attestation_trust_path` is the `x5c` chain as returned by the authenticator.
  In the local Yubico fixture it has length 1; the configured root is used for
  validation but is not part of the response.
- `attestation_certificate_key_id` is not a safe generic field. For `none` and
  self attestation there is no certificate, and calling it raises
  `NoMethodError` instead of returning nil.
- `aaguid` is nil for a zeroed AAGUID, but the raw 16 zero bytes are still
  present in `authData`. "No AAGUID" and "unknown model" must not be conflated.

## 2. Field classification

### A. Must retain for authentication and admission explanation

These are needed either to authenticate later or to explain why the
registration was admitted.

| Field | Retention form | Why |
| --- | --- | --- |
| Credential ID | Keyed reference (HMAC) plus byte length | It is the lookup key for every future assertion. The raw value can stay in the credential store, but the audit system should not need it |
| Credential public key | Raw bytes in the credential store only; never in audit | Required to verify assertions. It is a public value, but it is not needed to explain the admission decision |
| `sign_count` at registration | Integer | Baseline for clone/rollback detection |
| RP ID hash | Hex string | Ties the event to the RP scope; not a user identifier |
| `origin`, `cross_origin`, `top_origin` | Exact values | Explains origin and cross-origin policy decisions |
| Challenge | Keyed reference or SHA-256 | Proves the response was for this ceremony without retaining a reusable challenge |
| Client data hash | SHA-256 | Commits to the exact `clientDataJSON` without retaining it |
| UV/UP/BE/BS flags | Booleans | Explains user-presence, user-verification and backup policy decisions |
| Attestation format and type | Short enum strings | Explains which policy branch was taken |
| Policy version and digest | Version string plus SHA-256 of canonical policy | Explains the rule set that accepted the registration |
| Verifier implementation and version | String | Explains parser/verifier behavior |
| Result and error class | Boolean plus class name | Explains admission or rejection without storing raw input |

The audit record should also carry a stable event ID and timestamp. Neither is
derived from authenticator data.

### B. Optional, for troubleshooting and constrained retention

These help investigate a specific incident, but are not needed for every event.
Keep them behind a short retention window, a restricted access role, or an
explicit incident flag.

| Field | Suggested form | Risk |
| --- | --- | --- |
| AAGUID | Plain UUID, only when non-zero | Model/authenticator-family correlation |
| Attestation certificate leaf hash | SHA-256 of DER | Stable across registrations from the same model/batch; can link devices |
| Certificate issuer CN | String | May reveal vendor and model family |
| Certificate validity window | Timestamps | Low risk; useful for explaining chain validation at the time |
| Certificate serial | Hex, only if policy requires batch tracing | High correlation risk; can be a device/batch identifier |
| Certificate SKI | Hex, only if policy requires it | Key identifier; can link certificates from the same batch |
| `authenticator_attachment` | String | Client hint; weak device-class signal |
| `transports` | Sorted array | Client hint; can narrow device form factor |
| Raw attestation commitment | SHA-256 of the full `attestationObject` | Supports later proof that a specific object was seen, but the object itself is gone. Do not treat this as a substitute for the signature |
| Raw client data commitment | SHA-256 | Same caveat as above |
| Client extension outputs | Redacted JSON | May contain app IDs or other correlators; inspect per extension |

Certificate subject and SAN deserve special handling. In the local fixtures,
the Yubico subject contains a device serial
(`CN=Yubico U2F EE Serial 1955003842`), the TPM SAN contains
`tcg-at-tpmManufacturer`, `tcg-at-tpmModel` and `tcg-at-tpmVersion`, and the
Apple leaf subject contains a long opaque identifier. These are not merely
"device model" fields:

- A model string (for example `tcg-at-tpmModel=ADL`) is a model/family label,
  not a unique device ID.
- A serial or an opaque per-device subject identifier can uniquely or
  near-uniquely identify a device and link registrations.
- A CA subject and a leaf subject have different meanings; hashing the whole
  subject conflates them and loses the ability to explain chain validation.

Therefore, do not hash every value and do not treat a model string as a unique
device ID. Store only the specific attributes the policy actually evaluates,
and default to omitting the full subject/SAN.

### C. Do not retain long-term

| Field | Reason |
| --- | --- |
| Full `attestationObject` | Contains the entire certificate chain and signature; large, linkable, and not needed after verification |
| Full `clientDataJSON` | Contains the challenge and origin; the hash is enough for audit |
| Full `x5c` chain | Duplicates the attestation object and increases linkability; keep leaf hash and validation result instead |
| Raw credential public key in audit | Needed in the credential store, not in the audit system |
| Raw credential ID in audit | The credential store owns it; the audit system should use a keyed reference |
| Full certificate subject/SAN | Can contain device serials, batch IDs, and model strings; parse only named attributes if required |
| Raw signature (`sig`) | Verification result is sufficient; the signature alone does not explain admission without the full signed data |
| Raw challenge | Reusable within its validity window; use a keyed reference or hash |
| `userHandle` in registration audit | Not returned by registration; when handling assertions, treat it as a stable user identifier and use a keyed reference |
| Any raw request body or exception message containing the above | Accidental copies defeat the field-level policy |

Keyed references are not "hashing everything." They are a deliberate
pseudonymization tool for identifiers that must remain joinable inside the
audit system (credential ID, user handle, challenge). Use HMAC-SHA256 with a
secret key and a key ID, not a bare hash, so that low-entropy values cannot be
enumerated. Rotation requires keeping the old key available for old records or
accepting that old references are no longer joinable.

## 3. Correlation capability by identifier

| Identifier | What it can correlate | Scope | Recommended audit treatment |
| --- | --- | --- | --- |
| Credential ID | All assertions for one credential; re-registration attempts with the same ID | One credential, one RP | Keyed reference plus byte length. Raw value stays in the credential store |
| User handle | All credentials and assertions for one user, if the RP uses a stable handle | One user across authenticators | Keyed reference; never log raw in registration or assertion audit |
| AAGUID | Authenticator model/family; not a specific device | Model/family | Plain UUID only when non-zero; treat as model class, not device ID |
| Certificate serial | Certificates issued in the same batch; sometimes one device | Batch or device | Omit by default; if required, keep under short retention and restrict access |
| Full attestation chain | Vendor, model family, batch, and potentially a specific device; also links all registrations that share the chain | Vendor/batch/device | Do not retain the chain. Keep leaf hash, issuer CN, validity window, trust-path length, root anchor hash, and the verification result |

AAGUID and certificate serial are not interchangeable. AAGUID answers "what
kind of authenticator," while a serial can answer "which unit or batch." A
zeroed AAGUID means the authenticator did not provide a model identifier; it
does not mean the device is unknown or untrusted. The TPM SAN model string is
also a model label, not a unique device ID.

## 4. Evidence boundary after deleting the raw attestation

Deleting the raw attestation means the audit system can no longer re-run the
cryptographic verification. It can still explain the admission decision if it
retains:

1. The verifier implementation and version, so the exact parser and policy
   logic are known.
2. The policy version and canonical policy digest, so the accepted attestation
   types, UP/UV requirements, and root configuration are known.
3. The attestation format and type, plus whether the policy asked for statement
   verification and whether the statement signature/trust path were actually
   verified.
4. The leaf certificate hash and the root anchor hash used for validation.
   The chain count is useful context, but hashing every chain element is
   optional and should not be the default.
5. The RP ID hash, origin, cross-origin/top-origin values, client data hash,
   and challenge reference.
6. The credential reference, byte length, algorithm, sign count, and flags.
7. The result and error class, including the exact error name for a rejection.

This supports statements such as "on 2026-11-16, version 3.5.1 accepted a
packed/Basic_or_AttCA registration for RP hash X, origin Y, with UP=true,
UV=false, a valid statement signature, and a trust path anchored at root hash
Z." It does not support "re-verify this signature now" or "prove that the
certificate chain was valid under today's trust store." The latter requires the
original material or a separately retained trusted timestamp/validation
receipt.

If the policy needs post-hoc cryptographic re-verification, the correct design
is a separate, access-controlled evidence store with a defined retention
period, not a permanent copy in the audit log. The audit record can hold a
commitment (SHA-256) to that stored object.

## 5. Suggested audit objects for the three local responses

The examples below were generated by running the local fixtures through
`webauthn-ruby` 3.5.1 and the adapter in
`docs/examples/registration_audit_adapter.rb`. The `none` example is a
synthetic response built from `FakeAuthenticator::AuthenticatorData`; its
random credential key makes the `raw_attestation_sha256` value illustrative
rather than reproducible. The self and certificate examples use the
`security_key_packed_self` and `security_key_packed_x5c` fixtures; the
certificate example was verified against
`spec/support/roots/yubico_u2f_root.pem`.

### none

```json
{
  "schema": "webauthn.registration.audit/v1",
  "event_id": "<uuid>",
  "occurred_at": "<ISO-8601 UTC>",
  "ceremony": "webauthn.create",
  "result": {
    "verified": true,
    "error": null
  },
  "policy": {
    "version": "attestation-policy-2026-11",
    "sha256": "3920a9016d16dc6c04088542eba44cd75bcba680738fb7035e8588a154d91ad4",
    "acceptable_attestation_types": [
      "None",
      "Self",
      "Basic",
      "AttCA",
      "Basic_or_AttCA",
      "AnonCA"
    ],
    "require_user_presence": true,
    "require_user_verification": false,
    "verify_attestation_statement": true
  },
  "verifier": {
    "implementation": "webauthn-ruby/3.5.1",
    "policy_version": "attestation-policy-2026-11"
  },
  "reference": {
    "algorithm": "HMAC-SHA256",
    "key_id": "audit-ref-v1"
  },
  "rp": {
    "id_hash": "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763",
    "origin": "http://localhost",
    "cross_origin": null,
    "top_origin": null
  },
  "credential": {
    "ref": "hmac-sha256:cf0701e02d03258994d15db1212ff57ac1c4962dff85726f1a0c2426737320a4",
    "id_bytes": 18,
    "algorithm": "ES256"
  },
  "user": null,
  "authenticator": {
    "aaguid": null,
    "aaguid_zero": true,
    "flags": {
      "up": true,
      "uv": false,
      "be": false,
      "bs": false
    },
    "sign_count": 0,
    "attachment": "platform",
    "transports": [
      "internal"
    ]
  },
  "attestation": {
    "format": "none",
    "type": "None",
    "certificate": null,
    "trust_path_length": 0,
    "root_anchor_sha256": null,
    "proof": {
      "kind": "none",
      "statement_signature_verified": false,
      "trust_path_verified": false
    }
  },
  "client_data": {
    "hash_sha256": "b55d1bc00b5ac1a93926bf7cb52e7ddcafe562f684a49fde4a20f570cadb437d",
    "type": "webauthn.create",
    "challenge_ref": "hmac-sha256:c4c62223251fac4c3a892e2e578e6d05dccd0ee681160cbf1bd107ed872157ff",
    "origin": "http://localhost",
    "cross_origin": null,
    "top_origin": null
  },
  "evidence": {
    "raw_attestation_sha256": "eb6007e978cf959189ba1376476baefdbe62d5a63b76a719e28aaf9f03db14af",
    "raw_attestation_retained": false,
    "raw_client_data_retained": false
  }
}
```

### self

```json
{
  "schema": "webauthn.registration.audit/v1",
  "event_id": "<uuid>",
  "occurred_at": "<ISO-8601 UTC>",
  "ceremony": "webauthn.create",
  "result": {
    "verified": true,
    "error": null
  },
  "policy": {
    "version": "attestation-policy-2026-11",
    "sha256": "3920a9016d16dc6c04088542eba44cd75bcba680738fb7035e8588a154d91ad4",
    "acceptable_attestation_types": [
      "None",
      "Self",
      "Basic",
      "AttCA",
      "Basic_or_AttCA",
      "AnonCA"
    ],
    "require_user_presence": true,
    "require_user_verification": false,
    "verify_attestation_statement": true
  },
  "verifier": {
    "implementation": "webauthn-ruby/3.5.1",
    "policy_version": "attestation-policy-2026-11"
  },
  "reference": {
    "algorithm": "HMAC-SHA256",
    "key_id": "audit-ref-v1"
  },
  "rp": {
    "id_hash": "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763",
    "origin": "https://localhost:13010",
    "cross_origin": null,
    "top_origin": null
  },
  "credential": {
    "ref": "hmac-sha256:6fc0e8dc064b669a75ac0fc5a635813da9760022e729f8c5b79d63201ea98e7c",
    "id_bytes": 118,
    "algorithm": "ES256"
  },
  "user": null,
  "authenticator": {
    "aaguid": null,
    "aaguid_zero": true,
    "flags": {
      "up": true,
      "uv": true,
      "be": false,
      "bs": false
    },
    "sign_count": 1538712791,
    "attachment": "cross-platform",
    "transports": null
  },
  "attestation": {
    "format": "packed",
    "type": "Self",
    "certificate": null,
    "trust_path_length": 0,
    "root_anchor_sha256": null,
    "proof": {
      "kind": "self",
      "statement_signature_verified": true,
      "trust_path_verified": false
    }
  },
  "client_data": {
    "hash_sha256": "36decc142a631b25f9e21bd473461a2fb9edb9c2c5aec3510b675ac1116b97ea",
    "type": "webauthn.create",
    "challenge_ref": "hmac-sha256:f3fcc994d05ad119e6f326352521d3fd7b8cede7dab0cee584a54d9891c8c432",
    "origin": "https://localhost:13010",
    "cross_origin": null,
    "top_origin": null
  },
  "evidence": {
    "raw_attestation_sha256": "44ef3aa732d8c54c57193d75356fe9745c3ef7dbd0bb1ade9038c4d6a238401f",
    "raw_attestation_retained": false,
    "raw_client_data_retained": false
  }
}
```

### certificate

```json
{
  "schema": "webauthn.registration.audit/v1",
  "event_id": "<uuid>",
  "occurred_at": "<ISO-8601 UTC>",
  "ceremony": "webauthn.create",
  "result": {
    "verified": true,
    "error": null
  },
  "policy": {
    "version": "attestation-policy-2026-11",
    "sha256": "3920a9016d16dc6c04088542eba44cd75bcba680738fb7035e8588a154d91ad4",
    "acceptable_attestation_types": [
      "None",
      "Self",
      "Basic",
      "AttCA",
      "Basic_or_AttCA",
      "AnonCA"
    ],
    "require_user_presence": true,
    "require_user_verification": false,
    "verify_attestation_statement": true
  },
  "verifier": {
    "implementation": "webauthn-ruby/3.5.1",
    "policy_version": "attestation-policy-2026-11"
  },
  "reference": {
    "algorithm": "HMAC-SHA256",
    "key_id": "audit-ref-v1"
  },
  "rp": {
    "id_hash": "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763",
    "origin": "http://localhost:3000",
    "cross_origin": null,
    "top_origin": null
  },
  "credential": {
    "ref": "hmac-sha256:89f5e6031d2f20912c814b723fad7deb63c85c5a595e97935b8aa5872985828f",
    "id_bytes": 64,
    "algorithm": "ES256"
  },
  "user": null,
  "authenticator": {
    "aaguid": "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
    "aaguid_zero": false,
    "flags": {
      "up": true,
      "uv": false,
      "be": false,
      "bs": false
    },
    "sign_count": 45,
    "attachment": "cross-platform",
    "transports": null
  },
  "attestation": {
    "format": "packed",
    "type": "Basic_or_AttCA",
    "certificate": {
      "leaf_sha256": "aa2f963ab04eb965b906cd8d52e89d6694a45a9954333fc3a82f2c8dbaf33ff9",
      "issuer_cn": "Yubico U2F Root CA Serial 457200631",
      "not_before": "2014-08-01T00:00:00Z",
      "not_after": "2050-09-04T00:00:00Z"
    },
    "trust_path_length": 1,
    "root_anchor_sha256": "0fa1386f80eb8713263ae5c1d84deb455bdf08aea50ab05503cefee82b092d42",
    "proof": {
      "kind": "certificate-chain",
      "statement_signature_verified": true,
      "trust_path_verified": true
    }
  },
  "client_data": {
    "hash_sha256": "2aae5ff6ff101e96d55b64bbd26cce86998550ad8bf31bc9b64f3ee693644348",
    "type": "webauthn.create",
    "challenge_ref": "hmac-sha256:fa475073159406559773c3e249e35251174bb0d8c1d91d3c93fe79dd68a4c265",
    "origin": "http://localhost:3000",
    "cross_origin": null,
    "top_origin": null
  },
  "evidence": {
    "raw_attestation_sha256": "08b205fc56cf73b5ddb80409e297df18f4b1317d16dd763af881d10f9e9180aa",
    "raw_attestation_retained": false,
    "raw_client_data_retained": false
  }
}
```

## 6. What review capability is kept or lost

| Question a reviewer may ask | none | self | certificate | Why |
| --- | --- | --- | --- | --- |
| Was the attestation statement signed? | No | Yes, by the credential key | Yes, by the attestation key | Recorded in `proof.statement_signature_verified` |
| Was the certificate chain trusted? | Not applicable | No certificate | Yes, against the configured root | `proof.trust_path_verified` |
| Which authenticator model? | Unknown (zero AAGUID) | Unknown (zero AAGUID) | AAGUID `f8a011f3-...` | AAGUID is present only in the certificate example |
| Which specific device? | No | No | Not determinable from the retained fields | The chain could support batch/device correlation, but it is deleted |
| Was the challenge bound to this registration? | Yes, via challenge reference | Yes | Yes | `challenge_ref` is a keyed reference; the raw challenge is deleted |
| Can the signature be re-verified later? | No | No | No | Raw attestation and chain are deleted |
| Can the admission decision be explained? | Yes | Yes | Yes | Policy, verifier version, result, flags, and evidence commitments remain |
| Can the credential still authenticate? | Yes | Yes | Yes | The credential store keeps the credential ID and public key |

The certificate example's leaf is also its only `x5c` entry. The root is
external configuration, so `trust_path_length: 1` does not mean "self-signed."
It means "one certificate was returned by the authenticator." The audit record
therefore stores the root anchor hash separately.

For Apple and TPM attestation, the leaf certificate can contain a per-device
subject identifier or SAN model fields. If those are retained, they should be
treated as optional troubleshooting data, not as ordinary audit metadata. A
model string such as `tcg-at-tpmModel=ADL` is not a unique device ID; a serial
or per-device subject CN may be.

## 7. Minimal redaction adapter

`docs/examples/registration_audit_adapter.rb` implements the record above.
The adapter takes an already-verified credential and the raw attestation object
only to compute commitments. It never copies `attestationObject`,
`clientDataJSON`, the raw credential ID, or the certificate chain into the
record. `statement_verified` is the caller's record of whether the attestation
statement signature was checked and valid. It is false for `none` because that
format has no statement signature to verify.

```ruby
credential = WebAuthn::Credential.from_create(params[:publicKeyCredential])
credential.verify(session[:creation_challenge], user_verification: true)

statement_verified =
  !credential.response.attestation_type.nil? &&
  credential.response.attestation_type != "None"

audit = RegistrationAudit::Redactor.new(
  hmac_key: ENV.fetch("AUDIT_REFERENCE_KEY"), # >= 32 bytes, stored outside the audit DB
  policy: {
    version: "attestation-policy-2026-11",
    acceptable_attestation_types: ["None", "Self", "Basic", "AttCA", "Basic_or_AttCA", "AnonCA"],
    require_user_presence: true,
    require_user_verification: true,
    verify_attestation_statement: true
  },
  root_anchor_sha256: root_anchor_sha256 # hash of the root cert actually configured
).build(
  credential,
  raw_attestation_object: raw_attestation_object,
  statement_verified: statement_verified,
  user_handle: nil # registration has no user handle; use the RP's own user reference if needed
)

AuditLog.write(audit)
```

The signing path must keep using the full original material. Verify with
`credential.verify` before redaction, and store the credential ID and public
key in the credential store exactly as the library returns them. The audit
record is a derived artifact; it must not replace the credential store or the
verification input.

A verified end-to-end check in this checkout:

```text
registration verified; credential_id_bytes=16 public_key_bytes=77
audit_record_bytes=1595
raw_attestation_in_audit=false
raw_credential_id_in_audit=false
raw_certificate_absent=true
assertion verified after dropping raw registration material
```

That last line is the important boundary: after the raw attestation, client
data, and certificate chain are dropped, a later assertion still verifies with
the stored credential ID and public key. The audit record explains why the
registration was admitted, but it is not a substitute for the credential store
or for the original evidence if cryptographic re-verification is required.

## 8. Operational notes

- Keep the HMAC key out of the audit database. Store only the key ID in each
  record. Rotate keys deliberately and retain old keys for as long as old
  records must remain joinable.
- Define a retention period for optional fields (certificate hash, issuer CN,
  serial, SKI, AAGUID) independently from the core audit record. A common
  policy is 30-90 days for troubleshooting data and longer for the minimal
  admission record.
- Never log raw request bodies, raw `attestationObject`, raw `clientDataJSON`,
  or the full certificate chain at any log level. Redact exception messages
  that may embed them.
- If a regulator or incident requires post-hoc signature verification, store
  the original material in a separate evidence store with its own access
  controls and retention, and keep only a commitment in the audit record.
- Treat `transports` and `authenticator_attachment` as client hints. They can
  support a policy decision, but they are not proof of device type.
- Treat a zeroed AAGUID as "not provided," not as "untrusted" or "unknown
  device." The TPM SAN model string is a model label; a serial or per-device
  subject CN is the field that may identify a unit.

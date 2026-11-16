# Error contract of the public verification entries

`RelyingParty#verify_registration` and `RelyingParty#verify_authentication` (and the
underlying `PublicKeyCredential#verify` / `AuthenticatorResponse#verify` / `#valid?`)
separate failures into two reliably distinguishable categories.

## Categories

### Untrusted-input failures — `WebAuthn::VerificationError`

Anything wrong with the client-supplied response, whether semantically invalid
(challenge/origin/RP ID/signature mismatch) or malformed at the parser level, is a
`WebAuthn::VerificationError` descendant. `verify` raises it; `valid?` rescues it and
returns `false`. Malformed-input parse failures are further grouped under
`WebAuthn::FormatError`:

| Layer | Condition | Error raised by `verify` |
| --- | --- | --- |
| HTTP/JSON payload | undecodable base64(field), nil field | `WebAuthn::DecodingError` |
| clientDataJSON | invalid JSON, non-object JSON, missing | `WebAuthn::ClientDataFormatError`, `WebAuthn::ClientDataMissingError` |
| attestationObject | truncated/invalid CBOR, non-map | `WebAuthn::AttestationObjectFormatError` |
| authData | truncated structure | `WebAuthn::AuthenticatorDataVerificationError` (parse detail: `WebAuthn::AuthenticatorDataFormatError`) |
| attested credential data | truncated, truncated/invalid COSE key, incomplete public key params, unknown COSE algorithm | `WebAuthn::AttestedCredentialDataFormatError` |
| attestation statement | unknown `fmt` | `WebAuthn::AttestationStatement::FormatNotSupportedError` |
| attestation statement | unparsable `x5c` certificate | `WebAuthn::AttestationStatement::InvalidCertificateError` |
| attestation statement | statement algorithm not allowed | `WebAuthn::AttestationStatement::UnsupportedAlgorithm` |
| credential wrapper | invalid `type`/`id` | `WebAuthn::VerificationError` |

Every wrapped error keeps the original parser exception (`EOFError`,
`CBOR::MalformedFormatError`, `OpenSSL::X509::CertificateError`, `JSON::ParserError`,
`ArgumentError`, …) as its `cause` for controlled troubleshooting. Public messages are
static strings: they never contain the challenge, the user handle, or certificate
contents.

### Server-side failures — `WebAuthn::ConfigurationError` (and other non-`VerificationError`s)

Problems on the Relying Party's own side are never converted into an ordinary login
failure: both `verify` and `valid?` let them propagate.

| Condition | Error |
| --- | --- |
| `allowed_origins` not configured | `WebAuthn::ConfigurationError` |
| `legacy_u2f_appid` not configured but `appid` extension output present | `WebAuthn::ConfigurationError` |
| finder object does not implement `#find` | `WebAuthn::RootCertificateFinderNotSupportedError` (< `ConfigurationError`) |
| finder returns unparsable/non-certificate roots | `WebAuthn::ConfigurationError` |
| unsupported `encoding` configured | `WebAuthn::ConfigurationError` |
| the trusted finder itself raises | the finder's own exception, unchanged |
| stored credential public key undecodable | `WebAuthn::PublicKey::DeserializationError` |
| stored credential public key algorithm unknown | `WebAuthn::PublicKey::UnsupportedAlgorithm` |

## Still propagating unwrapped

- Exceptions raised by the application's own `verify_authentication` block (e.g. the
  credential lookup) propagate untouched.
- Errors raised inside third-party attestation verification gems
  (`android_key_attestation`, `safety_net_attestation`, `tpm-key_attestation`) and a few
  bare `RuntimeError`s inside the TPM statement implementation propagate as-is.
- `WebAuthn::PublicKeyCredential::InvalidChallengeError` is raised when the challenge
  argument passed by the application is not a `String` (a programming error, not
  untrusted input).

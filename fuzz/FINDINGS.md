# Findings — real interpretation differences

Scope: compact serialization + verification-failure handling. Both APIs were run
under the aligned policy (HS256, verify `exp`+`nbf`, other checks off, same local
HMAC secret). **No vulnerability-class issue was found.** All gaps below are
safe reject-vs-reject differences or intentional features. Each row is replayable.

Legend: verdict is accept/reject for the *aligned, verification-enabled* path;
`finder` = key-finder callback invoked; class = raised exception on rejection.

## 1. Compatibility — short tokens (segment-count gate) — NEEDS-CLARIFICATION on contract
Root cause: `Decode#validate_segment_count!` requires exactly 3 segments
(`lib/jwt/decode.rb:105`); `EncodedToken#validate_segment_count!` rejects only
"too many" (`lib/jwt/encoded_token.rb:207`), so a 1- or 2-segment token proceeds
into signature verification.

| id (replay) | token | legacy | new |
|---|---|---|---|
| `seg-1` | `eyJhbGciOiJIUzI1NiJ9` | reject `MalformedTokenError` "Not enough or too many segments", finder=no | reject `VerificationError` "Signature verification failed", finder=no |
| `seg-2` | `eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ` | reject `MalformedTokenError`, finder=no | reject `VerificationError`, finder=**yes** (with key-finder) |

Both still reject and neither exposes a trusted payload, so there is **no
bypass**. Two practical effects worth a maintainer decision:
- different exception class/message for the same malformed input (migration
  friction for callers rescuing specific errors);
- with a key-finder, the new API calls the callback on a structurally-invalid
  short token where legacy never does — an observable side-effect/timing
  difference (e.g. a finder that performs network or audit work would run).

Classified **compatibility / needs-clarification** (error taxonomy + finder
side-effect contract), not a vulnerability.

## 2. Compatibility — detached payload (intentional feature)
`EncodedToken` supports RFC 7515 Appendix F detached content via
`encoded_payload=`; `JWT.decode` has no equivalent and only ever sees the compact
string. `probe_detached.rb` shows the full round trip: a correctly signed
detached token (`header..signature`, payload re-attached out of band) is
**accepted with a readable trusted payload** by the new API, while the legacy
entry point rejects the same compact token (`VerificationError`, empty-payload
signature mismatch; `MalformedTokenError` for the 2-segment `b64:false` shapes).

This is an intentional capability, **not a vulnerability**: acceptance still
requires a valid HMAC over the re-attached signing input and passing claim
checks; there is no path where an unsigned/forged payload becomes trusted.
Classified **compatibility (intentional feature)**.

Replay: `replay.rb detached-b64-empty-sig-seg` (reject-side gap) and
`probe_detached.rb` (accept-side feature demonstration).

## 3. Needs-clarification — exception class when the header alg is unusable
When the header cannot supply a usable `alg`, legacy fails during its explicit
algorithm gate (`Decode#verify_algo`) with `IncorrectAlgorithm`, while the new
API reaches HMAC verification and raises `VerificationError`. Both reject.

| id (replay) | shape | legacy class | new class |
|---|---|---|---|
| `dup-alg-reverse` | header `{"alg":"HS256","alg":"none"}` (last wins -> none) | `IncorrectAlgorithm` "Expected a different algorithm" | `VerificationError` "Signature verification failed" |
| `nonobj-header-5` | header `{}` (no alg) | `IncorrectAlgorithm` "Token is missing alg header" | `VerificationError` "Signature verification failed" |
| seeded `3:29` | header `{"alg":"HS512"}` vs allowed HS256 | `IncorrectAlgorithm` | `VerificationError` |

Note duplicate JSON members themselves are **not** a divergence: Ruby's
`JSON.parse` keeps the last member in both APIs, and a validly-signed duplicate
header is accepted by both (`probe_dup.rb`). Classified **needs-clarification**
(error taxonomy); security outcome identical.

## 4. Confirmed equivalent (no difference) — base64url & non-object headers
- Base64url decoding is shared (`JWT::Base64`), so padding, `+`/`/`, whitespace,
  NUL, unicode and truncation produce identical `Base64DecodeError` /
  `MalformedTokenError` outcomes in both.
- Non-object headers (`[]`, `"x"`, numbers, `null`, `true`, malformed/empty
  JSON) raise the same `MalformedTokenError` in both, via the shared
  `EncodedToken#header` used by `Decode` as well.
- Tampered but well-formed tokens are rejected by both; valid tokens accepted by
  both (baseline sanity in `main.rb`).

## Default-policy trap (not itself a finding, but required alignment)
Out of the box the two APIs disagree on `nbf`: legacy rejects a future-`nbf`
token (`ImmatureSignature`), the new default (exp-only) accepts it
(`probe_defaults.rb`). Any comparison that does not first pin the claim policy
would report this as a false "bypass". The harness pins both to exp+nbf, under
which they agree.

## Verdict table
| Class | Count | Items |
|---|---|---|
| Vulnerability (crash / bypass / payload exposure) | 0 | none observed across 3,642 cases |
| Compatibility (intentional feature) | 1 family | detached-payload workflow (#2) |
| Compatibility / needs-clarification | 2 families | segment-count gate + finder timing (#1), exception-class taxonomy (#3) |
| Equivalent behaviour | — | base64url edges, non-object headers, duplicate-member parse (#4) |

# Signature acceptance review: DigestSha256, HMAC, and public-key signatures

## Executive verdict

Do **not** label DigestSha256 packets as "authenticated" alongside certificate
signatures. The three signer families answer three different questions:

| Signature | Proves | Proves a publisher? |
|---|---|---|
| `DigestSha256` (type 0) | The covered bytes match the digest carried in the same packet | No |
| `HMAC-SHA256` (type 4) | The sender holds a shared secret | Only to holders of that secret |
| Public key (type 1/3/5) | The sender holds the private key matching the named public key | Only after a certificate chain and a name policy bind that key to the name |

"Authenticated" should mean *the packet is authorized to be published under
this name by a specific identity*. Only the third row can support that claim,
and only when the KeyLocator resolves to a trusted certificate and a name
policy authorizes the key for that namespace. Digest acceptance is an integrity
decision. Treating it as authentication converts every cache and every
forwarder into an authority that any client can impersonate.

The executable evidence is in `verification/` (see [Reproducing](#reproducing)).
The key result: an anonymous DigestSha256 packet renamed to
`/protected/news/bob/article1` and re-digested **passes a digest-only policy**
and **fails the strict and policy-aware policies**. No key material is needed
for the attack.

## 1. What each signature proves

### 1.1 DigestSha256

`DigestSha256Signer` writes `SignatureType = 0` and no KeyLocator, and computes
a 32-byte SHA-256 over the packet body: `Name | MetaInfo | Content |
SignatureInfo`, excluding the outer Data TLV header and the SignatureValue that
carries the digest. Verification is `sha256(covered) == signature_value`.

- It is a checksum against corruption or truncation.
- It has no key, so it carries no identity and no authorization.
- The digest is inside the packet it protects, so anyone who can rewrite the
  packet can rewrite the digest. This is not a subtle weakness; it is the
  designed semantics of an integrity-only signature.
- A Name with an implicit SHA-256 component (`.../sha256digest=...`) is the
  same idea: it commits to bytes, not to a publisher.

Acceptable use: public, cacheable data where detecting accidental corruption is
the whole requirement (`/protected/public/...` in the policy below).

### 1.2 HMAC-SHA256

`HmacSha256Signer` writes `SignatureType = 4` and a KeyLocator name, and
computes HMAC-SHA256 with a provisioned symmetric key.

- It proves the sender knows the shared key.
- Every verifier also knows the key, so any verifier can forge any packet.
- There is no third-party verification and no non-repudiation.
- The KeyLocator is only a lookup hint; it does not become an identity.

Acceptable use: a closed group that provisioned the key out of band, scoped to
that group's namespace. Never for public publication authority.

### 1.3 Public-key signatures (Ed25519, ECDSA, RSA)

These prove possession of a private key. On their own, that is all: **any key
can sign any name**. Identity appears only when two more things hold:

1. **Certificate chain** — the KeyLocator names a certificate that chains to a
   configured trust anchor.
2. **Name policy** — a policy authorizes that key for the exact packet name.

The library's `CascadeChecker` and `lvs_validator` implement exactly this
split: `lvs_validator` first calls `checker.check(name, key_name)` and only then
verifies the signature against the chained key.

### 1.4 The authorization equation

```
accept(packet) =
    signature_type in policy.allowed_types(packet.name)      # type allow-list
    AND signature_value verifies under the selected algorithm
    AND (signature_type == DIGEST_SHA256
         OR key_locator resolves to a trusted key)
    AND name_policy.authorizes(packet.name, key_locator)
```

Missing or unknown `SignatureType` fails the first clause. It must never fall
through to a more permissive verifier.

## 2. Empirical results

Generated with `verification/run_review.py` against this repository's signers.
All packets carry the same content (`quarterly numbers: revenue up 4%`).

### 2.1 Packet classes

| Packet | SignatureType | KeyLocator | Size |
|---|---|---|---|
| digest | 0 | none | 115 B |
| hmac | 4 | `/protected/news/author/alice/KEY/hmac-demo/key` | 173 B |
| ed25519 | 5 | `/protected/news/author/alice/KEY/demo` | 195 B |
| cert-chain | 3 (ECDSA) | derived cert under `/protected/KEY/.../self/...` | 232 B |

(The cert-chain locator includes a random key id and version, so its exact
string varies per run; the harness prints the current value.)

### 2.2 Verification matrix

Policies:

- **naive** — `sha256_digest_checker` used as the only gate (the anti-pattern).
- **strict** — type allow-list per namespace, explicit KeyLocator, per-algorithm
  verifier (`verification/signature_policy.py`).
- **lvs** — certificate chain to the trust anchor plus `verification/policy.lvs`.

| Case | naive | strict | lvs |
|---|---|---|---|
| digest: original | PASS | PASS | FAIL |
| digest: name changed | FAIL | FAIL | FAIL |
| digest: name changed + re-digest | **PASS** | FAIL | FAIL |
| digest: content changed | FAIL | FAIL | FAIL |
| digest: content changed + re-digest | **PASS** | FAIL | FAIL |
| digest: re-digest named as protected | **PASS** | FAIL | FAIL |
| hmac: original | PASS | PASS | FAIL |
| hmac: name changed | PASS | FAIL | FAIL |
| hmac: content changed | PASS | FAIL | FAIL |
| hmac: relabelled as Ed25519 | PASS | FAIL | FAIL |
| ed25519: original | PASS | PASS | FAIL |
| ed25519: name changed to bob | PASS | FAIL | FAIL |
| ed25519: content changed | PASS | FAIL | FAIL |
| ed25519: relabelled as digest | FAIL | FAIL | FAIL |
| ed25519: KeyLocator spoofed to bob | PASS | FAIL | FAIL |
| digest: unknown SignatureType 99 | PASS | FAIL | FAIL |
| unsigned: no SignatureInfo | PASS | FAIL | FAIL |
| cert-chain: original | PASS | FAIL | **PASS** |
| cert-chain: name changed to bob | PASS | FAIL | FAIL |
| cert-chain: outside policy | PASS | FAIL | FAIL |

Two rows deserve explanation:

- `ed25519: original` fails LVS because the demo key is not certificate-chained,
  so it has no publication authority. That is the intended outcome.
- `digest: original` fails LVS because the LVS model is the *publication
  authority* policy and deliberately has no rule for anonymous integrity data.
  Digest-only data is admitted by the `strict` policy for `/protected/public`,
  and is never admitted by the authority policy.

### 2.3 Why re-digesting defeats the naive policy

The digest is computed over the covered region and stored in the same packet.
The harness performs the attack with pure byte operations:

1. Rewrite the Name TLV inside the covered region.
2. Recompute `sha256(covered)`.
3. Splice the new 32-byte digest into the SignatureValue TLV.

No private key, HMAC key, or certificate is involved. The resulting packet is a
perfectly valid DigestSha256 packet for the attacker-chosen name. A digest-only
gate reports `PASS`, which is why it can never grant publication rights under a
protected prefix.

### 2.4 Library defect: `sha256_digest_checker` fails open

`src/ndn/security/validator/digest_validator.py` returns `PASS` whenever the
SignatureType is not `DIGEST_SHA256`, including `None` (unsigned), unknown
values, and public-key packets. The docstring frames this as "not my packet",
but `ValidResult.SILENCE` is the value designed for that; `PASS` means
"verified". Any application that chains this checker as a catch-all silently
accepts every signature type it does not understand. The harness parametrizes
this and asserts it.

Recommended library change (out of scope for this review, flagged for owners):
return `ValidResult.SILENCE` for non-digest types, so a caller must opt in
explicitly rather than inherit an accidental pass.

## 3. Routing and admission policy example

NFD forwards Data packets without validating content signatures. The admission
decision therefore belongs to the consumer, or to an NDN gateway that sits
between the forwarder and the publishing application. The forwarder's job is to
route; the policy engine's job is to decide whether a Data packet may satisfy an
Interest for a protected name.

Routes are ordinary prefix routes and carry no trust semantics
(`pynfdc nr` is this repository's `New-Route` / `nr` command):

```bash
pynfdc nr /protected/public 1     # cacheable, integrity-only data
pynfdc nr /protected/news   1     # must be admitted by the policy engine
```

Admission policy is expressed per namespace. The example below is the contract
the executable check enforces:

```yaml
namespaces:
  /protected/public:
    accept: [digest-sha256]
    identity_required: false
    verdict_label: intact          # never "authenticated"

  /protected/news:
    accept: [ed25519, ecdsa-p256, rsa-2048]
    identity_required: true
    trust_anchor: /etc/ndn/keys/protected-root.cert
    name_policy: verification/policy.lvs
    reject: [digest-sha256, hmac-sha256, unknown]
```

Operational rules:

1. **Two planes, two verdicts.** `/protected/public/*` may be served and cached
   on a digest. `/protected/news/*` requires a certificate-chained public-key
   signature authorized by the name policy.
2. **Namespace-scoped trust anchors.** A producer face is configured with the
   anchor(s) it may publish under. A valid signature under a different anchor is
   a different identity and must not satisfy a protected Interest.
3. **No algorithmic downgrade.** The validator is selected by the Interest's
   namespace policy, not by the Data packet's `SignatureType`. A Data packet
   claiming a weaker type than the namespace requires is rejected.
4. **Reject unknowns.** Missing SignatureInfo, missing KeyLocator, or an
   unregistered SignatureType fails closed.
5. **Cache separation.** Responses admitted as digest-only must not be inserted
   into a cache that serves `/protected/news`; otherwise a re-digested forgery
   can be replayed under a protected name.
6. **Signed Interests.** A protected publication should use a signed Interest
   with the same policy, so the publisher can reject unauthenticated requests
   rather than relying on the network to drop them. The signature on a Data
   packet protects the response; it does not protect the request.

The name policy (Light VerSec, compiled by
`ndn.app_support.light_versec.compile_lvs`):

```
// verification/policy.lvs
#KEY: "KEY"/_/_/_
#news: "protected"/"news"/author/_ <= #news_author
#news_author: "protected"/"news"/"author"/author/"KEY"/_/_/_ <= #root
#root: "protected"/#KEY
```

`author` is a named tag, so LVS binds it across rules: the author component in
the data name must equal the author component in the signing key name. Alice's
certified key can publish `/protected/news/alice/*` and cannot publish
`/protected/news/bob/*`. (An underscore-prefixed identifier is a rule-local
temporary and silently does not bind across rules — a policy pitfall worth
calling out.)

## 4. Acceptance and rejection basis

**Accept** when all of the following hold:

- DigestSha256: name is under `/protected/public`; the digest verifies. The
  verdict is "intact", never "authenticated".
- HMAC: the KeyLocator matches a provisioned key name for a closed group, and
  the name is inside that group's namespace.
- Public key: the KeyLocator resolves through a certificate chain to the
  configured trust anchor, the certificate is within its validity period, and
  the name policy authorizes that key for the exact name.
- The SignatureType is one the namespace policy permits.

**Reject** when any of the following hold:

- Missing SignatureInfo, missing SignatureType, or unknown SignatureType.
- Missing KeyLocator for any non-digest signature.
- SignatureType does not match the algorithm the namespace policy requires.
- Signature bytes do not verify under the selected key.
- A digest or HMAC signature is presented for a namespace that requires
  publication authority.
- The certificate chain does not reach the trust anchor, is expired, or the key
  is not authorized for the name (including cross-author attempts).

## 5. Findings

| ID | Severity | Finding |
|---|---|---|
| F1 | High | DigestSha256 proves integrity, not a publisher; re-digesting is a trivial forgery. |
| F2 | High | `sha256_digest_checker` returns `PASS` for every non-digest type (fail-open). |
| F3 | High | `SignatureType` is attacker-controlled; it must not select the verifier. |
| F4 | High | A trusted signature still needs a name policy binding the key to the exact namespace. |
| F5 | Medium | A KeyLocator is a hint, not an identity; it needs a certificate chain. |
| F6 | Medium | HMAC authenticates a key holder, not a third-party-verifiable publisher. |

## 6. Reproducing

```bash
.venv/bin/python verification/run_review.py          # full report, assertions on
.venv/bin/python verification/run_review.py --json   # machine-readable
.venv/bin/python -m pytest verification -q           # 16 regression tests
.venv/bin/python .feedback/baseline.py               # untouched upstream baseline
```

The harness asserts every security claim above, so a future change that makes a
forgery pass fails the run instead of silently producing a nicer-looking table.

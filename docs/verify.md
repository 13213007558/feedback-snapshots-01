# Verifying

## Generic identities

This is the most common verification done with `sigstore`, and therefore
the one you probably want: you can use it to verify that a signature was
produced by a particular identity (like `hamilcar@example.com`), as attested
to by a particular OIDC provider (like `https://github.com/login/oauth`).

```console
$ sigstore verify identity --cert-identity <IDENTITY> --cert-oidc-issuer <URL> FILE_OR_DIGEST
```

The following command will verify that the bundle `tests/assets/bundle.txt.sigstore` was signed by `a@tny.town` using
the staging infrastructure of `sigstore`.

```console
$ sigstore --staging verify identity --cert-identity "a@tny.town" --cert-oidc-issuer "https://github.com/login/oauth" test/assets/bundle.txt
```

## Verifying from GitHub Actions

If your signatures are coming from GitHub Actions (e.g., a workflow that uses its [ambient credentials](./signing.md#signing-with-ambient-credentials)),
then you can use the `sigstore verify github` subcommand to verify
claims more precisely than `sigstore verify identity` allows.

`sigstore verify github` can be used to verify claims specific to signatures coming from GitHub
Actions. `sigstore-python` signs releases via GitHub Actions, so the examples below are working
examples of how you can verify a given `sigstore-python` release.

When using `sigstore verify github`, you must pass `--cert-identity` or `--repository`, or both.
Unlike `sigstore verify identity`, `--cert-oidc-issuer` is **not** required (since it's
inferred to be GitHub Actions).

Verifying with `--cert-identity`:

```console
$ sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --cert-identity https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v0.10.0
```

Verifying with `--repository`:

```console
$ sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --repository sigstore/sigstore-python
```

Additional GitHub Actions specific claims can be verified like so:

```console
$ sigstore verify github sigstore-0.10.0-py3-none-any.whl \
    --bundle sigstore-0.10.0-py3-none-any.whl.bundle \
    --cert-identity https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v0.10.0 \
    --trigger release \
    --sha 66581529803929c3ccc45334632ccd90f06e0de4 \
    --name Release \
    --repository sigstore/sigstore-python \
    --ref refs/tags/v0.10.0
```

## Verifying against a bundle

By default, `sigstore verify identity` will attempt to find a `<filename>.sigstore.json`
or `<filename>.sigstore` in the same directory as the file being verified:

```console
# looks for foo.txt.sigstore.json
$ sigstore verify identity foo.txt \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
```

Multiple files can be verified at once:

```console
# looks for {foo,bar}.txt.sigstore.json
$ python -m sigstore verify identity foo.txt bar.txt \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
```

## Verifying a digest instead of a file

`sigstore-python` supports verifying digests directly, without requiring the artifact to be
present. The digest should be prefixed with the `sha256:` string:

```console
$ sigstore verify identity sha256:ce8ab2822671752e201ea1e19e8c85e73d497e1c315bfd9c25f380b7625d1691 \
    --cert-identity 'hamilcar@example.com' \
    --cert-oidc-issuer 'https://github.com/login/oauth'
    --bundle 'foo.txt.sigstore.json'
```
## Verifying build attestations for intake

`sigstore verify` (and `Verifier.verify_dsse`) answers "is this DSSE envelope
valid?". Artifact intake services usually need two more decisions before an
attestation may be admitted:

* the statement's subject must cover the digest of the artifact being reported;
* the statement's predicate type must be one the service has registered.

`sigstore.verify.AttestationVerifier` adds those two authorization steps on top
of the existing DSSE verification. The generic API is unchanged: existing
`verify_dsse` callers keep receiving the raw `(payload_type, payload)` tuple and
remain responsible for any further authorization.

!!! note

    `AttestationVerifier` assumes a cert-based Sigstore bundle (one carrying a
    DSSE envelope, a signing certificate and a transparency log entry), which
    is what `sigstore attest` and GitHub Artifact Attestations produce. A DSSE
    bundle signed with a bare key pair (no certificate) is outside its scope.

```python
import hashlib
from pathlib import Path

from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify import AttestationVerifier, Verifier, policy
from sigstore_models.common.v1 import HashAlgorithm

verifier = Verifier.production()
intake = AttestationVerifier(
    verifier,
    predicate_types=["https://slsa.dev/provenance/v1"],
)

artifact = Hashed(
    algorithm=HashAlgorithm.SHA2_256,
    digest=hashlib.sha256(Path("dist/release.tar.gz").read_bytes()).digest(),
)

result = intake.verify(
    artifact=artifact,
    bundle=Bundle.from_json(Path("dist/release.tar.gz.sigstore.json").read_bytes()),
    policy=policy.Identity(
        identity="builder@example.com",
        issuer="https://token.actions.githubusercontent.com",
    ),
)

print(result.predicate_type)   # guaranteed to be a registered type
print(result.subject)          # the single subject authorized for this artifact
print(result.predicate)        # opaque, untrusted: bound to the verified subject
```

`artifact` is a pre-hashed `Hashed` so the digest checked is exactly the digest
the service recorded for the report.

### Selecting a subject

A statement with more than one subject is ambiguous for intake, even if only
one of them happens to carry the reported digest. Pass `subject=` to say which
subject is being admitted, either as a zero-based index or as a unique subject
name:

```python
artifact = Hashed(
    algorithm=HashAlgorithm.SHA2_256,
    digest=hashlib.sha256(Path("dist/release.tar.gz").read_bytes()).digest(),
)

result = intake.verify(
    artifact=artifact,
    bundle=bundle,
    policy=policy,
    subject="release.tar.gz",  # or subject=0
)
```

If the statement has a single subject, no selector is needed. The selected
subject must still declare the reported digest; otherwise the check fails with
`SubjectDigestMismatch`.

### Failure modes

`AttestationVerifier.verify` raises, in order:

* any `VerificationError` from the underlying verifier (bad signature, bad
  certificate chain, bad transparency log entry, policy failure). Authorization
  never runs on a payload that did not verify;
* `PredicateTypeNotAccepted` when the statement's predicate type is not
  registered;
* `SubjectDigestMismatch` when the selected subject does not cover the reported
  digest;
* `SubjectSelectionError` when a multi-subject statement has no explicit
  selector, when a selector does not match exactly one subject, or when a name
  is ambiguous.

All of these subclass `sigstore.verify.attestation.AttestationVerificationError`
(itself a `VerificationError`).

### Offline example

The repository ships a fully offline fixture set under
`test/assets/offline-attestation/`: a synthetic CA, CT log and transparency log,
plus bundles signed with them. `build-fixtures.py` regenerates everything with
fresh keys.

```python
import hashlib
from pathlib import Path

from sigstore.hashes import Hashed
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import AttestationVerifier, Verifier, policy
from sigstore.verify.attestation import SubjectDigestMismatch
from sigstore_models.common.v1 import HashAlgorithm

fixtures = Path("test/assets/offline-attestation")
intake = AttestationVerifier(
    Verifier(trusted_root=TrustedRoot.from_file(str(fixtures / "trusted-root.json"))),
    predicate_types=["https://slsa.dev/provenance/v1"],
)

artifact = Hashed(
    algorithm=HashAlgorithm.SHA2_256,
    digest=hashlib.sha256((fixtures / "artifact.bin").read_bytes()).digest(),
)

# Admitted: subject covers the reported digest and the predicate type is registered.
intake.verify(
    artifact=artifact,
    bundle=Bundle.from_json((fixtures / "matching.bundle.json").read_bytes()),
    policy=policy.UnsafeNoOp(),  # test fixture: certificate chain/SCT/tlog still verified
)

# Refused: valid signature and log entry, but the subject declares another digest.
try:
    intake.verify(
        artifact=artifact,
        bundle=Bundle.from_json((fixtures / "wrong-digest.bundle.json").read_bytes()),
        policy=policy.UnsafeNoOp(),
    )
except SubjectDigestMismatch:
    pass
```

The fixtures also include:

* `unregistered-predicate.bundle.json`: correct digest, but a predicate type
  the example service has not registered;
* `multi-subject.bundle.json`: two subjects, requiring an explicit `subject=`;
* `duplicate-digest.bundle.json`: two subjects with the same digest, also
  requiring an explicit `subject=`.

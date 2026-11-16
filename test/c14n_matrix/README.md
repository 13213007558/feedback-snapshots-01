# SAML canonicalization compatibility matrix

This directory pins the canonicalization rules ruby-saml applies to SAML
Response and Metadata signatures. It exists because interoperating IdPs fail
in ways that only show up when an XML prefix, namespace declaration, comment,
or signature position changes.

Every positive fixture was signed by an implementation other than ruby-saml.
`fixtures/expected.json` stores the exact bytes that implementation fed to the
digest and signature operations:

- `reference_canonical_b64` — the Reference node-set after transforms
  (enveloped-signature, optional c14n transform) and canonicalization
- `reference_digest_b64` — SHA-256 of those bytes, also present in the fixture
- `signed_info_canonical_b64` — the canonicalized `ds:SignedInfo`
- `signed_info_sha256_b64` — SHA-256 of those bytes

The tests compare these bytes directly, so a rule change that still happens to
match a fixture digest is not enough to pass undetected.

## How to reproduce

Generate fixtures (needs `xmlsec1`, `xmllint`, `openssl`, `python3`):

```sh
python3 test/c14n_matrix/generate_fixtures.py
```

Run the matrix:

```sh
bundle exec ruby -Ilib:test test/c14n_matrix_test.rb
```

## Matrix

| Case | SignedInfo c14n | Reference c14n | InclusiveNamespaces | Expected |
| --- | --- | --- | --- | --- |
| `exclusive_prefix_list` | exclusive (no list) | exclusive, `xs foo` | Reference | Accept |
| `exclusive_no_prefix_list` | exclusive (no list) | exclusive (no list) | none | Accept |
| `exclusive_comments_dropped` | exclusive | exclusive | Reference | Accept; comments excluded |
| `exclusive_with_comments` | exclusive `#WithComments` | exclusive `#WithComments` | none | Accept; both comments included |
| `default_ns_reference_included` | exclusive (no list) | exclusive, `#default` | Reference | Accept; default ns in Reference bytes |
| `default_ns_reference_omitted` | exclusive (no list) | exclusive (no list) | none | Accept; default ns absent from Reference bytes |
| `default_ns_signed_info_only` | exclusive, `#default` | exclusive (no list) | SignedInfo | Accept; Reference bytes unchanged |
| `signed_info_prefix_only` | exclusive, `xs foo` | exclusive (no list) | SignedInfo | Accept; only SignedInfo carries `xmlns:foo` |
| `reference_prefix_only` | exclusive (no list) | exclusive, `xs foo` | Reference | Accept; SignedInfo bytes unchanged |
| `signed_info_ancestor_prefix` | exclusive, `xs foo` | exclusive (no list) | SignedInfo | Accept; ancestor declaration pulled into SignedInfo only |
| `signed_info_inclusive` | inclusive c14n 1.0 | exclusive (no list) | none | Accept |
| `reference_without_c14n_transform` | exclusive | implicit inclusive c14n 1.0 | none | Accept; SignedInfo algorithm not inherited |
| `signature_in_place` | exclusive, `xs foo` | exclusive | SignedInfo | Accept |
| `signature_moved_out_of_scope` | exclusive, `xs foo` | exclusive | SignedInfo | Reject; `foo` is no longer in scope |
| `two_signature_layers` | exclusive / exclusive | inclusive 1.0 (Response), exclusive (Assertion) | Reference (Assertion) | Accept with per-layer rules |
| `signed_metadata` | exclusive | exclusive | none | Accept through `validate_document`/`validate_document_with_cert` |
| `tampered_reference_prefix_removed` | exclusive (no list) | exclusive | removed | Reject; Digest mismatch |
| `tampered_reference_prefix_added` | exclusive (no list) | exclusive, `xs foo` | added | Reject; Digest mismatch |
| `tampered_signed_info_prefix_changed` | exclusive, `xs bar` | exclusive | changed | Reject; Key validation error |
| `tampered_default_namespace_dropped` | exclusive (no list) | exclusive (no list) | removed `#default` | Reject; Digest mismatch |

## Rules the matrix locks in

1. **SignedInfo and Reference are independent layers.** The canonicalization
   method on `ds:SignedInfo/ds:CanonicalizationMethod` never changes how the
   Reference is canonicalized, and a Reference transform never changes
   SignedInfo.
2. **InclusiveNamespaces belongs to the element that declares it.** It is read
   from the c14n `Transform` for the Reference and from
   `CanonicalizationMethod` for SignedInfo, never from "the first
   InclusiveNamespaces in the document".
3. **Only exclusive c14n accepts a prefix list.** libxml2 raises
   `This canonicalizer does not support this operation` if a prefix list is
   passed with inclusive c14n. ruby-saml therefore drops prefix lists for
   non-exclusive algorithms rather than passing them through.
4. **A Reference with no c14n transform defaults to inclusive c14n 1.0.** It
   does not inherit the SignedInfo canonicalization method. This is visible in
   `reference_without_c14n_transform`; the old behavior canonicalized the
   Reference with exclusive c14n and then crashed when a SignedInfo prefix list
   was present.
5. **Comments are included only when the algorithm URI ends in
   `#WithComments`.** Signing and verification both pass the comment flag to
   libxml2. Comments are not globally stripped before verification.
6. **The enveloped-signature transform removes the signature node from the
   referenced subtree, not from the whole document.** A signature elsewhere in
   the document is outside the Reference node-set and stays.
7. **Namespaces are whatever the namespace resolution rules produce.** A
   declaration is emitted only when the c14n algorithm requires it: exclusive
   c14n only emits visibly utilized declarations plus explicitly named
   InclusiveNamespaces; inclusive c14n emits all in-scope declarations. There
   is no namespace "fixup" step and no pretty-printing before verification.

## Accept or reject: semantic equivalence vs. different bytes

These are the rulings maintainers should apply when an IdP reports an
interop failure.

### Accept — different source XML, same canonical bytes

The signature covers canonical bytes, not the original serialization. All of
the following are accepted when the canonical bytes match the digest:

- Different prefix names for the same namespace URI (`saml2:` vs `saml:`).
- Different attribute order, quote style, or insignificant whitespace.
- A namespace declaration moved from the root to an ancestor or to the element
  itself, provided the resolved node-set is unchanged.
- XML declaration changes, self-closing vs. explicit end tags.
- Re-encoding encoding entities or CDATA with the same text value.

These cases are not separate fixtures because canonicalization deliberately
erases them. The fixtures above cover the boundary where "semantically
equivalent" becomes a *different* node-set.

### Reject — same XML meaning to a human, different canonical bytes

Reject when canonical bytes differ while the document still "looks" the same:

- Adding or removing comments under a non-`#WithComments` algorithm. A comment
  is not in the node-set, so adding one is harmless; under `#WithComments` it
  changes the digest and must fail (`exclusive_with_comments`).
- Adding `InclusiveNamespaces PrefixList="#default"` (or a prefix that is
  actually in scope) to the Reference. The declaration enters the Reference
  bytes and changes the digest (`tampered_reference_prefix_added`).
- Removing a prefix list that the signer used
  (`tampered_reference_prefix_removed`).
- Moving the `Signature` element to a different ancestor. Same signature bytes,
  different inherited namespace context, so SignedInfo canonical bytes differ
  (`signature_moved_out_of_scope`).
- Pretty-printing a document after signing. Whitespace between elements
  becomes text nodes and prefixes may be re-declared; the digest or the RSA
  signature fails (`test_pretty_printing_signed_metadata_is_rejected`).
- Changing a SignedInfo-only prefix list. The Reference still validates, but
  the RSA signature over SignedInfo must fail
  (`tampered_signed_info_prefix_changed`).

The last two are the important interop distinction: a Reference-only change is
a digest failure, while a SignedInfo-only change is a signature failure. IdPs
often report both as "invalid signature"; ruby-saml's error distinguishes them.

## Why xmlsec1 and xmllint

Neither tool shares ruby-saml's verifier code. xmlsec1 signs the Response,
Assertion, two-layer, and Metadata fixtures and prints its own pre-digest and
pre-signature buffers. `xmllint --exc-c14n` produces the `#WithComments`
fixture because xmlsec1 1.3.13 strips comments from Reference digests even
when the transform URI says `#WithComments`; that fixture is signed with
`openssl dgst -sha256 -sign` over xmllint's output.

If a fixture is regenerated, confirm the independent signer still verifies it:

```sh
openssl x509 -in test/certificates/ruby-saml.crt -pubkey -noout > /tmp/ruby-saml-pub.pem
xmlsec1 --verify --pubkey-pem:matrix /tmp/ruby-saml-pub.pem \
  --id-attr:ID Response --id-attr:ID Assertion --id-attr:ID EntityDescriptor \
  test/c14n_matrix/fixtures/<fixture>.xml
```

## Non-goals

- Do not pretty-print before verifying and expect the matrix to pass. The
  fixtures are stored exactly as signed; reformatting them is itself a
  canonicalization change.
- Do not treat this matrix as a signature-policy test. It does not decide
  whether SHA-1, RSA-SHA1, or particular key sizes should be accepted; it
  only pins what bytes each layer covers.
- Do not infer one layer's parameters from another. In particular,
  `document.extract_inclusive_namespaces` is a legacy document-wide helper;
  verification itself uses the per-layer resolution exposed as
  `reference_canonicalization` and `signed_info_canonicalization`.

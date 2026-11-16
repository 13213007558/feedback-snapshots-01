# Migrating stored public keys to the versioned `CredentialRecord` format

Historically this gem persisted a credential's public key in one of two
undocumented binary formats, with nothing on the record to say which one:

- **Legacy P-256 point** — a 65 byte ANSI X9.62 uncompressed point
  (`0x04 || x || y`) written by webauthn-ruby `<= v1.11.0`.
- **COSE_Key** — the CBOR encoded `credentialPublicKey`
  ([RFC 8152](https://www.rfc-editor.org/rfc/rfc8152)) written by newer
  versions.

`WebAuthn::CredentialRecord` introduces an explicit, versioned envelope so an
application can know what it stored and evolve the format over time. This
document describes the conversion interface and a safe migration path.

## Why classification is strict

A leading `0x04` byte and a length of 65 are **not** sufficient to treat data
as a P-256 point. The detector (`WebAuthn::PublicKey::Format`) only accepts a
record after it independently verifies:

1. the coordinates are each exactly 32 bytes,
2. the point is actually on the P-256 curve (`EC_POINT` membership check), and
3. for a COSE_Key, the key type is EC2, the curve is P-256 (`crv = 1`) and the
   algorithm is ES256 (`alg = -7`), if present.

A record that cannot be classified is reported with a precise reason rather
than guessed as another algorithm. Typical reasons include
`:point_not_on_curve`, `:bad_point_length`, `:malformed_cose`,
`:unsupported_algorithm`, `:unsupported_curve` and `:unsupported_key_type`.

## The versioned envelope

```ruby
require "webauthn/credential_record"

record = WebAuthn::CredentialRecord.from_cose_key(cose_key)
json   = record.serialize
# => {"format_version":1,"key_format":"cose_key","alg":-7,"crv":"P-256",
#     "public_key":"pQMmIAEhWCA…(base64url COSE_Key)…"}

restored = WebAuthn::CredentialRecord.deserialize(json)
restored.key_fingerprint # => SHA-256 of the uncompressed P-256 point
```

The fingerprint is a stable identity for the underlying key. The legacy point,
the COSE blob and the migrated envelope belonging to the same keypair all
produce the same fingerprint, which is how a migration proves the public key
did not change.

## Converting a single record

```ruby
require "webauthn/public_key_migrator"

result = WebAuthn::PublicKeyMigrator.migrate(id: credential.id, public_key: stored_blob)

result.source_format       # :legacy_p256_point or :cose_key
result.original_public_key # the untouched input bytes — keep this for rollback
result.record.serialize    # the new versioned envelope
result.fingerprint         # key identity, stable across formats
```

A bad record raises `WebAuthn::PublicKey::UnrecognizedPublicKey`, whose
`reason` identifies the problem.

## Backfilling a table without losing data

Use `migrate_many` for a batch job. It never raises for an individual row:
valid records come back as results and corrupt ones as failures.

```ruby
outcome = WebAuthn::PublicKeyMigrator.new.migrate_many(
  Credential.all.map { |c| { id: c.id, public_key: c.public_key } }
)

outcome[:results].each do |result|
  Credential.find(result.id).update!(
    # New columns: preserve the original and write the versioned record.
    original_public_key: result.original_public_key, # enables rollback
    migrated_public_key: result.record.serialize
  )
end

outcome[:failures].each do |failure|
  # Alert / queue for manual review. These rows are left untouched.
  Rails.logger.warn("credential #{failure.id} not migrated: #{failure.reason}")
end
```

Operational properties:

- **Rollback** — because `original_public_key` is retained, reverting is a
  matter of repointing the login flow at the original bytes.
- **Idempotent** — migrating the same key (or an already-migrated envelope)
  again produces byte-identical output, so the job is safe to re-run.
- **No guessing** — off-curve points and malformed COSE records are reported,
  not converted.

## Login during the transition

The existing login path keeps accepting both historical formats, so the
backfill does not require a cut-over. `WebAuthn::PublicKey.deserialize` now
uses the same strict detector before deciding how to parse a key:

```ruby
# Both work for the same authenticator signature during the transition.
WebAuthn::PublicKey.deserialize(legacy_point).verify(signature, verification_data)
WebAuthn::PublicKey.deserialize(cose_blob).verify(signature, verification_data)

# And so does the key stored inside a migrated envelope.
migrated = WebAuthn::CredentialRecord.deserialize(row.migrated_public_key).public_key
WebAuthn::PublicKey.deserialize(migrated).verify(signature, verification_data)
```

A complete, runnable walk-through (including an off-curve point and a
malformed COSE record) lives in
[`examples/migrate_public_keys.rb`](../examples/migrate_public_keys.rb).

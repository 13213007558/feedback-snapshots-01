# frozen_string_literal: true

# Migration example: convert a credential store that mixes legacy P-256
# uncompressed points (webauthn-ruby <= v1.11.0) and newer COSE_Key blobs into
# the versioned WebAuthn::CredentialRecord format.
#
# This script uses an in-memory store on purpose: it shows the library
# conversion interface end to end without requiring a real user database. In a
# real application the same calls are made inside your backfill task.
#
# Run it with:
#   ruby -Ilib examples/migrate_public_keys.rb

require "securerandom"
require "json"

require "webauthn"
require "webauthn/public_key/format"
require "webauthn/credential_record"
require "webauthn/public_key_migrator"

# --- A minimal table stand-in ------------------------------------------------
# Each row is what a real migration would read/update. +public_key+ holds the
# legacy bytes; +migrated_public_key+ and +original_public_key+ are the new
# columns the backfill writes.
class CredentialTable
  Row = Struct.new(:id, :public_key, :migrated_public_key, :original_public_key, keyword_init: true)

  def initialize
    @rows = []
  end

  attr_reader :rows

  def add(id:, public_key:)
    @rows << Row.new(id: id, public_key: public_key)
  end

  def each_stored_credential
    @rows.each { |row| yield(row) }
  end
end

table = CredentialTable.new

# --- Build representative records --------------------------------------------
ec_key = OpenSSL::PKey::EC.generate("prime256v1")
legacy_point = ec_key.public_key.to_octet_string(:uncompressed) # 0x04 || x || y

cose_key = COSE::Key::EC2.from_pkey(ec_key.public_key)
cose_key.alg = COSE::Algorithm.by_name("ES256").id
cose_blob = cose_key.serialize

# A second, distinct key so the report contains more than one credential.
other_key = OpenSSL::PKey::EC.generate("prime256v1")
other_point = other_key.public_key.to_octet_string(:uncompressed)

# Deliberately corrupt rows: an off-curve point and a malformed COSE blob.
off_curve_point = legacy_point.dup
off_curve_point[-1] = (off_curve_point[-1].ord ^ 0xFF).chr
malformed_cose = "\xA5\x01\x02not-a-real-cose-map".b

table.add(id: "cred-legacy", public_key: legacy_point)
table.add(id: "cred-cose", public_key: cose_blob)
table.add(id: "cred-other-legacy", public_key: other_point)
table.add(id: "cred-off-curve", public_key: off_curve_point)
table.add(id: "cred-malformed", public_key: malformed_cose)

# --- Backfill ----------------------------------------------------------------
# migrate_many never raises for an individual bad row: valid records are
# returned as results while anything that cannot be classified is reported.
migrator = WebAuthn::PublicKeyMigrator.new
pairs = table.rows.map { |row| { id: row.id, public_key: row.public_key } }
outcome = migrator.migrate_many(pairs)

outcome[:results].each do |result|
  row = table.rows.find { |candidate| candidate.id == result.id }

  # Keep the original bytes untouched so the migration can always be rolled
  # back. Idempotency means re-running this task writes the same value.
  row.original_public_key = result.original_public_key
  row.migrated_public_key = result.record.serialize
end

puts "Migrated #{outcome[:results].size} record(s):"
outcome[:results].each do |result|
  puts "  #{result.id.ljust(20)} source=#{result.source_format} fingerprint=#{result.fingerprint[0, 12]}…"
end

puts "\nSkipped #{outcome[:failures].size} record(s) (left unchanged, reported only):"
outcome[:failures].each do |failure|
  puts "  #{failure.id.ljust(20)} reason=#{failure.reason} (#{failure.message})"
end

# --- Identity proof: the public key did not change ---------------------------
# The two storage forms of the same key must have the same fingerprint, and a
# signature from that key must verify under the legacy point, the COSE blob and
# the migrated envelope alike.
legacy_result = outcome[:results].find { |result| result.id == "cred-legacy" }
cose_result = outcome[:results].find { |result| result.id == "cred-cose" }

fail "fingerprints of the same key differ!" unless legacy_result.fingerprint == cose_result.fingerprint

authenticator_data = SecureRandom.random_bytes(32)
client_data_hash = OpenSSL::Digest::SHA256.digest(SecureRandom.random_bytes(32))
verification_data = authenticator_data + client_data_hash
signature = ec_key.sign("SHA256", verification_data)

forms = {
  "legacy point" => legacy_point,
  "COSE blob" => cose_blob,
  "migrated envelope" => WebAuthn::CredentialRecord.deserialize(legacy_result.record.serialize).public_key
}

puts "\nSame-signature verification across storage forms:"
forms.each do |label, bytes|
  public_key = WebAuthn::PublicKey.deserialize(bytes)
  puts "  #{label.ljust(20)} verifies=#{public_key.verify(signature, verification_data)}"
end

# --- Rollback ----------------------------------------------------------------
# Because original bytes are retained, reverting a row is a single assignment.
example_row = table.rows.find { |row| row.id == "cred-legacy" }
example_row.migrated_public_key = nil
puts "\nRolled back cred-legacy; original record intact: " \
     "#{example_row.original_public_key == legacy_point}"

# --- Idempotency -------------------------------------------------------------
# Migrating an already-migrated record again produces byte-identical output.
re_run = migrator.migrate(id: "cred-legacy", public_key: legacy_point)
puts "Re-migration is byte-identical: " \
     "#{re_run.record.serialize == legacy_result.record.serialize}"

puts "\nDone. Wrote #{outcome[:results].size} versioned records, reported #{outcome[:failures].size} failures."

# frozen_string_literal: true

# End-to-end, dependency-free walkthrough of an OIDC signing-key rotation.
#
# It drives the real Doorkeeper::OpenidConnect library (no test doubles for the
# signing/JWKS code paths) through the rotation contract:
#
#   1. Two local key generations exist: an active key and its retired predecessor.
#   2. A rotation candidate that fails validation never reaches any public state.
#   3. A candidate is prepared but not yet committed: discovery, JWKS and the
#      signing entry point keep serving the previous, consistent configuration.
#   4. An issuance is paused on the rotation boundary, then the key is committed;
#      concurrent issuance is attributed to exactly one generation via its kid.
#   5. Tokens from before and after the cutover are each verified against the
#      real public key published in the JWKS for their generation.
#
# Run it with the project's offline harness:
#
#   sh .feedback/ruby-env.sh ruby script/key_rotation_scenario.rb [report.json]
#
# Without arguments the structured record is printed to STDOUT; pass a path to
# also write it there. Every assertion raises on failure, so a clean exit means
# the whole contract held.

require "json"
require "openssl"
require "securerandom"

# Minimal Rails shim: doorkeeper's config references Rails at load time, but the
# signing/JWKS paths used here need neither a database nor a full application.
require "rails"
require "active_support/all"
require "action_controller/railtie"
require "doorkeeper"
require "jwt"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "doorkeeper/openid_connect"

ISSUER = "https://issuer.example.com".freeze
ALGORITHM = "RS256".freeze

# A tiny stand-in for IdToken's signing path: it asks the module for the active
# key exactly the way IdToken#select_key does, then issues a JWS carrying the
# keyring generation in the JOSE kid. `gate` lets a run block until released so
# issuance can be parked at the rotation boundary.
class IssuerProbe
  def initialize(gate: nil)
    @gate = gate
  end

  def issue
    oidc = Doorkeeper::OpenidConnect
    jwk = oidc.signing_key
    generation = oidc.signing_generation
    @gate&.key_selected!
    @gate&.wait_for_release
    payload = {
      "iss" => ISSUER,
      "sub" => "user-#{SecureRandom.hex(4)}",
      "aud" => "client-id",
      "iat" => Time.now.to_i,
      "exp" => Time.now.to_i + 120,
      "nonce" => SecureRandom.hex(8),
    }
    token = JWT.encode(payload, jwk.keypair, ALGORITHM, { "typ" => "JWT", "kid" => jwk.kid })
    { token: token, kid: jwk.kid, generation: generation }
  end
end

# A two-phase rendezvous. The issuing thread calls `key_selected!` once it has
# resolved the active key (and therefore its generation), then blocks on
# `wait_for_release`. The scenario thread waits on `wait_for_selection` so it
# only commits once issuance has provably captured the old generation, then
# calls `release!`. Condition variables make both handoffs deterministic with
# no sleep-based timing assumptions.
class Gate
  def initialize
    @mutex = Mutex.new
    @condition = ConditionVariable.new
    @selected = false
    @released = false
  end

  def key_selected!
    @mutex.synchronize do
      @selected = true
      @condition.broadcast
    end
  end

  def wait_for_selection
    @mutex.synchronize do
      @condition.wait(@mutex) until @selected
    end
  end

  def wait_for_release
    @mutex.synchronize do
      @condition.wait(@mutex) until @released
    end
  end

  def release!
    @mutex.synchronize do
      @released = true
      @condition.broadcast
    end
  end
end

# Verifies a token strictly against the public JWK the JWKS endpoint publishes
# for its kid — the exact path a relying party takes. Returns the decoded
# payload and header, or raises JWT::VerificationError / JWT::DecodeError.
def verify_with_jwks(token, jwks)
  header_segment = token.split(".").first
  headers = JSON.parse(Base64.urlsafe_decode64(header_segment))
  jwk_hash = jwks.fetch(:keys).find { |key| key[:kid] == headers["kid"] }
  raise "no published JWK for kid #{headers['kid'].inspect}" unless jwk_hash

  public_key = JWT::JWK.import(jwk_hash).verify_key
  JWT.decode(token, public_key, true, algorithms: [ALGORITHM], iss: ISSUER)
end

# The discovery document fields a relying party actually consumes for token
# validation, built from the same module methods the DiscoveryController uses.
def discovery_snapshot
  oidc = Doorkeeper::OpenidConnect
  {
    issuer: ISSUER,
    jwks_uri: "#{ISSUER}/oauth/discovery/keys",
    id_token_signing_alg_values_supported: [oidc.signing_algorithm.to_s],
    active_signing_generation: oidc.signing_generation,
    active_kid: oidc.signing_key.kid,
  }
end

def jwks_snapshot
  Doorkeeper::OpenidConnect.signing_keys_normalized
end

def assert(condition, message)
  raise "ASSERTION FAILED: #{message}" unless condition
end

report = { stages: [] }
def record(report, stage, data)
  $stderr.puts "-> #{stage}"
  report[:stages] << { stage: stage, **data }
end

# Two locally generated RSA generations: gen 0 (predecessor, still verifiable)
# and gen 1 will be introduced by rotation. We start with only the predecessor
# active so the rotation itself creates the second generation.
predecessor = OpenSSL::PKey::RSA.generate(2048)
candidate = OpenSSL::PKey::RSA.generate(2048)
bad_candidate = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"

oidc = Doorkeeper::OpenidConnect
oidc.configure do
  issuer ISSUER
  signing_algorithm :rs256
  signing_key [predecessor.to_pem]
end

# ---------------------------------------------------------------------------
# Stage 0 — baseline: one active generation, discoverable and verifiable.
# ---------------------------------------------------------------------------
baseline_discovery = discovery_snapshot
baseline_jwks = jwks_snapshot
baseline_token = IssuerProbe.new.issue
baseline_decoded, baseline_header =
  verify_with_jwks(baseline_token[:token], { keys: baseline_jwks })
assert(baseline_jwks.size == 1, "baseline JWKS should hold one key")
assert(baseline_header["kid"] == baseline_token[:kid], "baseline token kid matches JWKS")
assert(baseline_token[:generation].zero?, "baseline token is generation 0")
record(report, "00_baseline", {
  discovery: baseline_discovery,
  jwks_kids: baseline_jwks.map { |k| k[:kid] },
  jwks_size: baseline_jwks.size,
  issued: { kid: baseline_token[:kid], generation: baseline_token[:generation] },
  verified: true,
  verified_iss: baseline_decoded["iss"],
})

# ---------------------------------------------------------------------------
# Stage 1 — candidate validation failure must not touch any public state.
# ---------------------------------------------------------------------------
validation_error = begin
  oidc.prepare_signing_key(bad_candidate)
  nil
rescue OpenSSL::PKey::PKeyError, ArgumentError => e
  e.class.name
end
after_bad_discovery = discovery_snapshot
after_bad_jwks = jwks_snapshot
assert(validation_error, "malformed candidate should raise a parse error")
assert(!oidc.key_ring.pending?, "failed candidate must not be parked as pending")
assert(after_bad_jwks.map { |k| k[:kid] } == baseline_jwks.map { |k| k[:kid] },
       "JWKS unchanged after failed candidate")
assert(after_bad_discovery[:active_kid] == baseline_discovery[:active_kid],
       "discovery active key unchanged after failed candidate")
record(report, "01_candidate_validation_failure", {
  error: validation_error,
  pending: oidc.key_ring.pending?,
  discovery: after_bad_discovery,
  jwks_kids: after_bad_jwks.map { |k| k[:kid] },
  jwks_size: after_bad_jwks.size,
  consistent_with_baseline: true,
})

# ---------------------------------------------------------------------------
# Stage 2 — prepare a valid candidate; nothing public changes until commit.
# ---------------------------------------------------------------------------
pending = oidc.prepare_signing_key(candidate.to_pem)
prepared_discovery = discovery_snapshot
prepared_jwks = jwks_snapshot
prepared_token = IssuerProbe.new.issue
assert(oidc.key_ring.pending?, "valid candidate is parked as pending")
assert(prepared_jwks.map { |k| k[:kid] } == baseline_jwks.map { |k| k[:kid] },
       "pending key must not appear in JWKS")
assert(!prepared_jwks.map { |k| k[:kid] }.include?(pending.kid),
       "pending kid must be absent from public JWKS")
assert(prepared_token[:generation].zero?, "signing still uses the old generation while pending")
assert(prepared_discovery[:active_kid] == baseline_discovery[:active_kid],
       "discovery still advertises the old active key while pending")
record(report, "02_candidate_prepared_not_published", {
  pending_kid: pending.kid,
  pending_visible_in_jwks: false,
  discovery: prepared_discovery,
  jwks_kids: prepared_jwks.map { |k| k[:kid] },
  jwks_size: prepared_jwks.size,
  issued: { kid: prepared_token[:kid], generation: prepared_token[:generation] },
})

# ---------------------------------------------------------------------------
# Stage 3 — persistence failure at commit keeps the old configuration live.
# ---------------------------------------------------------------------------
oidc.key_ring.persister = ->(_snapshot) { raise "simulated persistence outage" }
persistence_error = begin
  oidc.commit_signing_key
  nil
rescue RuntimeError => e
  e.message
end
failed_jwks = jwks_snapshot
failed_discovery = discovery_snapshot
assert(persistence_error, "failing persister should abort the commit")
assert(oidc.key_ring.pending?, "candidate stays pending after a failed write")
assert(failed_jwks.map { |k| k[:kid] } == baseline_jwks.map { |k| k[:kid] },
       "JWKS stays on the old config after persistence failure")
assert(failed_discovery[:active_kid] == baseline_discovery[:active_kid],
       "discovery stays on the old config after persistence failure")
record(report, "03_persistence_failure_keeps_old_config", {
  error: persistence_error,
  pending: oidc.key_ring.pending?,
  discovery: failed_discovery,
  jwks_kids: failed_jwks.map { |k| k[:kid] },
  jwks_size: failed_jwks.size,
  consistent_with_baseline: true,
})

# Restore a healthy persister (records the snapshot the operational layer would
# durably store) and keep the candidate pending for the boundary test.
persisted_snapshots = []
oidc.key_ring.persister = ->(snapshot) { persisted_snapshots << snapshot }

# ---------------------------------------------------------------------------
# Stage 4 — issuance paused at the switch boundary, then an atomic commit.
# Two issuers race the commit; each must land on exactly one generation and
# that generation must be identifiable from the token's kid.
# ---------------------------------------------------------------------------
gate = Gate.new
parked = IssuerProbe.new(gate: gate)
results = {}
threads = []

# Issuer A resolves its active key and generation, then blocks before encoding.
threads << Thread.new { results[:before] = parked.issue }
gate.wait_for_selection

# Commit while A is parked: the ring swaps atomically to the new generation.
committed = oidc.commit_signing_key
commit_generation = oidc.signing_generation
# Issuer B issues after the commit and must use the new generation.
results[:after] = IssuerProbe.new.issue
gate.release!
threads.each(&:join)

boundary_jwks = jwks_snapshot
boundary_discovery = discovery_snapshot
assert(results[:before][:generation].zero?, "parked issuance stays on generation 0")
assert(results[:after][:generation] == commit_generation,
       "post-commit issuance uses the new generation #{commit_generation}")
assert(results[:before][:kid] != results[:after][:kid], "the two tokens use different kids")
assert(boundary_jwks.size == 2, "JWKS now publishes both generations")
assert(oidc.generation_for_kid(results[:before][:kid]).zero?, "old kid resolves to generation 0")
assert(oidc.generation_for_kid(results[:after][:kid]) == commit_generation,
       "new kid resolves to the committed generation")
record(report, "04_switch_boundary_concurrent_issuance", {
  discovery: boundary_discovery,
  jwks_kids: boundary_jwks.map { |k| k[:kid] },
  jwks_size: boundary_jwks.size,
  persisted_snapshot: persisted_snapshots.last,
  before_commit_issuance: {
    kid: results[:before][:kid], generation: results[:before][:generation],
  },
  after_commit_issuance: {
    kid: results[:after][:kid], generation: results[:after][:generation],
  },
  generations_distinct: results[:before][:kid] != results[:after][:kid],
})

# ---------------------------------------------------------------------------
# Stage 5 — verify both tokens against the real public keys in the JWKS.
# ---------------------------------------------------------------------------
before_decoded, before_header = verify_with_jwks(results[:before][:token], { keys: boundary_jwks })
after_decoded, after_header = verify_with_jwks(results[:after][:token], { keys: boundary_jwks })
assert(before_header["kid"] == results[:before][:kid], "old token verified with its own public key")
assert(after_header["kid"] == results[:after][:kid], "new token verified with its own public key")
assert(before_decoded["iss"] == ISSUER && after_decoded["iss"] == ISSUER, "both issuers match")

# Negative control: the new token must NOT verify under the predecessor's key.
wrong_key = boundary_jwks.find { |k| k[:kid] == results[:before][:kid] }
negative = begin
  JWT.decode(results[:after][:token], JWT::JWK.import(wrong_key).verify_key, true,
             algorithms: [ALGORITHM], iss: ISSUER)
  false
rescue JWT::VerificationError
  true
end
assert(negative, "new token must fail verification under the predecessor key")
record(report, "05_verify_both_generations_against_public_keys", {
  predecessor_token: {
    kid: results[:before][:kid],
    generation: results[:before][:generation],
    verified: true,
    header_alg: before_header["alg"],
  },
  current_token: {
    kid: results[:after][:kid],
    generation: results[:after][:generation],
    verified: true,
    header_alg: after_header["alg"],
  },
  current_token_rejected_by_predecessor_key: negative,
})

json = JSON.pretty_generate(report)
output_path = ARGV.first
if output_path
  File.write(output_path, json)
  $stderr.puts "Report written to #{output_path}"
end
puts json
$stderr.puts "All rotation invariants held across #{report[:stages].size} stages."

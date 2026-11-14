# frozen_string_literal: true

require_relative "../test_helper"

require "oauth/signature/hmac/sha1"
require "oauth/signature/hmac/sha256"
require "oauth/signature/plaintext"

# Verifies rotating, versioned consumer secrets without disconnecting clients:
# overlapping validity windows, revocation, expiry, token ownership, server-side
# algorithm/version control, ambiguity and audit reporting.
class SignatureRotationTest < Minitest::Test
  T0 = Time.utc(2026, 1, 1, 12, 0, 0).freeze
  T1 = Time.utc(2026, 1, 1, 11, 0, 0).freeze
  T2 = Time.utc(2026, 1, 1, 13, 0, 0).freeze

  CONSUMER_KEY = "dpf43f3p2l4k3l03"
  TOKEN = "nnch734d00sl2jdk"
  TOKEN_SECRET = "pfkkdhi9sl3r4s00"

  OLD_SECRET = "kd94hf93k423kf44"
  NEW_SECRET = "new-rotated-secret"

  def setup
    @clock = OAuth::Signature::Clock.new(T0)
    @events = []
  end

  def candidate(version, secret, valid_from: nil, expires_at: nil, revoked_at: nil)
    OAuth::Signature::SecretCandidate.new(
      version: version,
      secret: secret,
      valid_from: valid_from,
      expires_at: expires_at,
      revoked_at: revoked_at
    )
  end

  def credentials(candidates, token_secret: TOKEN_SECRET)
    OAuth::Signature::Credentials.new(candidates, token_secret)
  end

  def build_request(consumer_secret:, token_secret: TOKEN_SECRET, method: "HMAC-SHA1",
                    extra_parameters: {})
    request = OAuth::RequestProxy::MockRequest.new(
      "method" => "POST",
      "uri" => "https://photos.example.net/initialize",
      "parameters" => {
        "oauth_consumer_key" => CONSUMER_KEY,
        "oauth_token" => TOKEN,
        "oauth_signature_method" => method,
        "oauth_timestamp" => @clock.now.to_i.to_s,
        "oauth_nonce" => "wIjqoS",
        "oauth_version" => "1.0"
      }.merge(extra_parameters)
    )
    request.parameters["oauth_signature"] = OAuth::Signature.sign(
      request,
      consumer_secret: consumer_secret,
      token_secret: token_secret
    )
    request
  end

  def verifier(request, creds, **options)
    default_options = { clock: @clock, audit: ->(event) { @events << event } }
    OAuth::Signature.build(request, default_options.merge(options)) do |token, consumer_key, nonce, timestamp|
      # exercise the four-argument resolver contract
      refute_nil token
      refute_nil consumer_key
      refute_nil nonce
      refute_nil timestamp
      creds
    end
  end

  def overlapping_credentials
    credentials([
                  candidate("v1", OLD_SECRET, expires_at: T2),
                  candidate("v2", NEW_SECRET, valid_from: T1)
                ])
  end

  def test_secret_candidate_reports_validity_against_the_clock
    v1 = candidate("v1", OLD_SECRET, valid_from: T1, expires_at: T2)
    assert v1.valid_at?(@clock.now)
    refute v1.valid_at?(T2)
    refute v1.valid_at?(T1 - 1)
  end

  def test_revoked_candidate_is_never_valid
    revoked = candidate("v2", NEW_SECRET, valid_from: T1, revoked_at: T0)
    assert revoked.revoked?
    refute revoked.valid_at?(@clock.now)
  end

  def test_new_secret_version_verifies_during_overlap_and_audits_that_version
    request = build_request(consumer_secret: NEW_SECRET)
    subject = verifier(request, overlapping_credentials)

    assert subject.verify
    assert_equal "v2", subject.matched_consumer_version
    assert_equal 1, @events.size
    event = @events.first
    assert event.success?
    assert_equal "v2", event.consumer_version
    assert_equal CONSUMER_KEY, event.consumer_key
    assert_equal TOKEN, event.token
    assert_equal "HMAC-SHA1", event.signature_method
    assert_equal %w[v1 v2], event.considered_versions
    assert_nil event.error
  end

  def test_old_secret_version_still_verifies_during_overlap_window
    request = build_request(consumer_secret: OLD_SECRET)
    subject = verifier(request, overlapping_credentials)

    assert subject.verify
    assert_equal "v1", subject.matched_consumer_version
    assert_equal "v1", @events.first.consumer_version
  end

  def test_old_version_is_rejected_once_it_expires
    request = build_request(consumer_secret: OLD_SECRET)
    @clock.advance(2 * 3600) # past v1 expires_at (T2)
    subject = verifier(request, overlapping_credentials)

    refute subject.verify
    assert_nil subject.matched_consumer_version
    assert_equal :no_match, @events.first.error
    assert_equal ["v2"], @events.first.considered_versions
  end

  def test_version_not_yet_valid_is_excluded
    future = candidate("v3", NEW_SECRET, valid_from: T2)
    request = build_request(consumer_secret: NEW_SECRET)
    subject = verifier(request, credentials([future]))

    refute subject.verify
    assert_equal :no_match, @events.first.error
    assert_empty @events.first.considered_versions
  end

  def test_revoked_version_is_excluded_immediately
    revoked = candidate("v2", NEW_SECRET, valid_from: T1, revoked_at: T0)
    request = build_request(consumer_secret: NEW_SECRET)
    subject = verifier(request, credentials([candidate("v1", OLD_SECRET, expires_at: T2), revoked]))

    refute subject.verify
    # the revoked version never reaches the signature comparison stage
    assert_equal ["v1"], @events.first.considered_versions
    assert_equal :no_match, @events.first.error
  end

  def test_revocation_wins_over_an_otherwise_active_window
    revoked = candidate("v2", NEW_SECRET, valid_from: T1, expires_at: T2, revoked_at: T0)
    assert revoked.revoked?
    assert_empty credentials([revoked]).active_candidates(@clock.now)
  end

  def test_time_windows_accept_integer_epoch_seconds
    integer_window = candidate("v2", NEW_SECRET,
                               valid_from: T1.to_i, expires_at: T2.to_i, revoked_at: T0.to_i)
    assert_equal T1.to_i, integer_window.valid_from.to_i
    assert_equal T2.to_i, integer_window.expires_at.to_i
    assert_equal T0.to_i, integer_window.revoked_at.to_i
    assert integer_window.revoked?
    refute integer_window.valid_at?(@clock.now)
  end

  def test_wrong_token_secret_fails_without_revealing_which_secret_was_wrong
    request = build_request(consumer_secret: NEW_SECRET, token_secret: "someone-elses-token-secret")
    subject = verifier(request, overlapping_credentials)

    refute subject.verify
    assert_nil subject.matched_consumer_version

    error = assert_raises(OAuth::Signature::VerificationError) { subject.verify! }
    assert_equal OAuth::Signature::VerificationError::DEFAULT_MESSAGE, error.message
    refute_match(/v1|v2|token|consumer/i, error.message)
  end

  def test_unknown_token_secret_lookup_fails_generically
    request = build_request(consumer_secret: NEW_SECRET)
    subject = verifier(request, credentials(overlapping_credentials.consumer_candidates,
                                            token_secret: nil))

    refute subject.verify
    assert_equal :no_match, @events.first.error
  end

  def test_message_cannot_select_a_version_the_server_did_not_resolve
    request = build_request(consumer_secret: NEW_SECRET,
                            extra_parameters: { "oauth_consumer_secret_version" => "v99" })
    subject = verifier(request, overlapping_credentials)

    assert subject.verify
    # the server's resolver, not the message, decides the winning version
    assert_equal "v2", subject.matched_consumer_version
    assert_equal %w[v1 v2], @events.first.considered_versions
  end

  def test_message_cannot_select_a_signature_algorithm_the_server_disallows
    request = build_request(consumer_secret: NEW_SECRET, method: "HMAC-SHA256")
    subject = verifier(request, overlapping_credentials,
                       allowed_signature_methods: %w[HMAC-SHA1])

    refute subject.verify
    assert_equal :signature_method_rejected, @events.first.error
    assert_raises(OAuth::Signature::SignatureMethodRejected) { subject.verify! }
  end

  def test_allowed_signature_method_case_insensitive
    request = build_request(consumer_secret: NEW_SECRET, method: "HMAC-SHA1")
    subject = verifier(request, overlapping_credentials,
                       allowed_signature_methods: %w[hmac-sha1])

    assert subject.verify
    assert_equal "v2", subject.matched_consumer_version
  end

  def test_simultaneous_matches_are_ambiguous
    shared = [
      candidate("va", "same-secret"),
      candidate("vb", "same-secret")
    ]
    request = build_request(consumer_secret: "same-secret")
    subject = verifier(request, credentials(shared))

    refute subject.verify
    assert_equal :ambiguous, @events.first.error
    error = assert_raises(OAuth::Signature::AmbiguousSignatureError) { subject.verify! }
    assert_equal %w[va vb], error.versions
    assert_nil subject.matched_consumer_version
  end

  def test_rotation_works_with_hmac_sha256
    request = build_request(consumer_secret: NEW_SECRET, method: "HMAC-SHA256")
    subject = verifier(request, overlapping_credentials,
                       allowed_signature_methods: %w[HMAC-SHA1 HMAC-SHA256])

    assert subject.verify
    assert_equal "v2", subject.matched_consumer_version
    assert_equal "HMAC-SHA256", @events.first.signature_method
  end

  def test_rotation_works_with_plaintext
    request = build_request(consumer_secret: NEW_SECRET, method: "PLAINTEXT")
    subject = verifier(request, overlapping_credentials)

    assert subject.verify
    assert_equal "v2", subject.matched_consumer_version
  end

  def test_legacy_two_element_array_callback_keeps_working
    request = build_request(consumer_secret: NEW_SECRET)
    subject = OAuth::Signature.build(request, clock: @clock) do |_token, _consumer_key, _nonce, _timestamp|
      [TOKEN_SECRET, NEW_SECRET]
    end

    assert subject.verify
    assert_nil subject.matched_consumer_version
  end

  def test_legacy_one_argument_block_keeps_working
    request = build_request(consumer_secret: NEW_SECRET)
    subject = OAuth::Signature.build(request, clock: @clock) do |_request|
      [TOKEN_SECRET, NEW_SECRET]
    end

    assert subject.verify
  end

  def test_static_consumer_secret_option_keeps_working
    request = build_request(consumer_secret: OLD_SECRET)
    subject = OAuth::Signature::HMAC::SHA1.new(
      request, consumer_secret: OLD_SECRET, token_secret: TOKEN_SECRET, clock: @clock
    )

    assert subject.verify
  end

  def test_failure_audit_event_does_not_carry_a_consumer_version
    request = build_request(consumer_secret: "a-secret-the-server-does-not-have")
    subject = verifier(request, overlapping_credentials)

    refute subject.verify
    event = @events.first
    assert event.failure?
    assert_nil event.consumer_version
    assert_equal :no_match, event.error
  end

  def test_audit_event_is_also_available_on_the_verifier
    request = build_request(consumer_secret: NEW_SECRET)
    subject = verifier(request, overlapping_credentials)
    subject.verify

    assert_equal subject.last_audit_event, @events.first
    assert_equal "v2", subject.last_audit_event.consumer_version
  end

  def test_verifier_restores_static_secrets_after_a_candidate_run
    request = build_request(consumer_secret: NEW_SECRET)
    subject = verifier(request, overlapping_credentials)
    subject.verify

    assert_nil subject.consumer_secret
    assert_equal TOKEN_SECRET, subject.token_secret
  end

  def test_no_candidates_at_all_fails_generically
    request = build_request(consumer_secret: NEW_SECRET)
    subject = verifier(request, credentials([]))

    refute subject.verify
    assert_equal :no_match, @events.first.error
    assert_empty @events.first.considered_versions
  end
end

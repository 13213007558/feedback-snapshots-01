# frozen_string_literal: true

# Differential harness comparing the legacy JWT.decode API against the
# JWT::EncodedToken API under explicitly aligned security policies.
#
# All keys are generated locally. Nothing leaves the process.
require 'jwt'

module DiffFuzz
  # A single shared secret + an intentionally wrong secret, both local.
  GOOD_SECRET = 'local-differential-secret-do-not-use-elsewhere-0123456789'
  BAD_SECRET  = 'a-different-local-secret-9876543210'

  # Aligned claim policy used by BOTH APIs. The library defaults differ
  # (legacy verifies exp+nbf; EncodedToken verifies only exp), so we make the
  # comparison explicit and identical: verify only :exp and :nbf.
  ALIGNED_CLAIMS = %i[exp nbf].freeze
  ALIGNED_ALG    = 'HS256'

  # Outcome of feeding one token to one API.
  #   accepted?   -> true only when the API returned normally (no raise)
  #   trusted?    -> whether a *trusted* payload is readable afterwards
  #   finder_called? -> whether the key-finder callback was invoked
  #   crash?      -> a non-JWT::Error exception (robustness bug, NOT a clean reject)
  Outcome = Struct.new(:api, :accepted, :trusted, :finder_called, :error_class,
                       :error_message, :crash, keyword_init: true) do
    def accepted?        = accepted
    def finder_called?   = finder_called
    def crash?           = crash
    def rejected?        = !accepted
    def verdict
      return :crash if crash
      return :accept if accepted
      :reject
    end
  end

  module_function

  def b64u(raw) = JWT::Base64.url_encode(raw)
  def b64u_dec(seg) = JWT::Base64.url_decode(seg || '')

  # ---- Legacy API (JWT.decode) ----
  # Claims aligned to the new API: only exp/nbf, everything else explicitly off.
  def run_legacy(token, payload_override: nil, use_finder: false)
    finder_called = false
    finder = proc { |_header| finder_called = true; GOOD_SECRET }
    options = {
      algorithm: ALIGNED_ALG,
      verify_expiration: true,
      verify_not_before: true,
      verify_iss: false, verify_iat: false, verify_jti: false,
      verify_aud: false, verify_sub: false, required_claims: []
    }
    key = use_finder ? nil : GOOD_SECRET

    result = nil
    begin
      if payload_override
        # Detached payload: the legacy API has no setter, so it only ever sees
        # the compact token (two segments, empty signature segment).
        payload, _header = JWT.decode(token, key, true, options, &(use_finder ? finder : nil))
      else
        payload, _header = JWT.decode(token, key, true, options, &(use_finder ? finder : nil))
      end
      result = Outcome.new(api: 'legacy', accepted: true, trusted: !payload.nil?,
                           finder_called: finder_called, error_class: nil,
                           error_message: nil, crash: false)
    rescue JWT::Error => e
      result = Outcome.new(api: 'legacy', accepted: false, trusted: false,
                           finder_called: finder_called, error_class: e.class.name,
                           error_message: e.message, crash: false)
    rescue StandardError => e
      result = Outcome.new(api: 'legacy', accepted: false, trusted: false,
                           finder_called: finder_called, error_class: e.class.name,
                           error_message: e.message, crash: true)
    end
    result
  end

  # ---- New API (JWT::EncodedToken) ----
  def run_new(token, payload_override: nil, use_finder: false)
    finder_called = false
    finder = proc { |_et| finder_called = true; GOOD_SECRET }
    result = nil
    begin
      et = JWT::EncodedToken.new(token)
      et.encoded_payload = payload_override if payload_override
      if use_finder
        et.verify_signature!(algorithm: ALIGNED_ALG, key_finder: finder)
      else
        et.verify_signature!(algorithm: ALIGNED_ALG, key: GOOD_SECRET)
      end
      et.verify_claims!(*ALIGNED_CLAIMS)
      trusted = begin
                  et.payload
                  true
                rescue JWT::Error
                  false
                end
      result = Outcome.new(api: 'new', accepted: true, trusted: trusted,
                           finder_called: finder_called, error_class: nil,
                           error_message: nil, crash: false)
    rescue JWT::Error => e
      result = Outcome.new(api: 'new', accepted: false, trusted: false,
                           finder_called: finder_called, error_class: e.class.name,
                           error_message: e.message, crash: false)
    rescue StandardError => e
      result = Outcome.new(api: 'new', accepted: false, trusted: false,
                           finder_called: finder_called, error_class: e.class.name,
                           error_message: e.message, crash: true)
    end
    result
  end

  # Run both APIs against the same token and return the two outcomes.
  def compare(token, payload_override: nil, use_finder: false)
    [
      run_legacy(token, payload_override: payload_override, use_finder: use_finder),
      run_new(token, payload_override: payload_override, use_finder: use_finder)
    ]
  end
end

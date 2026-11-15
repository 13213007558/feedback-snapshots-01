# frozen_string_literal: true
require "openssl"
require "base64"

module SecureHeaders
  # Raised when a response combines a CSP nonce with HTTP caching in a way
  # that cannot guarantee the nonce in the response headers matches the nonce
  # embedded in the (possibly cached) response body.
  class NonceCacheError < StandardError; end

  # Explicit cache policy for responses whose Content-Security-Policy uses a
  # nonce.
  #
  # A nonce'd CSP header and a cached HTML body are only safe together if the
  # nonce in the header always matches the nonce in the body the client
  # actually renders. This middleware makes the pairing explicit instead of
  # accidental. Place it OUTSIDE SecureHeaders::Middleware (and outside any
  # conditional-get middleware such as Rack::ConditionalGet/Rack::ETag) so it
  # sees the final status and validators:
  #
  #   use SecureHeaders::NonceCacheMiddleware, mode: :no_store
  #   use SecureHeaders::Middleware
  #   use Rack::ConditionalGet
  #   use Rack::ETag
  #   run MyApp
  #
  # Modes:
  #
  # :no_store (default) - any response that used a CSP nonce is marked
  #   `Cache-Control: private, no-store` and its ETag/Last-Modified
  #   validators are stripped so no cache can reuse the body and no
  #   conditional request can produce a 304 pairing a stale body with a
  #   fresh nonce. A 304 that still carries a nonce (e.g. a validator leaked
  #   from upstream) raises NonceCacheError. This mode is safe for streaming
  #   bodies: the body is never read.
  #
  # :pinned - the nonce is derived deterministically as
  #   Base64(HMAC-SHA256(secret, token)) where `token` identifies the exact
  #   body bytes (typically the content digest the app also uses as its
  #   ETag). Because the nonce is a pure function of the body, a 200, a HEAD
  #   and a 304 all emit the nonce that matches the cached body, and
  #   conditional caching may be kept. Requirements, all verified per
  #   response (NonceCacheError on violation):
  #     * `secret:` must be configured (rotating it changes every nonce, so
  #       it must be deployed together with a cache-key/ETag bump).
  #     * the app must set env[TOKEN_KEY] (or a `token:` lambda must be
  #       given) BEFORE the first call to
  #       SecureHeaders.content_security_policy_*_nonce.
  #     * the response must carry a strong ETag.
  #     * the response must not be `Cache-Control: no-store`.
  #     * with `enforce_token_etag_match: true`, the token must equal the
  #       response ETag, proving the token tracks the body.
  #
  # Responses that never use a nonce are passed through untouched in both
  # modes. A response whose CSP header contains a nonce that secure_headers
  # did not generate for this request always raises NonceCacheError: the
  # library cannot verify a pairing it did not create.
  class NonceCacheMiddleware
    MODE_KEY = "secure_headers_nonce_cache_mode".freeze
    TOKEN_KEY = "secure_headers_nonce_cache_token".freeze
    SECRET_KEY = "secure_headers_nonce_cache_secret".freeze

    NO_STORE = :no_store
    PINNED = :pinned
    MODES = [NO_STORE, PINNED].freeze

    CSP_HEADER_NAMES = [
      ContentSecurityPolicyConfig::HEADER_NAME,
      ContentSecurityPolicyReportOnlyConfig::HEADER_NAME,
    ].freeze

    NONCE_PATTERN = /'nonce-([^']+)'/
    VALIDATOR_HEADERS = ["ETag", "Last-Modified"].freeze
    NO_STORE_CACHE_CONTROL = "private, no-store".freeze

    # Public: derives a deterministic nonce from a secret and a token that
    # identifies the exact response body.
    def self.derive_nonce(secret, token)
      digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new("SHA256"), secret.to_s, token.to_s)
      Base64.urlsafe_encode64(digest).delete("=")
    end

    def initialize(app, mode: NO_STORE, secret: nil, token: nil, enforce_token_etag_match: false)
      unless MODES.include?(mode)
        raise ArgumentError, "mode must be one of #{MODES.inspect}, got #{mode.inspect}"
      end
      if mode == PINNED && (secret.nil? || secret.to_s.empty?)
        raise ArgumentError, "a non-empty secret: is required in :pinned mode"
      end

      @app = app
      @mode = mode
      @secret = secret
      @token_callback = token
      @enforce_token_etag_match = enforce_token_etag_match
    end

    def call(env)
      env[MODE_KEY] = @mode
      env[SECRET_KEY] = @secret if @secret
      if @token_callback && env[TOKEN_KEY].nil?
        env[TOKEN_KEY] = @token_callback.call(Rack::Request.new(env))
      end

      status, headers, body = @app.call(env)
      enforce_policy!(env, status, headers)
      [status, headers, body]
    end

    private

    def enforce_policy!(env, status, headers)
      nonce = env[NONCE_KEY]
      header_nonces = CSP_HEADER_NAMES.flat_map do |name|
        value = headers[name]
        value ? value.scan(NONCE_PATTERN).flatten : []
      end.uniq

      if nonce.nil?
        if header_nonces.any?
          raise NonceCacheError, "the CSP header contains a nonce that secure_headers did not generate for this request; the body/header nonce pairing cannot be verified"
        end
        return
      end

      foreign_nonces = header_nonces - [nonce]
      if foreign_nonces.any?
        raise NonceCacheError, "the CSP header contains a nonce (#{foreign_nonces.join(', ')}) that differs from this request's nonce; the body/header nonce pairing cannot be verified"
      end

      case @mode
      when NO_STORE
        enforce_no_store!(status, headers)
      when PINNED
        enforce_pinned!(env, headers)
      end
    end

    # A random per-request nonce can never be paired with a reused body, so
    # the response must not be storable or revalidatable at all.
    def enforce_no_store!(status, headers)
      if status.to_i == 304
        raise NonceCacheError, "a 304 response cannot carry a fresh random CSP nonce: the client would pair it with a cached body embedding a different nonce. Remove ETag/Last-Modified from nonce'd responses."
      end

      headers["Cache-Control"] = NO_STORE_CACHE_CONTROL
      VALIDATOR_HEADERS.each { |name| headers.delete(name) }
    end

    # A derived nonce is a pure function of the body token, so conditional
    # caching is safe as long as a strong validator identifies the body.
    def enforce_pinned!(env, headers)
      cache_control = headers["Cache-Control"].to_s
      if cache_control.match?(/no-store/i)
        raise NonceCacheError, "Cache-Control: no-store contradicts :pinned mode; either allow caching or use mode: :no_store"
      end

      etag = headers["ETag"]
      if etag.nil?
        raise NonceCacheError, ":pinned mode requires a strong ETag on nonce'd responses so 304s re-validate the exact body the nonce was derived from"
      end
      if etag.start_with?("W/")
        raise NonceCacheError, ":pinned mode requires a strong ETag; weak validators (W/) do not guarantee byte-identical bodies"
      end

      if @enforce_token_etag_match
        unquoted_etag = etag.sub(/\A"/, "").sub(/"\z/, "")
        if env[TOKEN_KEY].to_s != unquoted_etag
          raise NonceCacheError, "the nonce token (#{env[TOKEN_KEY].inspect}) does not match the response ETag (#{etag}); the token must identify the exact body bytes"
        end
      end
    end
  end
end

# frozen_string_literal: true

module JWT
  module Claims
    # Context class to contain the data passed to individual claim validators
    #
    # @api private
    VerificationContext = Struct.new(:payload, :verified_jwa, keyword_init: true)

    # Verifiers to support the ::JWT.decode method
    #
    # @api private
    module DecodeVerifier
      VERIFIERS = {
        verify_expiration: ->(options) { Claims::Expiration.new(leeway: options[:exp_leeway] || options[:leeway]) },
        verify_not_before: ->(options) { Claims::NotBefore.new(leeway: options[:nbf_leeway] || options[:leeway]) },
        verify_iss: ->(options) { options[:iss] && Claims::Issuer.new(issuers: options[:iss]) },
        verify_iat: ->(options) { Claims::IssuedAt.new(leeway: options[:verify_iat].is_a?(Hash) ? options[:verify_iat][:leeway] : nil) },
        verify_jti: ->(options) { Claims::JwtId.new(validator: options[:verify_jti]) },
        verify_aud: ->(options) { options[:aud] && Claims::Audience.new(expected_audience: options[:aud]) },
        verify_sub: ->(options) { options[:sub] && Claims::Subject.new(expected_subject: options[:sub]) },
        required_claims: ->(options) { Claims::Required.new(required_claims: options[:required_claims]) },
        token_binding: ->(options) { Claims::TokenBinding.new(options: options[:token_binding] || options['token_binding']) }
      }.freeze

      private_constant(:VERIFIERS)

      class << self
        # @api private
        def verify!(token, options)
          VERIFIERS.each do |key, verifier_builder|
            next unless configured?(options, key)

            verifier_builder&.call(options)&.verify!(context: VerificationContext.new(payload: token.unverified_payload, verified_jwa: token.verified_jwa))
          end
          nil
        end

        private

        # The token binding is opt-in, but once the caller mentions it a nil
        # or malformed value is a configuration error rather than "not set".
        def configured?(options, key)
          return options.key?(key) || options.key?(key.to_s) if key == :token_binding

          options[key] || options[key.to_s]
        end
      end
    end
  end
end

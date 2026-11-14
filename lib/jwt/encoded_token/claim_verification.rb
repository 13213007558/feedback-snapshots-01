# frozen_string_literal: true

module JWT
  class EncodedToken
    # Claim verification for an encoded token.
    #
    # Each claim is checked and recorded individually. That lets the token know
    # exactly what a success covers, so a weak check cannot silently stand in
    # for a stronger one that failed against the same contents.
    #
    # @private
    module ClaimVerification
      # Verifies the claims of the token.
      #
      # A successful verification only makes the payload readable if it verifies
      # at least one claim. Passing an empty Hash checks nothing, and cannot
      # establish that the claims are trustworthy.
      #
      # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
      # @raise [JWT::ClaimValidationError] if the claims are invalid.
      # @raise [JWT::MalformedTokenError] if the payload cannot be decoded, which happens before any claim is validated.
      def verify_claims!(*options)
        options  = claims_options(options)
        revision = @state.revision
        context  = ClaimsContext.new(self)
        policy   = []

        claim_checks(options).each do |check|
          policy = VerificationState.claim_policy([check])
          Claims::Verifier.verify!(context, check)
          @state.claims_succeeded!(policy, revision)
        end

        nil
      rescue ArgumentError
        raise
      rescue StandardError
        @state.claims_failed!(policy, revision)
        raise
      end

      # Returns the errors of the claims of the token.
      #
      # This is a diagnostic read. It does not change the verification state.
      #
      # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
      # @return [Array<JWT::Claims::Error>] the errors of the claims.
      def claim_errors(*options)
        Claims::Verifier.errors(ClaimsContext.new(self), *claims_options(options))
      end

      # Returns whether the claims of the token are valid for the given options.
      #
      # A successful check only makes the payload readable when it also covers
      # every claim check that has previously failed for the current token
      # contents. A check that covers no claims cannot clear such a failure.
      #
      # @param options [Array<Symbol>, Hash] the claims to verify. By default, it checks the 'exp' claim.
      # @return [Boolean] whether the claims are valid.
      def valid_claims?(*options)
        options  = claims_options(options)
        revision = @state.revision
        context  = ClaimsContext.new(self)
        policy   = []

        claim_checks(options).each do |check|
          policy = VerificationState.claim_policy([check])
          errors = Claims::Verifier.errors(context, check)

          next if errors.empty?

          @state.claims_failed!(policy, revision)
          return false
        end

        @state.claims_succeeded!(policy, revision)
        true
      rescue ArgumentError
        raise
      rescue StandardError
        @state.claims_failed!(policy, revision)
        raise
      end

      private

      def claims_options(options)
        return DEFAULT_CLAIMS if options.first.nil?

        options
      end

      # Claims are checked one option at a time so that each result can be
      # recorded on its own. A Hash option expands into one check per claim
      # key, which keeps the state exact when several claims share a Hash.
      def claim_checks(options)
        options.flat_map do |option|
          option.is_a?(Hash) ? option.each_key.map { |key| { key => option[key] } } : [option]
        end
      end
    end
  end
end

# frozen_string_literal: true

module JWT
  module Policy
    # Holds the server-registered verification policies, keyed by purpose.
    #
    # Policies are chosen by the application through the purpose it passes when
    # verifying a token; an unverified token can never select or alter a policy.
    # Registering two purposes whose accepted token sets overlap is a
    # configuration error that is reported eagerly rather than silently
    # resolving to whichever policy was registered first.
    class Registry
      def initialize
        @policies = {}
      end

      # @return [Array<VerificationPolicy>] the registered policies.
      def policies
        @policies.values
      end

      # Registers a policy.
      #
      # @param policy [VerificationPolicy] the policy to register.
      # @raise [JWT::PolicyError] if the purpose is already registered or the
      #   policy overlaps an existing one.
      # @return [void]
      def register(policy)
        ensure_unique_purpose!(policy)
        ensure_no_overlap!(policy)

        @policies[policy.purpose] = policy
        nil
      end

      # Fetches the policy for a purpose.
      #
      # @param purpose [Symbol, String] the purpose to look up.
      # @raise [JWT::UnknownPurposeError] if no policy is registered for it.
      # @return [VerificationPolicy]
      def fetch(purpose)
        @policies.fetch(purpose) do
          raise JWT::UnknownPurposeError,
                "No verification policy registered for purpose #{purpose.inspect}. " \
                "Registered purposes: #{@policies.keys.inspect}"
        end
      end

      private

      def ensure_unique_purpose!(policy)
        return unless @policies.key?(policy.purpose)

        raise JWT::PolicyError, "A verification policy is already registered for purpose #{policy.purpose.inspect}"
      end

      def ensure_no_overlap!(new_policy)
        @policies.each_value do |existing|
          next unless existing.overlaps?(new_policy)

          raise JWT::PolicyError, overlap_message(existing, new_policy)
        end
      end

      def overlap_message(existing, new_policy)
        dimensions = VerificationPolicy::CONSTRAINT_DIMENSIONS.map(&:to_s).join(', ')
        'Verification policies ' \
          "#{existing.purpose.inspect} and #{new_policy.purpose.inspect} overlap on every discriminator " \
          "(#{dimensions}); make at least one dimension distinct so a token cannot match both purposes"
      end
    end
  end
end

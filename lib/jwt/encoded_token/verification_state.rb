# frozen_string_literal: true

module JWT
  class EncodedToken
    # Tracks which checks have succeeded for the token's current contents.
    #
    # A token's contents count as one revision. Replacing the payload advances
    # the revision and clears everything, so a result can never be carried over
    # to different bytes. Within one revision the state also remembers claim
    # checks that failed: a later success only clears a failure when it is at
    # least as strong as the check that failed.
    #
    # @private
    class VerificationState
      LEEWAY_CLAIMS = %i[exp nbf iat].freeze

      attr_reader :revision

      def initialize
        @revision                    = 0
        @signature_verified_revision = nil
        @claims_verified_revision    = nil
        @failed_claim_policies       = []
      end

      def initialize_copy(other)
        super
        @failed_claim_policies = @failed_claim_policies.dup
      end

      def advance!
        @revision += 1
        @signature_verified_revision = nil
        @claims_verified_revision    = nil
        @failed_claim_policies       = []
      end

      # A new signature check starts in an undecided state. Earlier claim
      # results stay, because they describe contents that have not changed.
      def signature_pending!
        @signature_verified_revision = nil
      end

      def signature_succeeded!(revision)
        return unless revision == @revision

        @signature_verified_revision = revision
      end

      # A failed signature check means nothing can be considered verified: the
      # claim result may have been produced under a different signature. Both
      # results are dropped so they must be established again together.
      def signature_failed!
        @signature_verified_revision = nil
        @claims_verified_revision    = nil
      end

      def signature_verified?
        @signature_verified_revision == @revision
      end

      def claims_succeeded!(policy, revision)
        return if policy.empty? || revision != @revision

        @failed_claim_policies.reject! { |failed| covers?(policy, failed) }
        return if @failed_claim_policies.any?

        @claims_verified_revision = revision
      end

      def claims_failed!(policy, revision)
        return if policy.nil? || policy.empty? || revision != @revision

        @claims_verified_revision = nil
        @failed_claim_policies << policy unless @failed_claim_policies.include?(policy)
      end

      def claims_verified?
        @claims_verified_revision == @revision && @failed_claim_policies.empty?
      end

      # A claim policy describes one verification check as a key and its
      # parameters. A required list with no entries, or an empty options Hash,
      # checks nothing and is not recorded as a success.
      def self.claim_policy(options)
        options.each_with_object([]) do |option, policy|
          if option.is_a?(Hash)
            option.each_key { |key| policy << [key.to_sym, option[key]] }
          else
            policy << [option.to_sym, nil]
          end
        end.uniq.reject { |key, params| key == :required && Array(params).empty? }
      end

      private

      def covers?(policy, failed_policy)
        failed_policy.all? do |failed|
          policy.any? { |success| check_covers?(success, failed) }
        end
      end

      def check_covers?(success, failed)
        success_key, success_params = success
        failed_key, failed_params = failed
        return false unless success_key == failed_key

        case success_key
        when :required, :crit
          (Array(failed_params) - Array(success_params)).empty?
        when *LEEWAY_CLAIMS
          leeway(success_params) <= leeway(failed_params)
        else
          # A check on the same claim with different expected values is a
          # different assertion, not a weaker one. A success is allowed to
          # replace the earlier failure.
          true
        end
      end

      def leeway(params)
        return 0 unless params.is_a?(Hash)

        params[:leeway] || params['leeway'] || 0
      end
    end
  end
end

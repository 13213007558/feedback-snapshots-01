# frozen_string_literal: true

module ActChain
  # Structured outcome handed to the upper authorization layer.
  #
  # `valid?` answers only the topology questions the gateway can prove from the
  # outer signature plus policy. `fully_consented?` additionally requires that
  # every hop carries independently verifiable consent. They are deliberately
  # separate so callers never confuse "well-formed chain" with "everyone agreed".
  Result = Struct.new(:chain, :policy_errors, :hop_evidence, :final_audience, keyword_init: true) do
    def valid?
      policy_errors.empty?
    end

    def delegated?
      chain.delegated?
    end

    def original_subject
      chain.path.first
    end

    def actors
      chain.path.drop(1)
    end

    # True only when the chain is valid and no hop lacks verified consent.
    # A hop with no evidence, or evidence that could not be verified, fails this.
    # A token that carries no delegation at all has nothing to consent to, so it
    # does not fail this check (callers can use `delegated?` to distinguish).
    def fully_consented?
      valid? && (!delegated? || hop_evidence.all? { |entry| entry[:status] == :verified })
    end

    def unverified_hops
      hop_evidence.reject { |entry| entry[:status] == :verified }
    end

    def verdict
      return :rejected unless valid?
      return :not_delegated unless delegated?
      return :verified_consent if fully_consented?

      :valid_but_consent_unverified
    end
  end
end

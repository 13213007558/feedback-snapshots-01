# frozen_string_literal: true

module SecureHeaders
  module CspChangeChecker
    # Compares two parsed, effective policies directive by directive and
    # applies the default-src fallback for fetch directives exactly as the
    # browser resolution algorithm describes (non-fetch directives do not
    # fall back).
    module DirectiveComparison
      module_function

      Finding = Struct.new(
        :directive, :verdict, :evidence, :witness,
        :old_effective_sources, :new_effective_sources,
        keyword_init: true
      )

      def compare(old_policy, new_policy)
        unsupported_directives =
          (old_policy.directives.keys | new_policy.directives.keys).select do |directive|
            !EffectivePolicyParser::SUPPORTED_DIRECTIVES.include?(directive)
          end

        findings = unsupported_directives.map do |directive|
          unsupported_directive_finding(directive, old_policy, new_policy)
        end

        supported_directives(old_policy, new_policy).each do |directive|
          findings << compare_directive(directive, old_policy, new_policy)
        end

        findings
      end

      def supported_directives(old_policy, new_policy)
        (old_policy.directives.keys | new_policy.directives.keys) &
          EffectivePolicyParser::SUPPORTED_DIRECTIVES
      end

      def unsupported_directive_finding(directive, old_policy, new_policy)
        old_tokens = old_policy.directives[directive] || []
        new_tokens = new_policy.directives[directive] || []
        Finding.new(
          directive: directive,
          verdict: Verdict::CANNOT_DETERMINE,
          evidence: "directive #{directive} is not modelled by the checker; " \
                    "its change cannot be certified",
          witness: nil,
          old_effective_sources: old_tokens.map { |t| t[:raw] },
          new_effective_sources: new_tokens.map { |t| t[:raw] }
        )
      end

      def compare_directive(directive, old_policy, new_policy)
        old_tokens = effective_tokens(directive, old_policy)
        new_tokens = effective_tokens(directive, new_policy)

        if unsupported?(old_tokens) || unsupported?(new_tokens)
          return unsupported_token_finding(directive, old_policy, new_policy, old_tokens, new_tokens)
        end

        old_set = SourceSetSemantics.normalize_none(old_tokens)
        new_set = SourceSetSemantics.normalize_none(new_tokens)

        additions = new_set.reject do |new_token|
          old_set.any? { |old_token| SourceSetSemantics.covers?(old_token, new_token) }
        end
        removals = old_set.reject do |old_token|
          new_set.any? { |new_token| SourceSetSemantics.covers?(new_token, old_token) }
        end

        build_finding(directive, old_set, new_set, additions, removals)
      end

      def effective_tokens(directive, policy)
        tokens = policy.directives[directive]
        return tokens unless tokens.nil?
        # Only fetch directives inherit default-src.
        return [] unless EffectivePolicyParser::SUPPORTED_FETCH_DIRECTIVES.include?(directive)
        policy.directives[PolicyManagement::DEFAULT_SRC] || []
      end

      def unsupported?(tokens)
        tokens.any? { |t| t[:kind] == :unsupported }
      end

      def unsupported_token_finding(directive, old_policy, new_policy, old_tokens, new_tokens)
        Finding.new(
          directive: directive,
          verdict: Verdict::CANNOT_DETERMINE,
          evidence: "unsupported source grammar present in effective #{directive}; " \
                    "no sound tightening claim can be made",
          witness: nil,
          old_effective_sources: (old_policy.directives[directive] || []).map { |t| t[:raw] },
          new_effective_sources: (new_policy.directives[directive] || []).map { |t| t[:raw] }
        )
      end

      def build_finding(directive, old_set, new_set, additions, removals)
        if additions.empty? && removals.empty?
          Finding.new(
            directive: directive,
            verdict: Verdict::PROVABLY_TIGHTENED,
            evidence: "effective allow-set unchanged (equivalent sources after resolution; " \
                      "no new capability granted)",
            witness: nil,
            old_effective_sources: old_set.map { |t| t[:raw] },
            new_effective_sources: new_set.map { |t| t[:raw] }
          )
        elsif additions.any?
          witness = SourceSetSemantics.witness_for(directive, additions.first)
          Finding.new(
            directive: directive,
            verdict: Verdict::LOOSENED,
            evidence: "new source(s) not covered by the previous allow-set: " \
                      "#{additions.map { |t| t[:raw] }.join(', ')}",
            witness: witness,
            old_effective_sources: old_set.map { |t| t[:raw] },
            new_effective_sources: new_set.map { |t| t[:raw] }
          )
        else
          Finding.new(
            directive: directive,
            verdict: Verdict::PROVABLY_TIGHTENED,
            evidence: "removed source(s) with no replacement grant: " \
                      "#{removals.map { |t| t[:raw] }.join(', ')}",
            witness: nil,
            old_effective_sources: old_set.map { |t| t[:raw] },
            new_effective_sources: new_set.map { |t| t[:raw] }
          )
        end
      end
    end
  end
end

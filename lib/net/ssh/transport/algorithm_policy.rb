module Net
  module SSH
    module Transport
      # An optional, strict negotiation policy that constrains which
      # combinations of key-exchange, host-key signature, encryption and MAC
      # algorithms a session may settle on.
      #
      # Unlike the per-algorithm options (:kex, :host_key, :encryption,
      # :hmac), which merely reorder or extend preference lists, a policy is
      # applied *after* those lists have been composed, so compatibility
      # options such as :append_all_supported_algorithms or '+algo' additions
      # cannot reintroduce algorithms the policy forbids. The same policy
      # object is consulted for the initial key exchange and for every rekey,
      # and the negotiated combination is validated before any authentication
      # data is exchanged.
      #
      # A policy is a hash with any of these keys:
      #
      # * :kex, :host_key, :encryption, :hmac => allow-lists of algorithm
      #   names. When present, only the listed algorithms may be offered or
      #   accepted for that category.
      # * :combinations => an array of hashes, each naming one or more of
      #   :kex, :host_key, :encryption, :hmac. The negotiated set of
      #   algorithms must satisfy at least one of these rules; a rule matches
      #   when every category it names equals the negotiated value (both
      #   directions for :encryption and :hmac).
      #
      # Example:
      #
      #   Net::SSH.start(host, user, algorithm_policy: {
      #     kex: %w[curve25519-sha256 ecdh-sha2-nistp256],
      #     host_key: %w[ssh-ed25519 rsa-sha2-512],
      #     encryption: %w[aes256-gcm@openssh.com chacha20-poly1305@openssh.com],
      #     hmac: %w[hmac-sha2-512-etm@openssh.com],
      #     combinations: [
      #       { kex: 'curve25519-sha256', host_key: 'ssh-ed25519',
      #         encryption: 'aes256-gcm@openssh.com',
      #         hmac: 'hmac-sha2-512-etm@openssh.com' }
      #     ]
      #   })
      #
      # Diagnostics produced by this class contain algorithm names and rule
      # explanations only; they never include session keys, shared secrets or
      # authentication data.
      class AlgorithmPolicy
        # The algorithm categories a policy can restrict.
        CATEGORIES = %i[kex host_key encryption hmac].freeze

        # Creates a policy from its hash definition, raising ArgumentError
        # for malformed input.
        def initialize(definition)
          unless definition.is_a?(Hash)
            raise ArgumentError, "algorithm_policy must be a Hash, got #{definition.class}"
          end

          normalized = definition.each_with_object({}) { |(key, value), memo| memo[key.to_sym] = value }
          unknown = normalized.keys - (CATEGORIES + [:combinations])
          raise ArgumentError, "algorithm_policy has unknown keys: #{unknown.join(', ')}" if unknown.any?

          @allow = {}
          CATEGORIES.each do |category|
            next unless normalized.key?(category)

            list = Array(normalized[category]).map(&:to_s)
            if list.empty?
              raise ArgumentError, "algorithm_policy #{category} allow-list must not be empty"
            end

            @allow[category] = list
          end

          @combinations = Array(normalized[:combinations]).map { |rule| normalize_rule(rule) }
        end

        # Returns true if the policy restricts the given category.
        def restricted?(category)
          @allow.key?(category)
        end

        # Returns the allow-list for a restricted category (nil if the
        # category is not restricted).
        def allowed(category)
          @allow[category]
        end

        # Filters a composed preference list, keeping only entries the policy
        # allows for that category. Unrestricted categories pass through
        # unchanged.
        def filter(category, list)
          return list unless restricted?(category)

          list.select { |name| @allow[category].include?(name) }
        end

        # Returns true if any combination rules were defined.
        def combinations?
          @combinations.any?
        end

        # Evaluates a fully negotiated set of algorithms against the policy.
        # Returns [accepted, explanation] where the explanation names the
        # negotiated algorithms and the rule that accepted them, or why each
        # rule rejected them.
        def evaluate(kex:, host_key:, encryption_client:, encryption_server:, hmac_client:, hmac_server:)
          negotiated = {
            kex: kex,
            host_key: host_key,
            encryption: [encryption_client, encryption_server].uniq,
            hmac: [hmac_client, hmac_server].uniq
          }

          problems = []
          CATEGORIES.each do |category|
            next unless restricted?(category)

            disallowed = Array(negotiated[category]) - @allow[category]
            problems << "#{category} #{Array(negotiated[category]).join('/')} not in allow-list #{@allow[category].join(',')}" if disallowed.any?
          end

          combination_explanation = nil
          if problems.empty? && combinations?
            matched, mismatches = match_combination(negotiated)
            if matched
              combination_explanation = "matched combination rule #{describe_rule(matched)}"
            else
              problems << "no combination rule accepts the negotiated set (#{mismatches.join('; ')})"
            end
          end

          summary = "kex=#{kex} host_key=#{host_key} " \
                    "encryption_client=#{encryption_client} encryption_server=#{encryption_server} " \
                    "hmac_client=#{hmac_client} hmac_server=#{hmac_server}"

          if problems.empty?
            detail = combination_explanation || "all categories within allow-lists"
            [true, "accepted #{summary} (#{detail})"]
          else
            [false, "rejected #{summary}: #{problems.join('; ')}"]
          end
        end

        private

        def normalize_rule(rule)
          unless rule.is_a?(Hash)
            raise ArgumentError, "algorithm_policy combination rules must be Hashes, got #{rule.class}"
          end

          normalized = rule.each_with_object({}) { |(key, value), memo| memo[key.to_sym] = value.to_s }
          unknown = normalized.keys - CATEGORIES
          raise ArgumentError, "algorithm_policy combination rule has unknown keys: #{unknown.join(', ')}" if unknown.any?
          raise ArgumentError, "algorithm_policy combination rule must name at least one category" if normalized.empty?

          normalized
        end

        # Returns [matching_rule_or_nil, array_of_mismatch_descriptions].
        def match_combination(negotiated)
          mismatches = []
          @combinations.each do |rule|
            failed = rule.reject do |category, expected|
              Array(negotiated[category]).all? { |value| value == expected }
            end
            return [rule, mismatches] if failed.empty?

            mismatches << "rule #{describe_rule(rule)} mismatches #{failed.keys.join(', ')}"
          end
          [nil, mismatches]
        end

        def describe_rule(rule)
          "{" + rule.map { |category, expected| "#{category}: #{expected}" }.join(', ') + "}"
        end
      end
    end
  end
end

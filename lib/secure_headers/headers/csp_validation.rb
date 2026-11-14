# frozen_string_literal: true

module SecureHeaders
  # Phased validation for CSP directive-injection bytes.
  #
  # Caller-controlled source expressions can contain CR, LF or ";" bytes that
  # let a value break out of its directive and inject sibling directives.
  # Historically secure_headers replaced these bytes with spaces and emitted a
  # deprecation warning. This module adds the staged rollout machinery for
  # moving to strict rejection:
  #
  #   :observe - default. Existing scrubbed output is unchanged, while every
  #              offending value is surfaced as a structured, redacted
  #              violation so callers can find affected production configs.
  #   :strict  - the whole invalid change is rejected with a
  #              CspValidationError before any new policy is applied, so no
  #              half-written policy can survive.
  module CspValidation
    OBSERVE_MODE = :observe
    STRICT_MODE = :strict
    VALIDATION_MODES = [OBSERVE_MODE, STRICT_MODE].freeze

    # Caller surfaces where a policy can be introduced or mutated.
    ENFORCED_POLICY = :enforced
    REPORT_ONLY_POLICY = :report_only
    POLICY_ORDER = {
      ENFORCED_POLICY => 0,
      REPORT_ONLY_POLICY => 1
    }.freeze

    # Bytes that let a value break out of its directive. CR/LF are included so
    # naive downstreams that split on a bare \r cannot smuggle directives.
    INJECTION_REGEX = /[\n\r;]/.freeze

    # Matches a nonce source expression. The nonce material is secret and is
    # never reproduced in a violation.
    NONCE_REGEX = /'nonce-[^']*'/

    # Matches an absolute URL (scheme + host[:port]). The host/port identify
    # the tenant and are redacted; the path (which carries no tenant identity)
    # is retained.
    ABSOLUTE_URL_REGEX = %r{[a-z][a-z0-9+.-]*://[^/\s;]*}i

    class << self
      # Public: resolve the active mode. An explicit mode takes precedence,
      # otherwise the process-wide Configuration default is used, falling back
      # to :observe when secure_headers has not been configured.
      def resolve_mode(explicit_mode)
        return explicit_mode if explicit_mode
        if defined?(Configuration) && Configuration.respond_to?(:csp_validation_mode)
          Configuration.csp_validation_mode
        else
          OBSERVE_MODE
        end
      end

      def validate_mode!(mode)
        unless VALIDATION_MODES.include?(mode)
          raise ArgumentError, "Unknown CSP validation mode #{mode.inspect}. Must be one of #{VALIDATION_MODES.inspect}"
        end
        mode
      end

      # Public: collect every directive-injection violation in a policy.
      #
      # policy   - a ContentSecurityPolicyConfig or a plain config Hash.
      # policy_kind - :enforced or :report_only (defaults to :enforced).
      # source   - where the policy was checked, e.g. :default_registration,
      #            :named_override, :request_override, :request_append,
      #            :header_generation.
      #
      # Returns an Array of frozen violation Hashes with a deterministic order
      # so repeated checks of the same policy produce identical results, even
      # when several directives are affected.
      def violations_for(policy, policy_kind: ENFORCED_POLICY, source: :header_generation)
        hash = policy.respond_to?(:to_h) ? policy.to_h : policy.to_hash.dup
        violations = []

        PolicyManagement::ALL_DIRECTIVES.sort.each do |directive|
          next unless hash.key?(directive)
          value = hash[directive]
          next if value.nil? || value == OPT_OUT

          case PolicyManagement::DIRECTIVE_VALUE_TYPES[directive]
          when :source_list,
               :sandbox_list,
               :media_type_list,
               :require_sri_for_list,
               :require_trusted_types_for_list
            tokens = value.is_a?(Array) ? value : Array(value)
            tokens.each_with_index do |token, token_index|
              collect_token_violations(violations, policy_kind, source, directive, token_index, token)
            end
          when :report_to_endpoint
            collect_token_violations(violations, policy_kind, source, directive, nil, value)
          end
        end

        violations.sort_by { |violation| violation_sort_key(violation) }
      end

      # Public: strict gate. Raises CspValidationError carrying every violation
      # (both enforced and report-only) when any policy is invalid. The combined
      # list is re-sorted so the result is independent of argument order.
      def strict_violation_error(violations)
        violations = violations.reject(&:empty?).flatten
        return if violations.empty?
        CspValidationError.new(violations.sort_by { |violation| violation_sort_key(violation) })
      end

      # Public: redact secret/high-cardinality material from a value while
      # keeping enough shape to recognize and fix the offending expression.
      def redact(value)
        redacted = value.to_s.dup
        redacted.gsub!(NONCE_REGEX, "'nonce-[REDACTED]'")
        redacted.gsub!(ABSOLUTE_URL_REGEX) do |match|
          scheme = match.split("://", 2).first
          "#{scheme}://[REDACTED]"
        end
        redacted
      end

      private

      def collect_token_violations(violations, policy_kind, source, directive, token_index, token)
        str = token.to_s
        return unless str =~ INJECTION_REGEX

        offending = []
        offsets = []
        str.each_char.with_index do |char, index|
          if char =~ INJECTION_REGEX
            offending << char
            offsets << index
          end
        end

        violations << {
          policy: policy_kind,
          source: source,
          directive: directive,
          token_index: token_index,
          char_offsets: offsets,
          offending_bytes: offending.uniq,
          redacted_value: redact(str),
        }.freeze
      end

      def violation_sort_key(violation)
        [
          POLICY_ORDER.fetch(violation[:policy], 99),
          violation[:source].to_s,
          violation[:directive].to_s,
          violation[:token_index].nil? ? -1 : violation[:token_index],
          violation[:char_offsets].first || 0,
        ]
      end
    end
  end
end

# frozen_string_literal: true

module JWT
  class X5cKeyFinder
    # Immutable, validated description of how an x5c chain is evaluated.
    #
    # +purpose+ is resolved to an OpenSSL purpose constant, +at_time+ to a Time
    # (or nil to use the current time), and +revocation+ to :require or :none.
    # Unknown keys are rejected rather than silently ignored so a typo cannot
    # widen the policy.
    class Policy
      PURPOSES = {
        any: OpenSSL::X509::PURPOSE_ANY,
        ssl_client: OpenSSL::X509::PURPOSE_SSL_CLIENT,
        client_auth: OpenSSL::X509::PURPOSE_SSL_CLIENT,
        ssl_server: OpenSSL::X509::PURPOSE_SSL_SERVER,
        server_auth: OpenSSL::X509::PURPOSE_SSL_SERVER,
        ns_ssl_server: OpenSSL::X509::PURPOSE_NS_SSL_SERVER,
        smime_sign: OpenSSL::X509::PURPOSE_SMIME_SIGN,
        smime_encrypt: OpenSSL::X509::PURPOSE_SMIME_ENCRYPT,
        crl_sign: OpenSSL::X509::PURPOSE_CRL_SIGN,
        ocsp_helper: OpenSSL::X509::PURPOSE_OCSP_HELPER,
        timestamp_sign: OpenSSL::X509::PURPOSE_TIMESTAMP_SIGN
      }.freeze

      REVOCATION_POLICIES = %i[require none].freeze

      REVOCATION_ALIASES = {
        required: :require,
        chain: :require,
        full: :require,
        ignore: :none,
        disabled: :none,
        off: :none,
        skip: :none
      }.freeze

      OPTION_ALIASES = {
        certificate_purpose: :purpose,
        allowed_purpose: :purpose,
        purpose_name: :purpose,
        usage: :purpose,
        time: :at_time,
        verification_time: :at_time,
        verify_at: :at_time,
        verify_time: :at_time,
        check_time: :at_time,
        valid_at: :at_time,
        revocation_policy: :revocation,
        revocation_evidence: :revocation,
        revocation_check: :revocation,
        crl_policy: :revocation,
        crl_check: :revocation,
        check_crl: :revocation,
        require_crl: :revocation,
        crl_set: :crls,
        certificate_revocation_lists: :crls,
        revocation_data: :crls
      }.freeze

      DEFAULT = { purpose: :any, at_time: nil, revocation: :require }.freeze

      POLICY_KEYS = DEFAULT.keys.freeze

      attr_reader :purpose, :at_time, :revocation

      def self.build(options = {}, base: DEFAULT)
        new(base: base, options: options)
      end

      # Maps caller-supplied option names to canonical policy keys.
      def self.resolve_keys(options)
        unless options.respond_to?(:each_pair)
          raise ArgumentError, "Invalid x5c policy: expected a Hash, got #{options.class}"
        end

        options.each_pair.each_with_object({}) do |(name, value), result|
          key = name.to_sym
          result[OPTION_ALIASES.fetch(key, key)] = value
        end
      end

      def initialize(base:, options:)
        options = self.class.resolve_keys(options)
        unknown_keys = options.keys - POLICY_KEYS - [:crls]
        raise ArgumentError, "Unknown x5c policy option(s): #{unknown_keys.map(&:inspect).join(', ')}" unless unknown_keys.empty?

        base_options = base.is_a?(self.class) ? base.to_h : self.class.resolve_keys(base)
        merged = self.class.resolve_keys(base_options).merge(options)
        @purpose = resolve_purpose(merged[:purpose])
        @at_time = coerce_time(merged[:at_time])
        @revocation = resolve_revocation(merged[:revocation])
        freeze
      end

      def to_h
        { purpose: @purpose, at_time: @at_time, revocation: @revocation }
      end

      def revocation_required?
        @revocation == :require
      end

      private

      def resolve_purpose(value)
        return OpenSSL::X509::PURPOSE_ANY if value.nil?
        return value if value.is_a?(Integer) && PURPOSES.value?(value)

        PURPOSES.fetch(value.to_s.downcase.to_sym) do
          raise ArgumentError, "Unknown certificate purpose: #{value.inspect}"
        end
      end

      def resolve_revocation(value)
        return :require if value.nil?
        return value ? :require : :none if value == true || value == false

        normalized = value.to_s.downcase.to_sym
        normalized = REVOCATION_ALIASES.fetch(normalized, normalized)

        return normalized if REVOCATION_POLICIES.include?(normalized)

        raise ArgumentError, "Unknown revocation policy: #{value.inspect}"
      end

      def coerce_time(value)
        return nil if value.nil?
        return value if value.is_a?(Time)
        return value.to_time if value.respond_to?(:to_time)
        return Time.at(value) if value.is_a?(Numeric)

        raise ArgumentError, "Invalid verification time: #{value.inspect}"
      end
    end
  end
end

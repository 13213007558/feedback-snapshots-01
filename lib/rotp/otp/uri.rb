module ROTP
  class OTP
    # https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    class URI
      STANDARD_PARAMETERS = %w[secret issuer algorithm digits period counter].freeze

      def initialize(otp, account_name: nil, counter: nil)
        @otp = otp
        @account_name = account_name || ''
        @counter = counter
      end

      def to_s
        "otpauth://#{type}/#{label}?#{parameters}"
      end

      private

      def algorithm
        digest = @otp.digest.to_s
        return if skip_default_uri_params && digest.casecmp(DEFAULT_DIGEST).zero?

        digest.upcase
      end

      def counter
        return if @otp.is_a?(TOTP)
        raise ArgumentError, 'HOTP provisioning URIs require a counter' if @counter.nil?

        @counter
      end

      def digits
        return if skip_default_uri_params && @otp.digits == DEFAULT_DIGITS

        @otp.digits
      end

      def issuer
        value = @otp.issuer
        return if value.nil?

        value = value.to_s.strip
        value unless value.empty?
      end

      def label
        [issuer, @account_name.rstrip]
          .compact
          .map { |value| ERB::Util.url_encode(value) }
          .join(':')
      end

      def parameters
        standard = {
          'secret' => @otp.secret,
          'issuer' => issuer,
          'algorithm' => algorithm,
          'digits' => digits,
          'period' => period,
          'counter' => counter,
        }.reject { |_, value| value.nil? }

        standard.merge(extension_parameters(standard))
          .map { |key, value| "#{ERB::Util.url_encode(key)}=#{ERB::Util.url_encode(value)}" }
          .join('&')
      end

      def extension_parameters(standard)
        seen = {}
        @otp.provisioning_params.each_with_object({}) do |(key, value), params|
          key = key.to_s
          normalized = key.downcase
          next if value.nil?
          next if key.empty?
          next if standard.key?(key)
          next if STANDARD_PARAMETERS.include?(normalized)
          next if seen[normalized]

          seen[normalized] = true
          params[key] = value
        end
      end

      def period
        return if @otp.is_a?(HOTP)
        return if skip_default_uri_params && @otp.interval == DEFAULT_INTERVAL

        @otp.interval
      end

      def type
        case @otp
        when TOTP then 'totp'
        when HOTP then 'hotp'
        end
      end

      def skip_default_uri_params
        @otp.skip_default_uri_params
      end
    end
  end
end

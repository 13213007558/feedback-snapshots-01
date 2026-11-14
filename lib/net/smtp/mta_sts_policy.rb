# frozen_string_literal: true

module Net
  class SMTP
    #
    # A structured MTA-STS policy supplied by the caller.
    #
    # Net::SMTP does not fetch policies. The application is responsible for
    # obtaining the policy (for example, over HTTPS) and for telling Net::SMTP
    # when it was fetched. This class only represents the policy and validates
    # the values needed at SMTP connection time: the policy domain, the
    # allowed MX patterns, the policy lifetime, and the policy mode.
    #
    #   policy = Net::SMTP::MTASTSPolicy.new(
    #     domain: "example.com",
    #     mode: :enforce,
    #     mx: ["mail.example.com", "*.example.net"],
    #     max_age: 604800,
    #     fetched_at: Time.now
    #   )
    #
    class MTASTSPolicy
      # MTA-STS policy modes defined by RFC 8461.
      MODES = [:enforce, :testing, :none].freeze

      # Upper bound of the MTA-STS max_age field defined by RFC 8461.
      MAX_MAX_AGE = 31557600

      # The Policy Domain this policy belongs to.
      attr_reader :domain

      # One of +:enforce+, +:testing+, or +:none+.
      attr_reader :mode

      # Allowed MX patterns, for example <tt>["mail.example.com", "*.example.net"]</tt>.
      attr_reader :mx

      # Lifetime of the policy in seconds, as declared by the policy.
      attr_reader :max_age

      # Time at which the application fetched the policy.
      attr_reader :fetched_at

      # Time at which the policy expires.
      attr_reader :expires_at

      # Policy version. RFC 8461 currently defines only "STSv1".
      attr_reader :version

      class << self
        # Coerce a Hash (or an already structured object) into a policy.
        def coerce(value)
          case value
          when nil
            nil
          when MTASTSPolicy
            value
          when Hash
            from_h(value)
          else
            if value.respond_to?(:domain) && value.respond_to?(:mode) && value.respond_to?(:mx)
              from_h(
                :domain => value.domain,
                :mode => value.mode,
                :mx => value.mx,
                :max_age => value.respond_to?(:max_age) ? value.max_age : nil,
                :fetched_at => value.respond_to?(:fetched_at) ? value.fetched_at : nil,
                :expires_at => value.respond_to?(:expires_at) ? value.expires_at : nil,
                :version => value.respond_to?(:version) ? value.version : nil
              )
            else
              raise ArgumentError, "MTA-STS policy must be a Hash or respond to #domain, #mode and #mx"
            end
          end
        end

        # Build a policy from a Hash. Symbol and String keys are both accepted.
        def from_h(hash)
          new(
            :domain => fetch_key(hash, :domain, :policy_domain),
            :mode => fetch_key(hash, :mode),
            :mx => fetch_key(hash, :mx),
            :max_age => fetch_key(hash, :max_age),
            :fetched_at => fetch_key(hash, :fetched_at),
            :expires_at => fetch_key(hash, :expires_at),
            :version => fetch_key(hash, :version)
          )
        end

        # Parse the text format of a policy that the application already
        # retrieved. This does not perform any network access.
        def parse(text, domain:, fetched_at: nil)
          values = Hash.new { |hash, key| hash[key] = [] }
          text.to_s.each_line do |line|
            line = line.chomp
            next if line.strip.empty?
            name, separator, value = line.partition(":")
            if separator.empty?
              raise ArgumentError, "invalid MTA-STS policy line: #{line.inspect}"
            end
            values[name.strip.downcase] << value.strip
          end

          version = values["version"].first || "STSv1"
          mode = values["mode"].first
          max_age = values["max_age"].first
          raise ArgumentError, "MTA-STS policy has no mode" if mode.nil?
          raise ArgumentError, "MTA-STS policy has no max_age" if max_age.nil?

          new(
            :domain => domain,
            :mode => mode,
            :mx => values["mx"],
            :max_age => max_age,
            :fetched_at => fetched_at,
            :version => version
          )
        end

        # Normalize a DNS name for comparison purposes.
        def normalize_host(host)
          host.to_s.strip.downcase.sub(/\.\z/, "")
        end

        # Returns true when +host+ matches the +pattern+ using the RFC 8461
        # (RFC 6125) MX matching rules. A wildcard is only allowed as the
        # entire left-most label and matches exactly one label.
        def mx_pattern_match?(pattern, host)
          pattern = normalize_host(pattern)
          host = normalize_host(host)
          return false if pattern.empty? || host.empty?

          if pattern.start_with?("*.")
            suffix = pattern[2..]
            return false if suffix.empty?
            labels = host.split(".")
            suffix_labels = suffix.split(".")
            labels.length == suffix_labels.length + 1 &&
              labels.last(suffix_labels.length) == suffix_labels
          elsif pattern.include?("*")
            false
          else
            pattern == host
          end
        end

        private

        def fetch_key(hash, *keys)
          keys.each do |key|
            return hash[key] if hash.key?(key)
            string_key = key.to_s
            return hash[string_key] if hash.key?(string_key)
          end
          nil
        end
      end

      def initialize(domain:, mode:, mx:, max_age: nil, fetched_at: nil,
                     expires_at: nil, version: "STSv1")
        @domain = normalize_domain(domain)
        raise ArgumentError, "MTA-STS policy domain is required" if @domain.empty?

        @mode = normalize_mode(mode)
        @mx = normalize_mx(mx)
        if @mode != :none && @mx.empty?
          raise ArgumentError, "MTA-STS policy must specify at least one mx pattern"
        end

        @version = (version || "STSv1").to_s
        unless @version == "STSv1"
          raise ArgumentError, "unsupported MTA-STS policy version: #{@version.inspect}"
        end

        @fetched_at = normalize_time(fetched_at || Time.now)
        if expires_at
          @expires_at = normalize_time(expires_at)
          if max_age.nil?
            @max_age = [(@expires_at - @fetched_at).ceil, 0].max
          else
            @max_age = normalize_max_age(max_age)
          end
        else
          raise ArgumentError, "max_age is required" if max_age.nil?
          @max_age = normalize_max_age(max_age)
          @expires_at = @fetched_at + @max_age
        end
      end

      # The policy is active only when its mode is not +:none+ and it has not
      # exceeded its max_age at +time+.
      def valid_at?(time = Time.now)
        return false if @mode == :none
        normalize_time(time) < @expires_at
      end

      # True when the policy's lifetime has elapsed. Mode "none" is not
      # "expired"; it simply declares that the domain has no policy.
      def expired?
        normalize_time(Time.now) >= @expires_at
      end

      def enforce?
        @mode == :enforce
      end

      def testing?
        @mode == :testing
      end

      def none?
        @mode == :none
      end

      # True when this policy should be applied to a connection.
      def active?
        valid_at?
      end

      # True when the policy allows an MX with the given host name.
      def mx_allowed?(host)
        host = self.class.normalize_host(host)
        return false if host.empty?
        @mx.any? { |pattern| self.class.mx_pattern_match?(pattern, host) }
      end

      def to_h
        {
          :domain => @domain,
          :mode => @mode,
          :mx => @mx.dup,
          :max_age => @max_age,
          :fetched_at => @fetched_at,
          :expires_at => @expires_at,
          :version => @version,
        }
      end

      def inspect
        "#<#{self.class} domain=#{@domain.inspect} mode=#{@mode.inspect} " \
          "mx=#{@mx.inspect} expires_at=#{@expires_at.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}>"
      end

      private

      def normalize_domain(domain)
        normalized = self.class.normalize_host(domain)
        if normalized.empty? || normalized =~ /\s/
          raise ArgumentError, "invalid MTA-STS policy domain: #{domain.inspect}"
        end
        normalized
      end

      def normalize_mode(mode)
        symbol = mode.to_s.downcase.to_sym
        unless MODES.include?(symbol)
          raise ArgumentError, "invalid MTA-STS policy mode: #{mode.inspect}"
        end
        symbol
      end

      def normalize_mx(mx)
        normalized_patterns = []
        Array(mx).each do |pattern|
          normalized = self.class.normalize_host(pattern)
          next if normalized.empty?
          if normalized.include?("*") && !normalized.start_with?("*.")
            raise ArgumentError, "invalid MTA-STS mx pattern: #{pattern.inspect}"
          end
          if normalized.start_with?("*.") && normalized[2..].include?("*")
            raise ArgumentError, "invalid MTA-STS mx pattern: #{pattern.inspect}"
          end
          normalized_patterns << normalized
        end
        normalized_patterns.uniq
      end

      def normalize_max_age(max_age)
        value = Integer(max_age)
        if value < 0 || value > MAX_MAX_AGE
          raise ArgumentError, "invalid MTA-STS max_age: #{max_age.inspect}"
        end
        value
      rescue ArgumentError, TypeError
        raise ArgumentError, "invalid MTA-STS max_age: #{max_age.inspect}"
      end

      def normalize_time(time)
        case time
        when Time
          time
        when Numeric
          Time.at(time)
        else
          raise ArgumentError, "invalid time: #{time.inspect}"
        end
      end
    end
  end
end

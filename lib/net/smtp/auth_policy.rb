module Net
  class SMTP
    # A client-side policy for selecting exactly one SMTP AUTH mechanism from
    # the mechanisms the server currently advertises.
    #
    # A policy contains:
    #
    # +mechanisms+:: an ordered list of mechanisms the caller is willing to
    #                use, most preferred first.
    # +credential+:: the type of credential that will be presented, for example
    #                +:password+ or +:oauth2+.
    #
    # Mechanism selection intersects the allowed order with:
    #
    # * the most recent EHLO +AUTH+ capabilities (after STARTTLS when it is
    #   used), and
    # * the credential type declared by each registered authenticator.
    #
    # Exactly one mechanism is selected.  If nothing matches, SMTPAuthMechanismError
    # is raised before the secret is sent.  Selection never falls through to
    # another mechanism after a server rejects an attempt.
    #
    # Example:
    #
    #     policy = Net::SMTP::AuthPolicy.new(
    #       mechanisms: [:xoauth2, :plain],
    #       credential: :oauth2
    #     )
    #     Net::SMTP.start('smtp.example.com', 587, user: 'me',
    #                     secret: token, auth_policy: policy)
    #
    # Mechanism names may be Strings or Symbols and are matched
    # case-insensitively.  Duplicate entries are ignored, preserving the first
    # occurrence.
    class AuthPolicy
      # Ordered allowed mechanisms, normalized to Symbols.
      attr_reader :mechanisms

      # Normalized credential type.
      attr_reader :credential

      alias credential_type credential

      def self.coerce(policy)
        case policy
        when self
          policy
        when Hash
          options = {}
          policy.each { |key, value| options[key.to_sym] = value }
          new(**options)
        when Array
          raise ArgumentError, 'a mechanism list also requires a credential type'
        else
          raise ArgumentError, "auth_policy must be a #{name} or Hash, not #{policy.class}"
        end
      end

      # Coerces the different public spellings of a policy into one object.
      #
      # +value+ may be an AuthPolicy, a Hash, or an ordered mechanism Array
      # (in which case +credential:+ must be supplied).  Alternatively, the
      # order and credential type may be given with separate keyword options.
      # Returns nil when no policy was requested.
      def self.resolve(value = nil, mechanisms: nil, allowed: nil, order: nil,
                       auth_mechanisms: nil, credential: nil,
                       credential_type: nil, credential_kind: nil)
        mechanism_options = [mechanisms, allowed, order, auth_mechanisms].compact
        if mechanism_options.size > 1
          raise ArgumentError, 'give only one mechanism option'
        end
        mechanism_option = mechanism_options.first

        credential_options = [credential, credential_type, credential_kind].compact
        if credential_options.size > 1
          raise ArgumentError, 'give only one credential option'
        end
        credential_option = credential_options.first

        if value.nil?
          return nil if mechanism_option.nil? && credential_option.nil?
          return new(mechanism_option, credential_option)
        end

        if value.is_a?(Array)
          if mechanism_option
            raise ArgumentError, 'mechanisms may not be given twice'
          end
          unless credential_option
            raise ArgumentError, 'a mechanism list also requires a credential type'
          end
          return new(value, credential_option)
        end

        unless mechanism_option.nil? && credential_option.nil?
          raise ArgumentError,
                'auth_policy cannot be combined with separate mechanism or credential options'
        end
        coerce(value)
      end

      def initialize(ordered_mechanisms = nil, positional_credential = nil,
                     mechanisms: nil, allowed: nil, order: nil, allow: nil,
                     allowed_mechanisms: nil, auth_mechanisms: nil,
                     credential: nil, credential_type: nil, credential_kind: nil,
                     auth_credential: nil)
        mechanism_options = [mechanisms, allowed, order, allow,
                             allowed_mechanisms, auth_mechanisms].compact
        keyword_mechanisms = mechanism_options.first
        if mechanism_options.size > 1
          raise ArgumentError, 'give only one mechanism option'
        end
        if ordered_mechanisms && keyword_mechanisms
          raise ArgumentError, 'mechanisms may be given either positionally or by keyword, not both'
        end
        mechanisms = ordered_mechanisms || keyword_mechanisms
        raise ArgumentError, 'authentication policy requires at least one mechanism' if mechanisms.nil?
        credential_options = [credential, credential_type, credential_kind,
                              auth_credential].compact
        if credential_options.size > 1
          raise ArgumentError, 'give only one credential option'
        end
        keyword_credential = credential_options.first
        if positional_credential && keyword_credential
          raise ArgumentError, 'credential may be given either positionally or by keyword, not both'
        end

        @mechanisms = Array(mechanisms).map do |mechanism|
          mechanism = mechanism.to_s.strip
          mechanism.empty? ? nil : Authenticator.normalize_type(mechanism)
        end.compact.uniq
        raise ArgumentError, 'authentication policy requires at least one mechanism' if @mechanisms.empty?

        credential = positional_credential || keyword_credential
        if credential.nil?
          raise ArgumentError, 'authentication policy requires a credential type'
        end
        @credential = Authenticator.normalize_credential(credential)
        validate_mechanisms!
      end

      # Raises unless every mechanism in the policy is registered, so a typo
      # cannot silently weaken the policy.
      def validate_mechanisms!
        unknown = @mechanisms.reject { |mechanism| Authenticator.auth_class(mechanism) }
        unless unknown.empty?
          names = unknown.map { |mechanism| mechanism.to_s }.join(', ')
          raise SMTPAuthMechanismError,
                "unknown authentication mechanism in policy: #{names}"
        end
        self
      end

      # Returns the single mechanism to attempt for +smtp+'s current
      # capabilities.  Raises SMTPAuthMechanismError when no single mechanism can
      # be selected.
      #
      # An SMTP object may also be passed directly; it is converted with
      # #auth_mechanisms so that a lightweight capability holder can be used
      # in tests or offline policy checks.
      def select(smtp)
        validate_mechanisms!
        advertised = advertised_mechanisms_for(smtp)
        if advertised.empty?
          raise SMTPAuthMechanismError,
                'server does not advertise any authentication mechanisms'
        end

        mechanism = @mechanisms.find do |candidate|
          advertised.include?(candidate) &&
            Authenticator.credential_for(candidate) == @credential
        end
        return mechanism if mechanism

        allowed = @mechanisms.map(&:to_s).join(', ')
        available = advertised.map(&:to_s).join(', ')
        raise SMTPAuthMechanismError,
              "no allowed authentication mechanism is available " \
              "(allowed: #{allowed}; server advertises: #{available}; " \
              "credential type: #{@credential})"
      end

      private

      def advertised_mechanisms_for(smtp)
        if smtp.respond_to?(:auth_mechanisms)
          Array(smtp.auth_mechanisms).map do |mechanism|
            Authenticator.normalize_type(mechanism)
          end.uniq
        else
          []
        end
      end
    end
  end
end

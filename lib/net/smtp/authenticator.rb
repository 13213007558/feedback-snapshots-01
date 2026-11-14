module Net
  class SMTP
    class Authenticator
      # The fallback credential type for a mechanism that neither declares a
      # credential type nor has an OAuth-style name.
      DEFAULT_CREDENTIAL = :password

      # Credential types recognized by the policy selector.
      CREDENTIAL_TYPES = [:password, :oauth2].freeze

      def self.auth_classes
        @classes ||= {}
      end

      def self.normalize_type(type)
        type.to_s.upcase.tr(?_, ?-).to_sym
      end

      def self.normalize_credential(type)
        case type.to_s.downcase.tr(?-, ?_).to_sym
        when :password, :passwd, :secret
          :password
        when :oauth2, :oauth, :bearer, :token, :access_token,
             :oauth2_token, :bearer_token, :oauth_token
          :oauth2
        else
          raise ArgumentError, "unknown credential type: #{type.inspect}"
        end
      end

      # Registers +type+ for this authenticator.  +credential:+ optionally
      # declares the credential type at the same time.
      def self.auth_type(type, credential: nil)
        @auth_credential = normalize_credential(credential) if credential
        Authenticator.auth_classes[normalize_type(type)] = self
        self
      end

      def self.auth_class(type)
        return nil if type.nil?
        Authenticator.auth_classes[normalize_type(type)]
      end

      # Declares or returns the credential type accepted by this authenticator.
      # Subclasses inherit the declaration from their superclass.
      #
      # When no authenticator declares a type, a mechanism named like an
      # OAuth bearer mechanism is inferred to accept +:oauth2+; every other
      # mechanism defaults to +:password+.  This keeps a third-party or test
      # authenticator registered for XOAUTH2 from silently accepting a
      # password-shaped credential policy.
      def self.auth_credential(type = nil)
        unless type.nil?
          credential = normalize_credential(type)
          unless CREDENTIAL_TYPES.include?(credential)
            raise ArgumentError, "unknown credential type: #{type.inspect}"
          end
          @auth_credential = credential
          return @auth_credential
        end
        if instance_variable_defined?(:@auth_credential)
          @auth_credential
        elsif superclass.respond_to?(:declared_auth_credential)
          superclass.declared_auth_credential
        else
          nil
        end
      end

      # Returns the explicitly declared or inherited credential type, or nil
      # when the authenticator has not declared one.
      def self.declared_auth_credential
        if instance_variable_defined?(:@auth_credential)
          @auth_credential
        elsif superclass.respond_to?(:declared_auth_credential)
          superclass.declared_auth_credential
        end
      end

      class << self
        alias credential_type auth_credential
        alias auth_credential_type auth_credential
        alias credential auth_credential
      end

      # Infers the credential type a mechanism conventionally expects from its
      # name.  OAuth-style mechanisms are never assumed to accept passwords.
      def self.default_credential_for(type)
        name = normalize_type(type).to_s
        if name.include?('OAUTH') || name.include?('BEARER')
          :oauth2
        else
          DEFAULT_CREDENTIAL
        end
      end

      # Returns the credential type for +type+, or nil if the mechanism is not
      # registered.
      def self.credential_for(type)
        klass = auth_class(type)
        return nil unless klass
        klass.auth_credential || default_credential_for(type)
      end

      def self.check_args(user_arg = nil, secret_arg = nil, *, **)
        unless user_arg
          raise ArgumentError, 'SMTP-AUTH requested but missing user name'
        end
        unless secret_arg
          raise ArgumentError, 'SMTP-AUTH requested but missing secret phrase'
        end
      end

      attr_reader :smtp
      attr_accessor :credential_type

      # The base initializer intentionally accepts only +smtp+ so that custom
      # authenticators written against earlier net-smtp releases continue to
      # work.  When the policy path selects a mechanism, it assigns the
      # mechanism's credential type after construction.
      def initialize(smtp)
        @smtp = smtp
        @credential_type = self.class.auth_credential || DEFAULT_CREDENTIAL
      end

      # @param arg [String] message to server
      # @return [String] message from server
      def continue(arg)
        res = smtp.get_response arg
        raise res.exception_class.new(res) unless res.continue?
        res.string.split[1]
      end

      # @param arg [String] message to server
      # @return [Net::SMTP::Response] response from server
      def finish(arg)
        res = smtp.get_response arg
        raise SMTPAuthenticationError.new(res) unless res.success?
        res
      end

      # @param str [String]
      # @return [String] Base64 encoded string
      def base64_encode(str)
        # expects "str" may not become too long
        [str].pack('m0')
      end
    end
  end
end

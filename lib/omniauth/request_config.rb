module OmniAuth
  # A bounded, request-scoped set of strategy option overrides, for
  # multi-tenant applications that pick client credentials per request
  # instead of mutating the shared strategy options in the setup phase.
  #
  # The application assigns a config during the setup phase, taking the
  # tenant from its own verified context (an authorized subdomain, a
  # record loaded for the signed-in user), never from an unchecked query
  # parameter:
  #
  #   use OmniAuth::Builder do
  #     provider :oauth2, :setup => lambda { |env|
  #       tenant = env['myapp.current_tenant'] # verified by the app
  #       OmniAuth::RequestConfig.assign(env,
  #         :tenant => tenant.id,
  #         :version => tenant.config_version,
  #         :overrides => {
  #           :client_id => tenant.client_id,
  #           :client_secret => tenant.client_secret
  #         }
  #       )
  #     }
  #   end
  #
  # The request phase binds the tenant and version into the session, and
  # the callback phase verifies a freshly assigned config against that
  # binding, so a callback can't switch tenants through a forged query
  # parameter, and a credential rotation between the two phases fails the
  # sign-in instead of mixing old and new credentials. The binding is
  # consumed when the callback phase ends, however it ends.
  #
  # Overrides never touch OmniAuth.config or the strategy's default
  # options: Strategy#effective_options merges them into a fresh copy per
  # request. Values under keys that look sensitive are redacted from
  # #inspect, so client secrets don't reach the logs.
  class RequestConfig
    # The Rack env key an assigned config is stored under.
    ENV_KEY = 'omniauth.request_config'

    # The session key the request-phase binding is stored under.
    SESSION_KEY = 'omniauth.request_config'

    # The options a request config may override: per-tenant credentials
    # and protocol parameters. Options that decide routing or dispatch
    # (name, path_prefix, request_path, callback_path, setup, ...) can't
    # be overridden: they're evaluated before the setup phase runs and
    # must stay identical between the request and callback phases.
    ALLOWED_OVERRIDES = %w[
      client_id client_secret scope redirect_uri
      authorize_params token_params client_options
    ].freeze

    # Keys whose values never appear in #inspect, matched recursively.
    SENSITIVE_KEY = /secret|token|password|credential|private_key/i.freeze

    # The placeholder shown in place of a sensitive value.
    REDACTED = '[REDACTED]'.freeze

    # Raised when a request config can't be assigned or verified. The
    # strategy turns it into a fail! with #message_key.
    class Error < OmniAuth::Error
      attr_reader :message_key

      def initialize(message_key, detail = nil)
        @message_key = message_key
        super(detail ? "#{message_key} (#{detail})" : message_key.to_s)
      end
    end

    attr_reader :tenant, :version

    # @param attributes [Hash] :tenant (required, an identifier from the
    #   caller's verified context), :version (optional, changed whenever
    #   the tenant's configuration changes), and :overrides (a hash
    #   limited to ALLOWED_OVERRIDES).
    def initialize(attributes)
      attributes ||= {}
      attributes = attributes.each_pair.with_object({}) { |(key, value), hash| hash[key.to_sym] = value }
      @tenant = attributes[:tenant]
      raise(Error.new(:missing_tenant, 'assign a tenant from the verified context')) if @tenant.nil? || @tenant.to_s.empty?

      @version = attributes[:version]
      @overrides = self.class.send(:normalize, attributes[:overrides] || {})
      freeze
    end

    # Assigns a request config to the env. Called by the application
    # during the setup phase.
    def self.assign(env, attributes)
      env[ENV_KEY] = new(attributes)
    end

    # The request config assigned to this env, if any.
    def self.fetch(env)
      env[ENV_KEY]
    end

    # The request-phase binding waiting for a callback, if any. The
    # application uses it at the callback phase to reload the tenant
    # from its own storage instead of trusting a query parameter.
    def self.pending(session)
      marker = session[SESSION_KEY]
      marker.is_a?(Hash) ? marker : nil
    end

    # Checks a freshly assigned callback-phase config against the
    # request-phase binding, raising Error on any inconsistency.
    def self.verify!(session, config)
      marker = pending(session)
      if config.nil?
        raise(Error.new(:missing_request_config, 'the request phase bound a tenant but the callback phase assigned no config')) if marker

        return
      end
      raise(Error.new(:unbound_request_config, 'assigned at the callback phase without a request-phase binding')) unless marker
      raise(Error.new(:request_config_tenant_mismatch, 'the callback-phase tenant differs from the request-phase tenant')) unless marker['tenant'] == config.tenant.to_s
      raise(Error.new(:stale_request_config, 'the tenant configuration changed between the request and callback phases')) unless marker['version'] == (config.version&.to_s)
    end

    # Removes the request-phase binding. Called when the callback phase
    # ends, however it ends, so a binding is used at most once.
    def self.conclude(session)
      session.delete(SESSION_KEY)
    end

    # The value assigned to an override key, or nil.
    def [](key)
      @overrides[key.to_s]
    end

    # The overridden option keys.
    def keys
      @overrides.keys
    end

    # The overrides as a fresh, mutable, string-keyed hash, safe to
    # merge into a copy of the strategy's options.
    def to_h
      OmniAuth::Utils.deep_dup(@overrides)
    end

    # Binds the tenant and version into the session for the callback
    # phase. The overrides themselves are never stored in the session.
    def bind(session)
      session[SESSION_KEY] = {'tenant' => tenant.to_s, 'version' => version&.to_s}
    end

    # A description with sensitive values replaced by REDACTED, so the
    # config can be logged without leaking client secrets.
    def inspect
      "#<#{self.class} tenant=#{tenant.inspect} version=#{version.inspect} overrides=#{self.class.redact(@overrides).inspect}>"
    end

    # The overrides with sensitive values replaced by REDACTED.
    def self.redact(hash)
      hash.each_pair.with_object({}) do |(key, value), result|
        result[key] = if SENSITIVE_KEY.match?(key.to_s)
                        REDACTED
                      elsif value.is_a?(Hash)
                        redact(value)
                      else
                        value
                      end
      end
    end

    # String-keys the overrides, restricts them to ALLOWED_OVERRIDES,
    # and deep-freezes a private copy the caller can't change later.
    def self.normalize(overrides)
      overrides.each_pair.with_object({}) do |(key, value), normalized|
        key = key.to_s
        raise(Error.new(:unallowed_override, "#{key} is not in ALLOWED_OVERRIDES")) unless ALLOWED_OVERRIDES.include?(key)

        normalized[key] = deep_freeze(OmniAuth::Utils.deep_dup(value))
      end.freeze
    end
    private_class_method :normalize

    def self.deep_freeze(value)
      case value
      when Hash
        value.each_value { |element| deep_freeze(element) }
      when Array
        value.each { |element| deep_freeze(element) }
      end
      value.freeze
    end
    private_class_method :deep_freeze
  end
end

# frozen_string_literal: true

require 'securerandom'
require 'faraday/request/authorization/credential_provider'

module Faraday
  class Request
    # Request middleware for the Authorization HTTP header
    class Authorization < Faraday::Middleware
      KEY = 'Authorization'

      # Per-request session stored on the env. It ties every middleware
      # invocation for the same request (including retries) to one stable
      # request id, so the credential provider can be reconsulted safely.
      #
      # @!attribute request_id
      #   @return [String] stable id shared by every attempt of this request.
      # @!attribute denied
      #   @return [Boolean] true once the provider has refused this request.
      # @!attribute outbound_attempted
      #   @return [Boolean] true once an approved credential has been passed
      #     down the stack for an outbound attempt.
      Session = Struct.new(:request_id, :denied, :outbound_attempted, keyword_init: true) do
        # @return [Boolean]
        def denied?
          denied
        end

        # @return [Boolean]
        def outbound_attempted?
          outbound_attempted
        end
      end

      # Error raised when a {CredentialProvider} denies a request. No
      # credential is ever sent when this is raised.
      class CredentialDeniedError < Faraday::Error
        def initialize(message = nil)
          super(message || 'credential provider denied the request')
        end
      end

      # @param app [#call]
      # @param type [String, Symbol] Type of Authorization
      # @param params [Array<String, Proc, #call, CredentialProvider>]
      #   parameters to build the Authorization header.
      #   If the type is `:basic`, then these can be a login and password pair.
      #   Otherwise, a single value is expected that will be appended after the
      #   type. This value can be a proc or an object responding to `.call`, in
      #   which case it will be invoked on each request. It can also be a
      #   {CredentialProvider}, which is consulted for an explicit credential
      #   decision on every request and reconfirmed on each retry.
      def initialize(app, type, *params)
        @type = type
        @params = params
        super(app)
      end

      # @param env [Faraday::Env]
      def on_request(env)
        provider = credential_provider

        if provider
          apply_provider_credential(env, provider)
        else
          # A header set explicitly by the application always wins over static
          # credentials, procs or callables.
          return if env.request_headers[KEY]

          env.request_headers[KEY] = header_from(@type, env, *@params)
        end
      end

      private

      # @return [CredentialProvider, nil]
      def credential_provider
        @params.first if @params.size == 1 && @params.first.is_a?(CredentialProvider)
      end

      # Resolves the per-request session, creating it on the first invocation
      # and reusing it on retries.
      #
      # @param env [Faraday::Env]
      # @return [Session]
      def session_for(env)
        env[CredentialProvider::ENV_SESSION_KEY] ||=
          Session.new(request_id: SecureRandom.uuid, denied: false,
                      outbound_attempted: false)
      end

      # @param env [Faraday::Env]
      # @param provider [CredentialProvider]
      # @return [void]
      def apply_provider_credential(env, provider)
        existing_session = env[CredentialProvider::ENV_SESSION_KEY]

        # On the first attempt only, a header set explicitly by the application
        # takes precedence and the provider is never consulted. On a retry the
        # session already exists and any header present is one we wrote, so the
        # provider is reconsulted to reconfirm the credential.
        return if existing_session.nil? && env.request_headers[KEY]

        session = session_for(env)

        raise CredentialDeniedError, 'credential provider already denied this request' if session.denied?

        result = provider.credential_for(env, session.request_id)

        unless result.approved?
          session.denied = true
          raise CredentialDeniedError, result.reason
        end

        env.request_headers[KEY] = header_from_provider(@type, result.value)
        provider.mark_outbound!(session.request_id)
        session.outbound_attempted = true
      end

      # @param type [String, Symbol]
      # @param value [String] the credential value supplied by the provider.
      # @return [String] a header value
      def header_from_provider(type, value)
        "#{type} #{value}"
      end

      # @param type [String, Symbol]
      # @param env [Faraday::Env]
      # @param params [Array]
      # @return [String] a header value
      def header_from(type, env, *params)
        if type.to_s.casecmp('basic').zero? && params.size == 2
          Utils.basic_header_from(*params)
        elsif params.size != 1
          raise ArgumentError, "Unexpected params received (got #{params.size} instead of 1)"
        else
          value = params.first
          if (value.is_a?(Proc) && value.arity == 1) || (value.respond_to?(:call) && value.method(:call).arity == 1)
            value = value.call(env)
          elsif value.is_a?(Proc) || value.respond_to?(:call)
            value = value.call
          end
          "#{type} #{value}"
        end
      end
    end
  end
end

Faraday::Request.register_middleware(authorization: Faraday::Request::Authorization)

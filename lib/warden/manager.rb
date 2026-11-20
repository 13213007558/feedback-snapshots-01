# encoding: utf-8
# frozen_string_literal: true
require 'warden/hooks'
require 'warden/config'

module Warden
  # The middleware for Rack Authentication
  # The middleware requires that there is a session upstream
  # The middleware injects an authentication object into
  # the rack environment hash
  class Manager
    extend Warden::Hooks

    attr_accessor :config

    # Initialize the middleware. If a block is given, a Warden::Config is yielded so you can properly
    # configure the Warden::Manager.
    # :api: public
    def initialize(app, options={})
      default_strategies = options.delete(:default_strategies)

      @app, @config = app, Warden::Config.new(options)
      @config.default_strategies(*default_strategies) if default_strategies
      yield @config if block_given?
    end

    # Invoke the application guarding for throw :warden.
    # If this is downstream from another warden instance, the proxy is
    # reused, but the failure is still guarded so that the layer closest
    # to the application owns the failure response.
    # :api: private
    def call(env) # :nodoc:
      return downstream_call(env) if env['warden'] && env['warden'].manager != self

      env['warden'] = Proxy.new(env, self)
      result = catch(:warden) do
        env['warden'].on_request
        @app.call(env)
      end

      handle_result(result, env)
    end

    # :api: private
    def _run_callbacks(*args) #:nodoc:
      self.class._run_callbacks(*args)
    end

    class << self
      # Prepares the user to serialize into the session.
      # Any object that can be serialized into the session in some way can be used as a "user" object
      # Generally however complex object should not be stored in the session.
      # If possible store only a "key" of the user object that will allow you to reconstitute it.
      #
      # You can supply different methods of serialization for different scopes by passing a scope symbol
      #
      # Example:
      #   Warden::Manager.serialize_into_session{ |user| user.id }
      #   # With Scope:
      #   Warden::Manager.serialize_into_session(:admin) { |user| user.id }
      #
      # :api: public
      def serialize_into_session(scope = nil, &block)
        method_name = scope.nil? ? :serialize : "#{scope}_serialize"
        Warden::SessionSerializer.send :define_method, method_name, &block
      end

      # Reconstitutes the user from the session.
      # Use the results of user_session_key to reconstitute the user from the session on requests after the initial login
      # You can supply different methods of de-serialization for different scopes by passing a scope symbol
      #
      # Example:
      #   Warden::Manager.serialize_from_session{ |id| User.get(id) }
      #   # With Scope:
      #   Warden::Manager.serialize_from_session(:admin) { |id| AdminUser.get(id) }
      #
      # :api: public
      def serialize_from_session(scope = nil, &block)
        method_name = scope.nil? ? :deserialize : "#{scope}_deserialize"

        if Warden::SessionSerializer.method_defined? method_name
          Warden::SessionSerializer.send :remove_method, method_name
        end

        Warden::SessionSerializer.send :define_method, method_name, &block
      end
    end

  private

    # Handles a request downstream from another Warden manager. The
    # proxy (and its on_request callbacks) belongs to the upstream
    # manager, so they are not run again here. A failure raised by the
    # application is owned by this layer when it has a failure app of
    # its own, and deferred to the upstream layer otherwise.
    # :api: private
    def downstream_call(env)
      result = catch(:warden) { @app.call(env) }

      if result.is_a?(Hash) || result.nil?
        # The application threw :warden.
        config.failure_app ? process_unauthenticated(env, result || {}) : throw(:warden, result)
      elsif config.failure_app
        handle_result(result, env)
      else
        result
      end
    end

    def handle_result(result, env) # :nodoc:
      result ||= {}
      case result
      when Array
        handle_chain_result(result.first, result, env)
      when Hash
        process_unauthenticated(env, result)
      when Rack::Response
        handle_chain_result(result.status, result, env)
      end
    end

    def handle_chain_result(status, result, env)
      if status == 401 && intercept_401?(env)
        process_unauthenticated(env)
      else
        result
      end
    end

    def intercept_401?(env)
      config[:intercept_401] && !env['warden'].custom_failure?
    end

    # When a request is unauthenticated, here's where the processing occurs.
    # It looks at the result of the proxy to see if it's been executed and what action to take.
    # :api: private
    def process_unauthenticated(env, options={})
      options[:action] ||= begin
        opts = config[:scope_defaults][config.default_scope] || {}
        opts[:action] || 'unauthenticated'
      end

      proxy  = env['warden']
      # This layer owns the failure response from here on. Flag it so
      # that any upstream Warden layer passes the response through
      # untouched instead of intercepting the 401 a second time.
      proxy.custom_failure!
      result = options[:result] || proxy.result

      case result
      when :redirect
        body = proxy.message || "You are being redirected to #{proxy.headers['Location']}"
        [proxy.status, proxy.headers, [body]]
      when :custom
        proxy.custom_response
      else
        options[:message] ||= proxy.message
        call_failure_app(env, options)
      end
    end

    # Calls the failure app.
    # The before_failure hooks are run on each failure
    # :api: private
    def call_failure_app(env, options = {})
      if config.failure_app
        options.merge!(:attempted_path => ::Rack::Request.new(env).fullpath)
        # Keep the scope the request was attempted under, so the failure
        # app can scope its response even when the 401 was intercepted
        # rather than thrown with options.
        if !options.key?(:scope) && (strategy = env['warden'].winning_strategy)
          options[:scope] = strategy.scope
        end
        env["PATH_INFO"] = "/#{options[:action]}"
        env["warden.options"] = options

        _run_callbacks(:before_failure, env, options)
        config.failure_app.call(env).to_a
      else
        raise "No Failure App provided"
      end
    end # call_failure_app
  end
end # Warden

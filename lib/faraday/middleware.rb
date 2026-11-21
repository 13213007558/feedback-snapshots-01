# frozen_string_literal: true

require 'monitor'

module Faraday
  # Middleware is the basic base class of any Faraday middleware.
  class Middleware
    extend MiddlewareRegistry

    attr_reader :app, :options

    DEFAULT_OPTIONS = {}.freeze
    LOCK = Mutex.new

    def initialize(app = nil, options = {})
      @app = app
      @options = self.class.default_options.merge(options)
    end

    class << self
      # Faraday::Middleware::default_options= allows user to set default options at the Faraday::Middleware
      # class level.
      #
      # @example Set the Faraday::Response::RaiseError option, `include_request` to `false`
      # my_app/config/initializers/my_faraday_middleware.rb
      #
      # Faraday::Response::RaiseError.default_options = { include_request: false }
      #
      def default_options=(options = {})
        validate_default_options(options)
        LOCK.synchronize do
          @default_options = default_options.merge(options)
        end
      end

      # default_options attr_reader that initializes class instance variable
      # with the values of any Faraday::Middleware defaults, and merges with
      # subclass defaults
      def default_options
        @default_options ||= DEFAULT_OPTIONS.merge(self::DEFAULT_OPTIONS)
      end

      private

      def validate_default_options(options)
        invalid_keys = options.keys.reject { |opt| self::DEFAULT_OPTIONS.key?(opt) }
        return unless invalid_keys.any?

        raise(Faraday::InitializationError,
              "Invalid options provided. Keys not found in #{self}::DEFAULT_OPTIONS: #{invalid_keys.join(', ')}")
      end
    end

    def call(env)
      on_request(env) if respond_to?(:on_request)
      app.call(env).on_complete do |environment|
        on_complete(environment) if respond_to?(:on_complete)
      end
    rescue StandardError => e
      notify_error(e, env)
      raise
    end

    def close
      if app.respond_to?(:close)
        app.close
      else
        warn "#{app} does not implement #close!"
      end
    end

    private

    # Calls the error hook, passing the request Env when the hook accepts it.
    # Hooks written as `on_error(error)` keep working unchanged.
    def notify_error(error, env)
      return unless respond_to?(:on_error)

      if error_hook_accepts_env?(method(:on_error))
        on_error(error, env)
      else
        on_error(error)
      end
    end

    # A hook receives the Env when it declares a second positional argument
    # (`def on_error(error, env)`) or an optional one
    # (`def on_error(error, env = nil)`). Variadic and one-argument hooks keep
    # the historical single-argument call.
    def error_hook_accepts_env?(handler)
      arity = handler.arity
      arity == 2 || arity <= -2
    end
  end
end

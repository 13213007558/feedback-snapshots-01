# frozen_string_literal: true

require 'forwardable'
require 'logger'
require 'faraday/logging/formatter'

module Faraday
  class Response
    # Logger is a middleware that logs internal events in the HTTP request
    # lifecycle to a given Logger object. By default, this logs to STDOUT. See
    # Faraday::Logging::Formatter to see specifically what is logged.
    class Logger < Middleware
      DEFAULT_OPTIONS = { formatter: Logging::Formatter }.merge(Logging::Formatter::DEFAULT_OPTIONS).freeze

      def initialize(app, logger = nil, options = {})
        super(app, options)
        logger ||= ::Logger.new($stdout)
        formatter_class = @options.delete(:formatter)
        @formatter = formatter_class.new(logger: logger, options: @options)
        yield @formatter if block_given?
      end

      def call(env)
        @formatter.request(env)
        super
      end

      def on_complete(env)
        @formatter.response(env)
      end

      def on_error(exc, env = nil)
        return unless @formatter.respond_to?(:exception)

        # The Env is only passed when a disclosure policy applies, so the
        # historical one-argument formatter contract is preserved otherwise.
        if env && Faraday::Disclosure.policy_for(env) && accepts_env?(@formatter)
          @formatter.exception(exc, env)
        else
          @formatter.exception(exc)
        end
      end

      private

      # Formatters may keep the historical `exception(exc)` signature; the
      # bundled formatter accepts the optional Env as a second argument.
      def accepts_env?(formatter)
        arity = formatter.method(:exception).arity
        arity == 2 || arity <= -2
      end
    end
  end
end

Faraday::Response.register_middleware(logger: Faraday::Response::Logger)

# frozen_string_literal: true

require 'pp' # This require is necessary for Hash#pretty_inspect to work, do not remove it, people rely on it.

module Faraday
  module Logging
    # Serves as an integration point to customize logging
    #
    # A {Faraday::DisclosureOptions} policy configured on the connection narrows
    # what `request` and `exception` may write to the shared logger. When no
    # policy is configured, logging keeps its historical behavior.
    class Formatter
      extend Forwardable

      DEFAULT_OPTIONS = { headers: true, bodies: false, errors: false,
                          log_level: :info }.freeze

      def initialize(logger:, options:)
        @logger = logger
        @options = DEFAULT_OPTIONS.merge(options)
        unless %i[debug info warn error fatal].include?(@options[:log_level])
          @options[:log_level] = :info
        end
        @filter = []
      end

      def_delegators :@logger, :debug, :info, :warn, :error, :fatal

      def request(env)
        policy = disclosure_for(env)
        if policy
          log_disclosed_request(env, policy)
        else
          public_send(log_level) do
            "request: #{env.method.upcase} #{apply_filters(env.url.to_s)}"
          end

          log_headers('request', env.request_headers) if log_headers?(:request)
          log_body('request', env[:body]) if env[:body] && log_body?(:request)
        end
      end

      def response(env)
        public_send(log_level) { "response: Status #{env.status}" }

        log_headers('response', env.response_headers) if log_headers?(:response)
        log_body('response', env[:body]) if env[:body] && log_body?(:response)
      end

      def exception(exc, env = nil)
        return unless log_errors?

        policy = disclosure_for(env)
        policy ||= disclosure_for(exc.response) if exc.respond_to?(:response)
        return log_disclosed_exception(exc, policy) if policy

        public_send(log_level) { "error: #{apply_filters(exc.full_message)}" }

        log_headers('error', exc.response_headers) if exc.respond_to?(:response_headers) && log_headers?(:error)
        return unless exc.respond_to?(:response_body) && exc.response_body && log_body?(:error)

        log_body('error', exc.response_body)
      end

      def filter(filter_word, filter_replacement)
        @filter.push([filter_word, filter_replacement])
      end

      private

      def dump_headers(headers)
        return if headers.nil?

        headers.map { |k, v| "#{k}: #{v.inspect}" }.join("\n")
      end

      def dump_body(body)
        if body.respond_to?(:to_str)
          body.to_str.encode(::Encoding::UTF_8, undef: :replace, invalid: :replace)
        else
          pretty_inspect(body)
        end
      end

      def pretty_inspect(body)
        body.pretty_inspect
      end

      def log_headers?(type)
        case @options[:headers]
        when Hash
          @options[:headers][type]
        else
          @options[:headers]
        end
      end

      def log_body?(type)
        case @options[:bodies]
        when Hash
          @options[:bodies][type]
        else
          @options[:bodies]
        end
      end

      def log_errors?
        @options[:errors]
      end

      def apply_filters(output)
        @filter.each do |pattern, replacement|
          output = output.to_s.gsub(pattern, replacement)
        end
        output
      end

      def log_level
        @options[:log_level]
      end

      def log_headers(type, headers)
        public_send(log_level) { "#{type}: #{apply_filters(dump_headers(headers))}" }
      end

      def log_body(type, body)
        public_send(log_level) { "#{type}: #{apply_filters(dump_body(body))}" }
      end

      def disclosure_for(source)
        Faraday::Disclosure.policy_for(source)
      end

      # Logs a request using only the request attributes selected by the
      # connection's disclosure policy. Header and body logging still require
      # the matching header/body option, so the policy only narrows output.
      def log_disclosed_request(env, policy)
        method = policy.request_attribute?(:method) ? env.method : nil
        url = Faraday::Disclosure.request_url(env, policy)
        public_send(log_level) do
          parts = ['request:']
          parts << method.to_s.upcase if method
          parts << apply_filters(url.to_s) if url
          apply_filters(parts.join(' '))
        end

        if policy.request_attribute?(:headers) && log_headers?(:request)
          headers = env.request_headers
          log_headers('request', headers) if headers
        end

        if policy.request_attribute?(:body) && env[:body] && log_body?(:request)
          log_body('request', env[:body])
        end
      end

      # Logs an error using only the error details selected by the connection's
      # disclosure policy. The error class and the response status are always
      # kept so a failure stays identifiable.
      def log_disclosed_exception(exc, policy)
        public_send(log_level) { "error: #{apply_filters(error_summary(exc, policy))}" }

        if policy.error_detail?(:response_headers) && log_headers?(:error) &&
           exc.respond_to?(:response_headers) && exc.response_headers
          log_headers('error', exc.response_headers)
        end

        return unless policy.error_detail?(:response_body) && log_body?(:error) &&
                      exc.respond_to?(:response_body) && exc.response_body

        log_body('error', exc.response_body)
      end

      def error_summary(exc, policy)
        summary = +exc.class.name.to_s
        status = exc.response_status if exc.respond_to?(:response_status)
        summary << " (status #{status})" unless status.nil?
        summary << ": #{exc.message}" if policy.error_detail?(:message)

        if policy.error_detail?(:wrapped_exception) && exc.is_a?(Faraday::Error) &&
           exc.wrapped_exception
          wrapped = "#{exc.wrapped_exception.class}: #{exc.wrapped_exception.message}"
          summary << " (#{wrapped})"
        end

        summary << "\n#{exc.backtrace.join("\n")}" if policy.error_detail?(:backtrace) && exc.backtrace
        summary
      end
    end
  end
end

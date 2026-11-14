# frozen_string_literal: true

require 'rack/protection'
require 'rack/utils'
require 'digest'
require 'logger'
require 'uri'

module Rack
  module Protection
    ##
    # Base class for middlewares provided by rack-protection.
    #
    # == Options
    #
    # These may be given to any subclass, however they may affect different subclasses differently.
    #
    # [<tt>:reaction</tt>] - name of a method of the class that will be used to respond when the
    #                        middleware rejects the response. Default behavior is to use #default_reaction.
    #                        For rejections decided after the downstream application has returned
    #                        (see #reject_response), a reaction must return a Rack response triple
    #                        to replace the original response. The built-in +:report+ reaction is
    #                        the only reaction allowed to return a non-Rack value and keep the
    #                        original response.
    # [<tt>:logging</tt>] - if true, debug and warning statements are sent to the logger.
    # [<tt>:message</tt>] - if set, this is the message sent when a request is rejected via <tt>deny</tt>.
    #                       See DEFAULT_OPTIONS.
    # [<tt>:session_key</tt>] - string to use as the key into <tt>env</tt> where the current
    #                           session is stored. See DEFAULT_OPTIONS.
    # [<tt>:status</tt>] - HTTP status to use when a request is rejected via <tt>deny</tt>.
    #                      See DEFAULT_OPTIONS.
    # [<tt>:report_key</tt>] - key set in <tt>env</tt> if the request has been denied
    #                          and <tt>:reaction</tt> is set to <tt>:report</tt> (see #report). See DEFAULT_OPTIONS.
    # [<tt>:html_types</tt>] - Array of strings containing content types that are consider HTML
    #                          for the purposes of this gem. See DEFAULT_OPTIONS.
    #
    class Base
      # Raised when a custom reaction used to reject an already-generated
      # response returns something other than a Rack response triple or nil.
      ResponseReactionError = Class.new(ArgumentError)

      # Tracks ownership of a response body for a single middleware call.
      # Closing is attempted at most once, even when decision, reaction and
      # cleanup failures are combined.
      class ResponseBody
        def initialize(body)
          @body = body
          @closed = false
        end

        attr_reader :body

        def closed?
          @closed
        end

        def close
          return if @closed

          @closed = true
          body.close if body.respond_to?(:close)
          true
        rescue StandardError => e
          yield e if block_given?
          false
        end
      end

      DEFAULT_OPTIONS = {
        reaction: :default_reaction, logging: true,
        message: 'Forbidden', encryptor: Digest::SHA1,
        session_key: 'rack.session', status: 403,
        allow_empty_referrer: true,
        report_key: 'protection.failed',
        html_types: %w[text/html application/xhtml text/xml application/xml]
      }

      attr_reader :app, :options

      # Used by subclasses to declare default values for options they require.
      # These defaults are merged onto the DEFAULT_OPTIONS provided by this class.
      def self.default_options(options)
        define_method(:default_options) { super().merge(options) }
      end

      # Used by subclasses to declare default reaction when a request is rejected.
      # This replaces the default provided by this class.
      # See #default_reaction.
      def self.default_reaction(reaction)
        alias_method(:default_reaction, reaction)
      end

      def default_options
        DEFAULT_OPTIONS
      end

      def initialize(app, options = {})
        @app = app
        @options = default_options.merge(options)
      end

      def safe?(env)
        %w[GET HEAD OPTIONS TRACE].include? env['REQUEST_METHOD']
      end

      def accepts?(env)
        raise NotImplementedError, "#{self.class} implementation pending"
      end

      def call(env)
        unless accepts? env
          instrument env
          result = react env
        end
        result or app.call(env)
      end

      def react(env)
        result = send(options[:reaction], env)
        result if (Array === result) && (result.size == 3)
      end

      # Calls the downstream application and yields its status, headers and
      # body to the given block. The block should return a truthy value when
      # the response must be rejected.
      #
      # This is the shared lifecycle for protections that can only decide
      # after the application has generated a response (for example, after
      # inspecting its +content-type+ header). If the block raises, the
      # response is rejected as a fail-closed default.
      #
      # When the response is rejected:
      #
      # * the configured reaction is invoked exactly once;
      # * +:report+ keeps the original response and records the finding;
      # * any other reaction must return a Rack response triple, in which
      #   case the original body is closed exactly once;
      # * a reaction returning +nil+ falls back to the middleware's default
      #   denial response (so reactions such as +:drop_session+ remain
      #   fail-closed);
      # * a non-+nil+, non-Rack return value raises ResponseReactionError.
      #
      # Body ownership follows the Rack contract. The original body is closed
      # before a replacement is returned, but never iterated. The replacement
      # body is returned unclosed and belongs to the server. Under +:report+,
      # the original body is also left for the server to consume and close.
      def check_response(env, &decision)
        response = app.call(env)
        status, headers, body = response

        reject = begin
          decision.call(status, headers, body)
        rescue StandardError => error
          begin
            debug env, "failed to evaluate response rejection: #{error.class}: #{error.message}"
          rescue StandardError
            # Diagnosis is advisory; decision failures remain fail-closed.
          end
          true
        end

        return response unless reject

        reject_response(env, body) || response
      end

      # Reacts to a response-level rejection and returns the replacement
      # response, or +nil+ when the original response should be preserved
      # (the +:report+ reaction).
      def reject_response(env, body)
        ownership = ResponseBody.new(body)
        preserve = false

        begin
          begin
            instrument env
          rescue StandardError
            # Instrumentation is advisory. A broken instrumenter must not turn
            # a rejection into a pass-through of the original response.
          end

          if report_reaction?
            begin
              send(options[:reaction], env)
            rescue StandardError
              return denial_response(env)
            end

            preserve = true
            return nil
          end

          result = begin
            send(options[:reaction], env)
          rescue StandardError
            nil
          end

          if rack_response?(result)
            if result[2].equal?(body)
              raise ResponseReactionError,
                    "#{self.class} reaction #{options[:reaction].inspect} must not reuse the original body; " \
                    "the original body is closed when the response is replaced (use the :report reaction " \
                    "to keep the original response)"
            end

            result
          elsif result.nil?
            denial_response(env)
          else
            raise ResponseReactionError,
                  "#{self.class} reaction #{options[:reaction].inspect} must return a Rack response triple, " \
                  "nil (to use the default denial), or use the :report reaction"
          end
        ensure
          close_owned_body(env, ownership) unless preserve
        end
      end

      # Whether the configured reaction is the built-in +:report+ reaction.
      # +:report+ is the only reaction allowed to preserve the original
      # response after a post-response rejection.
      def report_reaction?
        reaction = options[:reaction]
        return false unless reaction

        name = reaction.to_sym
        return true if name == :report
        return false unless name == :default_reaction

        method(:default_reaction).unbind == method(:report).unbind
      rescue StandardError
        false
      end

      def rack_response?(response)
        return false unless (Array === response) && (response.size == 3)

        status, headers, body = response
        return false unless status.is_a?(Integer) && headers.is_a?(Hash)

        body.respond_to?(:each) || body.respond_to?(:call)
      end

      def close_owned_body(env, ownership)
        ownership.close do |error|
          begin
            debug env, "failed to close rejected response body: #{error.class}: #{error.message}"
          rescue StandardError
            # Closing is best-effort; cleanup errors must not suppress the
            # rejection response.
          end
        end
      end

      # Builds the standard denial response without allowing a logging failure
      # to escape. Used both directly and as the fail-closed fallback when a
      # reaction raises or returns nil for a response-level rejection.
      def denial_response(env)
        begin
          warn env, "attack prevented by #{self.class}"
        rescue StandardError
          # Logging is advisory; it must not turn a rejection into a
          # pass-through of the rejected response.
        end

        [options[:status], { 'content-type' => 'text/plain' }, [options[:message]]]
      end

      def debug(env, message)
        return unless options[:logging]

        l = options[:logger] || env['rack.logger'] || ::Logger.new(env['rack.errors'])
        l.debug(message)
      end

      def warn(env, message)
        return unless options[:logging]

        l = options[:logger] || env['rack.logger'] || ::Logger.new(env['rack.errors'])
        l.warn(message)
      end

      def instrument(env)
        return unless (i = options[:instrumenter])

        env['rack.protection.attack'] = self.class.name.split('::').last.downcase
        i.instrument('rack.protection', env)
      end

      # Deny the request.  Sends a content type of "text/plain" using
      # the status and message set in the options.
      def deny(env)
        denial_response(env)
      end

      # When used as a reaction (with option <tt>reaction: :report</tt>),
      # any rejected request will be allowed through, and a warning is
      # omitted (note that warnings will not be shown if the
      # <tt>:logging</tt> option has been set to false).
      def report(env)
        env[options[:report_key]] = true

        begin
          warn env, "attack reported by #{self.class}"
        rescue StandardError
          # Reporting must not turn a recorded finding into a pass-through
          # or a false denial because the log sink failed.
        end

        true
      end

      def session?(env)
        env.include? options[:session_key]
      end

      def session(env)
        return env[options[:session_key]] if session? env

        raise "you need to set up a session middleware *before* #{self.class}"
      end

      def drop_session(env)
        return unless session? env

        session(env).clear

        return if ["1", "true"].include?(ENV["RACK_PROTECTION_SILENCE_DROP_SESSION_WARNING"])

        warn env, "session dropped by #{self.class}"
        nil
      end

      def referrer(env)
        ref = env['HTTP_REFERER'].to_s
        return if !options[:allow_empty_referrer] && ref.empty?

        URI.parse(ref).host || Request.new(env).host
      rescue URI::InvalidURIError
      end

      def origin(env)
        env['HTTP_ORIGIN'] || env['HTTP_X_ORIGIN']
      end

      def random_string(secure = defined? SecureRandom)
        secure ? SecureRandom.hex(16) : '%032x' % rand((2**128) - 1)
      rescue NotImplementedError
        random_string false
      end

      def encrypt(value)
        options[:encryptor].hexdigest value.to_s
      end

      def secure_compare(a, b)
        Rack::Utils.secure_compare(a.to_s, b.to_s)
      end

      alias default_reaction deny

      def html?(headers)
        return false unless (header = headers.detect { |k, _v| k.downcase == 'content-type' })

        options[:html_types].include? header.last[%r{^\w+/\w+}]
      end
    end
  end
end

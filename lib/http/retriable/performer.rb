# frozen_string_literal: true

require "date"
require "http/retriable/errors"
require "http/retriable/delay_calculator"
require "http/retriable/clock"
require "openssl"

module HTTP
  # Retry logic for failed HTTP requests
  module Retriable
    # Request performing watchdog.
    # @api private
    class Performer
      # Exceptions we should retry
      RETRIABLE_ERRORS = [
        HTTP::TimeoutError,
        HTTP::ConnectionError,
        IO::EAGAINWaitReadable,
        Errno::ECONNRESET,
        Errno::ECONNREFUSED,
        Errno::EHOSTUNREACH,
        OpenSSL::SSL::SSLError,
        EOFError,
        IOError
      ].freeze

      # Default time source, shared so no allocation happens per request
      DEFAULT_CLOCK = Clock.new.freeze

      # Create a new retry performer
      #
      # @param [#to_i] tries maximum number of attempts
      # @param [#call, #to_i, nil] delay delay between retries
      # @param [Array<Exception>] exceptions exception classes to retry
      # @param [Array<#to_i>, nil] retry_statuses status codes to retry
      # @param [#call] on_retry callback invoked on each retry
      # @param [#to_f] max_delay maximum delay between retries
      # @param [#call, nil] should_retry custom retry predicate
      # @param [Numeric, nil] deadline monotonic time after which no further
      #   attempt may start; the value is compared against the clock
      # @param [#now, #sleep] clock time source backing the deadline and sleeps
      # @api private
      # @return [HTTP::Retriable::Performer]
      def initialize(tries: 5, delay: nil, exceptions: RETRIABLE_ERRORS, retry_statuses: nil,
                     on_retry: ->(*_args) {}, max_delay: Float::MAX, should_retry: nil,
                     deadline: nil, clock: DEFAULT_CLOCK)
        @exception_classes = exceptions
        @retry_statuses = retry_statuses
        @tries = tries.to_i
        @on_retry = on_retry
        @should_retry_proc = should_retry
        @deadline = deadline
        @clock = clock
        @delay_calculator = DelayCalculator.new(delay: delay, max_delay: max_delay)
      end

      # Execute request with retry logic
      #
      # @see #initialize
      # @return [HTTP::Response]
      # @api private
      def perform(client, req, &block)
        1.upto(Float::INFINITY) do |attempt| # infinite loop with index
          err, res = try_request(&block)

          if retry_request?(req, err, res, attempt)
            retry_attempt(client, req, err, res, attempt)
          elsif err
            finish_attempt(client, err)
          elsif res
            return res
          end
        end
      end

      # Calculates delay between retries
      #
      # @param [Integer] iteration
      # @param [HTTP::Response, nil] response
      # @api private
      # @return [Numeric]
      def calculate_delay(iteration, response)
        @delay_calculator.call(iteration, response)
      end

      private

      # Executes a single retry attempt
      #
      # @api private
      # @return [void]
      def retry_attempt(client, req, err, res, attempt)
        # Some servers support Keep-Alive on any response. Thus we should
        # flush response before retry, to avoid state error (when socket
        # has pending response data and we try to write new request).
        # Alternatively, as we don't need response body here at all, we
        # are going to close client, effectively closing underlying socket
        # and resetting client's state.
        wait_for_retry_or_raise(req, err, res, attempt)
      ensure
        client.close
      end

      # Closes client and raises the error
      #
      # @api private
      # @return [void]
      def finish_attempt(client, err)
        client.close
        raise err
      end

      # Attempts to execute the request block
      #
      # @api private
      # @return [Array]
      # rubocop:disable-next Lint/RescueException
      def try_request
        err, res = nil

        begin
          res = yield
        rescue Exception => e
          err = e
        end

        [err, res]
      end

      # Checks whether the request should be retried
      #
      # @api private
      # @return [Boolean]
      def retry_request?(req, err, res, attempt)
        if @should_retry_proc
          @should_retry_proc.call(req, err, res, attempt)
        elsif err
          retry_exception?(err)
        else
          retry_response?(res)
        end
      end

      # Checks whether the exception is retriable
      #
      # @api private
      # @return [Boolean]
      def retry_exception?(err)
        @exception_classes.any? { |e| err.is_a?(e) }
      end

      # Checks whether the response status warrants retry
      #
      # @api private
      # @return [Boolean]
      def retry_response?(res)
        return false unless @retry_statuses

        response_status = Integer(res.status)
        retry_matchers = [@retry_statuses].flatten

        retry_matchers.any? do |matcher|
          case matcher
          when Range then matcher.cover?(response_status)
          when Numeric then matcher == response_status
          else matcher.call(response_status)
          end
        end
      end

      # Waits for retry delay or raises if out of attempts or past the deadline
      #
      # @api private
      # @return [void]
      def wait_for_retry_or_raise(req, err, res, attempt)
        if attempt >= @tries
          flush_and_raise(res, out_of_retries_error(req, res, err))
        end

        delay = calculate_delay(attempt, res)

        if deadline_exceeded_before_wait?(delay)
          flush_and_raise(res, deadline_exceeded_error(req, res, err))
        end

        @on_retry.call(req, err, res)
        sleep(delay)

        return unless deadline_exceeded_after_wait?

        flush_and_raise(res, deadline_exceeded_error(req, res, err))
      end

      # Flushes any pending response body before surfacing a terminal error
      #
      # @param response [HTTP::Response, nil]
      # @param error [Exception]
      # @api private
      # @return [void]
      def flush_and_raise(response, error)
        response&.flush
        raise error
      end

      # Remaining time on the operation lease, in seconds
      #
      # @api private
      # @return [Numeric]
      def remaining_lease
        @deadline - @clock.now
      end

      # Whether a deadline is configured
      #
      # @api private
      # @return [Boolean]
      def deadline?
        !@deadline.nil?
      end

      # The recommended wait would not finish before the lease runs out
      #
      # @param [Numeric] delay server/backoff suggested wait
      # @api private
      # @return [Boolean]
      def deadline_exceeded_before_wait?(delay)
        deadline? && remaining_lease <= delay
      end

      # Time already reached the deadline while we were waiting
      #
      # @api private
      # @return [Boolean]
      def deadline_exceeded_after_wait?
        deadline? && @clock.now >= @deadline
      end

      # Builds DeadlineExceededError
      #
      # @param request [HTTP::Request]
      # @param response [HTTP::Response, nil]
      # @param exception [Exception, nil]
      # @api private
      # @return [HTTP::DeadlineExceededError]
      def deadline_exceeded_error(request, response, exception)
        message = format("%s <%s> deadline exceeded", String(request.verb).upcase, request.uri)

        message += " with #{response.status}" if response
        message += ":#{exception}" if exception

        DeadlineExceededError.new(message).tap do |ex|
          ex.cause = exception
          ex.response = response
        end
      end

      # Sleeps using the injected clock so time stays controllable in tests
      #
      # @param [Numeric] seconds
      # @api private
      # @return [void]
      def sleep(seconds)
        @clock.sleep(seconds)
      end

      # Builds OutOfRetriesError
      #
      # @param request [HTTP::Request]
      # @param response [HTTP::Response, nil]
      # @param exception [Exception, nil]
      # @api private
      # @return [HTTP::OutOfRetriesError]
      def out_of_retries_error(request, response, exception)
        message = format("%s <%s> failed", String(request.verb).upcase, request.uri)

        message += " with #{response.status}" if response
        message += ":#{exception}" if exception

        OutOfRetriesError.new(message).tap do |ex|
          ex.cause = exception
          ex.response = response
        end
      end
    end
  end
end

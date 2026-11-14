# frozen_string_literal: true

require "cgi"
require "digest"
require "time"
require "uri"

require "oauth/errors"
require "oauth/oauth"

module OAuth
  module Client
    # Optional, opt-in handling for OAuth providers that answer with
    # +oauth_problem="timestamp_refused"+.
    #
    # The flow never changes the process clock. It records a per-service
    # offset and only applies that offset while signing requests to the
    # service which supplied the evidence.
    #
    # Server time is trusted only when the caller supplies an explicit
    # +:trusted_time_source+ callable. Error responses from a different origin
    # are never used as evidence, and an unknown transport outcome is never
    # replayed automatically.
    class ClockCorrection
      # Returned by a transport when a caller block stopped the request before
      # it was sent.
      HALT = Object.new.freeze

      DEFAULT_MAX_OFFSET_SECONDS = 300
      HARD_MAX_OFFSET_SECONDS = 86_400
      DEFAULT_MAX_RETRIES = 1
      HARD_MAX_RETRIES = 3

      WRITE_METHODS = %i[post put patch delete].freeze
      TIMESTAMP_PROBLEM = "timestamp_refused"

      # Describes one correction run and the decision state left to the caller.
      class Outcome
        attr_reader :target_origin, :http_method, :attempts, :result, :reason,
                    :offset_seconds, :observed_offset_seconds, :evidence_time,
                    :max_offset_seconds, :max_retries, :response, :problem, :error
        attr_writer :offset_seconds, :observed_offset_seconds, :evidence_time

        def initialize(target_origin:, http_method:, max_offset_seconds:, max_retries:)
          @target_origin = target_origin
          @http_method = http_method.to_sym
          @max_offset_seconds = max_offset_seconds
          @max_retries = max_retries
          @attempts = []
          @result = nil
          @reason = nil
          @offset_seconds = nil
          @observed_offset_seconds = nil
          @evidence_time = nil
          @response = nil
          @problem = nil
          @error = nil
          @manual_retry = false
        end

        def write?
          WRITE_METHODS.include?(http_method)
        end

        def request_count
          attempts.count { |attempt| attempt[:sent] }
        end

        def signatures
          attempts.map { |attempt| attempt[:oauth_parameters] || attempt }
        end

        def corrected?
          result == :corrected
        end

        def succeeded?
          result == :ok || result == :corrected
        end

        def failed?
          !succeeded? && !result.nil? && result != :halted
        end

        def manual_retry?
          @manual_retry
        end
        alias manual_retry_required? manual_retry?
        alias pending_manual_retry? manual_retry?
        alias retry_decision_required? manual_retry?

        def manual_retry!
          @manual_retry = true
          self
        end

        def finish(result, reason: nil, response: nil, problem: nil, error: nil, manual_retry: false)
          @result = result
          @reason = reason
          @response = response
          @problem = problem
          @error = error
          @manual_retry = manual_retry
          self
        end

        def to_h
          {
            target_origin: target_origin,
            http_method: http_method,
            result: result,
            reason: reason,
            request_count: request_count,
            offset_seconds: offset_seconds,
            observed_offset_seconds: observed_offset_seconds,
            evidence_time: evidence_time,
            max_offset_seconds: max_offset_seconds,
            max_retries: max_retries,
            manual_retry: manual_retry?,
            response_code: response && response.code,
            attempts: attempts.map(&:dup)
          }
        end
      end

      attr_reader :outcome, :max_offset_seconds, :max_retries, :offsets

      def initialize(options = {}, offsets: {})
        options = normalize_options(options)
        @trusted_time_source = build_time_source(options)
        @max_offset_seconds = bounded_integer(options[:max_offset_seconds], DEFAULT_MAX_OFFSET_SECONDS, 0,
                                              HARD_MAX_OFFSET_SECONDS)
        @max_retries = bounded_integer(options[:max_retries], DEFAULT_MAX_RETRIES, 0, HARD_MAX_RETRIES)
        @idempotency_headers = Array(options[:idempotency_headers] || "Idempotency-Key").map(&:to_s)
        @offsets = offsets
        @outcome = nil
      end

      def enabled?
        !@trusted_time_source.nil? || !@offsets.empty?
      end

      def offset_for(origin)
        @offsets[origin]
      end

      def reset!
        @offsets.clear
        @outcome = nil
        self
      end

      # Execute one signed request, retrying only after a trustworthy
      # +timestamp_refused+ response.
      #
      # +build_request+ receives signing options and must return a signed
      # Net::HTTP request. +transport+ sends it. +problem_for+ converts an
      # HTTP response into an OAuth::Problem (or nil).
      def execute(target_origin:, http_method:, build_request:, transport:, problem_for: nil, replayable_body: true)
        start_run(target_origin, http_method)
        context = {
          target_origin: target_origin,
          build_request: build_request,
          transport: transport,
          problem_for: problem_for,
          replayable_body: replayable_body
        }

        loop do
          return @outcome unless run_attempt(context) == :retry
        end
      end

      private

      def start_run(target_origin, http_method)
        @outcome = Outcome.new(
          target_origin: target_origin,
          http_method: http_method,
          max_offset_seconds: @max_offset_seconds,
          max_retries: @max_retries
        )
        @previous_timestamp = nil
        @retries_used = 0
        @first_attempt = nil
      end

      def run_attempt(context)
        attempt = prepare_attempt(context)
        return if attempt.nil? || attempt.is_a?(Outcome)

        request, record = attempt
        return unless send_attempt(request, record, context)
        return unless record_problem(record, context)

        problem = context[:problem]
        return handle_timestamp_refused(problem, request, record, context) if timestamp_refused?(problem)

        if problem
          record[:result] = :oauth_problem
          @outcome.finish(:oauth_problem, problem: problem)
        else
          record[:result] = :success
          @outcome.finish(@previous_timestamp ? :corrected : :ok, response: context[:response])
        end
        nil
      end

      def prepare_attempt(context)
        attempt_number = @outcome.attempts.length + 1
        options = signing_options(context[:target_origin], attempt_number, @previous_timestamp)
        request = context[:build_request].call(options)
        return @outcome.finish(:halted) if request.equal?(HALT)

        record = request_record(request, attempt_number)
        @outcome.attempts << record
        @first_attempt ||= record
        [request, record]
      rescue StandardError => e
        @outcome.finish(:build_error, error: e)
      end

      def send_attempt(request, record, context)
        record[:sent] = true
        @last_request_origin = context[:target_origin]
        context[:response] = context[:transport].call(request)
        true
      rescue StandardError => e
        record[:result] = :unknown_outcome
        @outcome.finish(:unknown_outcome, error: e, manual_retry: true)
        false
      end

      def record_problem(_record, context)
        return true unless context[:problem_for]

        context[:problem] = context[:problem_for].call(context[:response])
        true
      rescue StandardError => e
        record[:result] = :invalid_problem_response
        @outcome.finish(:invalid_problem_response, error: e, manual_retry: true)
        false
      end

      def handle_timestamp_refused(problem, request, record, context)
        record[:result] = :timestamp_refused
        @previous_timestamp = integer_timestamp(record[:oauth_timestamp])

        refusal = refusal_verdict(request, record, context, problem)
        return unless refusal == :retry

        @retries_used += 1
        :retry
      end

      def refusal_verdict(request, record, context, problem)
        target_origin = context[:target_origin]
        response = context[:response]

        unless same_origin?(target_origin, response_origin(response))
          return finish_refusal(:cross_origin_rejected, problem)
        end
        return finish_refusal(:timestamp_refused, problem) if @retries_used >= @max_retries
        return finish_refusal(:body_not_replayable, problem) unless context[:replayable_body]
        return finish_refusal(:business_request_changed, problem) unless stable_business_request?(record)

        evidence = trusted_time(response, request, record[:number], record[:oauth_timestamp])
        return finish_refusal(:evidence_unavailable, problem) unless evidence

        offset = evidence - now_seconds
        @outcome.evidence_time = evidence
        @outcome.observed_offset_seconds = offset
        unless offset.abs <= @max_offset_seconds
          return finish_refusal(:offset_rejected, problem, reason: :offset_exceeds_limit)
        end

        @outcome.offset_seconds = offset
        @offsets[target_origin] = offset
        :retry
      end

      def finish_refusal(result, problem, reason: nil)
        @outcome.finish(result, reason: reason, problem: problem, manual_retry: true)
        nil
      end

      def normalize_options(options)
        options.to_h.each_with_object({}) do |(key, value), result|
          result[key.to_sym] = value
        end
      end

      def build_time_source(options)
        return options[:trusted_time_source] if options[:trusted_time_source]
        return options[:server_time_source] if options[:server_time_source]

        %i[trusted_time_evidence server_time_evidence server_time].each do |key|
          next unless options.key?(key)

          value = options[key]
          return ->(*) { value }
        end
        nil
      end

      def bounded_integer(value, default, minimum, maximum)
        number = value.nil? ? default : Integer(value)
        [[number, minimum].max, maximum].min
      rescue ArgumentError, TypeError
        default
      end

      def signing_options(target_origin, attempt_number, previous_timestamp)
        options = {timestamp_offset: @offsets.fetch(target_origin, 0)}
        if previous_timestamp
          # A retry must carry a fresh timestamp and nonce. Caller-provided
          # values are only honored for the first attempt.
          options[:timestamp] = nil
          options[:timestamp_not_equal] = previous_timestamp
          options[:nonce] = nil
          options[:force_fresh_nonce] = true
        end
        options[:clock_correction_attempt] = attempt_number
        options
      end

      def integer_timestamp(value)
        Integer(value.to_s, 10)
      rescue ArgumentError, TypeError
        nil
      end

      def timestamp_refused?(problem)
        problem.respond_to?(:problem) && problem.problem.to_s.downcase == TIMESTAMP_PROBLEM
      end

      def stable_business_request?(record)
        first = @first_attempt
        return true if first.equal?(record)

        same = first[:method] == record[:method] &&
               first[:business_path] == record[:business_path] &&
               first[:idempotency_key] == record[:idempotency_key]
        return false unless same

        if first[:body_fingerprint] && record[:body_fingerprint]
          first[:body_fingerprint] == record[:body_fingerprint]
        else
          first[:body_sha256] == record[:body_sha256]
        end
      end

      def request_record(request, attempt_number)
        helper = request.respond_to?(:oauth_helper) ? request.oauth_helper : nil
        oauth_params = helper ? helper.oauth_parameters : {}
        oauth_params = oauth_params.merge("oauth_signature" => signature_from_request(request)) if helper

        {
          number: attempt_number,
          sent: false,
          method: request.method,
          path: request.respond_to?(:path) ? request.path : nil,
          business_path: business_path(request),
          body_fingerprint: body_fingerprint(request),
          oauth_timestamp: oauth_params["oauth_timestamp"],
          oauth_nonce: oauth_params["oauth_nonce"],
          oauth_signature: oauth_params["oauth_signature"],
          oauth_parameters: oauth_params,
          body_sha256: body_sha256(request),
          idempotency_key: idempotency_key(request),
          result: nil
        }
      end

      def signature_from_request(request)
        if request.respond_to?(:[]) && request["authorization"]
          header = request["authorization"]
          return parse_oauth_parameters(header)["oauth_signature"] if header.start_with?("OAuth ")
        end

        if request.respond_to?(:path) && request.path
          query = URI.parse(request.path).query
          signature = parse_form_parameters(query)["oauth_signature"] if query
          return signature if signature
        end

        if request.respond_to?(:body) && request.body
          parse_form_parameters(request.body)["oauth_signature"]
        end
      rescue URI::InvalidURIError, ArgumentError
        nil
      end

      def parse_oauth_parameters(header)
        OAuth::Helper.parse_header(header)
      rescue StandardError
        {}
      end

      def parse_form_parameters(encoded)
        CGI.parse(encoded).each_with_object({}) do |(key, values), result|
          result[key] = values.first
        end
      rescue ArgumentError
        {}
      end

      def body_sha256(request)
        return nil if request.respond_to?(:body_stream) && request.body_stream
        return nil unless request.respond_to?(:body) && request.body

        Digest::SHA256.hexdigest(request.body.to_s)
      end

      def business_path(request)
        return nil unless request.respond_to?(:path) && request.path

        uri = URI.parse(request.path)
        query = uri.query
        return uri.path if query.nil? || query.empty?

        business_params = parse_form_parameters(query).reject { |key, _value| OAuth::PARAMETERS.include?(key) }
        normalized = business_params.sort.map { |key, value| "#{key}=#{value}" }.join("&")
        normalized.empty? ? uri.path : "#{uri.path}?#{normalized}"
      rescue URI::InvalidURIError
        request.path
      end

      def body_fingerprint(request)
        return nil unless request.respond_to?(:body) && request.body
        return nil if request.respond_to?(:body_stream) && request.body_stream

        content_type = request.respond_to?(:[]) ? request["content-type"].to_s.downcase : ""
        if content_type.start_with?("application/x-www-form-urlencoded")
          params = parse_form_parameters(request.body.to_s).reject { |key, _value| OAuth::PARAMETERS.include?(key) }
          Digest::SHA256.hexdigest(params.sort.flatten.join("&"))
        else
          Digest::SHA256.hexdigest(request.body.to_s)
        end
      end

      def idempotency_key(request)
        return nil unless request.respond_to?(:each_header)

        request.each_header do |name, value|
          return value if @idempotency_headers.any? { |header| header.casecmp(name).zero? }
        end
        nil
      end

      def now_seconds
        Time.now.to_i
      end

      def trusted_time(response, request, attempt_number, oauth_timestamp)
        source = @trusted_time_source
        return nil unless source

        context = {
          target_origin: @outcome.target_origin,
          attempt: attempt_number,
          request: request,
          response: response,
          oauth_timestamp: oauth_timestamp
        }

        value = case source.arity
                when 0 then source.call
                when 1 then source.call(response)
                else source.call(response, context)
                end
        evidence_seconds(value)
      rescue StandardError
        nil
      end

      def evidence_seconds(value)
        case value
        when Time then value.to_i
        when Integer then value
        when Float then value.finite? ? value.to_i : nil
        when String
          Integer(value, 10)
        when Hash
          nested = value[:timestamp] || value["timestamp"] || value[:server_time] || value["server_time"] ||
                   value[:now] || value["now"]
          evidence_seconds(nested)
        when nil
          nil
        else
          value.respond_to?(:to_i) ? value.to_i : nil
        end
      rescue ArgumentError, TypeError
        nil
      end

      def response_origin(response)
        location = response.respond_to?(:[]) && response["location"]
        if location
          location_origin = origin_for_uri(location)
          return location_origin if location_origin
        end

        if response.respond_to?(:uri) && response.uri
          return origin_for_uri(response.uri)
        end

        @last_request_origin
      end

      def origin_for_uri(uri)
        parsed = uri.is_a?(URI) ? uri : URI.parse(uri.to_s)
        return nil unless parsed.scheme && parsed.host

        scheme = parsed.scheme.downcase
        default_port = scheme == "https" ? 443 : 80
        port = parsed.port
        port_suffix = port && port != default_port ? ":#{port}" : ""
        "#{scheme}://#{parsed.host.downcase}#{port_suffix}"
      rescue URI::InvalidURIError
        nil
      end

      def same_origin?(expected, actual)
        actual.nil? || expected == actual
      end
    end
  end
end

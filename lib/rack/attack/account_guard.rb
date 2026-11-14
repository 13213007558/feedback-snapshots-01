# frozen_string_literal: true

require 'rack/attack/account_guard/registry'
require 'rack/attack/account_guard/body_proxy'

module Rack
  class Attack
    # Response-based credential-stuffing protection.
    #
    # Unlike Fail2Ban/Throttle checks, which count requests when they enter the
    # application, an AccountGuard only records an attempt *after* the
    # downstream authentication endpoint has produced a response. The caller
    # supplies:
    #
    #   * an account discriminator extractor (e.g. the submitted login)
    #   * a result classifier that maps a response to :failure, :success or nil
    #
    # Failed attempts accumulate per account; a successful attempt clears the
    # failures that predated it. Reaching `maxretry` failures within
    # `findtime` bans the account for `bantime` seconds, and subsequent
    # requests for that account are answered by `blocked_responder` without
    # ever reaching the application. Basic IP throttling configured with
    # `Rack::Attack.throttle` still runs before the application is called.
    #
    # The classifier never receives the password or the response body: it only
    # sees a sanitized request snapshot plus the response status and headers.
    class AccountGuard
      RESULT_VALUES = [:failure, :success, nil].freeze

      MANDATORY_OPTIONS = [:maxretry, :findtime, :bantime].freeze

      DEFAULT_BLOCKED_RESPONDER =
        lambda { |_request| [429, { 'content-type' => 'text/plain' }, ["Retry later\n"]] }

      # Minimal, read-only request information handed to the classifier. It
      # deliberately exposes no parameter/body access, so credentials cannot
      # leak into classification logic.
      Result = Struct.new(:request_method, :path, :ip, :user_agent, :status, :headers)

      attr_reader :name, :maxretry, :findtime, :bantime, :account_extractor,
                  :classifier, :blocked_responder

      def initialize(name, options, &account_extractor)
        MANDATORY_OPTIONS.each do |option|
          raise ArgumentError, "Must pass #{option.inspect} option" unless options[option]
        end

        @name              = name
        @maxretry          = options[:maxretry].to_i
        @findtime          = options[:findtime].to_i
        @bantime           = options[:bantime].to_i
        @classifier        = options.fetch(:classifier) { raise ArgumentError, "Must pass :classifier option" }
        @blocked_responder = options.fetch(:blocked_responder, DEFAULT_BLOCKED_RESPONDER)
        @account_extractor = account_extractor
        @registry          = Registry.new(name, findtime: @findtime, bantime: @bantime, maxretry: @maxretry)
      end

      def registry
        @registry
      end

      # Runs the request through the guard. When the guard does not apply (no
      # account discriminator) it delegates to `bypass`, so the downstream app
      # is still invoked exactly once. When the account is banned the app is
      # never called; otherwise the request is registered as in-flight,
      # dispatched, and settled from the response classification.
      def wrap(request, app, bypass = app)
        account = extract_account(request)
        return bypass.call(request.env) unless account

        request_id = @registry.register(account)
        return blocked_response(request, account) if request_id.nil?

        seen = @registry.seen_seq(account)

        begin
          status, headers, body = app.call(request.env)
        rescue StandardError
          # The downstream failed before producing a response: do not guess a
          # result, just release the pending entry and re-raise.
          @registry.abort(account, request_id)
          raise
        end

        proxy = wrap_body(body, account, request_id)
        settle(account, request_id, seen, request, status, headers, proxy)
        [status, headers, proxy]
      end

      def reset!
        @registry.reset!
      end

      private

      def extract_account(request)
        return nil unless @account_extractor

        discriminator = @account_extractor.call(request)
        discriminator.nil? || discriminator.to_s.empty? ? nil : discriminator.to_s
      end

      def settle(account, request_id, seen, request, status, headers, proxy)
        result =
          begin
            classify(request, status, headers)
          rescue StandardError
            # A failing classifier must not leave the request pending.
            @registry.abort(account, request_id)
            raise
          end

        case result
        when :failure
          banned = @registry.record_failure(account, request_id)
          proxy.accounted!
          annotate(request, result, banned)
        when :success
          @registry.record_success(account, request_id, seen)
          proxy.accounted!
          annotate(request, result, false)
        else
          # Unknown outcome (e.g. a 3xx/5xx that is neither auth result):
          # do not count it, just release the pending entry.
          @registry.abort(account, request_id)
        end
      end

      def classify(request, status, headers)
        result = @classifier.call(build_result(request, status, headers))
        unless RESULT_VALUES.include?(result)
          raise ArgumentError, "classifier must return :failure, :success or nil, got #{result.inspect}"
        end

        result
      end

      def build_result(request, status, headers)
        Result.new(
          request.request_method,
          request.path,
          request.ip,
          request.user_agent,
          status,
          headers.dup
        )
      end

      def wrap_body(body, account, request_id)
        BodyProxy.new(body) do
          # Idempotent: after settle() the pending entry is already gone, so a
          # later close/stream error cannot double-count anything.
          @registry.abort(account, request_id)
        end
      end

      def blocked_response(request, account)
        request.env["rack.attack.matched"]             = name
        request.env["rack.attack.match_type"]          = :account_guard
        request.env["rack.attack.match_discriminator"] = account
        Rack::Attack.instrument(request)
        @blocked_responder.call(request)
      end

      def annotate(request, result, banned)
        request.env["rack.attack.account_guard"] ||= {}
        request.env["rack.attack.account_guard"][name] = { result: result, banned: banned }
      end
    end
  end
end

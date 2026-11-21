# frozen_string_literal: true

require 'monitor'

module Faraday
  class Request
    class Authorization < Faraday::Middleware
      # A CredentialProvider supplies the {Authorization} middleware with an
      # explicit credential decision for a single request.
      #
      # Unlike a plain proc, which only returns a header value, a provider is
      # asked for a {CredentialResult} that states whether the request is
      # allowed to carry credentials at all. The same provider can be shared
      # across many concurrent requests, so every lookup is scoped to a
      # request id and recorded independently.
      #
      # On a retry, the middleware calls the provider again with the request id
      # of the original request, giving the application a chance to reconfirm
      # that the credential may still be used before anything is sent again.
      #
      # @abstract Subclass and override {#fetch_credential} to implement a
      #   concrete provider.
      class CredentialProvider
        # Key used to stash the per-request session on the Faraday env. It lives
        # in the env custom members so it survives every middleware invocation
        # for the same request, including retries.
        ENV_SESSION_KEY = :faraday_authorization_credential_session

        # Per-request bookkeeping recorded by a provider.
        class RequestState
          # @return [String] stable id shared by every attempt of one request.
          attr_reader :request_id

          # @return [Integer] number of times the provider was consulted.
          attr_accessor :fetch_count

          # @return [Integer, nil] version returned by the credential source on
          #   the first approved lookup. It stays pinned for the whole request,
          #   including a legitimate retry.
          attr_accessor :version

          # @return [Boolean] true once an approved credential has been handed
          #   to the middleware for an outbound attempt.
          attr_accessor :outbound_attempted

          # @return [Boolean] true after the provider has denied the request.
          attr_accessor :denied

          # @param request_id [String]
          def initialize(request_id)
            @request_id = request_id
            @version = nil
            @fetch_count = 0
            @outbound_attempted = false
            @denied = false
          end

          # @return [Boolean] whether an outbound attempt has already happened.
          def outbound_attempted?
            @outbound_attempted
          end

          # @return [Boolean] whether the request has been denied.
          def denied?
            @denied
          end
        end

        def initialize
          @states = {}
          @monitor = Monitor.new
        end

        # Consults the provider for a request. The first call for a given
        # request id records the credential version; subsequent calls with the
        # same request id (retries) reconfirm the decision through the
        # subclass-provided block.
        #
        # @param env [Faraday::Env] the request env.
        # @param request_id [String] stable id for the request.
        # @return [CredentialResult] the explicit credential decision.
        def credential_for(env, request_id)
          state = state_for(request_id)
          @monitor.synchronize do
            state.fetch_count += 1
            result = fetch_credential(env, state)
            if result.approved?
              state.version ||= result.version
              result.version = state.version
            else
              state.denied = true
            end
            result
          end
        end

        # Marks that an approved credential is about to be sent on the wire.
        #
        # @param request_id [String]
        # @return [void]
        def mark_outbound!(request_id)
          @monitor.synchronize do
            state_for(request_id).outbound_attempted = true
          end
        end

        # @param request_id [String]
        # @return [RequestState, nil] recorded state for the request.
        def request_state(request_id)
          @monitor.synchronize { @states[request_id] }
        end

        # @return [Array<String>] the id of every request this provider has seen.
        def request_ids
          @monitor.synchronize { @states.keys }
        end

        # Convenience reader for the number of times a request consulted the
        # provider.
        #
        # @param request_id [String]
        # @return [Integer]
        def fetch_count(request_id)
          state = request_state(request_id)
          state ? state.fetch_count : 0
        end

        private

        # @return [Hash{String => RequestState}]
        attr_reader :states

        # @param request_id [String]
        # @return [RequestState]
        def state_for(request_id)
          @monitor.synchronize { @states[request_id] ||= RequestState.new(request_id) }
        end

        # @abstract Override in subclasses to produce the credential decision.
        #
        # @param _env [Faraday::Env] the request env.
        # @param _state [RequestState] the current per-request state.
        # @return [CredentialResult]
        def fetch_credential(_env, _state)
          raise NotImplementedError,
                "#{self.class} must implement #fetch_credential"
        end
      end

      # The explicit, unambiguous outcome of consulting a {CredentialProvider}.
      class CredentialResult
        # @return [String, nil] the value placed after the authorization type.
        attr_reader :value

        # @return [Integer, nil] version of the backing credential.
        attr_accessor :version

        # @return [String, nil] optional human-readable reason for a denial.
        attr_reader :reason

        # Builds an approved result.
        #
        # @param value [String] credential value appended to the header type.
        # @param version [Integer, nil] credential version.
        # @return [CredentialResult]
        def self.approved(value, version: nil)
          new(approved: true, value: value, version: version)
        end

        # Builds a denied result. No credential is ever sent for it.
        #
        # @param reason [String, nil] why the request was denied.
        # @param version [Integer, nil] credential version observed at denial.
        # @return [CredentialResult]
        def self.denied(reason = nil, version: nil)
          new(approved: false, reason: reason, version: version)
        end

        # @param approved [Boolean]
        # @param value [String, nil]
        # @param version [Integer, nil]
        # @param reason [String, nil]
        def initialize(approved:, value: nil, version: nil, reason: nil)
          @approved = approved
          @value = value
          @version = version
          @reason = reason
        end

        # @return [Boolean]
        def approved?
          @approved
        end

        # @return [Boolean]
        def denied?
          !@approved
        end
      end
    end
  end
end

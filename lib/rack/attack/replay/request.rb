# frozen_string_literal: true

module Rack
  class Attack
    module Replay
      # Request wrapper that records reads of fields the sanitized event did
      # not provide. Rules run unchanged; if a rule reads a missing field the
      # replay marks the decision undecidable instead of silently allowing.
      class Request < Rack::Attack::Request
        # Headers consulted by Rack::Request#ip / #user_agent themselves;
        # those accessors are tracked explicitly, so skip them here.
        UNTRACKED_HEADERS = %w[HTTP_FORWARDED HTTP_X_FORWARDED_FOR HTTP_CLIENT_IP HTTP_USER_AGENT].freeze

        attr_reader :missing_reads

        def initialize(env, provided_fields)
          @provided_fields = provided_fields
          @missing_reads = []
          super(env)
        end

        def ip
          record_missing(:ip) unless @provided_fields.include?(:ip)
          super
        end

        def user_agent
          record_missing(:user_agent) unless @provided_fields.include?(:user_agent)
          super
        end

        def params
          record_missing(:params) unless @provided_fields.include?(:params)
          super
        end

        def get_header(name)
          if name.is_a?(String) && name.start_with?("HTTP_") &&
             !UNTRACKED_HEADERS.include?(name) && !env.key?(name)
            record_missing(name)
          end
          super
        end

        private

        def record_missing(field)
          field = field.to_s
          @missing_reads << field unless @missing_reads.include?(field)
        end
      end
    end
  end
end

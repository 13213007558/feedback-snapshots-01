# frozen_string_literal: true

require 'digest'
require 'json'
require 'stringio'
require 'time'

module Rack
  class Attack
    module Replay
      # One sanitized request event. Events carry their own virtual
      # timestamp; the replay engine never consults the wall clock.
      #
      # Recognized keys:
      #   "at"         (required) ISO8601 timestamp or epoch seconds
      #   "method"     (required) HTTP method
      #   "path"       (required) path, optionally with query string
      #   "ip"         (optional) client IP
      #   "user_agent" (optional) User-Agent header
      #   "headers"    (optional) hash of additional HTTP headers
      #   "params"     (optional) hash of request params (query or body)
      #   "account"    (optional) sanitized account identifier; exposed to
      #                rules as params["account"], reported only as a hash
      #   "effects"    (optional) app side effects applied when the request
      #                is allowed, e.g.
      #                [{"allow2ban_reset": {"discriminator": "...", "findtime": 60}}]
      class Event
        REQUIRED_KEYS = %w[at method path].freeze
        SAFE_METHODS = %w[GET HEAD OPTIONS TRACE DELETE].freeze
        KNOWN_EFFECTS = %w[allow2ban_reset fail2ban_reset].freeze

        attr_reader :index, :at, :method, :path, :ip, :user_agent, :headers, :params, :account, :effects

        def initialize(raw, index)
          @raw = raw
          @index = index

          missing = REQUIRED_KEYS.reject { |key| raw.key?(key) }
          unless missing.empty?
            raise InvalidEventError, "event ##{index} is missing required key(s): #{missing.join(', ')}"
          end

          @at = self.class.parse_time(raw["at"], index)
          @method = raw["method"].to_s.upcase
          @path = raw["path"].to_s
          @ip = raw["ip"]
          @user_agent = raw["user_agent"]
          @headers = raw["headers"] || {}
          @account = raw["account"]
          @params = (raw["params"] || {}).dup
          @params["account"] ||= @account if @account
          @effects = raw["effects"] || []

          validate_effects!
        end

        def self.parse_time(value, index)
          case value
          when Integer then Time.at(value).utc
          when String then Time.iso8601(value).utc
          else
            raise InvalidEventError, "event ##{index} has unparseable \"at\": #{value.inspect}"
          end
        rescue ArgumentError
          raise InvalidEventError, "event ##{index} has unparseable \"at\": #{value.inspect}"
        end

        # Stable ordering: by virtual timestamp, ties keep input order.
        def <=>(other)
          [at.to_i, index] <=> [other.at.to_i, other.index]
        end

        def provided_fields
          fields = []
          fields << :ip if ip
          fields << :user_agent if user_agent || header_name?("user-agent")
          fields << :params if !@raw["params"].nil? || account || SAFE_METHODS.include?(method)
          fields
        end

        def build_env
          path_info, _, query = path.partition("?")
          env = {
            "REQUEST_METHOD" => method,
            "SCRIPT_NAME" => "",
            "PATH_INFO" => Rack::Attack::PathNormalizer.normalize_path(path_info),
            "QUERY_STRING" => query.to_s,
            "SERVER_NAME" => "rack-attack-replay.invalid",
            "SERVER_PORT" => "443",
            "HTTPS" => "on",
            "rack.url_scheme" => "https",
            "rack.input" => StringIO.new("")
          }
          env["REMOTE_ADDR"] = ip if ip
          env["HTTP_USER_AGENT"] = user_agent if user_agent
          headers.each { |name, value| env["HTTP_#{name.upcase.tr('-', '_')}"] = value.to_s }
          attach_params(env)
          env
        end

        # Traceable back to the event without exposing account plaintext.
        def report_entry
          entry = {
            "index" => index,
            "at" => at.utc.iso8601,
            "method" => method,
            "path" => path,
            "fingerprint" => fingerprint
          }
          entry["ip"] = ip if ip
          entry["account_sha256"] = self.class.digest(account) if account
          entry
        end

        def fingerprint
          "sha256:#{Digest::SHA256.hexdigest(canonical_json)[0, 16]}"
        end

        def self.digest(value)
          "sha256:#{Digest::SHA256.hexdigest(value.to_s)[0, 16]}"
        end

        private

        def attach_params(env)
          return if params.empty?

          if SAFE_METHODS.include?(method)
            encoded = Rack::Utils.build_query(params)
            env["QUERY_STRING"] = [env["QUERY_STRING"], encoded].reject(&:empty?).join("&")
          else
            body = Rack::Utils.build_query(params)
            env["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
            env["CONTENT_LENGTH"] = body.bytesize.to_s
            env["rack.input"] = StringIO.new(body)
          end
        end

        def header_name?(name)
          headers.keys.any? { |key| key.to_s.downcase == name }
        end

        def canonical_json
          JSON.generate(canonicalize(@raw))
        end

        def canonicalize(value)
          case value
          when Hash
            value.keys.map(&:to_s).sort.each_with_object({}) do |k, h|
              v = value.key?(k) ? value[k] : value[k.to_sym]
              h[k] = canonicalize(v)
            end
          when Array
            value.map { |v| canonicalize(v) }
          else
            value
          end
        end

        def validate_effects!
          effects.each do |effect|
            unknown = effect.keys - KNOWN_EFFECTS
            unless unknown.empty?
              raise InvalidEventError, "event ##{index} has unknown effect(s): #{unknown.join(', ')}"
            end
            KNOWN_EFFECTS.each do |kind|
              next unless effect[kind]

              %w[discriminator findtime].each do |required|
                unless effect[kind].key?(required)
                  raise InvalidEventError, "event ##{index} effect #{kind} is missing #{required.inspect}"
                end
              end
            end
          end
        end
      end
    end
  end
end

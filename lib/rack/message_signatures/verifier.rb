# frozen_string_literal: true

require 'openssl'
require 'digest'
require 'stringio'

require_relative '../constants'
require_relative '../utils'
require_relative 'structured_fields'

module Rack
  module MessageSignatures
    # Verifies HTTP Message Signatures (RFC 9421) on incoming requests.
    #
    # This middleware is intentionally opt-in. Add it explicitly to the
    # middleware stack only for services that require request signatures:
    #
    #   use Rack::MessageSignatures::Verifier,
    #     key: ENV.fetch("MESSAGE_SIGNATURE_KEY"),
    #     required_components: %w[@method @authority @path @query content-digest]
    #
    # The application supplies the shared secret (or a key resolver) and the
    # components that must be covered by every signature. A request is only
    # passed to the application after the signature, the requested target and
    # (when covered) the request body digest have all been verified.
    #
    # The request target is derived exclusively from the Rack request
    # environment. Forwarded and X-Forwarded-* fields are never consulted, so
    # they cannot change the target that the signature is checked against.
    class Verifier
      DEFAULT_COMPONENTS = %w[@method @authority @path @query content-digest].freeze
      SUPPORTED_ALGORITHMS = %w[hmac-sha256].freeze
      SUPPORTED_DERIVED_COMPONENTS = %w[
        @method @target-uri @authority @scheme @path @query
      ].freeze
      DIGESTS = {
        "sha-256" => ::Digest::SHA256,
        "sha-512" => ::Digest::SHA512,
      }.freeze
      DEFAULT_PORTS = {
        "http" => 80,
        "https" => 443,
        "ws" => 80,
        "wss" => 443,
      }.freeze
      # Rack maps field names to HTTP_<NAME> by upcasing and replacing
      # hyphens with underscores. Underscore is deliberately excluded because
      # "x_foo" and "x-foo" would both map to HTTP_X_FOO, making the original
      # field name unrecoverable.
      FIELD_NAME = /\A[a-z0-9!#$%&'*+\-.^`|~]+\z/.freeze
      REG_NAME = /\A[a-z0-9._~%!$&'()*+,;=-]+\z/i.freeze
      IP_LITERAL = /\A\[[0-9a-z:.%~_-]+\]\z/i.freeze
      READ_CHUNK_SIZE = 16 * 1024
      MAX_SIGNATURE_INPUT_BYTES = 64 * 1024
      MAX_SIGNATURE_BYTES = 16 * 1024
      UNSAFE_COVERED_FIELDS = %w[signature signature-input].freeze
      # These field values are not safely combinable with the ", " rule that
      # RFC 9421 requires (unquoted commas, semicolon-separated lists). A Rack
      # env String cannot tell us whether the server merged several field
      # lines, so we refuse them rather than guessing the original syntax.
      NON_REPRESENTABLE_FIELDS = %w[cookie set-cookie].freeze

      # The verified signature metadata is exposed under this environment key
      # after successful verification. It can be used by the application to
      # inspect the policy decision without re-parsing the signature fields.
      ENV_VERIFIED = "rack.message_signatures.verified".freeze

      class Rejection < StandardError
        attr_reader :status, :reason

        def initialize(status, reason)
          @status = status
          @reason = reason
          super(reason)
        end
      end

      class IncompleteEnv < Rejection
        def initialize(reason)
          super(400, reason)
        end
      end

      def initialize(app,
        key:,
        required_components: DEFAULT_COMPONENTS,
        label: nil,
        max_age: 300,
        clock_skew: 60,
        require_created: true,
        require_expires: false,
        require_keyid: false,
        key_id: nil,
        algorithms: SUPPORTED_ALGORITHMS,
        digest_algorithms: DIGESTS.keys,
        max_body_bytes: 10 * 1024 * 1024,
        clock: nil,
        on_failure: nil
      )
        @app = app
        @key = normalize_key(key)
        @required_components = normalize_required_components(required_components)
        @label = label.dup.freeze if label.is_a?(String)
        @max_age = max_age.nil? ? nil : integer_option(:max_age, max_age, minimum: 0)
        @clock_skew = integer_option(:clock_skew, clock_skew, minimum: 0)
        @require_created = boolean_option(:require_created, require_created)
        @require_expires = boolean_option(:require_expires, require_expires)
        @require_keyid = boolean_option(:require_keyid, require_keyid)
        @key_id = key_id.dup.freeze if key_id.is_a?(String)
        @algorithms = normalize_algorithms(algorithms)
        @digest_algorithms = normalize_digest_algorithms(digest_algorithms)
        @max_body_bytes = max_body_bytes.nil? ? nil : integer_option(:max_body_bytes, max_body_bytes, minimum: 1)
        @clock = clock
        @on_failure = on_failure

        unless @label.nil? || (@label.is_a?(String) && @label.match?(/\A[a-z*][a-z0-9_.*-]*\z/))
          raise ArgumentError, "label must be nil or a valid structured field key"
        end
        unless @key_id.nil? || @key_id.is_a?(String)
          raise ArgumentError, "key_id must be nil or a String"
        end
        unless @clock.nil? || @clock.respond_to?(:call)
          raise ArgumentError, "clock must be nil or a callable returning a Time or Integer"
        end
        unless @on_failure.nil? || @on_failure.respond_to?(:call)
          raise ArgumentError, "on_failure must be nil or a callable"
        end
      end

      def call(env)
        begin
          verification = verify_signature(env)

          if verification[:content_digest]
            digests = read_and_digest_request_body(env)
            verify_content_digest(verification[:content_digest], digests)
          end
        rescue Rejection => rejection
          return failure_response(env, rejection)
        end

        env[ENV_VERIFIED] = verification[:info]
        @app.call(env)
      end

      private

      def verify_signature(env)
        signature_input = parse_signature_input(env)
        signature = parse_signature(env)

        unless signature_input.keys.sort == signature.keys.sort
          raise Rejection.new(401, "Signature-Input and Signature labels do not match")
        end

        label = select_label(signature_input)
        input_member = signature_input.fetch(label)
        unless input_member.is_a?(StructuredFields::InnerList)
          raise Rejection.new(401, "Signature-Input member is not an inner list")
        end

        signature_member = signature.fetch(label)
        unless signature_member.is_a?(StructuredFields::Item) &&
            signature_member.value.is_a?(StructuredFields::Bytes) &&
            signature_member.parameters.empty?
          raise Rejection.new(401, "Signature member is not a byte sequence")
        end

        parameters = input_member.parameters
        created = integer_parameter(parameters, "created")
        expires = integer_parameter(parameters, "expires")
        algorithm = string_parameter(parameters, "alg")
        keyid = string_parameter(parameters, "keyid")

        enforce_algorithm(algorithm)
        enforce_key_id(keyid)
        enforce_timestamp_policy(created, expires)
        key = resolve_key(keyid)

        names, identifier_strings = covered_component_identifiers(input_member)
        enforce_required_components(identifier_strings)

        content_digest_header = field_value(env, "content-digest")
        if content_digest_header && !names.include?("content-digest")
          raise Rejection.new(401, "content-digest is present but not covered by the signature")
        end
        if names.include?("content-length") && !names.include?("content-digest")
          raise Rejection.new(401, "content-length cannot be covered without content-digest")
        end

        base = signature_base(env, input_member, names)
        expected = OpenSSL::HMAC.digest("SHA256", key, base)

        unless Utils.secure_compare(expected, signature_member.value.data)
          raise Rejection.new(401, "signature verification failed")
        end

        {
          content_digest: names.include?("content-digest") ? field_value(env, "content-digest") : nil,
          info: {
            "label" => label.freeze,
            "key_id" => keyid&.freeze,
            "algorithm" => "hmac-sha256".freeze,
            "components" => names.map(&:freeze).freeze,
            "created" => created,
            "expires" => expires,
          }.freeze,
        }
      end

      def parse_signature_input(env)
        value = signature_field(env, "HTTP_SIGNATURE_INPUT", "Signature-Input")

        begin
          StructuredFields.parse_dictionary(value, strict_duplicates: true)
        rescue StructuredFields::ParseError => error
          raise Rejection.new(401, "malformed Signature-Input: #{error.message}")
        end
      end

      def parse_signature(env)
        value = signature_field(env, "HTTP_SIGNATURE", "Signature")

        begin
          StructuredFields.parse_dictionary(value, strict_duplicates: true)
        rescue StructuredFields::ParseError => error
          raise Rejection.new(401, "malformed Signature: #{error.message}")
        end
      end

      def signature_field(env, key, name)
        value = env[key]

        if value.nil?
          raise Rejection.new(401, "missing #{name} field")
        end
        unless value.is_a?(String)
          raise IncompleteEnv.new("#{name} is not a single String value")
        end
        limit = name == "Signature-Input" ? MAX_SIGNATURE_INPUT_BYTES : MAX_SIGNATURE_BYTES
        if value.bytesize > limit
          raise Rejection.new(401, "#{name} field is too large")
        end

        value = value.sub(/\A[ \t]+/, "").sub(/[ \t]+\z/, "")
        if value.empty?
          raise Rejection.new(401, "empty #{name} field")
        end

        # A newline means the server combined multiple field lines without
        # preserving their boundaries. We refuse to guess how that happened.
        if value.include?("\r") || value.include?("\n") || value.include?("\0")
          raise IncompleteEnv.new("#{name} contains a line break and cannot be parsed unambiguously")
        end

        value
      end

      def select_label(signature_input)
        if @label
          unless signature_input.key?(@label)
            raise Rejection.new(401, "signature label #{@label.inspect} is not present")
          end
          return @label
        end

        if signature_input.size != 1
          raise Rejection.new(400, "multiple signatures are present; an explicit label is required")
        end

        signature_input.keys.first
      end

      def covered_component_identifiers(inner_list)
        names = []
        identifiers = []
        seen = {}

        inner_list.items.each do |item|
          unless item.is_a?(StructuredFields::Item) && item.value.is_a?(String)
            raise Rejection.new(401, "invalid covered component identifier")
          end

          name = item.value
          unless item.parameters.empty?
            raise Rejection.new(401, "unsupported parameters on component #{name.inspect}")
          end
          if name == "@signature-params"
            raise Rejection.new(401, "@signature-params must not be a covered component")
          end
          unless supported_component_name?(name)
            raise Rejection.new(401, "unsupported covered component #{name.inspect}")
          end
          if UNSAFE_COVERED_FIELDS.include?(name)
            raise Rejection.new(401, "signature fields must not be covered components")
          end
          if NON_REPRESENTABLE_FIELDS.include?(name)
            raise Rejection.new(401, "component #{name.inspect} cannot be represented unambiguously in Rack")
          end

          identifier = StructuredFields.serialize_item(item)
          if seen[identifier]
            raise Rejection.new(401, "duplicate covered component #{identifier}")
          end
          seen[identifier] = true

          names << name
          identifiers << identifier
        end

        [names, identifiers]
      end

      def enforce_required_components(identifiers)
        covered = identifiers.each_with_object({}) { |identifier, set| set[identifier] = true }

        @required_components.each do |required|
          unless covered[required]
            raise Rejection.new(401, "required component #{required} is not covered by the signature")
          end
        end
      end

      def signature_base(env, inner_list, names)
        lines = +""

        names.each do |name|
          identifier = StructuredFields.serialize_bare(name)
          value = component_value(env, name)
          lines << identifier << ": " << value << "\n"
        end

        lines << "\"@signature-params\": " << StructuredFields.serialize_inner_list(inner_list)
        lines
      end

      def component_value(env, name)
        value =
          if name.start_with?("@")
            derived_component(env, name)
          else
            field_value(env, name)
          end

        unless value
          raise Rejection.new(401, "covered component #{name.inspect} is not present")
        end
        unless value.ascii_only? && !value.include?("\r") && !value.include?("\n")
          raise IncompleteEnv.new("component #{name.inspect} cannot be represented as ASCII without line breaks")
        end

        value
      end

      def derived_component(env, name)
        case name
        when "@method"
          method = env[REQUEST_METHOD]
          unless method.is_a?(String) && !method.empty?
            raise IncompleteEnv.new("REQUEST_METHOD is missing")
          end
          method
        when "@authority"
          authority(env)
        when "@scheme"
          scheme(env)
        when "@path"
          path(env)
        when "@query"
          "?" + query_string(env)
        when "@target-uri"
          "#{scheme(env)}://#{authority(env)}#{path_with_query(env)}"
        else
          raise Rejection.new(401, "unsupported derived component #{name.inspect}")
        end
      end

      def path_with_query(env)
        query = query_string(env)
        query.empty? ? path(env) : "#{path(env)}?#{query}"
      end

      def path(env)
        script_name = env[SCRIPT_NAME]
        path_info = env[PATH_INFO]

        if script_name.nil? && path_info.nil?
          raise IncompleteEnv.new("PATH_INFO is missing")
        end
        unless (script_name.nil? || script_name.is_a?(String)) &&
            (path_info.nil? || path_info.is_a?(String))
          raise IncompleteEnv.new("PATH_INFO is not a String")
        end

        value = script_name.to_s + path_info.to_s
        value = "/" if value.empty?

        unless value.start_with?("/")
          raise IncompleteEnv.new("request target path cannot be reconstructed from PATH_INFO")
        end
        value
      end

      def query_string(env)
        value = env[QUERY_STRING]
        raise IncompleteEnv.new("QUERY_STRING is missing") unless value.is_a?(String)
        value
      end

      def scheme(env)
        value = env[RACK_URL_SCHEME]
        unless value.is_a?(String) && !value.empty?
          raise IncompleteEnv.new("rack.url_scheme is missing")
        end

        value = value.downcase
        unless DEFAULT_PORTS.key?(value)
          raise IncompleteEnv.new("rack.url_scheme is not supported")
        end
        value
      end

      def authority(env)
        value = env[HTTP_HOST]

        if value.nil?
          server_name = env[SERVER_NAME]
          unless server_name.is_a?(String) && !server_name.empty?
            raise IncompleteEnv.new("HTTP_HOST and SERVER_NAME are both missing")
          end

          server_port = env[SERVER_PORT]
          if server_port && !server_port.is_a?(String)
            raise IncompleteEnv.new("SERVER_PORT is not a String")
          end
          value = server_name
          value = "#{value}:#{server_port}" if server_port && !server_port.empty?
        end

        unless value.is_a?(String) && !value.empty?
          if value.is_a?(Array)
            raise IncompleteEnv.new("HTTP_HOST contains multiple field lines")
          end
          raise IncompleteEnv.new("HTTP_HOST is missing")
        end
        if value.include?(",") || value.include?("\r") || value.include?("\n")
          raise IncompleteEnv.new("HTTP_HOST cannot be parsed unambiguously")
        end

        normalize_authority(value, scheme(env))
      end

      def normalize_authority(value, scheme)
        if value.start_with?("[")
          closing = value.index("]")
          raise IncompleteEnv.new("invalid IPv6 authority") unless closing

          host = value[0..closing]
          remainder = value[(closing + 1)..]
          if remainder.nil? || remainder.empty?
            port = nil
          elsif remainder.start_with?(":")
            port = remainder[1..]
          else
            raise IncompleteEnv.new("invalid authority")
          end
        else
          host, separator, possible_port = value.rpartition(":")
          if separator.empty?
            host = value
            port = nil
          else
            if host.include?(":")
              raise IncompleteEnv.new("IPv6 authority must use brackets")
            end
            port = possible_port
          end
        end

        if host.empty?
          raise IncompleteEnv.new("authority host is empty")
        end
        unless host.match?(REG_NAME) || host.match?(IP_LITERAL)
          raise IncompleteEnv.new("invalid authority host")
        end

        if port
          unless port.match?(/\A\d{1,5}\z/) && port.to_i.between?(1, 65_535)
            raise IncompleteEnv.new("invalid authority port")
          end
          port = nil if port.to_i == DEFAULT_PORTS[scheme]
        end

        host = host.downcase
        port ? "#{host}:#{port}" : host
      end

      def field_value(env, name)
        unless name.match?(FIELD_NAME)
          raise Rejection.new(401, "invalid HTTP field name #{name.inspect}")
        end

        key =
          case name
          when "content-type"
            "CONTENT_TYPE"
          when "content-length"
            "CONTENT_LENGTH"
          else
            "HTTP_#{name.upcase.tr('-', '_')}"
          end

        value = env[key]
        return nil if value.nil?

        if value.is_a?(Array)
          raise IncompleteEnv.new("field #{name.inspect} contains multiple field lines")
        end
        unless value.is_a?(String)
          raise IncompleteEnv.new("field #{name.inspect} is not a String")
        end
        if value.include?("\r") || value.include?("\n") || value.include?("\0")
          raise IncompleteEnv.new("field #{name.inspect} contains a line break")
        end
        unless value.ascii_only?
          raise IncompleteEnv.new("field #{name.inspect} contains non-ASCII bytes")
        end

        value = value.sub(/\A[ \t]+/, "").sub(/[ \t]+\z/, "")

        # Content-Type and Content-Length are defined as singleton fields. A
        # comma therefore indicates that the server merged multiple field
        # lines (or that the message is malformed), and the original
        # boundaries are no longer available in the Rack environment.
        if name == "content-length" && !value.match?(/\A\d+\z/)
          raise IncompleteEnv.new("content-length is not a single decimal value")
        end
        if name == "content-type" && contains_unquoted_comma?(value)
          raise IncompleteEnv.new("content-type cannot be reconstructed as a single field value")
        end

        value
      end

      def contains_unquoted_comma?(value)
        quoted = false
        escaped = false

        value.each_char do |character|
          if escaped
            escaped = false
          elsif quoted && character == "\\"
            escaped = true
          elsif character == '"'
            quoted = !quoted
          elsif character == "," && !quoted
            return true
          end
        end

        false
      end

      def read_and_digest_request_body(env)
        input = env[RACK_INPUT]

        if input.nil?
          content_length = env["CONTENT_LENGTH"]
          if content_length.is_a?(String) && content_length.match?(/\A\d+\z/) && content_length.to_i > 0
            raise IncompleteEnv.new("rack.input is missing for a request with content")
          end
          return empty_body_digests
        end

        unless input.respond_to?(:read)
          raise IncompleteEnv.new("rack.input does not support reading")
        end

        rewound = false
        if input.respond_to?(:rewind)
          begin
            input.rewind
            rewound = true
          rescue StandardError
            rewound = false
          end
        end

        digests = @digest_algorithms.each_with_object({}) do |algorithm, result|
          result[algorithm] = DIGESTS.fetch(algorithm).new
        end
        buffer = +"".b
        bytes_read = 0

        begin
          while (chunk = input.read(READ_CHUNK_SIZE))
            break if chunk.empty?

            bytes_read += chunk.bytesize
            if @max_body_bytes && bytes_read > @max_body_bytes
              raise Rejection.new(413, "request body is too large to verify")
            end

            chunk = chunk.b
            digests.each_value { |digest| digest.update(chunk) }
            buffer << chunk unless rewound
          end
        rescue Rejection
          raise
        rescue StandardError
          raise Rejection.new(400, "request body could not be read")
        end

        if rewound
          begin
            input.rewind
          rescue StandardError
            raise IncompleteEnv.new("rack.input cannot be rewound after verification")
          end
        else
          # A one-shot stream must be replayed to the application. Only the
          # bounded amount already consumed is retained in memory.
          replacement = StringIO.new(buffer)
          replacement.set_encoding(Encoding::BINARY)
          env[RACK_INPUT] = replacement
        end

        digests.transform_values(&:digest)
      end

      def empty_body_digests
        @digest_algorithms.each_with_object({}) do |algorithm, result|
          result[algorithm] = DIGESTS.fetch(algorithm).digest("".b)
        end
      end

      def verify_content_digest(value, digests)
        begin
          dictionary = StructuredFields.parse_dictionary(value, strict_duplicates: true)
        rescue StructuredFields::ParseError
          raise Rejection.new(401, "malformed Content-Digest")
        end

        recognized = dictionary.select { |algorithm, _| @digest_algorithms.include?(algorithm) }
        if recognized.empty?
          raise Rejection.new(401, "no supported Content-Digest algorithm")
        end

        recognized.each do |algorithm, member|
          unless member.is_a?(StructuredFields::Item) &&
              member.value.is_a?(StructuredFields::Bytes) &&
              member.parameters.empty?
            raise Rejection.new(401, "invalid Content-Digest value for #{algorithm}")
          end

          unless Utils.secure_compare(digests.fetch(algorithm), member.value.data)
            raise Rejection.new(401, "Content-Digest verification failed")
          end
        end
      end

      def resolve_key(keyid)
        if @key_id && keyid != @key_id
          raise Rejection.new(401, "unexpected key identifier")
        end

        key =
          case @key
          when String
            @key
          when Hash
            keyid && @key[keyid]
          else
            begin
              @key.call(keyid)
            rescue StandardError
              raise Rejection.new(401, "key resolver failed")
            end
          end

        unless key.is_a?(String) && !key.empty?
          raise Rejection.new(401, "unknown key identifier")
        end

        key.b
      end

      def enforce_algorithm(algorithm)
        if algorithm && !@algorithms.include?(algorithm)
          raise Rejection.new(401, "unsupported signature algorithm")
        end

        # Only hmac-sha256 is currently implemented. A signature without an
        # explicit alg parameter is still bound to hmac-sha256 by policy; the
        # algorithm is never selected at runtime by an attacker.
        unless @algorithms.include?("hmac-sha256")
          raise Rejection.new(401, "no usable signature algorithm")
        end
      end

      def enforce_key_id(keyid)
        if @require_keyid && keyid.nil?
          raise Rejection.new(401, "keyid is required")
        end
      end

      def enforce_timestamp_policy(created, expires)
        if @require_created && created.nil?
          raise Rejection.new(401, "created signature parameter is required")
        end
        if @require_expires && expires.nil?
          raise Rejection.new(401, "expires signature parameter is required")
        end

        if created && created.negative?
          raise Rejection.new(401, "signature creation time is invalid")
        end
        if expires && expires.negative?
          raise Rejection.new(401, "signature expiration time is invalid")
        end
        if created && expires && expires < created
          raise Rejection.new(401, "signature expiration precedes its creation")
        end

        return if created.nil? && expires.nil?

        now = current_time
        if created
          if created > now + @clock_skew
            raise Rejection.new(401, "signature creation time is in the future")
          end
          if @max_age && now - created > @max_age + @clock_skew
            raise Rejection.new(401, "signature has expired")
          end
        end
        if expires && now > expires + @clock_skew
          raise Rejection.new(401, "signature expiration time has passed")
        end
      end

      def current_time
        value = @clock ? @clock.call : Time.now
        value = value.to_i if value.is_a?(Time) || value.is_a?(Integer)
        unless value.is_a?(Integer)
          raise Rejection.new(401, "signature clock is unavailable")
        end
        value
      rescue Rejection
        raise
      rescue StandardError
        raise Rejection.new(401, "signature clock is unavailable")
      end

      def integer_parameter(parameters, name)
        return nil unless parameters.key?(name)

        value = parameters[name]
        unless value.is_a?(Integer)
          raise Rejection.new(401, "#{name} signature parameter must be an integer")
        end
        value
      end

      def string_parameter(parameters, name)
        return nil unless parameters.key?(name)

        value = parameters[name]
        unless value.is_a?(String)
          raise Rejection.new(401, "#{name} signature parameter must be a string")
        end
        value
      end

      def normalize_key(key)
        case key
        when String
          raise ArgumentError, "key must not be empty" if key.empty?
          key.b.freeze
        when Hash
          result = {}
          key.each do |key_id, secret|
            unless key_id.is_a?(String) && !key_id.empty?
              raise ArgumentError, "key identifiers must be non-empty Strings"
            end
            unless secret.is_a?(String) && !secret.empty?
              raise ArgumentError, "keys must be non-empty Strings"
            end
            result[key_id.dup.freeze] = secret.b.freeze
          end
          result.freeze
        else
          unless key.respond_to?(:call)
            raise ArgumentError, "key must be a String, a Hash of key identifiers, or a callable"
          end
          key
        end
      end

      def normalize_required_components(components)
        unless components.is_a?(Array) && !components.empty?
          raise ArgumentError, "required_components must be a non-empty Array"
        end

        components.map do |component|
          unless component.is_a?(String) && supported_component_name?(component)
            raise ArgumentError, "invalid required component #{component.inspect}"
          end
          if component == "@signature-params"
            raise ArgumentError, "@signature-params cannot be a required component"
          end
          if UNSAFE_COVERED_FIELDS.include?(component)
            raise ArgumentError, "signature fields cannot be required components"
          end
          if NON_REPRESENTABLE_FIELDS.include?(component)
            raise ArgumentError, "component #{component.inspect} cannot be represented unambiguously in Rack"
          end
          StructuredFields.serialize_bare(component).freeze
        end.freeze
      end

      def normalize_algorithms(algorithms)
        unless algorithms.is_a?(Array) && !algorithms.empty?
          raise ArgumentError, "algorithms must be a non-empty Array"
        end
        unless (algorithms - SUPPORTED_ALGORITHMS).empty?
          raise ArgumentError, "unsupported signature algorithm"
        end
        algorithms.map(&:dup).freeze
      end

      def normalize_digest_algorithms(digest_algorithms)
        unless digest_algorithms.is_a?(Array) && !digest_algorithms.empty?
          raise ArgumentError, "digest_algorithms must be a non-empty Array"
        end
        unless (digest_algorithms - DIGESTS.keys).empty?
          raise ArgumentError, "unsupported content digest algorithm"
        end
        digest_algorithms.map(&:dup).freeze
      end

      def supported_component_name?(name)
        if name.start_with?("@")
          SUPPORTED_DERIVED_COMPONENTS.include?(name)
        else
          name.match?(FIELD_NAME)
        end
      end

      def integer_option(name, value, minimum:)
        unless value.is_a?(Integer) && value >= minimum
          raise ArgumentError, "#{name} must be an Integer >= #{minimum}"
        end
        value
      end

      def boolean_option(name, value)
        unless value == true || value == false
          raise ArgumentError, "#{name} must be true or false"
        end
        value
      end

      def failure_response(env, rejection)
        if @on_failure
          begin
            @on_failure.call(env, rejection.reason, rejection.status)
          rescue StandardError
            # A failure callback must never cause an invalid signature to be
            # treated as successful.
          end
        end

        [rejection.status,
         { CONTENT_TYPE => "text/plain", CONTENT_LENGTH => "0", "cache-control" => "no-store" },
         []]
      end
    end
  end
end

# encoding: utf-8
# frozen_string_literal: true
require 'yaml'
require 'base64'

module Mail
  # Mail::YAML reads historical mail dumps produced by Mail::Message#to_yaml.
  #
  # Those dumps are treated as untrusted input.  A real Mail::Message is never
  # reconstructed by asking YAML to instantiate classes.  Instead the document
  # is parsed into a Psych AST, walked with a strict tag allow-list, and reduced
  # to plain Ruby primitives (Hash, Array, String, Integer, Float, true, false
  # and nil).  Only once that validation pass has succeeded are
  # Mail::Message / Mail::Part objects built through their public API.
  #
  # As a result:
  #
  # * no arbitrary Ruby object is created from a tag found in the input;
  # * the +delivery_handler+ behaviour configuration is never loaded;
  # * internal instance variables (keys beginning with +@+) are never written
  #   onto a message;
  # * anything that cannot be explained safely is recorded on the
  #   {Mail::YAML::MigrationResult} rather than silently dropped.
  module YAML
    # Prefix shared by every Ruby-specific tag, e.g. !ruby/object:Mail::Body.
    RUBY_TAG_PREFIX = '!ruby/'.freeze

    # Plain YAML data tags from the yaml.org,2002 repository.  Both the full URI
    # and the local "!name" shorthand are listed because Psych keeps shorthand
    # tags inside embedded YAML documents.  None of these names a Ruby class.
    CORE_TAGS = {
      'tag:yaml.org,2002:null'   => :null,
      'tag:yaml.org,2002:bool'   => :bool,
      'tag:yaml.org,2002:int'    => :int,
      'tag:yaml.org,2002:float'  => :float,
      'tag:yaml.org,2002:str'    => :str,
      'tag:yaml.org,2002:binary' => :binary,
      '!null'                    => :null,
      '!bool'                    => :bool,
      '!int'                     => :int,
      '!float'                   => :float,
      '!str'                     => :str,
      '!binary'                  => :binary,
    }.freeze

    # Ruby tags that legitimately appear in a real Mail::Message#to_yaml dump.
    # They are accepted as *structure only*: the tagged node is reduced to a
    # plain Hash/Array of its safe inner values and the class is never
    # instantiated.  Any Ruby tag not on this list is refused outright.
    KNOWN_RUBY_TAGS = %w[
      !ruby/object:Mail::Body
      !ruby/object:Mail::SMTP
      !ruby/object:Mail::Part
      !ruby/object:Mail::Header
      !ruby/object:Mail::Field
      !ruby/array:Mail::FieldList
      !ruby/hash:Mail::ParameterHash
    ].freeze

    # Raised when the top-level document is not a mapping and therefore cannot
    # represent a serialized Mail::Message.
    class MalformedDocument < StandardError; end

    # Raised when the input cannot be parsed as YAML at all.
    class InvalidYAML < StandardError; end

    # One piece of input that could not be migrated verbatim.
    #
    # +severity+ distinguishes two situations:
    #
    # * +:error+   - the field named a class or construct that is unsafe to
    #   honour; it was refused and the migration is not lossless.
    # * +:warning+ - the field is a known Mail internal or behaviour setting
    #   that is intentionally not restored; content was still recovered.
    class RejectedField
      attr_reader :path, :tag, :reason, :severity

      def initialize(path, tag, reason, severity = :error)
        @path     = path
        @tag      = tag
        @reason   = reason
        @severity = severity
      end

      def error?
        severity == :error
      end

      def warning?
        severity == :warning
      end

      def to_s
        location = path.empty? ? '<root>' : path
        suffix   = tag ? " (tag #{tag})" : ''
        "[#{severity}] #{location}#{suffix}: #{reason}"
      end
    end

    # Outcome of migrating one historical YAML document.  +message+ is the
    # rebuilt Mail::Message (nil only when the document is fundamentally
    # unusable).  +notices+ enumerates every field that was not restored
    # verbatim, split into hard +errors+ (unsafe input) and +warnings+ (known
    # internals deliberately skipped), so a partial migration is never mistaken
    # for a lossless one.
    class MigrationResult
      attr_reader :message, :notices

      def initialize(message, notices)
        @message = message
        @notices = notices
      end

      def errors
        notices.select(&:error?)
      end

      def warnings
        notices.select(&:warning?)
      end

      # True only when no unsafe construct was encountered.  Warnings about
      # skipped Mail internals do not invalidate a migration.
      def ok?
        errors.empty?
      end

      def rejected?(path)
        notices.any? { |field| field.path == path }
      end
    end

    # Backwards-compatible, but now safe, loader.
    #
    # Returns the document reduced to plain primitives without instantiating
    # any class named by the input.  A recognized tagged node is reduced to a
    # plain container; an unknown tag is recorded in SafeTree#notices.
    def self.load(yaml)
      SafeTree.parse(yaml).result
    end

    # Safe migration entry point.
    #
    # Validates +yaml+ without instantiating any object named by the input,
    # then rebuilds a Mail::Message through its public API.  The returned
    # MigrationResult lists every field that had to be refused.
    def self.migrate(yaml)
      tree    = SafeTree.parse(yaml)
      data    = tree.result
      notices = tree.notices.dup

      unless data.is_a?(::Hash)
        actual = data.nil? ? 'an empty document' : data.class
        raise MalformedDocument,
              "expected a YAML mapping representing a Mail::Message, got #{actual}"
      end

      message = MessageBuilder.new(notices).build(data, '$', Mail::Message)
      MigrationResult.new(message, notices)
    end

    # Reduces a parsed Psych AST to plain primitives.  It deliberately does not
    # use Psych's to_ruby machinery, so class resolution, init_with/encode_with
    # hooks and const_get are all unreachable from the input.
    class SafeTree < Psych::Visitors::Visitor
      attr_reader :result, :notices
      attr_writer :result

      def self.parse(yaml)
        visitor = new
        ast = Psych.parse(yaml)
        # Psych.parse returns false (not an AST) for an empty document; leave
        # the visitor's result as nil in that case.
        visitor.accept(ast) if ast.is_a?(Psych::Nodes::Node)
        visitor
      rescue Psych::Exception => e
        raise InvalidYAML, "input is not valid YAML: #{e.message}"
      end

      def initialize
        super
        @stack    = []   # each frame is the container currently being filled
        @path     = ['$'] # components addressing the node being visited
        @result   = nil
        @notices  = []
      end

      # Document / Stream nodes are pure structure: pass children through.
      def visit_Psych_Nodes_Document(node)
        node.children.each { |child| accept(child) }
      end
      alias visit_Psych_Nodes_Stream visit_Psych_Nodes_Document

      def visit_Psych_Nodes_Alias(node)
        reject(node, current_path, 'YAML aliases are not permitted in trusted mail data')
        emit(nil)
      end

      def visit_Psych_Nodes_Scalar(node)
        emit(coerce_scalar(node))
      end

      def visit_Psych_Nodes_Mapping(node)
        guard_tag(node)
        container = {}
        with_container(container) do
          node.children.each_slice(2) do |key_node, value_node|
            @path.push(key_text(key_node))
            accept(value_node)
            @path.pop
          end
        end
      end

      def visit_Psych_Nodes_Sequence(node)
        guard_tag(node)
        container = []
        with_container(container) do
          node.children.each_with_index do |child, index|
            @path.push("[#{index}]")
            accept(child)
            @path.pop
          end
        end
      end

      private

      def with_container(container)
        @stack.push(container)
        yield
        @stack.pop
        emit(container)
      end

      def emit(value)
        if @stack.empty?
          @result = value
        else
          parent = @stack.last
          if parent.is_a?(::Hash)
            parent[current_key] = value
          else
            parent << value
          end
        end
      end

      def current_key
        @path.last
      end

      # Joins path components, keeping "[i]" index parts directly attached to
      # their predecessor: "$.multipart_body[0].@body".
      def current_path
        @path.each_with_index.each_with_object(+'') do |(component, index), memo|
          if component.start_with?('[')
            memo << component
          elsif index.zero?
            memo << component
          else
            memo << '.' << component
          end
        end
      end

      def key_text(node)
        if node.is_a?(Psych::Nodes::Scalar) && node.tag.nil?
          node.value
        else
          reject(node, current_path, 'mapping keys must be plain untagged scalars')
          "<invalid-key-#{node.object_id}>"
        end
      end

      # YAML 1.1 core-style implicit resolutions, applied only to untagged
      # plain scalars.  Quoted scalars always stay strings, so a value such as
      # "42" in quotes cannot be turned into an Integer.  The patterns are kept
      # deliberately narrow: anything that does not cleanly round-trip through
      # Integer/Float stays a string.
      PLAIN_NULL = %w[~ null Null NULL].freeze
      PLAIN_BOOL = { 'true' => true, 'True' => true, 'TRUE' => true,
                     'false' => false, 'False' => false, 'FALSE' => false }.freeze
      PLAIN_INT  = /\A[-+]?(0|[1-9][0-9_]*|0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[0-7_]+)\z/.freeze
      PLAIN_FLOAT = /\A[-+]?([0-9][0-9_]*)?\.[0-9_]*([eE][-+]?[0-9]+)?\z/.freeze

      def coerce_scalar(node)
        tag = node.tag
        return resolve_plain(node) if tag.nil?

        kind = CORE_TAGS[tag]
        if kind.nil?
          reject(node, current_path, "unsupported tag #{tag.inspect}")
          return node.value
        end

        case kind
        when :null   then nil
        when :bool   then node.value == 'true'
        when :int    then parse_integer(node)
        when :float  then parse_float(node)
        when :binary then Base64.decode64(node.value).dup.force_encoding(Encoding::ASCII_8BIT)
        else node.value
        end
      end

      def resolve_plain(node)
        value = node.value
        return value unless node.style == Psych::Nodes::Scalar::PLAIN
        return nil   if PLAIN_NULL.include?(value)
        return PLAIN_BOOL[value] if PLAIN_BOOL.key?(value)
        return parse_integer(node) if PLAIN_INT.match?(value)
        return parse_float(node)   if PLAIN_FLOAT.match?(value)
        value
      end

      def parse_integer(node)
        Integer(node.value.delete('_'))
      rescue ArgumentError
        node.value
      end

      def parse_float(node)
        Float(node.value.delete('_'))
      rescue ArgumentError
        node.value
      end

      # Refuses tags that could name an arbitrary class while letting the
      # known Mail structure tags through as plain data containers.
      def guard_tag(node)
        tag = node.tag
        return if tag.nil? || CORE_TAGS.key?(tag)

        if KNOWN_RUBY_TAGS.include?(tag)
          # Recognized Mail structure: keep walking, never instantiate.
          return
        end

        if tag.start_with?(RUBY_TAG_PREFIX)
          reject(node, current_path, "arbitrary Ruby tag #{tag.inspect} is not instantiated")
        else
          reject(node, current_path, "unsupported tag #{tag.inspect}")
        end
      end

      def reject(node, path, reason)
        return if @notices.any? { |existing| existing.path == path && existing.reason == reason }
        @notices << RejectedField.new(path, node.tag, reason)
      end
    end

    # Builds Mail::Message / Mail::Part objects from the validated primitive
    # tree using only the public Mail API.  There is no instance_variable_set,
    # constant lookup or delivery-handler assignment in this class.
    class MessageBuilder
      # Top-level keys that carry message content and are consumed explicitly.
      HANDLED_KEYS = %w[
        headers
        transport_encoding
        multipart_body
      ].freeze

      # Internal-state keys read only to recover body text; never written back
      # onto a message as instance variables.
      BODY_DATA_KEYS = %w[
        @body
        @body_raw
      ].freeze

      # Behaviour/configuration that a genuine to_yaml dump can carry.  None of
      # it is ever applied; the distinction below is only about severity.
      #
      # +delivery_handler+ names a constant the old code resolved with
      # const_get, so its presence is an attack surface and a hard rejection.
      # +@delivery_method+ is plain SMTP settings present in every dump; it is
      # safe to ignore and therefore only a warning.
      BEHAVIOUR_KEYS = {
        'delivery_handler' => [:error, 'delivery_handler behaviour is never loaded from untrusted data'],
        '@delivery_method' => [:warning, 'delivery method configuration is never applied from untrusted data'],
      }.freeze

      # Instance variables that a genuine Mail::Message#to_yaml emits.  They are
      # never written back onto a rebuilt message, but seeing them is expected,
      # so skipping them is reported as a warning rather than an attack.  Any
      # other "@"-prefixed key is an injected variable and is a hard error.
      KNOWN_INTERNAL_VARIABLES = %w[
        @body
        @body_raw
        @separate_parts
        @text_part
        @html_part
        @errors
        @charset
        @defaulted_charset
        @smtp_envelope_from
        @smtp_envelope_to
        @perform_deliveries
        @raise_delivery_errors
        @mark_for_delete
        @raw_source
      ].freeze

      def initialize(notices)
        @notices = notices
      end

      def build(data, path, klass = Mail::Part)
        message = klass.new

        apply_headers(message, data['headers'], "#{path}.headers")
        apply_transport_encoding(message, data['transport_encoding'], "#{path}.transport_encoding")

        if data.key?('multipart_body')
          build_parts(message, data['multipart_body'], "#{path}.multipart_body")
        else
          apply_body(message, data, path)
        end

        record_unhandled_keys(data, path)
        message
      end

      private

      def merge_rejections(fields, prefix)
        fields.each do |field|
          nested = field.path.sub(/^\$/, prefix)
          @notices << RejectedField.new(nested, field.tag, field.reason, field.severity)
        end
      end

      def apply_headers(message, headers, path)
        return if headers.nil?

        unless headers.is_a?(::Hash)
          @notices << RejectedField.new(path, nil, 'headers must be a mapping')
          return
        end

        headers.each do |name, value|
          unless name.is_a?(::String) && value.is_a?(::String)
            @notices << RejectedField.new("#{path}.#{name}", nil,
                                           'header names and values must be plain strings')
            next
          end
          message[name] = value
        end
      end

      def apply_transport_encoding(message, encoding, path)
        return if encoding.nil?

        unless encoding.is_a?(::String)
          @notices << RejectedField.new(path, nil, 'transport_encoding must be a string')
          return
        end
        message.transport_encoding(encoding)
      end

      def build_parts(message, parts, path)
        unless parts.is_a?(::Array)
          @notices << RejectedField.new(path, nil, 'multipart_body must be a sequence')
          return
        end

        parts.each_with_index do |entry, index|
          part_path = "#{path}[#{index}]"
          part_data =
            if entry.is_a?(::String)
              # to_yaml stores each nested part as its own embedded YAML
              # document; run it through the same untrusted-input pipeline.
              begin
                subtree = SafeTree.parse(entry)
                merge_rejections(subtree.notices, part_path)
                subtree.result
              rescue InvalidYAML, MalformedDocument => e
                @notices << RejectedField.new(part_path, nil, "unparseable nested part: #{e.message}")
                nil
              end
            else
              entry
            end

          if part_data.is_a?(::Hash)
            message.add_part(build(part_data, part_path))
          else
            @notices << RejectedField.new(part_path, nil, 'each part must be a mapping')
          end
        end
      end

      def apply_body(message, data, path)
        body = extract_body(data, path)
        message.body = body unless body.nil?
      end

      # Body text can appear as the primitive "@body_raw" string or as the
      # raw_source captured from a tagged Mail::Body node.  Only string content
      # is ever fed back through the public #body= writer.
      def extract_body(data, path)
        candidates = []
        candidates << data['@body_raw'] if data.key?('@body_raw')
        body_node = data['@body']
        if body_node.is_a?(::Hash) && body_node.key?('raw_source')
          candidates << body_node['raw_source']
        end
        candidates.reject! { |value| value.nil? || value == '' }
        return nil if candidates.empty?

        chosen = candidates.first
        unless chosen.is_a?(::String)
          @notices << RejectedField.new("#{path}.body", nil, 'body content must be a string')
          return nil
        end
        chosen
      end

      def record_unhandled_keys(data, path)
        data.each_key do |key|
          next unless key.is_a?(::String)
          next if HANDLED_KEYS.include?(key) || BODY_DATA_KEYS.include?(key)

          full_path = "#{path}.#{key}"
          # The parser already refused this value (e.g. an alias or an unsafe
          # tag); do not pile a second, less precise notice on top of it.
          next if @notices.any? { |notice| notice.path == full_path }
          if BEHAVIOUR_KEYS.key?(key)
            severity, reason = BEHAVIOUR_KEYS[key]
            @notices << RejectedField.new(full_path, nil, reason, severity)
          elsif key.start_with?('@') && KNOWN_INTERNAL_VARIABLES.include?(key)
            # A variable a genuine dump carries.  It is never injected; content
            # has already been recovered through the public API.
            @notices << RejectedField.new(full_path, nil,
                                          'known internal variable is not restored from untrusted data',
                                          :warning)
          elsif key.start_with?('@')
            # An unexpected internal variable offered by untrusted input.  Never
            # injected; reported as a hard error instead of being silently ignored.
            @notices << RejectedField.new(full_path, nil,
                                          'injected internal instance variable is refused')
          else
            # A genuinely unrecognized top-level field: cannot explain it, so
            # this counts as a hard error rather than a silent drop.
            @notices << RejectedField.new(full_path, nil,
                                          'unknown field is not part of the safe message schema')
          end
        end
      end
    end
  end
end

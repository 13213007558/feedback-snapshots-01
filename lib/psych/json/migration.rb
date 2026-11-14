# frozen_string_literal: true

module Psych
  module JSON
    ###
    # Raised when a YAML document cannot be migrated to JSON without
    # changing the meaning of the data.  Carries the JSONPath-ish
    # +path+ of the offending node and a human readable +reason+.
    class MigrationError < Psych::Exception
      attr_reader :path, :reason

      def initialize path, reason
        @path = path
        @reason = reason
        super "cannot losslessly migrate YAML to JSON at #{path}: #{reason}"
      end
    end

    # The subset of Ruby types a YAML document may resolve to and still
    # migrate to JSON losslessly:
    #
    # * NilClass, TrueClass, FalseClass
    # * Integer (any size)
    # * Float (finite only; NaN and +/- Infinity are rejected)
    # * String (validly encoded)
    # * Array of safe values
    # * Hash with unique String keys and safe values
    #
    # Anything else -- symbols, dates, custom tags, merge keys, shared
    # or circular references -- is rejected with a MigrationError that
    # points at the exact path instead of being silently coerced.
    SAFE_TYPES = [NilClass, TrueClass, FalseClass, Integer, Float, String, Array, Hash].freeze

    ###
    # Strictly migrate a YAML document to a JSON string.
    #
    # The document is parsed into an AST and every node is validated
    # against SAFE_TYPES before anything is emitted.  Unlike
    # Psych.load or Psych.safe_load this never instantiates Ruby
    # objects and never calls custom object hooks (yaml_new,
    # init_with, ...); an unknown tag is an error, not a
    # deserialization attempt.
    #
    # Returns the JSON string when, and only when, the whole document
    # fits the safe subset.  Otherwise raises
    # Psych::JSON::MigrationError with the exact path and reason.
    # Unrecognized values are never replaced with null and conflicting
    # keys are never silently overwritten.
    def self.migrate yaml
      Migrator.new.migrate yaml
    end

    class Migrator # :nodoc:
      STR_TAG   = 'tag:yaml.org,2002:str'
      SEQ_TAG   = 'tag:yaml.org,2002:seq'
      MAP_TAG   = 'tag:yaml.org,2002:map'
      MERGE_KEY = '<<'

      CORE_SCALAR_TAGS = %w[
        tag:yaml.org,2002:null
        tag:yaml.org,2002:bool
        tag:yaml.org,2002:int
        tag:yaml.org,2002:float
        tag:yaml.org,2002:str
      ].freeze

      STRING_ESCAPES = {
        '"' => '\\"', '\\' => '\\\\', "\b" => '\\b',
        "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t'
      }.freeze

      def initialize
        @scanner   = ScalarScanner.new ClassLoader.new
        @anchors   = {}
        @ancestors = {} # node object_id => true, for cycle detection
      end

      def migrate yaml
        documents = Psych.parse_stream(yaml).children
        if documents.length > 1
          raise MigrationError.new('$', "expected a single YAML document but found #{documents.length}; JSON holds exactly one root value")
        end
        root = documents.first && documents.first.children.first
        emit(root ? convert(root, '$') : nil)
      end

      private

      def convert node, path
        @anchors[node.anchor] = node if node.anchor && !(Nodes::Alias === node)
        case node
        when Nodes::Scalar   then convert_scalar node, path
        when Nodes::Sequence then convert_sequence node, path
        when Nodes::Mapping  then convert_mapping node, path
        when Nodes::Alias    then convert_alias node, path
        else
          raise MigrationError.new(path, "unsupported YAML node #{node_name node}")
        end
      end

      def convert_sequence node, path
        check_collection_tag node, path, SEQ_TAG
        track(node) do
          node.children.each_with_index.map { |child, index|
            convert child, "#{path}[#{index}]"
          }
        end
      end

      def convert_mapping node, path
        check_collection_tag node, path, MAP_TAG
        track(node) do
          result = {}
          node.children.each_slice(2) do |key_node, value_node|
            reject_merge_key key_node, path
            key = convert_key key_node, path, result
            result[key] = convert value_node, "#{path}.#{key}"
          end
          result
        end
      end

      def convert_alias node, path
        target = @anchors[node.anchor]
        unless target
          raise MigrationError.new(path, "alias '*#{node.anchor}' references an unknown anchor")
        end
        if @ancestors.key? target.object_id
          raise MigrationError.new(path, "circular reference through alias '*#{node.anchor}' cannot be represented in JSON")
        end
        unless Nodes::Scalar === target
          raise MigrationError.new(path, "shared reference '*#{node.anchor}' to a #{node_name target} has no JSON equivalent; refusing to silently expand or collapse it")
        end
        convert target, path
      end

      def convert_key key_node, path, result
        unless Nodes::Scalar === key_node
          raise MigrationError.new(path, "mapping key is a #{node_name key_node}; JSON object keys must be plain strings")
        end
        key = convert_scalar key_node, path
        unless String === key
          stringified = key.nil? ? '' : key.to_s
          reason = "non-string mapping key #{key_node.value.inspect} (#{key.class}) cannot be a JSON object key"
          if result.key? stringified
            reason += "; stringifying it would collide with the existing key #{stringified.inspect} and silently overwrite one of the two entries"
          end
          raise MigrationError.new(path, reason)
        end
        if result.key? key
          raise MigrationError.new("#{path}.#{key}", "duplicate key #{key.inspect}; migrating would silently overwrite one of the two entries")
        end
        key
      end

      def reject_merge_key key_node, path
        return unless Nodes::Scalar === key_node
        return unless key_node.plain && !key_node.quoted
        return unless key_node.value == MERGE_KEY
        return if key_node.tag == STR_TAG
        raise MigrationError.new(path, "merge key '<<' has no JSON equivalent; refusing to silently expand or drop inherited entries")
      end

      def convert_scalar node, path
        tag = node.tag
        if tag && !CORE_SCALAR_TAGS.include?(tag)
          raise MigrationError.new(path, "unsupported tag #{tag.inspect}; only the YAML core schema types (null, bool, int, float, str) migrate losslessly, and custom object hooks are never invoked")
        end

        value =
          if tag == STR_TAG || (tag.nil? && node.quoted)
            node.value
          elsif tag.nil?
            @scanner.tokenize node.value
          else
            convert_tagged_scalar node, path
          end

        check_safe_value value, node, path
      end

      def convert_tagged_scalar node, path
        value = @scanner.tokenize node.value
        ok = case node.tag
             when 'tag:yaml.org,2002:null' then value.nil?
             when 'tag:yaml.org,2002:bool' then true == value || false == value
             when 'tag:yaml.org,2002:int'  then Integer === value
             when 'tag:yaml.org,2002:float'
               if Integer === value
                 value = value.to_f
                 true
               else
                 Float === value
               end
             end
        unless ok
          raise MigrationError.new(path, "value #{node.value.inspect} does not match its tag #{node.tag.inspect}")
        end
        value
      end

      def check_safe_value value, node, path
        case value
        when NilClass, TrueClass, FalseClass, Integer
          value
        when Float
          unless value.finite?
            raise MigrationError.new(path, "non-finite float #{node.value.inspect} (NaN or Infinity) has no JSON representation")
          end
          value
        when String
          unless value.valid_encoding?
            raise MigrationError.new(path, "string is not valid #{value.encoding}; JSON requires Unicode text")
          end
          value
        when Symbol
          raise MigrationError.new(path, "symbol #{value.inspect} would lose its type in JSON")
        when Date, Time
          raise MigrationError.new(path, "#{value.class} value #{node.value.inspect} would silently become a plain string in JSON")
        else
          raise MigrationError.new(path, "#{value.class} cannot be represented in JSON")
        end
      end

      def check_collection_tag node, path, safe_tag
        tag = node.tag
        return if tag.nil? || tag == safe_tag
        raise MigrationError.new(path, "unsupported tag #{tag.inspect} on collection; only plain sequences and mappings migrate losslessly")
      end

      def track node
        @ancestors[node.object_id] = true
        yield
      ensure
        @ancestors.delete node.object_id
      end

      def node_name node
        node.class.name.split('::').last
      end

      def emit value
        out = String.new encoding: Encoding::UTF_8
        write_value value, out
        out
      end

      def write_value value, out
        case value
        when Hash
          out << '{'
          value.each_with_index do |(key, element), index|
            out << ',' if index > 0
            write_string key, out
            out << ':'
            write_value element, out
          end
          out << '}'
        when Array
          out << '['
          value.each_with_index do |element, index|
            out << ',' if index > 0
            write_value element, out
          end
          out << ']'
        when String  then write_string value, out
        when Integer then out << value.to_s
        when Float   then out << value.to_s
        when true    then out << 'true'
        when false   then out << 'false'
        when nil     then out << 'null'
        end
      end

      def write_string string, out
        out << '"'
        out << string.gsub(/["\\\x00-\x1f]/) { |char| STRING_ESCAPES[char] || ('\\u%04x' % char.ord) }
        out << '"'
      end
    end
    private_constant :Migrator
  end
end

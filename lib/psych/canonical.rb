# frozen_string_literal: true

require "digest"
require_relative "exception"

module Psych
  # = Psych::Canonical -- versioned YAML canonicalization for signing
  #
  # Psych::Canonical turns a YAML document into a deterministic byte string
  # (and SHA-256 digest) suitable for signing security policies.  It never
  # signs the output of +to_yaml+: emission details such as comments,
  # indentation, key order, flow/block style, and anchor names are
  # normalized away, while every semantic value and its type are preserved
  # in the digest.
  #
  #   Psych::Canonical.canonicalize(yaml)          # => canonical bytes
  #   Psych::Canonical.digest(yaml)                # => SHA-256 hex
  #   Psych::Canonical.canonicalize(yaml, version: 1)
  #
  # The +version:+ keyword selects the canonicalization profile.  Only
  # version 1 ("YCANON/1") exists; any other value raises ArgumentError, so
  # a future format change can never be confused with this one.  The format
  # identifier is embedded in the signed bytes themselves.
  #
  # == YCANON/1 specification
  #
  # === Input
  #
  # The input must be a YAML stream containing at most one document; an
  # empty (or comment-only) stream canonicalizes to +null+.  Streams with
  # more than one document are rejected.
  #
  # === Data model
  #
  # Only the YAML 1.2 core schema is signable:
  #
  # * null    (+~+, +null+, empty plain scalar)
  # * boolean (+true+ / +false+ and YAML 1.2 case variants)
  # * integer (decimal, +0x+ hexadecimal, +0o+ octal; no underscores)
  # * float   (finite IEEE-754 doubles only; +.inf+ / +.nan+ are rejected)
  # * string  (any quoted scalar, or a plain scalar matching nothing above;
  #            must be valid UTF-8)
  # * sequence
  # * mapping with string keys only
  #
  # Plain scalars are resolved with the YAML 1.2 core schema, NOT the
  # YAML 1.1 rules: +yes+, +no+, +on+, +off+, +y+, +n+ are plain strings.
  # Quoted scalars are always strings, so +"false"+ and +false+ digest
  # differently.
  #
  # === Mapping keys
  #
  # Keys must resolve to strings.  Integer, boolean, null, sequence, or
  # mapping keys raise KeyTypeError.  Duplicate explicit keys raise
  # DuplicateKeyError.
  #
  # === Merge keys and aliases
  #
  # The merge key +<<+ is expanded before canonicalization: entries from
  # the merge source are copied into the mapping unless an explicit key
  # overrides them (explicit always wins; the overridden merged value does
  # not appear in the digest).  A merge value must be a mapping, an alias
  # to a mapping, or a sequence of those.  If two merge sources provide
  # the same key, MergeConflictError is raised instead of silently picking
  # one -- ambiguous input must not be signed.
  #
  # Aliases are expanded to the value of their anchor.  Anchor names never
  # appear in the output, so renaming an anchor cannot change the digest.
  # An alias that (transitively) refers to one of its own ancestors cannot
  # be expanded to a finite value and raises CycleError.
  #
  # === Tags
  #
  # Explicit tags are honored only for the six core types
  # (+!!null+, +!!bool+, +!!int+, +!!float+, +!!str+, +!!seq+, +!!map+) and
  # +!!merge+.  Any other explicit or local tag (+!ruby/object+, +!!binary+,
  # +!custom+, ...) raises UnsupportedTagError: such values have no stable
  # cross-implementation meaning and must not be signed.
  #
  # === Canonical byte format
  #
  #   canonical := "YCANON/1\n" value "\n"
  #   value     := "null" | "true" | "false"
  #              | integer        # decimal, no leading zeros, "-" for negatives
  #              | float          # Ruby shortest round-trip (Float#to_s),
  #                               # always contains "." or "e"; "-0.0" kept
  #              | string         # '"' escaped '"'
  #              | "[" [value *("," value)] "]"
  #              | "{" [pair *("," pair)] "}"
  #   pair      := string ":" value
  #
  # * Strings are double-quoted; only +"+, +\+, and control characters
  #   U+0000-U+001F are escaped (+\n+, +\r+, +\t+, +\b+, +\f+, else
  #   +�XXXX+).  All other characters are emitted as raw UTF-8.
  # * Mapping pairs are sorted by the UTF-8 bytes of the key.
  # * No whitespace appears anywhere inside the payload.
  #
  # Because the header embeds the format version, a digest computed under
  # YCANON/1 can never collide with a future revision.
  module Canonical
    VERSION = 1

    # Byte-format identifier embedded in the canonical output.
    FORMAT_HEADER = "YCANON/1\n"

    # Base class for all canonicalization failures.
    class Error < Psych::Exception; end
    # An alias (transitively) refers to one of its own ancestors.
    class CycleError < Error; end
    # An explicit or local tag outside the YAML 1.2 core schema.
    class UnsupportedTagError < Error; end
    # The same explicit key appears twice in one mapping.
    class DuplicateKeyError < Error; end
    # Two merge sources provide the same key.
    class MergeConflictError < Error; end
    # A mapping key does not resolve to a string.
    class KeyTypeError < Error; end
    # A float is infinite or NaN, or an input string is not valid UTF-8.
    class UnrepresentableValueError < Error; end
    # Structural problem: wrong document count, bad merge value, dangling
    # alias, malformed tagged scalar.
    class InvalidDocumentError < Error; end

    NULL_TAG  = "tag:yaml.org,2002:null"
    BOOL_TAG  = "tag:yaml.org,2002:bool"
    INT_TAG   = "tag:yaml.org,2002:int"
    FLOAT_TAG = "tag:yaml.org,2002:float"
    STR_TAG   = "tag:yaml.org,2002:str"
    SEQ_TAG   = "tag:yaml.org,2002:seq"
    MAP_TAG   = "tag:yaml.org,2002:map"
    MERGE_TAG = "tag:yaml.org,2002:merge"

    SCALAR_TAGS = [NULL_TAG, BOOL_TAG, INT_TAG, FLOAT_TAG, STR_TAG].freeze

    NULL_VALUE  = /\A(?:~|null|Null|NULL|)\z/
    TRUE_VALUE  = /\A(?:true|True|TRUE)\z/
    FALSE_VALUE = /\A(?:false|False|FALSE)\z/
    INT_DECIMAL = /\A[-+]?[0-9]+\z/
    INT_HEX     = /\A0x[0-9a-fA-F]+\z/
    INT_OCTAL   = /\A0o[0-7]+\z/
    FLOAT_VALUE = /\A[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\z/
    NON_FINITE  = /\A[-+]?\.(?:inf|Inf|INF|nan|NaN|NAN)\z/

    STRING_ESCAPES = {
      '"'  => '\\"',
      "\\" => "\\\\",
      "\n" => "\\n",
      "\r" => "\\r",
      "\t" => "\\t",
      "\b" => "\\b",
      "\f" => "\\f",
    }.freeze

    module_function

    # Returns the canonical byte string (Encoding::UTF_8) for +yaml+.
    def canonicalize(yaml, version: VERSION)
      unless version == 1
        raise ArgumentError, "unsupported canonicalization version: #{version.inspect}"
      end

      document = sole_document(yaml)
      value = document && document.root ? Walker.new.walk(document.root) : nil

      out = +FORMAT_HEADER.dup
      emit(value, out)
      out << "\n"
      out.force_encoding(Encoding::UTF_8)
    end

    # Returns the lowercase hex SHA-256 digest of the canonical bytes.
    def digest(yaml, version: VERSION)
      Digest::SHA256.hexdigest(canonicalize(yaml, version: version))
    end

    def sole_document(yaml) # :nodoc:
      stream = Psych.parse_stream(yaml)
      count = stream.children.size
      if count > 1
        raise InvalidDocumentError, "expected at most one YAML document, got #{count}"
      end
      stream.children.first # nil for an empty stream, canonicalizes to null
    end
    private_class_method :sole_document

    def emit(value, out) # :nodoc:
      case value
      when nil        then out << "null"
      when true       then out << "true"
      when false      then out << "false"
      when Integer    then out << value.to_s
      when Float      then out << value.to_s
      when String
        out << '"' << escape_string(value) << '"'
      when Array
        out << "["
        value.each_with_index do |element, index|
          out << "," if index > 0
          emit(element, out)
        end
        out << "]"
      when Hash
        out << "{"
        value.keys.sort.each_with_index do |key, index|
          out << "," if index > 0
          emit(key, out)
          out << ":"
          emit(value[key], out)
        end
        out << "}"
      end
    end
    private_class_method :emit

    def escape_string(string) # :nodoc:
      string.gsub(/["\\\x00-\x1f]/) do |char|
        STRING_ESCAPES.fetch(char) { format("\\u%04x", char.ord) }
      end
    end
    private_class_method :escape_string

    # Recursive resolver: walks the Psych AST, expands anchors/aliases and
    # merge keys, and produces plain Ruby values (nil, true, false, Integer,
    # Float, String, Array, Hash) for the canonical emitter.
    class Walker
      def initialize
        @anchors = {}
        @expanding = {}
      end

      def walk(node)
        register_anchor(node)

        case node
        when Psych::Nodes::Alias
          walk(resolve_alias(node))
        when Psych::Nodes::Scalar
          resolve_scalar(node)
        when Psych::Nodes::Sequence
          check_collection_tag(node, SEQ_TAG)
          within(node) { node.children.map { |child| walk(child) } }
        when Psych::Nodes::Mapping
          check_collection_tag(node, MAP_TAG)
          within(node) { walk_mapping(node) }
        else
          raise InvalidDocumentError, "unexpected node: #{node.class}"
        end
      end

      private

      def register_anchor(node)
        return if node.is_a?(Psych::Nodes::Alias)
        @anchors[node.anchor] = node if node.respond_to?(:anchor) && node.anchor
      end

      def within(node)
        @expanding[node.object_id] = true
        begin
          yield
        ensure
          @expanding.delete(node.object_id)
        end
      end

      def resolve_alias(node)
        target = @anchors[node.anchor]
        raise InvalidDocumentError, "unknown alias: #{node.anchor.inspect}" unless target
        if @expanding.key?(target.object_id)
          raise CycleError, "alias #{node.anchor.inspect} refers to its own ancestor"
        end
        target
      end

      def check_collection_tag(node, expected)
        tag = node.tag
        return if tag.nil? || tag == expected
        raise UnsupportedTagError, "unsupported tag on collection: #{tag}"
      end

      def resolve_scalar(node)
        tag = node.tag
        if tag
          unless SCALAR_TAGS.include?(tag)
            raise UnsupportedTagError, "unsupported scalar tag: #{tag}"
          end
          convert_tagged(tag, node.value)
        elsif node.plain
          resolve_plain(node.value)
        else
          check_string(node.value)
        end
      end

      def convert_tagged(tag, value)
        case tag
        when STR_TAG
          check_string(value)
        when NULL_TAG
          raise InvalidDocumentError, "invalid !!null: #{value.inspect}" unless value =~ NULL_VALUE
          nil
        when BOOL_TAG
          return true  if value =~ TRUE_VALUE
          return false if value =~ FALSE_VALUE
          raise InvalidDocumentError, "invalid !!bool: #{value.inspect}"
        when INT_TAG
          parse_integer(value) || raise(InvalidDocumentError, "invalid !!int: #{value.inspect}")
        when FLOAT_TAG
          parse_float(value) || raise(InvalidDocumentError, "invalid !!float: #{value.inspect}")
        end
      end

      def resolve_plain(value)
        case value
        when NULL_VALUE  then nil
        when TRUE_VALUE  then true
        when FALSE_VALUE then false
        when NON_FINITE
          raise UnrepresentableValueError, "non-finite floats cannot be signed: #{value.inspect}"
        when INT_DECIMAL then Integer(value, 10)
        when INT_HEX     then Integer(value[2..], 16)
        when INT_OCTAL   then Integer(value[2..], 8)
        when FLOAT_VALUE
          float = Float(value)
          unless float.finite?
            raise UnrepresentableValueError, "non-finite floats cannot be signed: #{value.inspect}"
          end
          float
        else
          check_string(value)
        end
      end

      def parse_integer(value)
        case value
        when INT_DECIMAL then Integer(value, 10)
        when INT_HEX     then Integer(value[2..], 16)
        when INT_OCTAL   then Integer(value[2..], 8)
        end
      end

      def parse_float(value)
        if value =~ NON_FINITE
          raise UnrepresentableValueError, "non-finite floats cannot be signed: #{value.inspect}"
        end
        Float(value) if value =~ FLOAT_VALUE
      end

      def check_string(value)
        unless value.encoding == Encoding::UTF_8 && value.valid_encoding?
          raise UnrepresentableValueError, "string is not valid UTF-8"
        end
        value
      end

      def merge_key?(key_node)
        return false unless key_node.is_a?(Psych::Nodes::Scalar)
        (key_node.tag.nil? && key_node.plain && key_node.value == "<<") ||
          key_node.tag == MERGE_TAG
      end

      def walk_mapping(node)
        explicit = {}
        merge_values = []

        node.children.each_slice(2) do |key_node, value_node|
          if merge_key?(key_node)
            merge_values << value_node
            next
          end
          key = walk_key(key_node)
          if explicit.key?(key)
            raise DuplicateKeyError, "duplicate mapping key: #{key.inspect}"
          end
          explicit[key] = walk(value_node)
        end

        merged = {}
        merge_values.each do |value_node|
          each_merge_source(value_node) do |source|
            source.each do |key, source_value|
              next if explicit.key?(key) # explicit keys always win
              if merged.key?(key)
                raise MergeConflictError, "conflicting merge sources for key: #{key.inspect}"
              end
              merged[key] = source_value
            end
          end
        end

        explicit.merge(merged)
      end

      def walk_key(key_node)
        key = walk(key_node)
        unless key.is_a?(String)
          raise KeyTypeError, "mapping keys must be strings, got #{key.inspect}"
        end
        key
      end

      def each_merge_source(value_node, &block)
        case value_node
        when Psych::Nodes::Alias
          each_merge_source(resolve_alias(value_node), &block)
        when Psych::Nodes::Mapping
          check_collection_tag(value_node, MAP_TAG)
          yield within(value_node) { walk_mapping(value_node) }
        when Psych::Nodes::Sequence
          check_collection_tag(value_node, SEQ_TAG)
          value_node.children.each { |child| each_merge_source(child, &block) }
        else
          raise InvalidDocumentError,
                "merge value must be a mapping or a sequence of mappings"
        end
      end
    end
  end
end

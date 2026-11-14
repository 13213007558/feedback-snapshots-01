# frozen_string_literal: true

module StreamDomConsistency
  FORMAT_VERSION = "stream-dom-consistency/v1"
  DEFAULT_SEED = 20261114

  # XML 1.0 Char production.  This is deliberately duplicated here rather
  # than derived from REXML::Text::VALID_CHAR: the oracle must not inherit
  # the assumption set of either implementation under test.
  module XMLChar
    RANGES = [
      0x0009..0x000A,
      0x000D..0x000D,
      0x0020..0xD7FF,
      0xE000..0xFFFD,
      0x10000..0x10FFFF,
    ].freeze

    module_function

    def valid?(codepoint)
      RANGES.any? { |range| range.cover?(codepoint) }
    end

    def labels
      RANGES.map do |range|
        if range.begin == range.end
          format("U+%04X", range.begin)
        else
          format("U+%04X..U+%04X", range.begin, range.end)
        end
      end
    end
  end

  # Transcoding used by the oracle.  Literal text is encoded with the bytes
  # the case actually stores and decoded with the charset the document says
  # it uses.  Character references bypass this: they denote Unicode code
  # points, not encoded bytes.
  module Transcoding
    module_function

    def decode(literal, case_encoding)
      source_bytes = literal.encode(case_encoding.actual)
      target = case_encoding.effective
      unless target
        raise ArgumentError, "no effective encoding"
      end
      # UTF-16 bytes are byte-order dependent; without a BOM the plan has
      # already been rejected, so only single/multibyte charsets remain here.
      bytes = source_bytes.dup.force_encoding(target)
      unless bytes.valid_encoding?
        raise ArgumentError, "invalid byte sequence for #{target}"
      end
      bytes.encode("UTF-8")
    rescue Encoding::UndefinedConversionError,
           Encoding::InvalidByteSequenceError,
           Encoding::ConverterNotFoundError => error
      raise ArgumentError, error.message
    end
  end

  # A snapshot of "which charset does this document mean?".
  EncodingPlan = Struct.new(:actual, :declared, :effective, :problem,
                            keyword_init: true) do
    def valid?
      @problem.nil?
    end
  end

  module Parts
    Text = Struct.new(:text, keyword_init: true)
    CharRef = Struct.new(:codepoint, :style, keyword_init: true)
    EntityRef = Struct.new(:name, keyword_init: true)
    CData = Struct.new(:text, keyword_init: true)
    Comment = Struct.new(:text, keyword_init: true)
    Instruction = Struct.new(:target, :data, keyword_init: true)
    # Deliberately invalid bytes, injected after encoding.  A case containing
    # this part must be rejected by a decoding reader.
    RawBytes = Struct.new(:bytes, :description, keyword_init: true) do
      def marker
        "\u0001SDCI_RAW_#{bytes.bytesize}_#{description.hash.abs}_7f3a\u0001"
      end
    end
  end

  AttributeSpec = Struct.new(:name, :parts, :quote, keyword_init: true)
  EntityDecl = Struct.new(:name, :parts, keyword_init: true)
  Policy = Struct.new(:channels, :banned, keyword_init: true)

  class Case
    BOM_CHARACTER = "﻿"

    attr_reader :id, :seed, :category, :body, :attributes, :entities,
                :policy, :business_channels, :actual_encoding, :decl_encoding,
                :bom, :source_form, :notes, :stored_bytes

    def initialize(id:, seed:, category:, body:, attributes: [], entities: [],
                   policy:, business_channels: [:combined],
                   actual_encoding: "UTF-8", decl_encoding: "UTF-8",
                   bom: nil, source_form: :string, notes: nil,
                   stored_bytes: nil)
      @id = id
      @seed = seed
      @category = category
      @body = body
      @attributes = attributes
      @entities = entities
      @policy = policy
      @business_channels = business_channels
      @actual_encoding = actual_encoding
      @decl_encoding = decl_encoding
      @bom = bom
      @source_form = source_form
      @notes = notes
      @stored_bytes = stored_bytes
    end

    # Derive a modified case.  Dropping stored_bytes is deliberate: a
    # reduction changes the token tree, so any cached replay bytes would no
    # longer describe it.  Re-rendering keeps the shrinker honest.
    def with(**changes)
      values = {
        id: @id, seed: @seed, category: @category, body: @body,
        attributes: @attributes, entities: @entities, policy: @policy,
        business_channels: @business_channels,
        actual_encoding: @actual_encoding,
        decl_encoding: @decl_encoding, bom: @bom,
        source_form: @source_form, notes: @notes, stored_bytes: nil,
      }.merge(changes)
      self.class.new(**values)
    end

    def raw_bytes?
      deep_parts.any? { |part| part.is_a?(Parts::RawBytes) }
    end

    def deep_parts
      parts = @body.dup
      @attributes.each { |attribute| parts.concat(attribute.parts) }
      @entities.each { |entity| parts.concat(entity.parts) }
      parts
    end

    def logical_xml
      declaration =
        if @decl_encoding
          %(<?xml version="1.0" encoding="#{@decl_encoding}"?>)
        else
          %(<?xml version="1.0"?>)
        end
      prefix = @bom ? BOM_CHARACTER : ""
      rendered_attributes = @attributes.map do |attribute|
        quote = attribute.quote || '"'
        %(#{attribute.name}=#{quote}#{render_parts(attribute.parts)}#{quote})
      end.join(" ")
      rendered_attributes = " #{rendered_attributes}" unless rendered_attributes.empty?
      doctype = render_doctype
      body = render_parts(@body)
      "#{prefix}#{declaration}#{doctype}<r#{rendered_attributes}>#{body}</r>"
    end

    def xml_bytes
      return @stored_bytes if @stored_bytes

      encoded = logical_xml.encode(@actual_encoding).b
      deep_parts.each do |part|
        next unless part.is_a?(Parts::RawBytes)

        marker = part.marker.b
        encoded_marker = marker.encode(@actual_encoding).b
        unless encoded.include?(encoded_marker)
          raise "internal marker #{marker.inspect} missing from encoded document"
        end
        encoded = encoded.sub(encoded_marker, part.bytes.b)
      end
      encoded
    end

    def encoding_plan
      return EncodingPlan.new(
        actual: @actual_encoding,
        declared: @decl_encoding,
        effective: nil,
        problem: :invalid_encoding,
      ) if raw_bytes?

      declared = @decl_encoding
      if declared && !known_encoding?(declared)
        return EncodingPlan.new(
          actual: @actual_encoding,
          declared: declared,
          effective: nil,
          problem: :invalid_encoding_declaration,
        )
      end

      if @bom && !bom_matches_declaration?(@bom, declared)
        return EncodingPlan.new(
          actual: @actual_encoding,
          declared: declared,
          effective: nil,
          problem: :invalid_encoding_declaration,
        )
      end

      effective = resolve_effective_encoding(declared)

      # A UTF-16 document has no reliable byte order without a BOM, and the
      # XML spec requires the BOM for UTF-16.  This applies whether the stored
      # bytes happen to be UTF-16 or something else: the decoder must reject.
      if effective.start_with?("UTF-16") && @bom.nil?
        return EncodingPlan.new(
          actual: @actual_encoding,
          declared: declared,
          effective: effective,
          problem: :invalid_encoding,
        )
      end

      if declared.nil? && @bom.nil? && !["UTF-8"].include?(@actual_encoding)
        return EncodingPlan.new(
          actual: @actual_encoding,
          declared: nil,
          effective: effective,
          problem: :invalid_encoding_declaration,
        )
      end

      EncodingPlan.new(
        actual: @actual_encoding,
        declared: declared,
        effective: effective,
        problem: nil,
      )
    end

    def to_h
      body = @body.map { |part| serialize_part(part) }
      attributes = @attributes.map do |attribute|
        {
          "name" => attribute.name,
          "quote" => attribute.quote,
          "parts" => attribute.parts.map { |part| serialize_part(part) },
        }
      end
      entities = @entities.map do |entity|
        { "name" => entity.name, "parts" => entity.parts.map { |part| serialize_part(part) } }
      end
      {
        "format" => FORMAT_VERSION,
        "id" => @id,
        "seed" => @seed,
        "category" => @category.to_s,
        "source_form" => @source_form.to_s,
        "actual_encoding" => @actual_encoding,
        "decl_encoding" => @decl_encoding,
        "bom" => @bom&.to_s,
        "business_channels" => @business_channels.map(&:to_s),
        "policy" => {
          "channels" => @policy.channels.map(&:to_s),
          "banned" => @policy.banned,
        },
        "body" => body,
        "attributes" => attributes,
        "entities" => entities,
        "notes" => @notes,
        "xml_base64" => Encoding64.encode64(xml_bytes),
      }
    end

    def self.from_h(hash)
      unless hash["format"] == FORMAT_VERSION
        raise ArgumentError, "unsupported replay format: #{hash["format"].inspect}"
      end

      policy_hash = hash.fetch("policy")
      new(
        id: hash.fetch("id"),
        seed: hash.fetch("seed"),
        category: hash.fetch("category").to_sym,
        body: hash.fetch("body").map { |part| deserialize_part(part) },
        attributes: hash.fetch("attributes", []).map do |attribute|
          AttributeSpec.new(
            name: attribute.fetch("name"),
            quote: attribute["quote"],
            parts: attribute.fetch("parts").map { |part| deserialize_part(part) },
          )
        end,
        entities: hash.fetch("entities", []).map do |entity|
          EntityDecl.new(
            name: entity.fetch("name"),
            parts: entity.fetch("parts").map { |part| deserialize_part(part) },
          )
        end,
        policy: Policy.new(
          channels: policy_hash.fetch("channels").map(&:to_sym),
          banned: policy_hash.fetch("banned"),
        ),
        business_channels: hash.fetch("business_channels", ["combined"]).map(&:to_sym),
        actual_encoding: hash.fetch("actual_encoding", "UTF-8"),
        decl_encoding: hash["decl_encoding"],
        bom: hash["bom"]&.to_sym,
        source_form: hash.fetch("source_form", "string").to_sym,
        notes: hash["notes"],
        stored_bytes: Encoding64.decode64(hash.fetch("xml_base64")),
      )
    end

    private

    def render_doctype
      return "" if @entities.empty?

      declarations = @entities.map do |entity|
        %(<!ENTITY #{entity.name} "#{render_parts(entity.parts)}">)
      end.join("")
      %(<!DOCTYPE r [#{declarations}]>)
    end

    def render_parts(parts)
      parts.map do |part|
        case part
        when Parts::Text then part.text
        when Parts::CharRef then render_char_ref(part)
        when Parts::EntityRef then "&#{part.name};"
        when Parts::CData then "<![CDATA[#{part.text}]]>"
        when Parts::Comment then "<!--#{part.text}-->"
        when Parts::Instruction then "<?#{part.target} #{part.data}?>"
        when Parts::RawBytes then part.marker
        else
          raise "unknown XML part: #{part.inspect}"
        end
      end.join
    end

    def render_char_ref(part)
      case part.style
      when :dec then "&##{part.codepoint};"
      when :dec_pad then format("&#%07d;", part.codepoint)
      when :hex then format("&#x%x;", part.codepoint)
      when :hex_pad then format("&#x%08x;", part.codepoint)
      when :hex_upper_x then format("&#X%X;", part.codepoint)
      else
        raise "unknown character reference style: #{part.style.inspect}"
      end
    end

    def serialize_part(part)
      case part
      when Parts::Text
        { "type" => "text", "text" => part.text }
      when Parts::CharRef
        { "type" => "char_ref", "codepoint" => part.codepoint, "style" => part.style.to_s }
      when Parts::EntityRef
        { "type" => "entity_ref", "name" => part.name }
      when Parts::CData
        { "type" => "cdata", "text" => part.text }
      when Parts::Comment
        { "type" => "comment", "text" => part.text }
      when Parts::Instruction
        { "type" => "instruction", "target" => part.target, "data" => part.data }
      when Parts::RawBytes
        {
          "type" => "raw_bytes",
          "bytes_base64" => Encoding64.encode64(part.bytes),
          "description" => part.description,
        }
      else
        raise "unknown part: #{part.inspect}"
      end
    end

    def self.deserialize_part(hash)
      case hash.fetch("type")
      when "text" then Parts::Text.new(text: hash.fetch("text"))
      when "char_ref"
        Parts::CharRef.new(codepoint: hash.fetch("codepoint"), style: hash.fetch("style").to_sym)
      when "entity_ref" then Parts::EntityRef.new(name: hash.fetch("name"))
      when "cdata" then Parts::CData.new(text: hash.fetch("text"))
      when "comment" then Parts::Comment.new(text: hash.fetch("text"))
      when "instruction"
        Parts::Instruction.new(target: hash.fetch("target"), data: hash.fetch("data"))
      when "raw_bytes"
        Parts::RawBytes.new(
          bytes: Encoding64.decode64(hash.fetch("bytes_base64")),
          description: hash["description"],
        )
      else
        raise "unknown serialized part: #{hash.inspect}"
      end
    end

    # The charset the decoder must use.  A declaration of plain "UTF-16" is
    # resolved by the BOM; UTF-16 without a BOM is already rejected before
    # this runs.
    def resolve_effective_encoding(declared)
      if declared
        case declared.upcase
        when "UTF-16"
          case @bom
          when :utf16le then "UTF-16LE"
          when :utf16be then "UTF-16BE"
          else "UTF-16LE"
          end
        else
          declared
        end
      elsif @bom == :utf16le
        "UTF-16LE"
      elsif @bom == :utf16be
        "UTF-16BE"
      else
        "UTF-8"
      end
    end

    def known_encoding?(name)
      begin
        Encoding.find(name)
        true
      rescue ArgumentError
        false
      end
    end

    def bom_matches_declaration?(bom, declaration)
      return true if declaration.nil?

      normalized = declaration.upcase
      case bom
      when :utf8 then normalized == "UTF-8"
      when :utf16le then ["UTF-16", "UTF-16LE"].include?(normalized)
      when :utf16be then ["UTF-16", "UTF-16BE"].include?(normalized)
      else true
      end
    end
  end

  class SymbolTable
    def initialize(entities)
      @entities = entities.each_with_object({}) { |entity, table| table[entity.name] = entity }
    end

    def entity(name)
      @entities[name]
    end

    def predefined_value(name)
      {
        "amp" => "&", "lt" => "<", "gt" => ">", "quot" => '"', "apos" => "'",
      }[name]
    end
  end

  # Specification-derived expectation.  Never produced by running REXML.
  #
  # Nodes are modelled the way XML defines them, not the way REXML happens to
  # emit events:
  #
  #   * adjacent character data collapses into one Text node;
  #   * a CDATA section is its own node and does not merge with neighbours;
  #   * comments and processing instructions break text runs;
  #   * character data is compared after line-end normalization.
  #
  # Both adapters are normalised into this node model before comparison, so
  # arbitrary event/chunk splitting cannot make a correct implementation fail.
  class Expected
    Node = Struct.new(:kind, :text, keyword_init: true)

    attr_reader :status, :reason, :nodes, :attributes, :policy_decision

    def initialize(status:, reason: nil, nodes: [], attributes: {},
                   policy_decision: nil)
      @status = status
      @reason = reason
      @nodes = nodes
      @attributes = attributes
      # Invalid input must never be treated as "allowed": the oracle's
      # decision is what a policy engine *should* reach, and a document a
      # conforming parser rejects cannot be authorized.  This also makes the
      # consent rule meaningful for malformed input.
      @policy_decision = policy_decision || (status == :valid ? :allow : :reject)
    end

    def valid?
      @status == :valid
    end

    def invalid?
      !valid?
    end

    def channel(name)
      case name
      when :text
        @nodes.select { |node| node.kind == :text }.map(&:text).join
      when :cdata
        @nodes.select { |node| node.kind == :cdata }.map(&:text).join
      when :combined
        @nodes.map(&:text).join
      when :first_node
        @nodes.first&.text
      when :element_text
        @nodes.first&.text
      when :attributes
        @attributes
      else
        raise "unknown channel: #{name.inspect}"
      end
    end

    def policy_projection(channels)
      Array(channels).flat_map do |channel|
        case channel
        when :text then [channel(:text)]
        when :cdata then [channel(:cdata)]
        when :combined then [channel(:combined)]
        when :first_text, :first_node then [channel(:first_node).to_s]
        when :attributes then @attributes.values
        else
          raise "unknown policy channel: #{channel.inspect}"
        end
      end
    end

    class << self
      def compute(kase)
        plan = kase.encoding_plan
        return new(status: plan.problem, reason: encoding_reason(plan)) if plan.problem

        entities = SymbolTable.new(kase.entities)
        nodes = []
        status = :valid
        reason = nil

        kase.body.each do |part|
          case part
          when Parts::Comment, Parts::Instruction
            # Breaks a text run but contributes no character data.
            nodes << Node.new(kind: :break, text: "")
          when Parts::CData
            literal, error = decode_literal(part.text, plan)
            if error
              status = error
              reason = "CDATA is not valid in #{plan.effective}"
              break
            end
            if literal.include?("]]>")
              status = :malformed_cdata
              reason = "]]> inside one CDATA section"
              break
            end
            nodes << Node.new(kind: :cdata, text: normalize_newlines(literal))
          when Parts::RawBytes
            status = :invalid_encoding
            reason = "invalid byte sequence in document body"
            break
          else
            expanded, error = expand_parts([part], entities, [], plan)
            if error
              status = error
              reason = "content expansion failed: #{error}"
              break
            end
            append_text(nodes, expanded)
          end
        end
        nodes.reject! { |node| node.kind == :break }

        attributes = {}
        if status == :valid
          kase.attributes.each do |attribute|
            value, error = expand_attribute_parts(attribute.parts, entities, [], plan)
            if error
              status = error
              reason = "attribute #{attribute.name.inspect} expansion failed: #{error}"
              break
            end
            attributes[attribute.name] = value
          end
        end

        policy_decision = :reject
        if status == :valid
          strings = policy_strings(kase.policy.channels, nodes, attributes)
          allowed = strings.none? do |string|
            kase.policy.banned.any? { |pattern| string.include?(pattern) }
          end
          policy_decision = allowed ? :allow : :reject
        end

        new(
          status: status,
          reason: reason,
          nodes: nodes,
          attributes: attributes,
          policy_decision: policy_decision,
        )
      end

      def append_text(nodes, text)
        return if text.empty?

        if nodes.last && nodes.last.kind == :text
          nodes.last.text << text
        else
          nodes << Node.new(kind: :text, text: +text)
        end
      end

      def policy_strings(channels, nodes, attributes)
        joined = lambda do |kind|
          nodes.select { |node| node.kind == kind }.map(&:text).join
        end
        Array(channels).flat_map do |channel|
          case channel
          when :text then [joined.call(:text)]
          when :cdata then [joined.call(:cdata)]
          when :combined then [nodes.map(&:text).join]
          when :first_text, :first_node then [nodes.first&.text.to_s]
          when :attributes then attributes.values
          else
            raise "unknown policy channel: #{channel.inspect}"
          end
        end
      end

      def expand_attribute_parts(parts, entities, stack, plan, declaration_value: false)
        result = +""
        parts.each do |part|
          case part
          when Parts::Text
            literal, error = decode_literal(part.text, plan)
            return [nil, error] if error
            unless declaration_value
              return [nil, :literal_markup] if literal.include?("<")
              return [nil, :literal_ampersand] if literal.include?("&")
            end
            if declaration_value
              literal, error = expand_declaration_references(literal)
              return [nil, error] if error
            end

            # XML 1.0 attribute-value normalization: literal tab/newline/CR
            # become a space after line-end normalization.  Character
            # references are exempt and are handled below.
            result << normalize_newlines(literal).tr("\t\n\r", "   ")
          when Parts::CharRef
            expanded, error = expand_char_ref(part)
            return [nil, error] if error

            result << expanded
          when Parts::EntityRef
            expanded, error = expand_entity(part.name, entities, stack, :attribute)
            return [nil, error] if error

            result << expanded
          when Parts::CData, Parts::Comment, Parts::Instruction
            return [nil, :malformed_attribute]
          else
            return [nil, :malformed_attribute]
          end
        end
        [result, nil]
      end

      def expand_parts(parts, entities, stack, plan, declaration_value: false)
        result = +""
        parts.each do |part|
          case part
          when Parts::Text
            literal, error = decode_literal(part.text, plan)
            return [nil, error] if error
            unless declaration_value
              # Outside an entity value, literal markup and a bare ampersand
              # are not character data: they are malformed XML.
              return [nil, :literal_markup] if literal.include?("<")
              return [nil, :literal_ampersand] if literal.include?("&")
            end
            # XML 1.0: line ends are normalized before references expand, so
            # "&#13;" survives as CR while a literal CR becomes LF.
            literal = normalize_newlines(literal)
            if declaration_value
              literal, error = expand_declaration_references(literal)
              return [nil, error] if error
            end

            result << literal
          when Parts::CharRef
            expanded, error = expand_char_ref(part)
            return [nil, error] if error

            result << expanded
          when Parts::EntityRef
            expanded, error = expand_entity(part.name, entities, stack, :text)
            return [nil, error] if error

            result << expanded
          else
            return [nil, :malformed_content]
          end
        end
        [result, nil]
      end

      def expand_entity(name, entities, stack, context)
        predefined = entities.predefined_value(name)
        return [predefined, nil] if predefined
        return [nil, :entity_loop] if stack.include?(name)

        entity = entities.entity(name)
        # Contract note, not a claim of XML conformance: REXML keeps
        # undeclared general entity references literal.
        return ["&#{name};", nil] if entity.nil?

        # An entity's replacement text was parsed when the declaration was
        # read.  Character references in it are already expanded to their
        # characters; further general-entity references expand recursively.
        plan = EncodingPlan.new(
          actual: "UTF-8", declared: "UTF-8", effective: "UTF-8", problem: nil,
        )
        if context == :attribute
          expand_attribute_parts(entity.parts, entities, stack + [name], plan,
                                 declaration_value: true)
        else
          expand_parts(entity.parts, entities, stack + [name], plan,
                       declaration_value: true)
        end
      end

      # Expand character references that were written inside an entity value.
      # In XML, "&#13;" in a declaration is a carriage return, while a
      # literal CR is normalized to LF when the declaration is read.
      def expand_declaration_references(text)
        text.gsub(/&#(x?)([0-9a-fA-F]+);/) do |reference|
          digits = Regexp.last_match(2)
          codepoint = Regexp.last_match(1).empty? ? Integer(digits, 10) : Integer(digits, 16)
          return [nil, :invalid_character] unless XMLChar.valid?(codepoint)

          [codepoint].pack("U")
        end
      end

      def expand_char_ref(part)
        # XML only spells hexadecimal references with a lower-case x.
        # XML spells hexadecimal references with a lower-case x.  A capital X
        # is a bare ampersand and therefore malformed.
        return [nil, :malformed_reference] if part.style == :hex_upper_x
        return [nil, :invalid_character] unless XMLChar.valid?(part.codepoint)

        [[part.codepoint].pack("U"), nil]
      end

      def decode_literal(literal, plan)
        [Transcoding.decode(literal, plan), nil]
      rescue ArgumentError
        [nil, :invalid_encoding]
      end

      def normalize_newlines(string)
        string.gsub(/\r\n?/, "\n")
      end

      def encoding_reason(plan)
        case plan.problem
        when :invalid_encoding_declaration
          "encoding #{plan.declared.inspect} is unusable or contradicts the bytes"
        when :invalid_encoding
          "byte stream is not valid #{plan.actual}"
        else
          plan.problem.to_s
        end
      end
    end
  end

  module Encoding64
    module_function

    def encode64(string)
      [string.b].pack("m0")
    end

    def decode64(string)
      string.unpack1("m0").b
    end
  end
end

# frozen_string_literal: true

require_relative "model"

module StreamDomConsistency
  # Seeded case generator.  Every choice comes from an explicit Random, so a
  # (seed, iteration) pair reproduces identical bytes.  Cases are built from
  # small independent parts so the shrinker has a simple search space.
  #
  # Categories are split in two:
  #
  #   * :well_formed -- must parse; the only acceptable result is that the
  #     filter and the business DOM read the same character sequence.
  #   * :malformed -- must be rejected by any conforming reader.  These are
  #     used to prove the oracle does not simply bless whatever REXML does.
  class Generator
    POLICIES = {
      "script" => ["<script", "</script", "javascript:"],
      "shell" => [";rm -rf", "$(", "`id`"],
      "auth" => ["BEGIN PRIVATE KEY", "BEGIN CERTIFICATE"],
    }.freeze

    OFFENSIVE_SEQUENCES = [
      "<script>",
      "</script>",
      "javascript:",
      "BEGIN PRIVATE KEY",
    ].freeze

    HARMLESS_SEQUENCES = ["hello", "ok", "safe", "text", "αβγ"].freeze

    WELL_FORMED = %i[
      char_ref
      newline
      cdata_boundary
      encoding_decl
      attribute
      entity
      event_boundary
      unicode
    ].freeze

    MALFORMED = %i[malformed].freeze

    def initialize(seed: DEFAULT_SEED)
      @seed = seed
      @random = Random.new(seed)
      @counter = 0
    end

    attr_reader :seed

    def next_case(category: nil, well_formed_only: false)
      category ||= pick_categories(well_formed_only)
      @counter += 1
      send("build_#{category}", format("%s-%05d", category, @counter))
    end

    def well_formed_categories
      WELL_FORMED
    end

    def malformed_categories
      MALFORMED
    end

    private

    def pick_categories(well_formed_only)
      pool = well_formed_only ? WELL_FORMED : WELL_FORMED + MALFORMED
      pool.sample(random: @random)
    end

    def policy_for(channels: [:combined], banned: nil)
      name = POLICIES.keys.sample(random: @random)
      Policy.new(channels: channels, banned: banned || POLICIES.fetch(name))
    end

    def offensive_sequence
      OFFENSIVE_SEQUENCES.sample(random: @random)
    end

    def harmless_sequence
      HARMLESS_SEQUENCES.sample(random: @random)
    end

    def build_char_ref(id)
      token = offensive_sequence
      style = %i[dec hex hex_pad dec_pad].sample(random: @random)
      parts = token.codepoints.map do |codepoint|
        Parts::CharRef.new(codepoint: codepoint, style: style)
      end
      Case.new(
        id: id,
        seed: @seed,
        category: :char_ref,
        body: parts,
        policy: policy_for,
        business_channels: [:combined],
        notes: "every character of the marker as a character reference",
      )
    end

    def build_newline(id)
      variants = [
        [Parts::Text.new(text: "a\r\n"), Parts::Text.new(text: "b\rc")],
        [Parts::CharRef.new(codepoint: 13, style: :dec),
         Parts::Text.new(text: "b\r\nc")],
        [Parts::CData.new(text: "x\r\ny\rz")],
        [Parts::Text.new(text: "pre\r\n"),
         Parts::CData.new(text: "mid\rtail")],
        [Parts::Text.new(text: "literal\r\n"),
         Parts::CharRef.new(codepoint: 13, style: :hex),
         Parts::Text.new(text: "after\n")],
      ]
      Case.new(
        id: id,
        seed: @seed,
        category: :newline,
        body: variants.sample(random: @random),
        policy: Policy.new(
          channels: [:combined],
          banned: POLICIES.fetch("script"),
        ),
        business_channels: [:combined],
        notes: "line-end normalization across text, references and CDATA",
      )
    end

    def build_cdata_boundary(id)
      token = offensive_sequence
      variant = %i[plain split_inside text_then_cdata cdata_then_text split_cdata].sample(random: @random)
      parts =
        case variant
        when :plain
          [Parts::CData.new(text: token)]
        when :split_inside
          index = @random.rand(1...token.length)
          [
            Parts::CData.new(text: token[0...index]),
            Parts::Text.new(text: ""),
            Parts::CData.new(text: token[index..]),
          ]
        when :text_then_cdata
          [
            Parts::Text.new(text: token[0...2]),
            Parts::CData.new(text: token[2..]),
          ]
        when :cdata_then_text
          [
            Parts::CData.new(text: token[0...-2]),
            Parts::Text.new(text: token[-2..]),
          ]
        when :split_cdata
          [
            Parts::CData.new(text: token[0...2]),
            Parts::CData.new(text: token[2..]),
          ]
        end
      Case.new(
        id: id,
        seed: @seed,
        category: :cdata_boundary,
        body: parts,
        policy: policy_for,
        business_channels: [:combined],
      )
    end

    def build_encoding_decl(id)
      # Only combinations that describe real bytes: the declared charset must
      # match the stored bytes, optionally with a BOM.  Mismatched declarations
      # are covered by :malformed_declaration rather than silently producing
      # mojibake that both readers agree on.
      actual = %w[UTF-8 ISO-8859-1 Shift_JIS UTF-16LE UTF-16BE].sample(random: @random)
      declared =
        case actual
        when "UTF-16LE", "UTF-16BE"
          ["UTF-16", actual].sample(random: @random)
        when "UTF-8"
          ["UTF-8", nil].sample(random: @random)
        else
          # A non-UTF-8 byte stream without a declaration is not UTF-8 and
          # must be rejected, so declare it: this category tests decoding,
          # not missing declarations.
          actual
        end
      bom =
        if actual == "UTF-16LE" then :utf16le
        elsif actual == "UTF-16BE" then :utf16be
        elsif @random.rand < 0.2 then :utf8
        end
      token = [offensive_sequence, harmless_sequence].sample(random: @random)
      Case.new(
        id: id,
        seed: @seed,
        category: :encoding_decl,
        body: [Parts::Text.new(text: token)],
        policy: policy_for,
        actual_encoding: actual,
        decl_encoding: declared,
        bom: bom,
        business_channels: [:combined],
        notes: "declared #{declared.inspect}, bytes #{actual}, BOM #{bom.inspect}",
      )
    end

    def build_attribute(id)
      token = [offensive_sequence, harmless_sequence].sample(random: @random)
      variants = [
        [Parts::Text.new(text: "x\ty")],
        [Parts::Text.new(text: "x\r\ny")],
        [Parts::CharRef.new(codepoint: 13, style: :dec)],
        [Parts::EntityRef.new(name: "payload")],
        [Parts::Text.new(text: "pre"), Parts::EntityRef.new(name: "payload")],
        [Parts::Text.new(text: "pre"), Parts::CharRef.new(codepoint: 13, style: :hex)],
      ]
      entities = []
      if @random.rand < 0.6
        entities << EntityDecl.new(
          name: "payload",
          parts: [Parts::Text.new(text: token)],
        )
      end
      Case.new(
        id: id,
        seed: @seed,
        category: :attribute,
        body: [Parts::Text.new(text: "body")],
        attributes: [
          AttributeSpec.new(
            name: "p",
            parts: variants.sample(random: @random),
            quote: ['"', "'"].sample(random: @random),
          ),
        ],
        entities: entities,
        policy: Policy.new(
          channels: %i[attributes combined],
          banned: POLICIES.fetch("script"),
        ),
        business_channels: %i[attributes combined],
      )
    end

    def build_entity(id)
      token = [offensive_sequence, harmless_sequence].sample(random: @random)
      variants = [
        [Parts::Text.new(text: token)],
        [Parts::CharRef.new(codepoint: 13, style: :dec)],
        [Parts::CharRef.new(codepoint: 10, style: :dec)],
        [Parts::EntityRef.new(name: "inner")],
      ]
      entities = [
        EntityDecl.new(name: "outer", parts: variants.sample(random: @random)),
      ]
      if @random.rand < 0.4
        entities << EntityDecl.new(
          name: "inner",
          parts: [Parts::Text.new(text: token)],
        )
      end
      body = [
        Parts::Text.new(text: "start"),
        Parts::EntityRef.new(name: "outer"),
        Parts::Text.new(text: "end"),
      ]
      Case.new(
        id: id,
        seed: @seed,
        category: :entity,
        body: body,
        entities: entities,
        policy: policy_for,
        business_channels: [:combined],
      )
    end

    def build_event_boundary(id)
      token = offensive_sequence
      variants = [
        [Parts::Text.new(text: token)],
        [Parts::Text.new(text: token[0..2]), Parts::Text.new(text: token[3..])],
        [Parts::Text.new(text: token[0..1]), Parts::CData.new(text: ""), Parts::Text.new(text: token[2..])],
        [Parts::CData.new(text: token[0..1]), Parts::CData.new(text: token[2..])],
        [Parts::Text.new(text: ""), Parts::Text.new(text: token), Parts::Text.new(text: "")],
      ]
      Case.new(
        id: id,
        seed: @seed,
        category: :event_boundary,
        body: variants.sample(random: @random),
        policy: policy_for,
        business_channels: [:combined],
        notes: "event and node counts are intentionally unstable",
      )
    end

    def build_unicode(id)
      codepoint = [0x00E9, 0x03B1, 0x4E00, 0x1F600, 0x10FFFF, 0xFFFD, 0xD7FF, 0xE000].sample(random: @random)
      style = %i[dec hex].sample(random: @random)
      variant = %i[literal ref cdata mixed].sample(random: @random)
      parts =
        case variant
        when :literal
          [Parts::Text.new(text: "pre#{codepoint.chr(Encoding::UTF_8)}post")]
        when :ref
          [Parts::Text.new(text: "pre"),
           Parts::CharRef.new(codepoint: codepoint, style: style),
           Parts::Text.new(text: "post")]
        when :cdata
          [Parts::CData.new(text: "pre#{codepoint.chr(Encoding::UTF_8)}post")]
        when :mixed
          [Parts::Text.new(text: "pre"),
           Parts::CData.new(text: codepoint.chr(Encoding::UTF_8)),
           Parts::Text.new(text: "post")]
        end
      Case.new(
        id: id,
        seed: @seed,
        category: :unicode,
        body: parts,
        policy: policy_for,
        business_channels: [:combined],
        notes: format("code point U+%04X represented as %s", codepoint, variant),
      )
    end

    # Malformed inputs.  These are expected to be rejected by both readers;
    # accepting one is a finding regardless of the other reader.
    def build_malformed(id)
      variant = %i[
        uppercase_x
        bare_amp
        invalid_ref
        dec_control
        cdata_close
        invalid_utf8
        invalid_bom_declaration
        utf16_no_bom
      ].sample(random: @random)
      case variant
      when :uppercase_x
        malformed_case(id, "uppercase X reference",
                       [Parts::Text.new(text: "a"),
                        Parts::CharRef.new(codepoint: 0x3C, style: :hex_upper_x),
                        Parts::Text.new(text: "b")])
      when :bare_amp
        malformed_case(id, "bare ampersand",
                       [Parts::Text.new(text: "a & b")])
      when :invalid_ref
        malformed_case(id, "NUL character reference",
                       [Parts::Text.new(text: "a "),
                        Parts::CharRef.new(codepoint: 0x0, style: :dec),
                        Parts::Text.new(text: " b")])
      when :dec_control
        malformed_case(id, "control character reference",
                       [Parts::Text.new(text: "a "),
                        Parts::CharRef.new(codepoint: 0x01, style: :hex),
                        Parts::Text.new(text: " b")])
      when :cdata_close
        malformed_case(id, "]]> inside CDATA",
                       [Parts::CData.new(text: "a]]>b")])
      when :invalid_utf8
        bytes = invalid_utf8_bytes
        malformed_case(id, "invalid UTF-8 byte sequence",
                       [Parts::Text.new(text: "text"),
                        Parts::RawBytes.new(bytes: bytes, description: bytes.inspect)],
                       actual_encoding: "UTF-8", decl_encoding: "UTF-8")
      when :invalid_bom_declaration
        malformed_case(id, "BOM contradicts declaration",
                       [Parts::Text.new(text: "ab")],
                       actual_encoding: "UTF-16LE", decl_encoding: "UTF-8",
                       bom: :utf16le)
      when :utf16_no_bom
        malformed_case(id, "UTF-16 without BOM",
                       [Parts::Text.new(text: "ab")],
                       actual_encoding: "UTF-16LE", decl_encoding: "UTF-16")
      end
    end

    def malformed_case(id, note, body, **options)
      Case.new(
        id: id,
        seed: @seed,
        category: :malformed,
        body: body,
        policy: policy_for,
        business_channels: [:combined],
        notes: note,
        **options,
      )
    end

    def invalid_utf8_bytes
      [
        "\xFF".b,
        "\xC3".b,
        "\xC0\xAF".b,
        "\xED\xA0\x80".b,
        "\x80".b,
        "\xFE\xFF".b,
      ].sample(random: @random)
    end
  end
end

# frozen_string_literal: true

require "json"
require "tempfile"

require "rexml/document"

require_relative "stream_dom_consistency/model"
require_relative "stream_dom_consistency/generator"
require_relative "stream_dom_consistency/oracle"
require_relative "stream_dom_consistency/shrinker"
require_relative "stream_dom_consistency/runner"
require_relative "stream_dom_consistency/adapters"

module REXMLTests
  # Differential tests between REXML's streaming character-data callbacks and
  # the character values its DOM exposes to business code.
  #
  # The oracle never runs either parser: it computes the XML 1.0 character
  # sequence from the token tree.  Each implementation is compared with that
  # oracle, and then with the other implementation.  Aggregated characters are
  # compared, never event counts or node splits.
  class StreamDomConsistencyTester < Test::Unit::TestCase
    include StreamDomConsistency

    # Large enough to exercise the rarer malformed/attribute combinations
    # while staying fast (the whole sweep runs in well under a second).
    SWEEP_ITERATIONS = 1_000

    # Known, currently reproduced defects.  Each entry documents a real
    # divergence this suite exists to detect.  Fingerprints are
    # "finding-kind|category|channel" (see Oracle#fingerprint), so the same
    # defect stays covered across seeds and shrunk inputs while a new class of
    # divergence -- including a new channel in an already-known category --
    # fails the suite.
    #
    # Current defects:
    #
    # * StreamParser emits CDATA verbatim.  BaseParser returns the raw
    #   `read_until("]]>")` slice for :cdata without applying the XML 1.0
    #   line-end conversion that Text/CData in the DOM applies.  Any CDATA
    #   containing CR therefore diverges between the two readers.
    #     reader_divergence|newline|cdata
    #     reader_divergence|newline|combined
    #     reader_divergence|newline|first_node
    #
    # * StreamParser does not expand entity references in attribute values.
    #   BaseParser#parse_attributes stores the literal value and
    #   StreamParser#unnormalize is only applied to text events, while
    #   Attribute#value expands through the DOM's doctype.  A filter that
    #   inspects attributes sees `&payload;` while business code sees the
    #   payload.
    #     reader_divergence|attribute|attribute
    #
    # * A bare "&" in element text is accepted by StreamParser (it only
    #   expands the references it recognises).  A conforming parser rejects
    #   it; the DOM catches some cases via Text.check but not all positions.
    #     stream_accepted_invalid_input|malformed
    #
    # * "]]>" inside a CDATA literal is accepted by both: BaseParser splits
    #   at the first ]]>, turning the remainder into ordinary text.  A
    #   conforming reader rejects the section.
    #     dom_accepted_invalid_input|malformed
    #
    # These are recorded as known *errors* rather than warnings on purpose:
    # they are exactly the filter/business disagreements the harness is meant
    # to find.  They are pinned, not suppressed: if a fix lands, the entry
    # becomes unused and should be deleted along with the corresponding case.
    KNOWN_ERROR_FINGERPRINTS = [
      "reader_divergence|newline|cdata",
      "reader_divergence|newline|combined",
      "reader_divergence|newline|first_node",
      "reader_divergence|attribute|attribute",
      # Consequence of the same attribute-entity defect: the filter and the
      # business reader reach different policy decisions for that attribute.
      "policy_divergence|attribute",
      "stream_accepted_invalid_input|malformed",
      "dom_accepted_invalid_input|malformed",
    ].freeze

    def setup
      @runner = Runner.new(seed: DEFAULT_SEED)
    end

    # --- determinism -----------------------------------------------------

    def test_generator_is_reproducible_for_a_seed
      first = Generator.new(seed: 20261114)
      second = Generator.new(seed: 20261114)
      first_bytes = Array.new(40) { first.next_case.xml_bytes }
      second_bytes = Array.new(40) { second.next_case.xml_bytes }
      assert_equal(first_bytes, second_bytes)
    end

    def test_different_seeds_generate_different_sequences
      a = Array.new(20) { Generator.new(seed: 1).next_case }
      b = Array.new(20) { Generator.new(seed: 2).next_case }
      assert_not_equal(a.map(&:xml_bytes), b.map(&:xml_bytes))
    end

    def test_seeded_suite_is_identical_across_runs
      first = @runner.run_suite(iterations: 60).map { |failure| failure.case.xml_bytes }
      second = @runner.run_suite(iterations: 60).map { |failure| failure.case.xml_bytes }
      assert_equal(first, second)
    end

    # --- oracle independence --------------------------------------------

    def test_oracle_rejects_invalid_xml_without_running_rexml
      cases = [
        Case.new(id: "nul-ref", seed: 1, category: :malformed,
                 body: [Parts::CharRef.new(codepoint: 0, style: :dec)],
                 policy: Policy.new(channels: [:combined], banned: [])),
        Case.new(id: "uppercase-x", seed: 1, category: :malformed,
                 body: [Parts::CharRef.new(codepoint: 0x41, style: :hex_upper_x)],
                 policy: Policy.new(channels: [:combined], banned: [])),
        Case.new(id: "bare-amp", seed: 1, category: :malformed,
                 body: [Parts::Text.new(text: "a & b")],
                 policy: Policy.new(channels: [:combined], banned: [])),
        Case.new(id: "cdata-close", seed: 1, category: :malformed,
                 body: [Parts::CData.new(text: "a]]>b")],
                 policy: Policy.new(channels: [:combined], banned: [])),
      ]
      cases.each do |kase|
        expected = Expected.compute(kase)
        assert_true(expected.invalid?, "#{kase.id} should be invalid")
        assert_equal(:reject, expected.policy_decision)
      end
    end

    def test_oracle_accepts_legal_unicode
      codepoints = [0x09, 0x0A, 0x0D, 0x20, 0x7F, 0xD7FF, 0xE000, 0xFFFD,
                    0x10000, 0x1F600, 0x10FFFF]
      codepoints.each do |codepoint|
        kase = Case.new(
          id: format("u-%X", codepoint), seed: 1, category: :unicode,
          body: [Parts::CharRef.new(codepoint: codepoint, style: :hex)],
          policy: Policy.new(channels: [:combined], banned: []),
        )
        expected = Expected.compute(kase)
        assert_true(expected.valid?, format("U+%04X must be accepted", codepoint))
        assert_equal([codepoint].pack("U"), expected.channel(:combined))
      end
    end

    def test_oracle_rejects_non_characters_and_out_of_range
      [0x0, 0x1, 0xB, 0xD800, 0xDFFF, 0xFFFE, 0xFFFF, 0x110000].each do |codepoint|
        kase = Case.new(
          id: format("bad-%X", codepoint), seed: 1, category: :malformed,
          body: [Parts::CharRef.new(codepoint: codepoint, style: :hex)],
          policy: Policy.new(channels: [:combined], banned: []),
        )
        assert_true(Expected.compute(kase).invalid?,
                    format("U+%04X must be rejected", codepoint))
      end
    end

    # --- the central invariant ------------------------------------------

    def test_event_chunking_is_never_treated_as_an_error
      # Same logical text, deliberately split into a different number of
      # events/nodes.  If chunking were compared, these would diverge.
      base = Case.new(
        id: "one-event", seed: 1, category: :event_boundary,
        body: [Parts::Text.new(text: "abcdef")],
        policy: Policy.new(channels: [:combined], banned: ["zzz"]),
      )
      split = Case.new(
        id: "three-events", seed: 1, category: :event_boundary,
        body: [
          Parts::Text.new(text: "ab"),
          Parts::Text.new(text: "cd"),
          Parts::Text.new(text: "ef"),
        ],
        policy: Policy.new(channels: [:combined], banned: ["zzz"]),
      )
      assert_equal([], @runner.evaluate(base).select { |f| f.severity == :error })
      assert_equal([], @runner.evaluate(split).select { |f| f.severity == :error })
      stream_base = Adapters::StreamAdapter.run(base)
      stream_split = Adapters::StreamAdapter.run(split)
      assert_equal(stream_base.channel(:combined), stream_split.channel(:combined))
    end

    def test_char_refs_and_literal_text_yield_the_same_characters
      literal = Case.new(
        id: "literal", seed: 1, category: :char_ref,
        body: [Parts::Text.new(text: "safe")],
        policy: Policy.new(channels: [:combined], banned: ["<script"]),
      )
      referenced = Case.new(
        id: "referenced", seed: 1, category: :char_ref,
        body: "safe".codepoints.map do |codepoint|
          Parts::CharRef.new(codepoint: codepoint, style: :dec)
        end,
        policy: Policy.new(channels: [:combined], banned: ["<script"]),
      )
      stream_literal = Adapters::StreamAdapter.run(literal)
      stream_referenced = Adapters::StreamAdapter.run(referenced)
      assert_equal(stream_literal.channel(:combined),
                   stream_referenced.channel(:combined))
    end

    def test_legal_unicode_passes_through_both_readers
      text = "café αβγ 😀"
      kase = Case.new(
        id: "unicode", seed: 1, category: :unicode,
        body: [Parts::Text.new(text: text)],
        policy: Policy.new(channels: [:combined], banned: ["<script"]),
      )
      stream = Adapters::StreamAdapter.run(kase)
      dom = Adapters::DomAdapter.run(kase)
      assert_true(stream.ok)
      assert_true(dom.ok)
      assert_equal(text, stream.channel(:combined))
      assert_equal(text, dom.channel(:combined))
    end

    # --- encoding behaviour ---------------------------------------------

    def test_invalid_bytes_are_rejected_not_replaced
      %W[\xFF \xC3 \xC0\xAF \xED\xA0\x80 \x80].each_with_index do |bytes, index|
        kase = Case.new(
          id: "invalid-#{index}", seed: 1, category: :malformed,
          body: [Parts::Text.new(text: "prefix"),
                 Parts::RawBytes.new(bytes: bytes.b, description: bytes.inspect)],
          policy: Policy.new(channels: [:combined], banned: []),
        )
        expected = Expected.compute(kase)
        assert_equal(:invalid_encoding, expected.status)
        assert_equal(:reject, expected.policy_decision)

        stream = Adapters::StreamAdapter.run(kase)
        dom = Adapters::DomAdapter.run(kase)
        # Neither reader may silently turn invalid bytes into U+FFFD.
        [stream, dom].each do |result|
          next unless result.ok

          assert_false(result.channel(:combined).include?("�"),
                       "invalid bytes must not become a replacement character")
        end
      end
    end

    def test_declared_encoding_controls_decoding
      latin_bytes = "caf\xE9".b
      kase = Case.new(
        id: "latin", seed: 1, category: :encoding_decl,
        body: [Parts::Text.new(text: latin_bytes.force_encoding("ISO-8859-1").encode("UTF-8"))],
        policy: Policy.new(channels: [:combined], banned: []),
        actual_encoding: "ISO-8859-1",
        decl_encoding: "ISO-8859-1",
      )
      expected = Expected.compute(kase)
      assert_equal("café", expected.channel(:combined))
      assert_equal("café", Adapters::DomAdapter.run(kase).channel(:combined))
    end

    def test_bom_and_declaration_must_agree
      kase = Case.new(
        id: "bom-conflict", seed: 1, category: :malformed,
        body: [Parts::Text.new(text: "ab")],
        policy: Policy.new(channels: [:combined], banned: []),
        actual_encoding: "UTF-16LE", decl_encoding: "UTF-8", bom: :utf16le,
      )
      assert_equal(:invalid_encoding_declaration, Expected.compute(kase).status)
    end

    # --- policy consent --------------------------------------------------

    def test_char_ref_cannot_smuggle_a_banned_sequence_past_the_filter
      banned = ["<script"]
      kase = Case.new(
        id: "smuggle", seed: 1, category: :char_ref,
        body: "<script>".codepoints.map do |codepoint|
          Parts::CharRef.new(codepoint: codepoint, style: :dec)
        end,
        policy: Policy.new(channels: [:combined, :attributes], banned: banned),
      )
      expected = Expected.compute(kase)
      assert_equal(:reject, expected.policy_decision)

      findings = @runner.evaluate(kase)
      assert_equal([], findings.select { |finding| finding.severity == :error })
    end

    def test_shared_allow_on_invalid_input_is_a_finding
      # Both REXML paths accept this.  The oracle rejects it.  Agreement must
      # not be reported as a pass.
      kase = Case.new(
        id: "shared-wrong", seed: 1, category: :malformed,
        body: [Parts::Text.new(text: "a & b")],
        policy: Policy.new(channels: [:combined], banned: []),
      )
      findings = @runner.evaluate(kase)
      assert_true(
        findings.any? { |finding| finding.kind == :stream_accepted_invalid_input },
        "accepting a bare ampersand must be reported",
      )
    end

    def test_two_wrong_readings_cannot_certify_each_other
      # XML 1.0 attribute-value normalization turns the literal CR/LF into a
      # space, so the spec-correct value is "x y" and contains the banned
      # pattern.  Both REXML paths instead read "x\ny" and therefore both
      # allow it.  Their agreement must not count as a pass.
      kase = Case.new(
        id: "mutual-consent", seed: 1, category: :attribute,
        body: [Parts::Text.new(text: "body")],
        attributes: [
          AttributeSpec.new(
            name: "p",
            parts: [Parts::Text.new(text: "x\r\ny")],
          ),
        ],
        policy: Policy.new(channels: %i[attributes combined], banned: ["x y"]),
      )
      expected = Expected.compute(kase)
      assert_equal(:reject, expected.policy_decision)
      assert_equal("x y", expected.attributes.fetch("p"))

      findings = @runner.evaluate(kase)
      assert_true(findings.any? { |f| f.kind == :policy_shared_bypass },
                  "joint allow on a spec-distorted reading must be reported")
    end

    # --- shrinking and replay -------------------------------------------

    def test_shrinker_preserves_the_failure_class
      kase = Case.new(
        id: "shrink-source", seed: 1, category: :newline,
        body: [
          Parts::Text.new(text: "aaaaaaaa\r\n"),
          Parts::CData.new(text: "bbbb\rcccc"),
        ],
        policy: Policy.new(channels: [:combined], banned: []),
      )
      oracle = @runner.oracle_for(kase)
      original = oracle.evaluate(kase).select { |f| f.severity == :error }
      assert_false(original.empty?)

      shrunk = Shrinker.new(oracle: oracle).shrink(kase)
      shrunk_findings = oracle.evaluate(shrunk).select { |f| f.severity == :error }
      assert_false(shrunk_findings.empty?, "shrunk case must still fail")

      original_kinds = original.map(&:kind).sort
      shrunk_kinds = shrunk_findings.map(&:kind).sort
      assert_equal(original_kinds, shrunk_kinds)
      assert_true(shrunk.xml_bytes.bytesize <= kase.xml_bytes.bytesize)
    end

    def test_shrunk_failure_replays_from_stored_bytes_offline
      kase = Case.new(
        id: "replay-source", seed: 1, category: :newline,
        body: [Parts::CData.new(text: "x\r\ny")],
        policy: Policy.new(channels: [:combined], banned: []),
      )
      shrunk = Shrinker.new(oracle: @runner.oracle_for(kase)).shrink(kase)

      Tempfile.create(["case", ".json"]) do |file|
        Runner.dump_replay(shrunk, file.path)
        loaded = Runner.load_replay(file.path)
        # Bytes are preserved exactly, including any invalid sequences.
        assert_equal(shrunk.xml_bytes, loaded.xml_bytes)
        assert_equal(shrunk.body.map(&:class), loaded.body.map(&:class))

        original = @runner.evaluate(shrunk).map(&:kind).sort
        replayed = @runner.evaluate(loaded).map(&:kind).sort
        assert_equal(original, replayed)
      end
    end

    # --- generated regression sweep -------------------------------------

    def test_generated_suite_reports_no_new_error_classes
      failures = @runner.run_suite(iterations: SWEEP_ITERATIONS)
      unexpected = []
      failures.each do |failure|
        failure.findings.each do |finding|
          next unless finding.severity == :error
          next if known_error?(finding)

          unexpected << finding
        end
      end

      messages = unexpected.map do |finding|
        "#{finding.kind} (#{finding.case.category}): #{finding.message}\n" \
          "  xml: #{finding.case.xml_bytes.inspect}"
      end
      assert_equal([], unexpected, messages.join("\n\n"))
    end

    # An allowlist entry that no longer describes a real failure is stale:
    # it hides a fixed bug and could mask a new one with the same shape.
    def test_every_allowlisted_fingerprint_is_still_reproduced
      failures = @runner.run_suite(iterations: SWEEP_ITERATIONS)
      produced = failures.flat_map do |failure|
        failure.findings.select { |finding| finding.severity == :error }
      end.map { |finding| @runner.oracle_for(finding.case).fingerprint(finding) }

      stale = KNOWN_ERROR_FINGERPRINTS - produced
      assert_equal([], stale, "stale allowlist entries: #{stale.inspect}")
    end

    private

    def known_error?(finding)
      fingerprint = @runner.oracle_for(finding.case).fingerprint(finding)
      KNOWN_ERROR_FINGERPRINTS.any? do |known|
        fingerprint.start_with?(known) || known.start_with?(fingerprint)
      end
    end
  end
end

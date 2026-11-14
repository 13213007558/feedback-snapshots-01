# frozen_string_literal: true

require_relative 'helper'

module Psych
  # Structural injection tests for the YAML output chain.
  #
  # User controlled strings must never change the *structure* of the
  # emitted document: no extra documents, no aliases, and no object tags
  # may appear when the output is parsed again.  The expected node
  # structure is generated independently of the produced YAML and the
  # re-parsed tree is compared against it node by node.
  #
  # The same payloads are replayed through all three output paths:
  #
  # 1. Psych.dump (Visitors::YAMLTree)
  # 2. AST output (Psych::Nodes tree + Node#to_yaml)
  # 3. the event emitter (Psych::Emitter)
  #
  # Invalid explicit tag/anchor parameters must surface as errors; any
  # prefix already written to the IO must not be reported as a
  # successfully emitted configuration.  Failing inputs are kept in
  # FAILURE_CASES so they can be replayed against every output path.
  class TestOutputInjection < TestCase
    # Payloads exercising document separators, directives, tag syntax,
    # anchor/alias names, newlines and colons.  Every entry is a plain
    # Ruby String and must round-trip as exactly one plain scalar.
    INJECTION_STRINGS = [
      "---",                          # document start marker
      "...",                          # document end marker
      "---\ninjected: document",      # separator + newline
      "...\n---\nsecond: document",   # end marker followed by new doc
      "%YAML 1.1\n---\nfoo",          # directive lookalike
      "%TAG ! tag:example.com,2026:\n---\nfoo",
      "!ruby/object:Injected",        # object tag lookalike
      "!!str value",                  # shorthand tag lookalike
      "!<tag:example.com,2026:x> y",  # verbatim tag lookalike
      "&anchor",                      # anchor lookalike
      "*alias",                       # alias lookalike
      "&anchor *alias",               # anchor + alias pair
      "key: value",                   # colon + space
      "key:value",                    # colon without space
      "a: b\n---\nc: d",              # mapping plus separator
      "- one\n- two",                 # sequence lookalike
      "? explicit\n: key",            # explicit key lookalike
      "# comment",                    # comment lookalike
      "line one\nline two",           # legal multi-line text
      "multi\nline\n---\ntext",       # multi-line with separator
      "blank\n\nlines\n",             # blank lines + trailing newline
    ].freeze

    # Inputs with invalid explicit tag/anchor parameters.  Each case is
    # replayed against both the event emitter and the AST output path
    # and must raise the recorded error.
    FAILURE_CASES = [
      { name: "anchor with spaces",     anchor: "bad anchor",  tag: nil,   error: RuntimeError },
      { name: "anchor with newline",    anchor: "bad\nanchor", tag: nil,   error: RuntimeError },
      { name: "anchor with colon",      anchor: "bad:anchor",  tag: nil,   error: RuntimeError },
      { name: "anchor with asterisk",   anchor: "*bad",        tag: nil,   error: RuntimeError },
      { name: "anchor with ampersand",  anchor: "&bad",        tag: nil,   error: RuntimeError },
      { name: "anchor with brackets",   anchor: "bad[0]",      tag: nil,   error: RuntimeError },
      { name: "non-string anchor",      anchor: :bad,          tag: nil,   error: TypeError },
      { name: "non-string tag",         anchor: nil,           tag: :bad,  error: TypeError },
      { name: "alias with spaces",      anchor: "bad alias",   tag: nil,   error: RuntimeError, alias: true },
      { name: "alias with newline",     anchor: "bad\nalias",  tag: nil,   error: RuntimeError, alias: true },
    ].freeze

    ###
    # Structure normalizer / expected tree generator
    ###

    # Reduces a parsed node tree to plain arrays so it can be compared
    # against the independently generated expectation.  Aliases and
    # explicit tags/anchors show up here, so any structural injection
    # makes the comparison fail.
    #
    # The non-specific tag "!" (emitted by libyaml to force quoting of
    # plain scalars such as "---") resolves to a plain scalar per the
    # YAML spec and is normalized to nil; any *specific* tag (object
    # tags, shorthand tags) is kept and fails the comparison.
    def normalize(node)
      normalize_tag = ->(tag) { tag == "!" ? nil : tag }
      case node
      when Psych::Nodes::Stream
        [:stream, *node.children.map { |child| normalize(child) }]
      when Psych::Nodes::Document
        [:document, *node.children.map { |child| normalize(child) }]
      when Psych::Nodes::Scalar
        [:scalar, node.value, normalize_tag.(node.tag), node.anchor]
      when Psych::Nodes::Sequence
        [:sequence, normalize_tag.(node.tag), node.anchor, *node.children.map { |child| normalize(child) }]
      when Psych::Nodes::Mapping
        [:mapping, normalize_tag.(node.tag), node.anchor, *node.children.map { |child| normalize(child) }]
      when Psych::Nodes::Alias
        [:alias, node.anchor]
      else
        raise "unexpected node: #{node.inspect}"
      end
    end

    def expected_scalar(value)
      [:scalar, value, nil, nil]
    end

    def expected_document(root)
      [:stream, [:document, root]]
    end

    def assert_structure(expected, yaml, message)
      assert_equal expected, normalize(Psych.parse_stream(yaml)), message
    end

    ###
    # Output path 1: Psych.dump
    ###

    def test_dump_round_trip_preserves_structure
      INJECTION_STRINGS.each do |payload|
        yaml = Psych.dump(payload)

        assert_structure expected_document(expected_scalar(payload)), yaml,
          "dump changed the structure for #{payload.inspect}"
        assert_equal payload, Psych.load(yaml),
          "dump changed the content for #{payload.inspect}"
      end
    end

    def test_dump_in_mapping_and_sequence_positions
      INJECTION_STRINGS.each do |payload|
        as_value = Psych.dump({ "k" => payload })
        assert_structure expected_document(
          [:mapping, nil, nil, expected_scalar("k"), expected_scalar(payload)]
        ), as_value, "mapping value injection for #{payload.inspect}"

        as_key = Psych.dump({ payload => "v" })
        assert_structure expected_document(
          [:mapping, nil, nil, expected_scalar(payload), expected_scalar("v")]
        ), as_key, "mapping key injection for #{payload.inspect}"

        as_element = Psych.dump([payload])
        assert_structure expected_document(
          [:sequence, nil, nil, expected_scalar(payload)]
        ), as_element, "sequence element injection for #{payload.inspect}"
      end
    end

    ###
    # Output path 2: AST output
    ###

    def build_ast(value)
      document = Psych::Nodes::Document.new
      document.children << Psych::Nodes::Scalar.new(value)
      stream = Psych::Nodes::Stream.new
      stream.children << document
      stream
    end

    def test_ast_output_round_trip_preserves_structure
      INJECTION_STRINGS.each do |payload|
        yaml = build_ast(payload).to_yaml

        assert_structure expected_document(expected_scalar(payload)), yaml,
          "AST output changed the structure for #{payload.inspect}"
        assert_equal payload, Psych.load(yaml),
          "AST output changed the content for #{payload.inspect}"
      end
    end

    ###
    # Output path 3: event emitter
    ###

    def emit_scalar(value)
      io = StringIO.new
      emitter = Psych::Emitter.new(io)
      emitter.start_stream(Psych::Nodes::Stream::UTF8)
      emitter.start_document([], [], false)
      emitter.scalar(value, nil, nil, true, false, Psych::Nodes::Scalar::ANY)
      emitter.end_document(true)
      emitter.end_stream
      io.string
    end

    def test_emitter_round_trip_preserves_structure
      INJECTION_STRINGS.each do |payload|
        yaml = emit_scalar(payload)

        assert_structure expected_document(expected_scalar(payload)), yaml,
          "emitter changed the structure for #{payload.inspect}"
        assert_equal payload, Psych.load(yaml),
          "emitter changed the content for #{payload.inspect}"
      end
    end

    ###
    # Legal multi-line text keeps its content
    ###

    def test_legal_multiline_text_is_preserved
      multiline = INJECTION_STRINGS.select { |payload| payload.include?("\n") }
      assert_operator multiline.length, :>=, 3, "expected multi-line payloads"

      multiline.each do |payload|
        assert_equal payload, Psych.load(Psych.dump(payload)),
          "dump rejected or altered legal multi-line text #{payload.inspect}"
        assert_equal payload, Psych.load(build_ast(payload).to_yaml),
          "AST output rejected or altered legal multi-line text #{payload.inspect}"
        assert_equal payload, Psych.load(emit_scalar(payload)),
          "emitter rejected or altered legal multi-line text #{payload.inspect}"
      end
    end

    ###
    # Invalid explicit tag/anchor parameters
    ###

    def emit_with(anchor:, tag:, use_alias: false)
      io = StringIO.new
      emitter = Psych::Emitter.new(io)
      emitter.start_stream(Psych::Nodes::Stream::UTF8)
      emitter.start_document([], [], false)
      if use_alias
        emitter.alias(anchor)
      else
        emitter.scalar("v", anchor, tag, true, false, Psych::Nodes::Scalar::ANY)
      end
      emitter.end_document(true)
      emitter.end_stream
      io.string
    end

    def ast_with(anchor:, tag:, use_alias: false)
      node = if use_alias
        Psych::Nodes::Alias.new(anchor)
      else
        Psych::Nodes::Scalar.new("v", anchor, tag)
      end
      document = Psych::Nodes::Document.new
      document.children << node
      stream = Psych::Nodes::Stream.new
      stream.children << document
      stream
    end

    def test_invalid_tag_and_anchor_parameters_raise
      FAILURE_CASES.each do |failure|
        use_alias = !!failure[:alias]

        emitter_error = assert_raise(failure[:error], failure[:name]) do
          emit_with(anchor: failure[:anchor], tag: failure[:tag], use_alias: use_alias)
        end
        assert_match(/anchor|alias|type/i, emitter_error.message, failure[:name])

        ast_error = assert_raise(failure[:error], failure[:name]) do
          ast_with(anchor: failure[:anchor], tag: failure[:tag], use_alias: use_alias).to_yaml
        end
        assert_match(/anchor|alias|type/i, ast_error.message, failure[:name])
      end
    end

    # When emission fails partway through, bytes may already sit in the
    # IO.  That prefix must not be mistaken for a successfully emitted
    # configuration: the error must propagate and the prefix must not
    # parse back to the intended structure.
    def test_partial_prefix_is_not_marked_successful
      FAILURE_CASES.each do |failure|
        next if failure[:alias] # aliases cannot open a document

        io = StringIO.new
        emitter = Psych::Emitter.new(io)
        emitter.start_stream(Psych::Nodes::Stream::UTF8)
        emitter.start_document([], [], false)
        emitter.scalar("ok", nil, nil, true, false, Psych::Nodes::Scalar::ANY)
        emitter.end_document(true)

        emitter.start_document([], [], false)
        assert_raise(failure[:error], failure[:name]) do
          emitter.scalar("v", failure[:anchor], failure[:tag], true, false,
            Psych::Nodes::Scalar::ANY)
        end

        prefix = io.string
        intended = [:stream,
          [:document, [:scalar, "ok", nil, nil]],
          [:document, [:scalar, "v", nil, nil]]]

        if prefix.empty?
          assert_equal "", prefix, failure[:name]
        else
          # The prefix is at most the first document; it must never
          # equal the complete two-document configuration.
          refute_equal intended, normalize(Psych.parse_stream(prefix)), failure[:name]
        end
      end
    end
  end
end

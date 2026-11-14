# frozen_string_literal: false

require "rexml/document"
require "rexml/validation/relaxng"
require "set"

module REXMLTests
  # Generative checks for REXML::Validation::RelaxNG.
  #
  # The expected language is computed here, from the RelaxNG constructs only:
  # group, choice, interleave, optional, zeroOrMore, oneOrMore and local ref.
  # The validator is never asked what it expects.  Grammars are bounded by a
  # maximum input length so their language can be enumerated exactly.
  class RNGGenerativeValidation < Test::Unit::TestCase
    include REXML

    MAX_LANGUAGE_SIZE = 4096
    MAX_REPORTED_FAILURES = 20
    ALIEN = "Z"

    module Patterns
      module_function

      def element(name)
        [ :element, name ]
      end

      def group(left, right)
        [ :group, left, right ]
      end

      def choice(left, right)
        [ :choice, left, right ]
      end

      def interleave(left, right)
        [ :interleave, left, right ]
      end

      def optional(child)
        [ :optional, child ]
      end

      def zero_or_more(child)
        [ :zero_or_more, child ]
      end

      def one_or_more(child)
        [ :one_or_more, child ]
      end

      def ref(name)
        [ :ref, name ]
      end

    end

    include Patterns
    extend Patterns

    # Exact, test-side evaluator for the bounded language of a pattern.
    # L(group) = concatenation, L(choice) = union, L(interleave) = all merges,
    # L(optional) = epsilon plus L(child), L(zeroOrMore) = bounded closure,
    # L(oneOrMore) = bounded non-empty closure, L(ref) = L(define).
    class BoundedLanguage
      def initialize(defines, limit)
        @defines = defines
        @limit = limit
      end

      def language(pattern)
        language_with_depth(pattern, @limit + 1)
      end

      private

      def language_with_depth(pattern, depth)
        if depth < 0
          return []
        end
        result =
          case pattern[0]
          when :empty
            [ [] ]
          when :element
            [ [ pattern[1] ] ]
          when :group
            concatenate(language_with_depth(pattern[1], depth),
                        language_with_depth(pattern[2], depth))
          when :choice
            (language_with_depth(pattern[1], depth) +
             language_with_depth(pattern[2], depth)).uniq
          when :interleave
            interleave(language_with_depth(pattern[1], depth),
                       language_with_depth(pattern[2], depth))
          when :optional
            ([ [] ] + language_with_depth(pattern[1], depth)).uniq
          when :zero_or_more
            closure(language_with_depth(pattern[1], depth), false)
          when :one_or_more
            closure(language_with_depth(pattern[1], depth), true)
          when :ref
            name = pattern[1]
            language_with_depth(@defines.fetch(name), depth - 1)
          else
            raise "unknown pattern: #{pattern.inspect}"
          end
        if result.size > MAX_LANGUAGE_SIZE
          raise "language too large (#{result.size} > #{MAX_LANGUAGE_SIZE})"
        end
        result
      end

      def concatenate(left, right)
        result = []
        left.each do |prefix|
          right.each do |suffix|
            candidate = prefix + suffix
            result << candidate if candidate.size <= @limit
          end
        end
        result.uniq
      end

      def interleave(left, right)
        result = []
        left.each do |one|
          right.each do |other|
            each_merging(one, other, [], result)
          end
        end
        result.uniq
      end

      def each_merging(left, right, prefix, result)
        if left.empty?
          result << prefix + right
        elsif right.empty?
          result << prefix + left
        else
          each_merging(left[1..-1], right, prefix + left[0, 1], result)
          each_merging(left, right[1..-1], prefix + right[0, 1], result)
        end
      end

      def closure(pieces, at_least_once)
        results = at_least_once ? [] : [ [] ]
        seen = Set.new(results)
        frontier = [ [] ]
        loop do
          next_frontier = []
          frontier.each do |base|
            pieces.each do |piece|
              candidate = base + piece
              next if candidate.size > @limit
              next if seen.include?(candidate)
              seen << candidate
              next_frontier << candidate
            end
          end
          break if next_frontier.empty?
          results.concat(next_frontier)
          frontier = next_frontier
        end
        results.sort_by { |sequence| [ sequence.size, sequence ] }
      end
    end

    Grammar = Struct.new(:name, :pattern, :defines, :limit)

    def self.grammar(name, pattern, defines = {}, limit = 4)
      Grammar.new(name, pattern, defines, limit)
    end

    def self.grammars
      @grammars ||= [
        grammar("group(B,C)",
                group(element("B"), element("C"))),
        grammar("choice(B,C)",
                choice(element("B"), element("C"))),
        grammar("interleave(B,C)",
                interleave(element("B"), element("C"))),
        grammar("interleave(group(B,C),D)",
                interleave(group(element("B"), element("C")), element("D"))),
        grammar("interleave(oneOrMore(B),C)",
                interleave(one_or_more(element("B")), element("C"))),
        grammar("interleave(zeroOrMore(B),C)",
                interleave(zero_or_more(element("B")), element("C"))),
        grammar("interleave(optional(B),optional(C))",
                interleave(optional(element("B")), optional(element("C")))),
        grammar("choice(group(B,C),group(B,D))",
                choice(group(element("B"), element("C")),
                       group(element("B"), element("D")))),
        grammar("group(choice(B,C),choice(D,E))",
                group(choice(element("B"), element("C")),
                      choice(element("D"), element("E")))),
        grammar("group(zeroOrMore(B),oneOrMore(C))",
                group(zero_or_more(element("B")), one_or_more(element("C")))),
        grammar("zeroOrMore(group(B,C))",
                zero_or_more(group(element("B"), element("C")))),
        grammar("oneOrMore(group(B,C))",
                one_or_more(group(element("B"), element("C")))),
        grammar("optional(group(B,C))",
                optional(group(element("B"), element("C")))),
        grammar("group(optional(B),C)",
                group(optional(element("B")), element("C"))),
        grammar("ref(group(B,C))",
                ref("R1"),
                { "R1" => group(element("B"), element("C")) }),
        grammar("group(ref(R1),D)",
                group(ref("R1"), element("D")),
                { "R1" => group(element("B"), element("C")) }),
        grammar("group(ref(R1),ref(R1))",
                group(ref("R1"), ref("R1")),
                { "R1" => one_or_more(element("C")) }),
        grammar("interleave(ref(R1),ref(R2))",
                interleave(ref("R1"), ref("R2")),
                { "R1" => element("B"), "R2" => element("C") }),
        grammar("group(ref(R1),ref(R2))",
                group(ref("R1"), ref("R2")),
                { "R1" => group(element("B"), element("C")),
                  "R2" => interleave(element("D"), element("E")) },
                3),
        grammar("choice(ref(R1),ref(R2))",
                choice(ref("R1"), ref("R2")),
                { "R1" => group(element("B"), element("C")),
                  "R2" => group(element("B"), element("D")) }),
        grammar("recursive ref",
                ref("N"),
                { "N" => group(element("C"), optional(ref("N"))) },
                3),
      ]
    end

    def setup
      @failures = []
      @checked = 0
      @accepted = 0
      @rejected = 0
    end

    def teardown
      unless @failures.empty?
        report = @failures.first(MAX_REPORTED_FAILURES).join("\n")
        if @failures.size > MAX_REPORTED_FAILURES
          report += "\n... #{@failures.size - MAX_REPORTED_FAILURES} " \
                    "more failure(s)"
        end
        flunk("\n#{report}")
      end
      return if @checked.zero?
      assert_true(@accepted > 0, "the suite must exercise accepted documents")
      assert_true(@rejected > 0, "the suite must exercise rejected documents")
      # Keep the per-run coverage numbers useful when reading CI output.
      assert_operator(@checked, :>=, @accepted + @rejected)
    end

    def test_oracle_is_correct_and_independent
      cases = [
        [ "group(B,C)",
          group(element("B"), element("C")),
          [ [ "B", "C" ] ] ],
        [ "choice(B,C)",
          choice(element("B"), element("C")),
          [ [ "B" ], [ "C" ] ] ],
        [ "interleave(B,C)",
          interleave(element("B"), element("C")),
          [ [ "B", "C" ], [ "C", "B" ] ] ],
        [ "optional(B)",
          optional(element("B")),
          [ [], [ "B" ] ] ],
        [ "zeroOrMore(B)",
          zero_or_more(element("B")),
          [ [], [ "B" ], [ "B", "B" ], [ "B", "B", "B" ] ] ],
        [ "oneOrMore(B)",
          one_or_more(element("B")),
          [ [ "B" ], [ "B", "B" ], [ "B", "B", "B" ] ] ],
        [ "group(zeroOrMore(B),oneOrMore(C))",
          group(zero_or_more(element("B")), one_or_more(element("C"))),
          [ [ "C" ], [ "B", "C" ], [ "C", "C" ], [ "B", "B", "C" ],
            [ "B", "C", "C" ], [ "C", "C", "C" ] ] ],
        [ "interleave(group(B,C),D)",
          interleave(group(element("B"), element("C")), element("D")),
          [ [ "B", "C", "D" ], [ "B", "D", "C" ], [ "D", "B", "C" ] ] ],
        [ "choice(group(B,C),group(B,D))",
          choice(group(element("B"), element("C")),
                 group(element("B"), element("D"))),
          [ [ "B", "C" ], [ "B", "D" ] ] ],
        [ "ref(group(B,C))",
          ref("R1"),
          [ [ "B", "C" ] ] ],
      ]
      cases.each do |name, pattern, expected|
        defines = { "R1" => group(element("B"), element("C")) }
        actual = BoundedLanguage.new(defines, 3).language(pattern)
        assert_equal(expected.sort, actual.sort,
                     "oracle mismatch for #{name}: expected #{expected.inspect}, " \
                     "got #{actual.inspect}")
      end
    end

    def test_bounded_language_equivalence
      self.class.grammars.each do |grammar|
        validator = REXML::Validation::RelaxNG.new(schema_xml(grammar))
        oracle = oracle_for(grammar)
        alphabet = alphabet_for(grammar)
        all_sequences(alphabet, grammar.limit).each do |sequence|
          expected = oracle.include?(sequence) ? :accept : :reject
          observe(grammar, validator, sequence, expected, :enumerated)
        end
      end
    end

    def test_constructed_counterexamples
      self.class.grammars.each do |grammar|
        validator = REXML::Validation::RelaxNG.new(schema_xml(grammar))
        oracle = oracle_for(grammar)
        alphabet = alphabet_for(grammar)
        kind = grammar_has_interleave?(grammar.pattern, grammar.defines) ?
                 :legal_interleave : :enumerated
        oracle.each do |sequence|
          observe(grammar, validator, sequence, :accept, kind)
        end
        counterexamples(oracle, alphabet, grammar.limit).each do |sequence, label|
          next if oracle.include?(sequence)
          observe(grammar, validator, sequence, :reject, label)
        end
      end
    end

    # Negative control: proves the enumeration would notice a validator that
    # accepts everything.  Nothing in the production code is involved.
    def test_oracle_detects_a_skipped_constraint
      grammar = self.class.grammar("interleave(group(B,C),D)",
                                   interleave(group(element("B"), element("C")),
                                              element("D")))
      oracle = oracle_for(grammar)
      alphabet = alphabet_for(grammar)
      outside = all_sequences(alphabet + [ ALIEN ], grammar.limit).reject do |sequence|
        oracle.include?(sequence)
      end
      assert_false(outside.empty?,
                   "the oracle must reject inputs outside the bounded language")
      assert_true(oracle.include?([ "B", "D", "C" ]),
                  "the oracle must keep every legal interleaving")
      assert_false(oracle.include?([ "B", "D" ]),
                   "the oracle must not include an input with a missing branch")
      assert_false(oracle.include?([ "D", "B" ]),
                   "the oracle must not include an input with a missing branch")
      assert_false(oracle.include?([ "B", "C", "D", "D" ]),
                   "the oracle must not include an input with an extra node")
    end

    def test_reuse_after_rejection
      self.class.grammars.each do |grammar|
        validator = REXML::Validation::RelaxNG.new(schema_xml(grammar))
        oracle = oracle_for(grammar)
        accepted = oracle.sort_by { |sequence| [ sequence.size, sequence ] }
        next if accepted.empty?
        rejected = rejected_sequences(grammar, oracle)
        next if rejected.empty?

        sequence = []
        accepted.each_with_index do |good, index|
          bad = rejected[index % rejected.size]
          sequence << [ good, :accept ]
          sequence << [ bad, :reject ]
          sequence << [ good, :accept ]
        end
        sequence.each do |input, expected|
          observe(grammar, validator, input, expected, :after_rejection)
        end
      end
    end

    def test_document_boundaries
      schema = %Q{<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">} +
               %Q{<element name="B"/></element>}
      validator = REXML::Validation::RelaxNG.new(schema)
      cases = [
        [ "<A><B/></A>", :accept ],
        [ "<C><B/></C>", :reject ],
        [ "<A><B>text</B></A>", :reject ],
        [ "<A><B/><B/></A>", :reject ],
      ]
      cases.each do |xml, expected|
        record_observation(expected)
        actual, message = run_document_xml(validator, xml)
        next if actual == expected
        @failures << <<~REPORT.chomp
          [#{actual == :accept ? "skipped_constraint" : "unexpected_exception"}] document boundary
            schema:   #{schema}
            input:    #{xml}
            expected: #{expected}
            observed: #{actual}#{message ? " (#{message})" : ""}
            note:     the root and its direct content are constraints too; a
                      mismatch must be rejected, not admitted or raised
        REPORT
      end
    end

    # A rejection can also abort in the middle of a document (for example when
    # a streaming caller stops at the first error).  The next document must
    # still start from a clean state; leftover interleave progress must not
    # make the next valid document fail.
    def test_reuse_after_abandoned_document
      schema = %Q{<element name="A" xmlns="http://relaxng.org/ns/structure/1.0">} +
               %Q{<interleave><group><element name="B"/><element name="C"/></group>} +
               %Q{<element name="D"/></interleave></element>}
      validator = REXML::Validation::RelaxNG.new(schema)
      [
        [ "<A><B/><C/><D/></A>", :accept ],
        [ "<A><B/></A>", :reject ],
        [ "<A><B/><D/><C/></A>", :accept ],
        [ "<A><D/><B/><C/></A>", :accept ],
        [ "<A><B/><C/></A>", :reject ],
        [ "<A><B/><C/><D/></A>", :accept ],
      ].each do |xml, expected|
        record_observation(expected)
        actual, message = run_document_xml(validator, xml)
        next if actual == expected
        @failures << <<~REPORT.chomp
          [#{actual == :accept ? "skipped_constraint" : "unexpected_exception"}] abandoned document
            schema:   #{schema}
            input:    #{xml}
            expected: #{expected}
            observed: #{actual}#{message ? " (#{message})" : ""}
            note:     a rejection must not leave partial interleave state behind
        REPORT
      end
    end

    def test_minimal_reproductions
      minimal_reproduction_cases.each do |entry|
        validator = REXML::Validation::RelaxNG.new(entry[:schema])
        oracle = oracle_for(entry[:grammar])
        entry[:accept].each do |sequence|
          assert_true(oracle.include?(sequence),
                      "#{entry[:name]}: oracle disagrees with listed accept " \
                      "#{sequence.inspect}")
          observe_schema(entry, validator, sequence, :accept, :minimal_reproduction)
        end
        entry[:reject].each do |sequence|
          assert_false(oracle.include?(sequence),
                       "#{entry[:name]}: oracle disagrees with listed reject " \
                       "#{sequence.inspect}")
          observe_schema(entry, validator, sequence, :reject, :minimal_reproduction)
        end
      end
    end

    private

    def schema_xml(grammar)
      defines = grammar.defines.map do |name, pattern|
        %Q{<define name="#{name}">#{pattern_xml(pattern)}</define>}
      end.join
      %Q{<grammar xmlns="http://relaxng.org/ns/structure/1.0">} +
        %Q{<start><element name="A">#{pattern_xml(grammar.pattern)}</element></start>} +
        defines +
        %Q{</grammar>}
    end

    def pattern_xml(pattern)
      case pattern[0]
      when :empty
        "<empty/>"
      when :element
        %Q{<element name="#{pattern[1]}"/>}
      when :group
        "<group>#{pattern_xml(pattern[1])}#{pattern_xml(pattern[2])}</group>"
      when :choice
        "<choice>#{pattern_xml(pattern[1])}#{pattern_xml(pattern[2])}</choice>"
      when :interleave
        "<interleave>#{pattern_xml(pattern[1])}" \
          "#{pattern_xml(pattern[2])}</interleave>"
      when :optional
        "<optional>#{pattern_xml(pattern[1])}</optional>"
      when :zero_or_more
        "<zeroOrMore>#{pattern_xml(pattern[1])}</zeroOrMore>"
      when :one_or_more
        "<oneOrMore>#{pattern_xml(pattern[1])}</oneOrMore>"
      when :ref
        %Q{<ref name="#{pattern[1]}"/>}
      else
        raise "cannot render #{pattern.inspect}"
      end
    end

    def oracle_for(grammar)
      BoundedLanguage.new(grammar.defines, grammar.limit).language(grammar.pattern)
    end

    def alphabet_for(grammar, pattern = grammar.pattern, seen = Set.new)
      case pattern[0]
      when :element
        [ pattern[1] ]
      when :ref
        name = pattern[1]
        return [] if seen.include?(name)
        seen << name
        alphabet_for(grammar, grammar.defines.fetch(name), seen)
      when :group, :choice, :interleave
        (alphabet_for(grammar, pattern[1], seen) +
         alphabet_for(grammar, pattern[2], seen)).uniq
      when :optional, :zero_or_more, :one_or_more
        alphabet_for(grammar, pattern[1], seen)
      else
        []
      end
    end

    def all_sequences(alphabet, limit)
      (0..limit).flat_map do |length|
        alphabet.repeated_permutation(length).to_a
      end
    end

    def counterexamples(oracle, alphabet, limit)
      valid = oracle.to_a
      examples = []
      valid.each do |sequence|
        sequence.each_index do |index|
          examples << [ sequence[0...index] + sequence[(index + 1)..-1], :missing ]
        end
      end
      (alphabet + [ ALIEN ]).each do |name|
        valid.each do |sequence|
          next if sequence.size >= limit
          (0..sequence.size).each do |index|
            examples << [ sequence[0...index] + [ name ] + sequence[index..-1], :extra ]
          end
        end
      end
      valid.each do |sequence|
        (0...sequence.size - 1).each do |index|
          next if sequence[index] == sequence[index + 1]
          swapped = sequence.dup
          swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
          examples << [ swapped, :swap ]
        end
      end
      valid.combination(2).first(256).each do |left, right|
        prefix = common_prefix_length(left, right)
        next if prefix == 0 || prefix >= left.size || prefix >= right.size
        examples << [ left[0...prefix] + [ right[prefix] ] + left[(prefix + 1)..-1],
                      :shared_prefix ]
        examples << [ left[0...prefix] + [ left[prefix] ] + right[(prefix + 1)..-1],
                      :shared_prefix ]
      end
      examples.select { |sequence, _| sequence.size <= limit }.uniq
    end

    def common_prefix_length(left, right)
      length = 0
      length += 1 while length < left.size && length < right.size &&
                        left[length] == right[length]
      length
    end

    def grammar_has_interleave?(pattern, defines, seen = Set.new)
      case pattern[0]
      when :interleave
        true
      when :ref
        name = pattern[1]
        return false if seen.include?(name)
        seen << name
        grammar_has_interleave?(defines.fetch(name), defines, seen)
      when :group, :choice
        grammar_has_interleave?(pattern[1], defines, seen) ||
          grammar_has_interleave?(pattern[2], defines, seen)
      when :optional, :zero_or_more, :one_or_more
        grammar_has_interleave?(pattern[1], defines, seen)
      else
        false
      end
    end

    def rejected_sequences(grammar, oracle)
      alphabet = alphabet_for(grammar) + [ ALIEN ]
      all_sequences(alphabet, grammar.limit).reject do |sequence|
        oracle.include?(sequence)
      end.sort_by { |sequence| [ sequence.size, sequence ] }
    end

    def observe(grammar, validator, sequence, expected, kind)
      actual, message = run_document(validator, sequence)
      record_observation(expected)
      return if actual == expected
      report_mismatch(kind,
                      schema_xml(grammar),
                      sequence,
                      expected,
                      actual,
                      message,
                      grammar: grammar.name,
                      oracle: oracle_for(grammar),
                      validator: validator,
                      grammar_has_interleave_flag:
                        grammar_has_interleave?(grammar.pattern, grammar.defines))
    end

    def observe_schema(entry, validator, sequence, expected, kind)
      actual, message = run_document(validator, sequence)
      record_observation(expected)
      return if actual == expected
      report_mismatch(kind,
                      entry[:schema],
                      sequence,
                      expected,
                      actual,
                      message,
                      grammar: entry[:name])
    end

    def record_observation(expected)
      @checked += 1
      if expected == :accept
        @accepted += 1
      else
        @rejected += 1
      end
    end

    def run_document(validator, sequence)
      validator.reset
      parser = REXML::Parsers::TreeParser.new(instance_xml(sequence))
      parser.add_listener(validator)
      begin
        parser.parse
        [ :accept, nil ]
      rescue REXML::Validation::ValidationException => error
        [ :reject, error.message ]
      rescue => error
        [ :error, summarize_exception(error) ]
      end
    end

    def run_document_xml(validator, xml)
      validator.reset
      parser = REXML::Parsers::TreeParser.new(xml)
      parser.add_listener(validator)
      begin
        parser.parse
        [ :accept, nil ]
      rescue REXML::Validation::ValidationException => error
        [ :reject, error.message ]
      rescue SystemStackError => error
        [ :error, "#{error.class}: #{error.message}" ]
      rescue => error
        [ :error, summarize_exception(error) ]
      end
    end

    def instance_xml(sequence)
      children = sequence.map { |name| "<#{name}/>" }.join
      "<A>#{children}</A>"
    end

    def summarize_exception(error)
      message = error.message.to_s
      if message.include?("\n")
        message = message.split("\n").first
      end
      if message.size > 240
        message = message[0, 240] + "..."
      end
      "#{error.class}: #{message}"
    end

    def classify_input(oracle, sequence, interleaved)
      return [ 0, interleaved ? :legal_interleave : :legal ] if oracle.include?(sequence)
      permutations = oracle.select do |legal|
        legal.size == sequence.size && legal.sort == sequence.sort
      end
      return [ 1, :swap ] unless permutations.empty?

      nearest = nil
      oracle.each do |legal|
        missing, extra = multiset_difference(legal, sequence)
        distance = missing + extra
        if nearest.nil? || distance < nearest[0]
          nearest = [ distance, missing, extra ]
        end
      end
      return [ 1, :outside_language ] if nearest.nil?
      distance, missing, extra = nearest
      if extra > 0
        [ distance, :extra ]
      elsif missing > 0
        [ distance, :missing ]
      else
        [ distance, :outside_language ]
      end
    end

    def multiset_difference(legal, sequence)
      legal_counts = tally(legal)
      sequence_counts = tally(sequence)
      names = legal_counts.keys | sequence_counts.keys
      missing = 0
      extra = 0
      names.each do |name|
        expected = legal_counts.fetch(name, 0)
        observed = sequence_counts.fetch(name, 0)
        missing += expected - observed if expected > observed
        extra += observed - expected if observed > expected
      end
      [ missing, extra ]
    end

    def tally(sequence)
      sequence.each_with_object(Hash.new(0)) do |name, counts|
        counts[name] += 1
      end
    end

    def report_mismatch(kind, schema, sequence, expected, actual, message,
                        grammar:, oracle: nil, validator: nil,
                        grammar_has_interleave_flag: false)
      minimal = sequence
      if expected == :reject && actual == :accept && oracle && validator
        minimal = minimize_false_accept(validator, oracle, sequence)
      end
      detail = nil
      if oracle
        classification = classify_input(oracle, minimal,
                                        grammar_has_interleave_flag)
        detail = classification[1] if classification
      end
      outcome =
        case actual
        when :error then "unexpected_exception"
        when :accept
          expected == :accept ? "valid_sequence" : "skipped_constraint"
        when :reject
          expected == :accept ?
            (detail == :legal_interleave ? "legal_interleave" : "valid_sequence") :
            "valid_rejection_mistakenly_rejected"
        end
      label = detail && detail != :legal ? "#{outcome}:#{detail}" : outcome
      note = mismatch_note(outcome, detail, expected, actual)
      @failures << <<~REPORT.chomp
        [#{label}] #{grammar}
          schema:   #{schema}
          input:    #{instance_xml(minimal)}
          events:   #{minimal.inspect}
          expected: #{expected}
          observed: #{actual}#{message ? " (#{message})" : ""}
          note:     #{note}
      REPORT
    end

    def mismatch_note(outcome, detail, expected, actual)
      base =
        case outcome
        when "skipped_constraint"
          "the input is outside the independently enumerated language but was " \
            "accepted; a constraint was skipped"
        when "legal_interleave"
          "the input is one of the legal interleavings but was rejected; an " \
            "allowed ordering must still be accepted"
        when "valid_sequence"
          "the input is inside the independently enumerated language but was " \
            "rejected"
        when "unexpected_exception"
          "the validator raised an exception instead of returning a clean " \
            "accept/reject"
        else
          "the validator status differs from the independently enumerated " \
            "language"
        end
      case detail
      when :missing
        base += " (a required node is missing)"
      when :extra
        base += " (the input contains an extra node)"
      when :swap
        base += " (an exchange makes the order invalid)"
      end
      if expected == :accept && actual == :reject
        base += "; after a rejection the same validator instance must still " \
                "classify the next document"
      end
      base
    end

    # Greedy one-token deletion, keeping only candidates that are still
    # outside the oracle language and still accepted by the validator.
    def minimize_false_accept(validator, oracle, sequence)
      current = sequence.dup
      changed = true
      while changed
        changed = false
        current.each_index do |index|
          candidate = current[0...index] + current[(index + 1)..-1]
          next if oracle.include?(candidate)
          actual, = run_document(validator, candidate)
          next unless actual == :accept
          current = candidate
          changed = true
          break
        end
      end
      current
    end

    def minimal_reproduction_cases
      [
        {
          name: "repeated local ref to oneOrMore",
          pattern: group(ref("R"), ref("R")),
          defines: { "R" => one_or_more(element("C")) },
          limit: 5,
          accept: [ [ "C", "C" ], [ "C", "C", "C" ] ],
          reject: [ [], [ "C" ], [ "C", "C", "C", "C", "D" ] ],
        },
        {
          name: "interleave with a grouped branch",
          pattern: interleave(group(element("B"), element("C")), element("D")),
          accept: [ [ "B", "C", "D" ], [ "B", "D", "C" ], [ "D", "B", "C" ] ],
          reject: [ [ "B", "C" ], [ "B", "D" ], [ "D", "C" ],
                    [ "B", "C", "D", "C" ], [ "B", "D", "C", "B" ] ],
        },
        {
          name: "interleave with oneOrMore",
          pattern: interleave(one_or_more(element("B")), element("C")),
          accept: [ [ "B", "C" ], [ "C", "B" ], [ "B", "B", "C" ],
                    [ "B", "C", "B" ], [ "C", "B", "B" ] ],
          reject: [ [ "C" ], [ "B" ], [ "C", "C" ], [ "B", "C", "C" ],
                    [ "C", "B", "C" ] ],
        },
        {
          name: "interleave with optional branches",
          pattern: interleave(optional(element("B")), optional(element("C"))),
          accept: [ [], [ "B" ], [ "C" ], [ "B", "C" ], [ "C", "B" ] ],
          reject: [ [ "B", "B" ], [ "C", "C" ], [ "B", "C", "B" ] ],
        },
        {
          name: "choice with a shared prefix",
          pattern: choice(group(element("B"), element("C")),
                          group(element("B"), element("D"))),
          accept: [ [ "B", "C" ], [ "B", "D" ] ],
          reject: [ [ "B" ], [ "B", "C", "D" ], [ "B", "D", "C" ],
                    [ "C" ], [ "D" ] ],
        },
        {
          name: "optional before a required node",
          pattern: group(optional(element("B")), element("C")),
          accept: [ [ "B", "C" ], [ "C" ] ],
          reject: [ [ "B" ], [ "C", "B" ], [ "B", "C", "C" ], [ "C", "C" ] ],
        },
        {
          name: "zeroOrMore then oneOrMore",
          pattern: group(zero_or_more(element("B")), one_or_more(element("C"))),
          accept: [ [ "C" ], [ "B", "C" ], [ "C", "C" ], [ "B", "B", "C" ],
                    [ "B", "C", "C" ] ],
          reject: [ [], [ "B" ], [ "C", "B" ], [ "B", "C", "B" ] ],
        },
        {
          name: "ref to a choice",
          pattern: group(ref("R"), element("D")),
          defines: { "R" => choice(element("B"), element("C")) },
          accept: [ [ "B", "D" ], [ "C", "D" ] ],
          reject: [ [ "D" ], [ "B" ], [ "B", "C", "D" ], [ "B", "B", "D" ],
                    [ "B", "D", "D" ] ],
        },
        {
          name: "nested refs",
          pattern: group(ref("R1"), ref("R2")),
          defines: {
            "R1" => group(element("B"), element("C")),
            "R2" => interleave(element("D"), element("E")),
          },
          accept: [ [ "B", "C", "D", "E" ], [ "B", "C", "E", "D" ] ],
          reject: [ [ "B", "C", "D" ], [ "B", "D", "C", "E" ],
                    [ "D", "E", "B", "C" ], [ "B", "C", "D", "D" ] ],
        },
        {
          name: "zeroOrMore over a group",
          pattern: zero_or_more(group(element("B"), element("C"))),
          accept: [ [], [ "B", "C" ], [ "B", "C", "B", "C" ] ],
          reject: [ [ "B" ], [ "C" ], [ "B", "C", "B" ], [ "C", "B" ] ],
        },
      ].map do |entry|
        defines = entry.fetch(:defines, {})
        grammar = self.class.grammar(entry[:name], entry[:pattern],
                                     defines, entry.fetch(:limit, 4))
        entry.merge(schema: schema_xml(grammar),
                    grammar: grammar)
      end
    end

  end
end

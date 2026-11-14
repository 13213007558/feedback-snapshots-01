require_relative '../test'
require 'brakeman/checks/validation_regex_parser'

class ValidationRegexParserTests < Minitest::Test
  Parser = Brakeman::ValidationRegexParser

  def parser regex
    @parsers ||= {}
    @parsers[regex.object_id] ||= Parser.new(regex.source, extended: (regex.options & Regexp::EXTENDED) != 0)
  end

  def anchored? regex
    parser(regex).anchored?
  end

  def assert_full_string regex, accepted, rejected
    accepted.each do |string|
      match = regex.match(string)
      refute_nil match, "#{regex.inspect} should match #{string.inspect}"
      assert_equal 0, match.begin(0), "#{regex.inspect} did not start at 0 for #{string.inspect}"
      assert_equal string.length, match.end(0), "#{regex.inspect} left an unverified suffix of #{string.inspect}"
    end

    rejected.each do |string|
      refute regex.match?(string), "#{regex.inspect} unexpectedly matched #{string.inspect}"
    end
  end

  def assert_rejected regex, matching_strings
    refute anchored?(regex), "#{regex.inspect} should not be treated as fully anchored"

    matching_strings.each do |string|
      match = regex.match(string)
      refute_nil match, "#{regex.inspect} should still match #{string.inspect}"
      refute(match.begin(0) == 0 && match.end(0) == string.length,
             "#{regex.inspect} unexpectedly covers all of #{string.inspect}")
    end
  end

  def test_legal_controls
    cases = {
      /\Afoo\z/ => [%w[foo], %w[fooXYZ XYZfoo foo\n foo\nbar]],
      /\Afoo\Z/ => [%w[foo], %w[fooXYZ XYZfoo foo\nbar]]
    }

    cases.each do |regex, (accepted, rejected)|
      assert anchored?(regex), "legal control #{regex.inspect} was not treated as anchored"
      assert_full_string regex, accepted, rejected
    end
  end

  def test_top_level_alternation_leaks_suffix
    regex = /\Afoo|bar\z/

    assert_rejected regex, ["fooXYZ", "XYZbar", "foobarXYZ"]
    refute anchored?(regex)
    assert_match(/Alternative 1 of 2/, parser(regex).problem)
  end

  def test_nested_alternation_leaks_suffix
    regex = /\Afoo(?:bar|baz\z)/

    assert_rejected regex, ["foobarXYZ"]
    refute anchored?(regex)
    assert_match(/Alternative 1 of 2/, parser(regex).problem)
  end

  def test_escaped_backslash_is_literal_not_anchor
    regex = /\Afoo\\z/

    assert_rejected regex, ["foo\\zXYZ"]
    refute anchored?(regex)
    assert_match(/escaped backslash/, parser(regex).problem)
  end

  def test_extended_comment_is_not_anchor
    regex = /\Afoo # not really \z/x

    assert_rejected regex, ["fooXYZ"]
    refute anchored?(regex)
    assert_match(/extended-mode comment/, parser(regex).problem)
  end

  def test_extended_comment_without_anchor_text_is_reported_as_unanchored
    regex = /\Afoo # just a comment/x

    assert_rejected regex, ["fooXYZ"]
    refute anchored?(regex)
    assert_match(/not followed by an end anchor/, parser(regex).problem)
  end

  def test_extended_comment_on_later_line_is_not_anchor
    regex = %r{\Afoo
# trailing comment with \z}x

    assert_rejected regex, ["fooXYZ"]
    refute anchored?(regex)
    assert_match(/extended-mode comment/, parser(regex).problem)
  end

  def test_extended_comment_after_real_anchor_is_secure
    regex = %r{\Afoo # c
\z}x

    assert anchored?(regex), "real \\z after an extended-mode comment should count"
    assert_full_string regex, ["foo"], ["fooXYZ", "foo\n"]
  end

  def test_quantified_anchor_is_not_an_anchor
    regex = /\Afoo\z?/

    refute anchored?(regex), "quantified \\z should not be treated as a full anchor"
    assert_match(/optional/, parser(regex).problem)
    refute_nil regex.match("fooX")
  end

  def test_quantified_start_anchor_is_not_an_anchor
    regex = /\A?foo\z/

    refute anchored?(regex), "quantified \\A should not be treated as a full anchor"
    assert_match(/optional/, parser(regex).problem)
    refute_nil regex.match("Xfoo")
  end

  def test_literal_newline_pattern_is_anchored
    regex = /\Afoo
bar\z/

    assert anchored?(regex), "a literal newline in the source should not disable anchoring"
    assert_full_string regex, ["foo\nbar"], ["foo", "foo\nbarXYZ", "foo\nbar\n"]
  end

  def test_terminal_newline_distinction_between_z_and_Z
    strict = /\Afoo\z/
    soft = /\Afoo\Z/

    assert anchored?(strict)
    assert anchored?(soft)
    refute strict.match?("foo\n")
    assert soft.match?("foo\n"), "\\Z is expected to admit one trailing newline"
    assert_equal 3, soft.match("foo\n").end(0), "\\Z match ends before the trailing newline"
    refute soft.match?("foo\nbar")
    refute soft.match?("foo\n\n")
  end

  def test_multiline_data_is_not_admitted_by_a_z_anchor
    regex = /\Afoo[\s\S]*bar\z/

    assert anchored?(regex)
    assert_full_string regex, ["foo\nbar", "foo\nmiddle\nbar"], ["Xfoo\nbar", "foo\nbar\n"]
    refute regex.match?("foo\nbar\nX")
  end

  def test_character_class_contents_are_not_anchors
    regex = /\A[z\A]foo\z/

    assert anchored?(regex), "anchor-looking text inside a character class is a literal"
    assert_full_string regex, ["zfoo", "Afoo"], ["foo", "zfooX"]
  end

  def test_extended_character_class_is_not_a_comment
    regex = /\A[#]x\z/x

    assert anchored?(regex)
    assert_full_string regex, ["#x"], ["x", "#xX"]
  end

  def test_anchored_alternatives_are_secure
    regex = /\A(?:foo|bar)\z/

    assert anchored?(regex)
    assert_full_string regex, ["foo", "bar"], ["fooX", "Xbar", "foobar"]
  end

  def test_unanchored_control
    regex = /foo/

    refute anchored?(regex)
    refute_nil regex.match("XfooY")
  end

  def test_unprovable_construct_is_reported
    regex = /\Afoo(?>(?:bar)\z)/

    assert anchored?(regex), "atomic groups should be provable here"
    assert_full_string regex, ["foobar"], ["foobarX"]
  end
end

class ValidationRegexCheckTests < Minitest::Test
  class FakeTracker
    attr_reader :models, :app_tree

    def initialize regex
      @app_tree = Object.new
      def @app_tree.file_path path
        path
      end

      model = Brakeman::Model.new(:User, nil, "app/models/user.rb", nil, self)
      call = s(:call, nil, :validates_format_of,
               s(:lit, :email),
               s(:hash, s(:lit, :with), s(:lit, regex))).line(12)
      model.add_option :validates_format_of, call
      @models = { User: model }
    end
  end

  def run_check regex
    check = Brakeman::CheckValidationRegex.new(FakeTracker.new(regex))
    check.run_check
    check.warnings
  end

  def test_warning_names_field_and_leaking_branch
    warnings = run_check(/\A(foo|bar\z)/)

    assert_equal 1, warnings.length
    warning = warnings.first

    assert_equal "Format Validation", warning.warning_type
    assert_equal "High", warning.confidence_name
    assert_match(/`email`/, warning.message.to_s)
    assert_match(/Alternative 1 of 2 \(`foo`\)/, warning.message.to_s)
    assert_match(/unverified suffix/, warning.message.to_s)
    assert_equal 12, warning.line
  end

  def test_secure_control_produces_no_warning
    assert_empty run_check(/\A(?:foo|bar)\z/)
  end

  def test_soft_end_anchor_is_allowed
    assert_empty run_check(/\Afoo\Z/)
  end

  def test_escaped_backslash_produces_warning
    warnings = run_check(/\Afoo\\z/)

    assert_equal 1, warnings.length
    assert_match(/escaped backslash/, warnings.first.message.to_s)
  end
end

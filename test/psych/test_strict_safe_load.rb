# frozen_string_literal: true
require 'psych/helper'

module Psych
  class TestStrictSafeLoad < TestCase
    class HookedObject
      def self.calls
        @calls ||= []
      end

      def self.reset
        @calls = []
      end

      def init_with coder
        self.class.calls << coder
      end
    end

    # An IO-like object that never returns more than one byte per read.
    class ShortReadIO
      def initialize string
        @string = string
        @pos = 0
      end

      def external_encoding
        nil
      end

      def read length
        return nil if @pos >= @string.bytesize
        chunk = @string.byteslice(@pos, 1)
        @pos += 1
        chunk
      end
    end

    # An IO-like object that fails once the first document has been served.
    class FailingReadIO
      def initialize string
        @string = string
        @pos = 0
      end

      def external_encoding
        nil
      end

      def read length
        raise IOError, "simulated read failure" if @pos > 0
        @pos = @string.bytesize
        @string
      end
    end

    def setup
      HookedObject.reset
    end

    [1, 2.2, {}, [], "foo"].each do |obj|
      define_method(:"test_basic_#{obj.class}") do
        assert_equal obj, Psych.strict_safe_load(Psych.dump(obj))
      end
    end

    def test_empty_input_returns_fallback
      assert_nil Psych.strict_safe_load("")
      assert_equal false, Psych.strict_safe_load("", fallback: false)
    end

    def test_comment_only_input_returns_fallback
      assert_nil Psych.strict_safe_load("# nothing here\n")
      assert_equal false, Psych.strict_safe_load("# nothing here\n", fallback: false)
    end

    def test_raises_on_multiple_documents
      ex = assert_raise(Psych::Exception) do
        Psych.strict_safe_load("--- a\n--- b\n")
      end
      assert_match(/single YAML document/, ex.message)
    end

    def test_raises_on_document_after_explicit_end_marker
      assert_raise(Psych::Exception) do
        Psych.strict_safe_load("--- a\n...\n--- b\n")
      end
    end

    def test_explicit_end_marker_terminates_single_document
      assert_equal "a", Psych.strict_safe_load("--- a\n...\n")
    end

    def test_document_markers_inside_scalars_are_not_boundaries
      yaml = <<~YAML
        ---
        plain: '---'
        double: "..."
        block: |
          ---
          ...
      YAML
      assert_equal(
        { "plain" => "---", "double" => "...", "block" => "---\n...\n" },
        Psych.strict_safe_load(yaml)
      )
    end

    def test_document_markers_inside_comments_are_not_boundaries
      yaml = <<~YAML
        # ---
        ---
        foo: bar # ...
      YAML
      assert_equal({ "foo" => "bar" }, Psych.strict_safe_load(yaml))
    end

    def test_raises_on_invalid_second_document
      assert_raise(Psych::SyntaxError) do
        Psych.strict_safe_load("--- a\n--- [", filename: "conf.yml")
      end
    end

    def test_syntax_error_reports_filename
      ex = assert_raise(Psych::SyntaxError) do
        Psych.strict_safe_load("--- a\n--- [", filename: "conf.yml")
      end
      assert_equal "conf.yml", ex.file
    end

    def test_raises_on_trailing_garbage_after_document
      assert_raise(Psych::SyntaxError) do
        Psych.strict_safe_load("--- a\nfoo: [")
      end
    end

    def test_hooks_not_run_when_second_document_is_invalid
      yaml = "--- !ruby/object:Psych::TestStrictSafeLoad::HookedObject {}\n--- ["
      assert_raise(Psych::SyntaxError) do
        Psych.strict_safe_load(yaml, permitted_classes: [HookedObject])
      end
      assert_empty HookedObject.calls
    end

    def test_hooks_not_run_when_multiple_documents
      yaml = "--- !ruby/object:Psych::TestStrictSafeLoad::HookedObject {}\n--- {}\n"
      assert_raise(Psych::Exception) do
        Psych.strict_safe_load(yaml, permitted_classes: [HookedObject])
      end
      assert_empty HookedObject.calls
    end

    def test_permitted_class_loads_in_single_document
      yaml = "--- !ruby/object:Psych::TestStrictSafeLoad::HookedObject {}\n"
      result = Psych.strict_safe_load(yaml, permitted_classes: [HookedObject])
      assert_instance_of HookedObject, result
      assert_equal 1, HookedObject.calls.length
    end

    def test_disallowed_class_still_raises
      yaml = "--- !ruby/object:Psych::TestStrictSafeLoad::HookedObject {}\n"
      assert_raise(Psych::DisallowedClass) do
        Psych.strict_safe_load(yaml)
      end
    end

    def test_aliases_require_opt_in
      yaml = "---\na: &x 1\nb: *x\n"
      assert_raise(Psych::AliasesNotEnabled) do
        Psych.strict_safe_load(yaml)
      end
      assert_equal({ "a" => 1, "b" => 1 }, Psych.strict_safe_load(yaml, aliases: true))
    end

    def test_symbolize_names
      assert_equal({ foo: "bar" }, Psych.strict_safe_load("---\nfoo: bar\n", symbolize_names: true))
    end

    def test_short_read_io
      yaml = "---\nfoo: bar\nlist:\n  - 1\n  - 2\n"
      assert_equal(
        { "foo" => "bar", "list" => [1, 2] },
        Psych.strict_safe_load(ShortReadIO.new(yaml))
      )
    end

    def test_short_read_io_with_multiple_documents_raises
      assert_raise(Psych::Exception) do
        Psych.strict_safe_load(ShortReadIO.new("--- a\n--- b\n"))
      end
    end

    def test_trailing_read_failure_raises_and_skips_hooks
      yaml = "--- !ruby/object:Psych::TestStrictSafeLoad::HookedObject {}\n"
      assert_raise(IOError) do
        Psych.strict_safe_load(FailingReadIO.new(yaml), permitted_classes: [HookedObject])
      end
      assert_empty HookedObject.calls
    end

    def test_safe_load_ignores_what_strict_safe_load_rejects
      yaml = "--- a\n--- b\n"
      assert_equal "a", Psych.safe_load(yaml)
      assert_raise(Psych::Exception) do
        Psych.strict_safe_load(yaml)
      end
    end
  end
end

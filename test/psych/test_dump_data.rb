# frozen_string_literal: true
require_relative 'helper'

module Psych
  class TestDumpData < TestCase
    # Records every serialization hook that runs so a test can prove the new
    # mode never executes application-defined methods.
    class SideEffect
      attr_reader :events

      def initialize
        @events = []
      end

      def record(name)
        @events << name
      end
    end

    def hooked_string(side_effect)
      string = String.new("hooked")
      string.define_singleton_method(:encode_with) do |coder|
        side_effect.record(:string_encode_with)
        coder["ran"] = true
      end
      string
    end

    def hooked_object(side_effect)
      object = Object.new
      object.define_singleton_method(:encode_with) do |coder|
        side_effect.record(:object_encode_with)
        coder["ran"] = true
      end
      object
    end

    def test_exports_basic_scalars
      [nil, true, false, 42, 3.14, "plain"].each do |value|
        assert_equal value, Psych.safe_load(Psych.dump_data(value))
      end
    end

    def test_exports_empty_containers
      assert_equal "--- []\n", Psych.dump_data([])
      assert_equal "--- {}\n", Psych.dump_data({})
    end

    def test_exports_nested_structure_and_round_trips
      data = {
        "string" => "x",
        "number" => 7,
        "float"  => 1.5,
        "flags"  => [true, false, nil],
        "nested" => [1, [2, { "key" => "value" }]],
      }

      yaml = Psych.dump_data(data)
      assert_equal data, Psych.safe_load(yaml)
    end

    def test_output_can_be_written_to_an_io
      io = StringIO.new
      returned = Psych.dump_data({ "a" => 1 }, io)

      assert_same io, returned
      assert_equal "---\na: 1\n", io.string
    end

    def test_accepts_formatting_options
      assert_equal "---\n-   - x\n", Psych.dump_data([["x"]], indentation: 4)
      assert_match(/\A%YAML 1\.1\n---\n/, Psych.dump_data({ "a" => 1 }, header: true))
      assert_include Psych.dump_data({ "a" => 1 }, canonical: true), "{"
    end

    def test_stringify_names_only_applies_to_allowed_string_keys
      assert_equal "---\na: 1\n", Psych.dump_data({ "a" => 1 }, stringify_names: true)
    end

    def test_singleton_method_string_is_dumped_as_plain_string
      side_effect = SideEffect.new
      string = hooked_string(side_effect)

      assert_equal "--- hooked\n", Psych.dump_data(string)
      assert_equal [], side_effect.events
    end

    def test_encode_with_hook_is_not_invoked_at_any_depth
      side_effect = SideEffect.new
      string = hooked_string(side_effect)
      data = { "outer" => [{ "inner" => string }] }

      yaml = Psych.dump_data(data)

      assert_equal "---\nouter:\n- inner: hooked\n", yaml
      assert_equal [], side_effect.events
    end

    def test_hook_is_not_invoked_before_rejecting_other_objects
      side_effect = SideEffect.new
      object = hooked_object(side_effect)

      assert_raise(Psych::DisallowedClass) { Psych.dump_data(object) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data([object]) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data({ "k" => object }) }
      assert_equal [], side_effect.events
    end

    def test_rejects_arbitrary_objects
      assert_raise(Psych::DisallowedClass) { Psych.dump_data(Object.new) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data(1..2) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data(Rational(1, 2)) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data(/regexp/) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data(Time.now) }
    end

    def test_rejects_symbols
      error = assert_raise(Psych::DisallowedClass) { Psych.dump_data(:foo) }
      assert_equal "Tried to dump unspecified class: Symbol", error.message

      assert_raise(Psych::DisallowedClass) { Psych.dump_data({ foo: 1 }) }
    end

    def test_rejects_subclasses_even_when_nested
      hash_subclass = Class.new(Hash)
      string_subclass = Class.new(String)

      assert_raise(Psych::DisallowedClass) { Psych.dump_data(hash_subclass.new) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data([string_subclass.new("z")]) }
      assert_raise(Psych::DisallowedClass) { Psych.dump_data({ "k" => hash_subclass.new }) }
    end

    def test_rejects_subclass_that_recurses_through_allowed_containers
      nested_subclass = Class.new(Array)
      assert_raise(Psych::DisallowedClass) do
        Psych.dump_data([1, { "k" => [nested_subclass.new] }])
      end
    end

    def test_instance_variables_are_not_exported
      array = [1, 2]
      array.instance_variable_set(:@secret, 42)
      string = String.new("abc")
      string.instance_variable_set(:@secret, 42)
      hash = { "k" => 1 }
      hash.instance_variable_set(:@secret, 42)

      [array, string, hash].each do |object|
        yaml = Psych.dump_data(object)
        assert_not_include yaml, "!ruby"
        assert_not_include yaml, "secret"
      end
    end

    def test_binary_string_round_trips
      binary = "\xFF\xFE".dup.force_encoding(Encoding::ASCII_8BIT)

      restored = Psych.safe_load(Psych.dump_data(binary))

      assert_equal Encoding::ASCII_8BIT, restored.encoding
      assert_equal binary, restored
    end

    def test_shared_reference_is_rejected_by_default
      member = [1, 2]
      shared = [member, member]

      error = assert_raise(Psych::BadAlias) { Psych.dump_data(shared) }
      assert_equal "Tried to dump an aliased object", error.message
    end

    def test_recursive_array_is_rejected_by_default
      recursive = []
      recursive << recursive

      assert_raise(Psych::BadAlias) { Psych.dump_data(recursive) }
    end

    def test_recursive_hash_is_rejected_by_default
      recursive = {}
      recursive["self"] = recursive

      assert_raise(Psych::BadAlias) { Psych.dump_data(recursive) }
    end

    def test_shared_reference_is_anchored_when_aliases_enabled
      omit "libfyaml formats anchors and aliases differently" if libfyaml?
      member = [1, 2]
      shared = [member, member]

      yaml = Psych.dump_data(shared, aliases: true)

      assert_equal "---\n- &1\n  - 1\n  - 2\n- *1\n", yaml
      restored = Psych.safe_load(yaml, aliases: true)
      assert_same restored.first, restored.last
    end

    def test_recursive_structure_round_trips_when_aliases_enabled
      omit "libfyaml formats anchors and aliases differently" if libfyaml?
      recursive = []
      recursive << recursive

      yaml = Psych.dump_data(recursive, aliases: true)

      assert_equal "--- &1\n- *1\n", yaml
      restored = Psych.safe_load(yaml, aliases: true)
      assert_same restored, restored.first
    end

    def test_legacy_dump_entries_still_run_serialization_hooks
      side_effect = SideEffect.new
      string = hooked_string(side_effect)

      Psych.dump(string)
      Psych.safe_dump(string)

      assert_equal [:string_encode_with, :string_encode_with], side_effect.events
    end
  end
end

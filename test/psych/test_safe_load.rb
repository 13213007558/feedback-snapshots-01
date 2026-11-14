# frozen_string_literal: true
require 'psych/helper'

module Psych
  class TestSafeLoad < TestCase
    def setup
      @orig_verbose, $VERBOSE = $VERBOSE, nil
    end

    def teardown
      $VERBOSE = @orig_verbose
    end

    class Foo; end

    [1, 2.2, {}, [], "foo"].each do |obj|
      define_method(:"test_basic_#{obj.class}") do
        assert_safe_cycle obj
      end
    end

    def test_raises_when_alias_found_if_alias_parsing_not_enabled
      yaml_with_aliases = <<~YAML
        ---
        a: &ABC
          k1: v1
          k2: v2
        b: *ABC
      YAML

      assert_raise(Psych::AliasesNotEnabled) do
        Psych.safe_load(yaml_with_aliases)
      end
    end

    def test_aliases_are_parsed_when_alias_parsing_is_enabled
      yaml_with_aliases = <<~YAML
        ---
        a: &ABC
          k1: v1
          k2: v2
        b: *ABC
      YAML

      result = Psych.safe_load(yaml_with_aliases, aliases: true)
      assert_same result.fetch("a"), result.fetch("b")
    end

    def test_permitted_symbol
      yml = Psych.dump :foo
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load yml
      end
      assert_equal(
        :foo,
        Psych.safe_load(
          yml,
          permitted_classes: [Symbol],
          permitted_symbols: [:foo]
        )
      )
    end

    def test_symbol
      assert_raise(Psych::DisallowedClass) do
        assert_safe_cycle :foo
      end
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load '--- !ruby/symbol foo', permitted_classes: []
      end

      assert_safe_cycle :foo, permitted_classes: [Symbol]
      assert_safe_cycle :foo, permitted_classes: %w{ Symbol }
      assert_equal :foo, Psych.safe_load('--- !ruby/symbol foo', permitted_classes: [Symbol])
    end

    def test_encoding
      yaml = "--- !ruby/encoding UTF-8\n"
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load yaml
      end
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load yaml, permitted_classes: []
      end

      assert_equal Encoding::UTF_8, Psych.safe_load(yaml, permitted_classes: [Encoding])
      assert_equal Encoding::UTF_8, Psych.safe_load(yaml, permitted_classes: %w{ Encoding })
    end

    def test_foo
      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load '--- !ruby/object:Foo {}', permitted_classes: [Foo]
      end

      assert_raise(Psych::DisallowedClass) do
        assert_safe_cycle Foo.new
      end
      assert_kind_of(Foo, Psych.safe_load(Psych.dump(Foo.new), permitted_classes: [Foo]))
    end

    X = Struct.new(:x)
    def test_struct_depends_on_sym
      assert_safe_cycle(X.new, permitted_classes: [X, Symbol])
      assert_raise(Psych::DisallowedClass) do
        cycle X.new, permitted_classes: [X]
      end
    end

    def test_anon_struct
      assert Psych.safe_load(<<-eoyml, permitted_classes: [Struct, Symbol])
--- !ruby/struct
  foo: bar
                      eoyml

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Struct])
--- !ruby/struct
  foo: bar
                      eoyml
      end

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Symbol])
--- !ruby/struct
  foo: bar
                      eoyml
      end
    end

    D = Data.define(:d) unless RUBY_VERSION < "3.2"

    def test_data_depends_on_sym
      omit "Data requires ruby >= 3.2" if RUBY_VERSION < "3.2"
      assert_safe_cycle(D.new(nil), permitted_classes: [D, Symbol])
      assert_raise(Psych::DisallowedClass) do
        cycle D.new(nil), permitted_classes: [D]
      end
    end

    def test_anon_data
      omit "Data requires ruby >= 3.2" if RUBY_VERSION < "3.2"
      assert Psych.safe_load(<<-eoyml, permitted_classes: [Data, Symbol])
--- !ruby/data
  foo: bar
      eoyml

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Data])
--- !ruby/data
  foo: bar
        eoyml
      end

      assert_raise(Psych::DisallowedClass) do
        Psych.safe_load(<<-eoyml, permitted_classes: [Symbol])
--- !ruby/data
  foo: bar
        eoyml
      end
    end

    def test_safe_load_default_fallback
      assert_nil Psych.safe_load("")
    end

    def test_safe_load
      assert_equal %w[a b], Psych.safe_load("- a\n- b")
    end

    def test_safe_load_raises_on_bad_input
      assert_raise(Psych::SyntaxError) { Psych.safe_load("--- `") }
    end

    private

    def cycle object, permitted_classes: []
      Psych.safe_load(Psych.dump(object), permitted_classes: permitted_classes)
    end

    def assert_safe_cycle object, permitted_classes: []
      other = cycle object, permitted_classes: permitted_classes
      assert_equal object, other
    end
  end

  class TestSafeLoadClassIdentity < TestCase
    class Approved
      attr_reader :init_count

      def init_with coder
        self.class.record_hook_call
        @init_count = (@init_count || 0) + 1
        coder.map.each { |k, v| instance_variable_set(:"@#{k}", v) }
      end

      def self.hook_calls
        @hook_calls ||= 0
      end

      def self.record_hook_call
        @hook_calls = hook_calls + 1
      end

      def self.reset_hook_calls
        @hook_calls = 0
      end
    end

    class ApprovedChild < Approved; end

    class ApprovedHash < Hash; end
    class ApprovedArray < Array; end
    class ApprovedString < String; end

    class Evil
      def init_with coder
        self.class.record_hook_call
        coder.map.each { |k, v| instance_variable_set(:"@#{k}", v) }
      end

      def self.record_hook_call
        @hook_calls = hook_calls + 1
      end

      def self.hook_calls
        @hook_calls ||= 0
      end

      def self.reset_hook_calls
        @hook_calls = 0
      end
    end

    def setup
      @verbose, $VERBOSE = $VERBOSE, nil
      @stash = {}
      @structs = []
      Approved.reset_hook_calls
      Evil.reset_hook_calls
    end

    def teardown
      @stash.each do |_name, (mod, short, value)|
        mod.const_set(short, value)
      end
      # Remove only structs that still refer to the class this test created.
      @structs.each do |struct|
        name = struct.name
        next unless name
        short = name.sub(/\AStruct::/, '')
        if Struct.const_defined?(short, false) && Struct.const_get(short, false).equal?(struct)
          Struct.send(:remove_const, short)
        end
      end
      $VERBOSE = @verbose
    end

    # Rebind +name+ (a fully qualified constant path) to +value+, restoring
    # it in teardown.  The previous value is returned for assertions.
    def rebind name, value
      parts = name.split('::')
      short = parts.pop
      mod = parts.inject(Object) { |m, part| m.const_get(part) }
      previous = mod.const_get(short)
      @stash[name] = [mod, short, previous] unless @stash.key?(name)
      mod.const_set(short, value)
      previous
    end

    def struct_new name, *members
      struct = Struct.new(name, *members)
      @structs << struct
      struct
    end

    def remove_struct struct
      name = struct.name
      return unless name

      short = name.sub(/\AStruct::/, '')
      Struct.send(:remove_const, short) if Struct.const_defined?(short, false)
    end

    def identity_load yaml, permitted_classes:, aliases: false
      Psych.safe_load(yaml, permitted_classes: permitted_classes,
                     aliases: aliases, permitted_classes_mode: :identity)
    end

    def test_approves_exact_class_object
      loaded = identity_load("--- !ruby/object:Psych::TestSafeLoadClassIdentity::Approved\nfoo: bar\n",
                             permitted_classes: [Approved])
      assert_instance_of Approved, loaded
      assert_equal 'bar', loaded.instance_variable_get(:@foo)
      assert_equal 1, loaded.init_count
      assert_equal 1, Approved.hook_calls
    end

    def test_exception_path_does_not_run_hooks_for_rejected_nested_class
      yaml = <<~YAML
        ---
        approved: !ruby/object:Psych::TestSafeLoadClassIdentity::Approved
          foo: bar
        rejected: !ruby/object:Psych::TestSafeLoadClassIdentity::Evil
          foo: baz
      YAML
      assert_raise(Psych::DisallowedClass) do
        identity_load(yaml, permitted_classes: [Approved])
      end
      assert_raise(Psych::DisallowedClass) do
        identity_load("--- !ruby/object:Psych::TestSafeLoadClassIdentity::Evil\nfoo: baz\n",
                      permitted_classes: [Approved])
      end
      assert_equal 0, Evil.hook_calls
    end

    def test_rebound_name_is_never_permitted_by_name_alone
      rebind 'Psych::TestSafeLoadClassIdentity::Approved', Evil
      assert_raise(Psych::DisallowedClass) do
        identity_load("--- !ruby/object:Psych::TestSafeLoadClassIdentity::Approved {}\n",
                      permitted_classes: [])
      end
      assert_equal 0, Evil.hook_calls
    end

    def test_constant_alias_of_approved_class_is_permitted
      origin = Psych::TestSafeLoadClassIdentity::Approved
      Object.const_set :SafeLoadAliasForApproved, origin
      begin
        loaded = identity_load("--- !ruby/object:SafeLoadAliasForApproved\nfoo: one\n",
                               permitted_classes: [origin])
        assert_same origin, loaded.class
        assert_equal 'one', loaded.instance_variable_get(:@foo)
      ensure
        Object.send(:remove_const, :SafeLoadAliasForApproved)
      end
    end

    def test_ambiguous_short_struct_name_resolves_the_currently_bound_approved_class
      first = struct_new('SafeLoadAmbiguousStruct', :x)
      second = struct_new('SafeLoadAmbiguousStruct', :x)
      loaded = identity_load("--- !ruby/struct:SafeLoadAmbiguousStruct\nx: 1\n",
                             permitted_classes: [first, second, Symbol])
      assert_same second, loaded.class
      refute_same first, loaded.class

      rebind 'Struct::SafeLoadAmbiguousStruct', Evil
      assert_raise(Psych::DisallowedClass) do
        identity_load("--- !ruby/struct:SafeLoadAmbiguousStruct\nx: 1\n",
                      permitted_classes: [first, second, Symbol])
      end
    ensure
      remove_struct(first) if first
      remove_struct(second) if second
    end

    def test_unapproved_child_class_is_rejected_even_if_parent_is_approved
      assert_raise(Psych::DisallowedClass) do
        identity_load("--- !ruby/object:Psych::TestSafeLoadClassIdentity::ApprovedChild {}\n",
                      permitted_classes: [Approved])
      end
    end

    def test_unapproved_class_autoload_does_not_run
      Object.send(:remove_const, :AutoloadProbe) if defined?(AutoloadProbe)
      $autoload_probe_loaded = false
      probe = Tempfile.new(['autoload_probe', '.rb'])
      probe.write("$autoload_probe_loaded = true\nAutoloadProbe = Class.new\n")
      probe.flush
      Object.autoload(:AutoloadProbe, probe.path)
      begin
        assert_raise(Psych::DisallowedClass) do
          identity_load("--- !ruby/object:AutoloadProbe {}\n", permitted_classes: [Approved])
        end
        assert_false $autoload_probe_loaded
        assert_equal probe.path, Object.autoload?(:AutoloadProbe)
      ensure
        $autoload_probe_loaded = nil
        Object.send(:remove_const, :AutoloadProbe) if defined?(AutoloadProbe)
        Object.const_set(:AutoloadProbe, Class.new)
        probe.close!
      end
    end

    def test_unapproved_nested_tag_does_not_run_init_with
      yaml = <<~YAML
        ---
        outer:
          - !ruby/object:Psych::TestSafeLoadClassIdentity::Evil
            foo: bar
      YAML
      assert_raise(Psych::DisallowedClass) do
        identity_load(yaml, permitted_classes: [])
      end
      assert_equal 0, Evil.hook_calls
    end

    def test_identity_mode_requires_class_or_module_entries
      assert_raise(ArgumentError) do
        identity_load("--- a\n", permitted_classes: %w[Approved])
      end
      assert_raise(ArgumentError) do
        Psych.safe_load("--- a\n", permitted_classes: [Approved],
                        permitted_classes_mode: :bogus)
      end
    end

    def test_name_mode_is_the_compatibility_entry
      name = 'Psych::TestSafeLoadClassIdentity::Approved'
      loaded = Psych.safe_load("--- !ruby/object:#{name}\nfoo: bar\n",
                               permitted_classes: [name],
                               permitted_classes_mode: :name)
      assert_instance_of Approved, loaded
      assert_equal 'bar', loaded.instance_variable_get(:@foo)
    end

    def test_default_mode_binds_class_entries_by_identity
      approved = Approved
      rebind 'Psych::TestSafeLoadClassIdentity::Approved', Evil
      loaded = Psych.safe_load("--- !ruby/object:Psych::TestSafeLoadClassIdentity::Approved\nfoo: bar\n",
                               permitted_classes: [approved])
      assert_same approved, loaded.class
    end

    def test_name_mode_rebinds_to_the_new_constant
      rebind 'Psych::TestSafeLoadClassIdentity::Approved', Evil
      loaded = Psych.safe_load("--- !ruby/object:Psych::TestSafeLoadClassIdentity::Approved\nfoo: bar\n",
                               permitted_classes: ['Psych::TestSafeLoadClassIdentity::Approved'],
                               permitted_classes_mode: :name)
      assert_same Evil, loaded.class
    end

    def test_default_mode_keeps_name_entries_working
      loaded = Psych.safe_load("--- !ruby/object:Psych::TestSafeLoadClassIdentity::Approved\nfoo: bar\n",
                               permitted_classes: ['Psych::TestSafeLoadClassIdentity::Approved'])
      assert_instance_of Approved, loaded
    end

    def test_struct_name_fallback_resolves_only_the_approved_struct
      x = struct_new('SafeLoadApprovedStruct', :x)
      y = struct_new('SafeLoadUnapprovedStruct', :y)

      loaded = identity_load("--- !ruby/struct:SafeLoadApprovedStruct\nx: 1\n",
                             permitted_classes: [x, Symbol])
      assert_same x, loaded.class
      assert_equal 1, loaded.x

      assert_raise(Psych::DisallowedClass) do
        identity_load("--- !ruby/struct:SafeLoadUnapprovedStruct\ny: 1\n",
                      permitted_classes: [x, Symbol])
      end
      assert_raise(Psych::DisallowedClass) do
        identity_load("--- !ruby/struct:SafeLoadApprovedStruct\nx: 1\n",
                      permitted_classes: [y, Symbol])
      end
    ensure
      [x, y].compact.each { |s| remove_struct(s) }
    end

    def test_struct_fallback_still_binds_to_the_approved_class_after_rebinding
      x = struct_new('SafeLoadApprovedStruct2', :x)
      loaded = identity_load("--- !ruby/struct:SafeLoadApprovedStruct2\nx: 1\n",
                             permitted_classes: [x, Symbol])
      assert_same x, loaded.class

      rebind 'Struct::SafeLoadApprovedStruct2', Evil
      loaded = identity_load("--- !ruby/struct:SafeLoadApprovedStruct2\nx: 2\n",
                             permitted_classes: [x, Symbol])
      assert_same x, loaded.class
      assert_equal 2, loaded.x
      assert_equal 0, Evil.hook_calls
    ensure
      remove_struct(x)
    end

    def test_container_subclass_tags_require_the_exact_approved_class
      hash = identity_load("--- !ruby/hash:Psych::TestSafeLoadClassIdentity::ApprovedHash\na: 1\n",
                           permitted_classes: [ApprovedHash])
      assert_instance_of ApprovedHash, hash
      assert_equal 1, hash['a']

      ary = identity_load("--- !ruby/array:Psych::TestSafeLoadClassIdentity::ApprovedArray\n- a\n",
                          permitted_classes: [ApprovedArray])
      assert_instance_of ApprovedArray, ary

      str = identity_load("--- !ruby/string:Psych::TestSafeLoadClassIdentity::ApprovedString\nstr: ok\n",
                          permitted_classes: [ApprovedString])
      assert_instance_of ApprovedString, str
      assert_equal 'ok', str

      assert_raise(Psych::DisallowedClass) do
        identity_load("--- !ruby/hash:Psych::TestSafeLoadClassIdentity::ApprovedHash\na: 1\n",
                      permitted_classes: [ApprovedArray])
      end
    end

    def test_nested_tags_cannot_resolve_through_another_name
      approved = Approved
      rebind 'Psych::TestSafeLoadClassIdentity::Approved', Evil
      yaml = <<~YAML
        ---
        top:
          nested: !ruby/object:Psych::TestSafeLoadClassIdentity::Approved
            foo: bar
      YAML
      loaded = identity_load(yaml, permitted_classes: [approved, ApprovedChild])
      assert_same approved, loaded['top']['nested'].class
      assert_equal 0, Evil.hook_calls
      assert_equal 1, approved.hook_calls
    end

    def test_alias_permitted_object_is_still_the_approved_object
      origin = Approved
      rebind 'Psych::TestSafeLoadClassIdentity::Approved', Evil
      yaml = <<~YAML
        ---
        a: &A !ruby/object:Psych::TestSafeLoadClassIdentity::Approved
          foo: bar
        b: *A
      YAML
      loaded = identity_load(yaml, permitted_classes: [origin], aliases: true)
      assert_same origin, loaded['a'].class
      assert_same loaded['a'], loaded['b']
    end

    def test_unapproved_aliased_object_is_rejected
      yaml = <<~YAML
        ---
        a: &A !ruby/object:Psych::TestSafeLoadClassIdentity::Evil
          foo: bar
        b: *A
      YAML
      assert_raise(Psych::DisallowedClass) do
        identity_load(yaml, permitted_classes: [], aliases: true)
      end
      assert_equal 0, Evil.hook_calls
    end
  end
end

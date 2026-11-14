# frozen_string_literal: true
require 'psych/helper'
require 'stringio'

module Psych
  module Nodes
    class TestASTValidator < TestCase
      TAG = '!ruby/object:Psych::Nodes::TestASTValidator::HookTarget'

      def setup
        super
        HookTarget.hook_count = 0
        @original_load_tags = Psych.load_tags.dup
        Psych.add_tag TAG, HookTarget
      end

      def teardown
        Psych.load_tags = @original_load_tags
        super
      end

      # A class whose object-construction hook we can observe, so tests can
      # prove malformed trees never reach deserialization.
      class HookTarget
        class << self
          attr_accessor :hook_count
        end
        self.hook_count = 0

        attr_accessor :fields

        def init_with coder
          self.class.hook_count += 1
          @fields = coder.map
        end
      end

      # ---- well-formed, parser-produced trees are admitted ----------------

      VALID_YAML = [
        '--- foo',
        '--- ~',
        '--- {}',
        '--- []',
        "---\na: b\nc: d",
        "---\n- 1\n- 2",
        "---\nkey:\n",
        "--- &a\n- 1\n- *a\n",
        "---\n- &s hello\n- *s\n",
        "---\na: &m {x: 1}\nb: *m",
        "---\ndefaults: &d\n  timeout: 30\nother: *d",
        '--- !omap',
      ].freeze

      def test_parser_trees_are_valid
        VALID_YAML.each do |yaml|
          tree = Psych.parse_stream(yaml)
          assert tree.valid_ast?, "expected valid: #{yaml.inspect}"
          assert_same tree, tree.validate!
        end
      end

      def test_document_and_content_subtrees_are_valid_roots
        assert Psych.parse('--- a').valid_ast?
        assert Psych.parse('--- {}').root.valid_ast?
        assert Psych.parse('--- []').root.valid_ast?
        assert Psych.parse('--- foo').root.valid_ast?
      end

      def test_multi_document_stream_is_valid
        assert Psych.parse_stream("--- a\n--- b\n").valid_ast?
      end

      def test_alias_sharing_is_not_treated_as_a_cycle
        # Alias nodes do not share object identity, so anchor/alias usage must
        # validate even though the same anchored value is referenced twice.
        assert Psych.parse_stream("---\na: &x 1\nb: *x\n").valid_ast?
        assert Psych.parse_stream("--- &a\n- 1\n- *a\n").valid_ast?
      end

      # ---- malformed hand-built trees are rejected ------------------------

      def test_real_children_self_cycle_is_rejected
        seq = Sequence.new
        seq.children << Scalar.new('a')
        seq.children << seq
        assert_invalid wrap(seq)
      end

      def test_indirect_children_cycle_is_rejected
        mapping = Mapping.new
        inner = Sequence.new
        mapping.children << Scalar.new('k')
        mapping.children << inner
        inner.children << mapping
        assert_invalid wrap(mapping)
      end

      def test_cross_document_node_reuse_is_rejected
        shared = Scalar.new('evil')
        first = Document.new; first.children << shared
        second = Document.new; second.children << shared
        stream = Stream.new; stream.children << first; stream.children << second
        assert_invalid stream
      end

      def test_same_node_used_twice_as_child_is_rejected
        node = Scalar.new('dup')
        seq = Sequence.new; seq.children << node; seq.children << node
        assert_invalid wrap(seq)
      end

      def test_scalar_under_stream_is_illegal_root
        stream = Stream.new; stream.children << Scalar.new('x')
        assert_invalid stream
      end

      def test_document_with_two_roots_is_rejected
        doc = Document.new
        doc.children << Scalar.new('a')
        doc.children << Scalar.new('b')
        assert_invalid wrap(doc)
      end

      def test_alias_document_root_is_rejected
        doc = Document.new; doc.children << Alias.new('a')
        assert_invalid wrap(doc)
      end

      def test_empty_stream_is_rejected
        assert_invalid Stream.new
      end

      def test_bare_alias_cannot_be_a_root
        assert_invalid Alias.new('a')
      end

      def test_non_node_root_is_rejected
        assert_invalid Object.new
      end

      def test_incomplete_mapping_is_rejected
        mapping = Mapping.new
        mapping.children << Scalar.new('only_key')
        assert_invalid wrap(mapping)
      end

      def test_document_nested_in_mapping_is_rejected
        mapping = Mapping.new
        mapping.children << Scalar.new('k')
        mapping.children << Document.new
        assert_invalid wrap(mapping)
      end

      def test_terminal_scalar_with_children_is_rejected
        scalar = Scalar.new('x')
        scalar.instance_variable_set(:@children, [Scalar.new('y')])
        assert_invalid wrap(scalar)
      end

      def test_terminal_alias_with_children_is_rejected
        alias_node = Alias.new('a')
        alias_node.instance_variable_set(:@children, [Scalar.new('y')])
        assert_invalid wrap(alias_node)
      end

      def test_alias_to_undefined_anchor_is_rejected
        mapping = Mapping.new
        mapping.children << Scalar.new('k')
        mapping.children << Alias.new('missing')
        assert_invalid wrap(mapping)
      end

      def test_alias_across_documents_is_rejected
        anchored = Mapping.new; anchored.anchor = 'shared'
        first = Document.new; first.children << anchored
        other = Mapping.new
        other.children << Scalar.new('k')
        other.children << Alias.new('shared')
        second = Document.new; second.children << other
        stream = Stream.new; stream.children << first; stream.children << second
        assert_invalid stream
      end

      def test_non_node_child_is_rejected
        mapping = Mapping.new
        mapping.children << 'plain string'
        mapping.children << Scalar.new('v')
        assert_invalid wrap(mapping)
      end

      def test_non_string_scalar_value_is_rejected
        scalar = Scalar.new(123)
        assert_invalid wrap(scalar)
      end

      def test_validation_is_iterative_and_does_not_overflow
        # A cyclic tree would overflow a recursive walk; the validator must
        # raise a clean InvalidAST instead of SystemStackError.
        seq = Sequence.new
        seq.children << seq
        err = assert_raise(Psych::InvalidAST) { wrap(seq).validate! }
        assert_match(/reachable more than once/, err.message)
      end

      # ---- controlled transformation entry --------------------------------

      def test_transform_ast_returns_tree_and_preserves_semantics
        tree = Psych.parse_stream("---\nname: app\nports:\n- 80\n")
        result = Psych.transform_ast(tree) { |node| node }
        assert_same tree, result
        assert_equal [{ 'name' => 'app', 'ports' => [80] }], result.validated_to_ruby
      end

      def test_transform_ast_allows_legitimate_rewrite
        result = Psych.transform_ast(Psych.parse_stream('--- a')) do |tree|
          tree.children.first.root.value = 'b'
          tree
        end
        assert_equal ['b'], result.validated_to_ruby
      end

      def test_transform_ast_rejects_cycle_introduced_by_callback
        assert_raise(Psych::InvalidAST) do
          Psych.transform_ast(Psych.parse_stream("---\n- 1")) do |tree|
            seq = tree.children.first.root
            seq.children << seq
            tree
          end
        end
      end

      def test_transform_ast_rejects_non_node_returned_by_callback
        assert_raise(Psych::InvalidAST) do
          Psych.transform_ast(Psych.parse_stream('--- a')) { 42 }
        end
      end

      def test_transform_ast_rejects_input_before_callback_runs
        callback_ran = false
        assert_raise(Psych::InvalidAST) do
          Psych.transform_ast(Stream.new) do |tree|
            callback_ran = true
            tree
          end
        end
        refute callback_ran
      end

      # ---- guarded sinks never run hooks or emit output -------------------

      def test_valid_tagged_tree_runs_construction_hook
        tagged_tree.validated_to_ruby
        assert_equal 1, HookTarget.hook_count
      end

      def test_malformed_tree_never_runs_construction_hook
        bad = tagged_tree
        bad.children.first.root.children << Scalar.new('dangling')
        assert_raise(Psych::InvalidAST) { bad.validated_to_ruby }
        assert_equal 0, HookTarget.hook_count
      end

      def test_cyclic_tree_never_runs_construction_hook
        tree = tagged_tree
        seq = Sequence.new
        root = tree.children.first.root
        root.children << Scalar.new('loop') << seq
        seq.children << root
        assert_raise(Psych::InvalidAST) { tree.validated_to_ruby }
        assert_equal 0, HookTarget.hook_count
      end

      def test_malformed_tree_emits_nothing
        bad = tagged_tree
        bad.children.first.root.children << Scalar.new('orphan')
        io = StringIO.new
        assert_raise(Psych::InvalidAST) { bad.validated_yaml(io) }
        assert io.string.empty?
      end

      def test_valid_tree_guarded_yaml_round_trips
        tree = Psych.parse_stream("---\na: 1\nb: 2\n")
        emitted = tree.validated_yaml
        assert_equal tree.validated_to_ruby, Psych.parse_stream(emitted).validated_to_ruby
      end

      # ---- alias semantics survive the guarded path ------------------------

      def test_alias_identity_is_preserved
        tree = Psych.parse_stream("---\nd: &x\n  k: 1\nr: *x\n")
        loaded = tree.validated_to_ruby.first
        assert_same loaded['d'], loaded['r']
      end

      def test_merge_key_semantics_are_preserved
        yaml = "---\nbase: &b\n  x: 1\n  y: 2\nchild:\n  <<: *b\n  y: 9\n"
        child = Psych.parse_stream(yaml).validated_to_ruby.first['child']
        assert_equal 1, child['x']
        assert_equal 9, child['y']
      end

      private

      def wrap content_node
        doc = Document.new
        doc.children << content_node
        stream = Stream.new
        stream.children << doc
        stream
      end

      def tagged_tree
        mapping = Mapping.new(nil, TAG)
        mapping.children << Scalar.new('fields')
        mapping.children << Scalar.new('payload')
        wrap(mapping)
      end

      def assert_invalid node
        refute Psych::Nodes::ASTValidator.valid?(node)
        err = assert_raise(Psych::InvalidAST) { Psych::Nodes::ASTValidator.validate!(node) }
        assert_kind_of Psych::Exception, err
        err
      end
    end
  end
end

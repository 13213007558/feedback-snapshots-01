# frozen_string_literal: true

require 'test_helper'

class DropExposureUnitTest < Minitest::Test
  include Liquid

  def test_declaration_before_method_definition_is_sealed_on_first_use
    klass = Class.new(Liquid::Drop) do
      liquid_expose :name

      def name
        'Widget'
      end
    end

    assert_equal('Widget', Liquid::Template.parse('{{ d.name }}').render!('d' => klass.new))
    assert_includes(klass.invokable_methods, 'name')
  end

  def test_declaration_before_later_redefinition_tracks_first_sealed_implementation
    klass = Class.new(Liquid::Drop)

    klass.class_eval do
      liquid_expose :value

      def value
        'first'
      end
    end

    assert_equal('first', Liquid::Template.parse('{{ d.value }}').render!('d' => klass.new))

    klass.class_eval do
      def value
        'second'
      end
    end

    assert_equal('', Liquid::Template.parse('{{ d.value }}').render!('d' => klass.new))
    refute(klass.invokable?('value'))

    klass.liquid_expose :value
    assert_equal('second', Liquid::Template.parse('{{ d.value }}').render!('d' => klass.new))
  end

  def test_aliasing_after_a_seal_revokes_the_original_declaration
    klass = Class.new(Liquid::Drop) do
      liquid_expose :approved

      def secret
        'SECRET'
      end

      def approved
        'approved'
      end
    end

    assert_equal('approved', Liquid::Template.parse('{{ d.approved }}').render!('d' => klass.new))

    klass.class_eval do
      alias_method :approved, :secret
    end

    assert_equal('', Liquid::Template.parse('{{ d.approved }}').render!('d' => klass.new))
    refute(klass.invokable?('approved'))
  end

  def test_alias_declared_before_the_alias_exists_is_sealed_later
    klass = Class.new(Liquid::Drop) do
      liquid_expose :display_name

      def secret
        'SECRET'
      end
    end

    refute(klass.invokable?('display_name'))

    klass.class_eval { alias_method :display_name, :secret }
    assert_equal('SECRET', Liquid::Template.parse('{{ d.display_name }}').render!('d' => klass.new))
  end

  def test_preprended_module_does_not_clobber_parent_approval
    parent = Class.new(Liquid::Drop) do
      liquid_expose :name

      def name
        'parent'
      end
    end

    child = Class.new(parent)
    child.prepend(Module.new do
      def name
        'prepended'
      end
    end)

    assert_equal('', Liquid::Template.parse('{{ d.name }}').render!('d' => child.new))
    refute(child.invokable?('name'))
  end

  def test_removing_an_exposed_method_revokes_it
    klass = Class.new(Liquid::Drop) do
      liquid_expose :removable

      def removable
        'here'
      end
    end

    assert_equal('here', Liquid::Template.parse('{{ d.removable }}').render!('d' => klass.new))
    klass.class_eval { remove_method :removable }

    assert_equal('', Liquid::Template.parse('{{ d.removable }}').render!('d' => klass.new))
    refute(klass.invokable_methods.include?('removable'))
  end

  def test_undefining_an_exposed_method_revokes_it
    klass = Class.new(Liquid::Drop) do
      liquid_expose :gone

      def gone
        'here'
      end
    end

    assert_equal('here', Liquid::Template.parse('{{ d.gone }}').render!('d' => klass.new))
    klass.class_eval { undef_method :gone }

    assert_equal('', Liquid::Template.parse('{{ d.gone }}').render!('d' => klass.new))
    refute(klass.invokable_methods.include?('gone'))
  end

  def test_visibility_killed_then_restored_requires_redeclaration
    klass = Class.new(Liquid::Drop) do
      liquid_expose :value

      def value
        'value'
      end
    end

    assert_equal('value', Liquid::Template.parse('{{ d.value }}').render!('d' => klass.new))
    klass.class_eval { private :value }
    assert_equal('', Liquid::Template.parse('{{ d.value }}').render!('d' => klass.new))

    klass.class_eval { public :value }
    assert_equal('', Liquid::Template.parse('{{ d.value }}').render!('d' => klass.new))

    klass.liquid_expose :value
    assert_equal('value', Liquid::Template.parse('{{ d.value }}').render!('d' => klass.new))
  end

  def test_drop_core_methods_cannot_be_exposed
    klass = Class.new(Liquid::Drop) do
      liquid_expose :inspect, :to_s, :dup, :send
    end

    assert_equal(['to_liquid'], klass.invokable_methods.to_a)
    assert_equal('', Liquid::Template.parse('{{ d.inspect }}').render!('d' => klass.new))
    assert_equal('', Liquid::Template.parse('{{ d.to_s }}').render!('d' => klass.new))
  end

  def test_declaration_on_base_drop_is_rejected
    error = assert_raises(ArgumentError) do
      Liquid::Drop.liquid_expose :value
    end

    assert_match(/subclass/, error.message)
  end

  def test_dynamic_contract_alone_switches_to_explicit_mode
    klass = Class.new(Liquid::Drop) do
      liquid_expose_missing

      def title
        'Widget'
      end
    end

    assert_equal('', Liquid::Template.parse('{{ d.title }}').render!('d' => klass.new))
    assert_equal('', Liquid::Template.parse('{{ d.whatever }}').render!('d' => klass.new))
  end

  def test_fallback_never_serves_a_declared_name_after_removal
    klass = Class.new(Liquid::Drop) do
      liquid_expose :secret
      liquid_expose_missing

      def secret
        'STATIC'
      end

      def liquid_method_missing(name)
        "DYN:#{name}"
      end
    end

    assert_equal('STATIC', Liquid::Template.parse('{{ d.secret }}').render!('d' => klass.new))
    klass.class_eval { remove_method :secret }

    assert_equal('', Liquid::Template.parse('{{ d.secret }}').render!('d' => klass.new))
    assert_equal('DYN:other', Liquid::Template.parse('{{ d.other }}').render!('d' => klass.new))
  end

  def test_integer_and_boolean_bracket_keys_do_not_raise
    klass = Class.new(Liquid::Drop) do
      liquid_expose :name

      def name
        'Widget'
      end
    end

    assert_equal('', Liquid::Template.parse('{{ d[0] }}').render!('d' => klass.new))
    assert_equal('', Liquid::Template.parse('{{ d[true] }}').render!('d' => klass.new))
  end

  def test_invokable_methods_returns_the_effective_allow_list
    klass = Class.new(Liquid::Drop) do
      liquid_expose :name, :missing

      def name
        'Widget'
      end
    end

    assert_equal(['to_liquid', 'name'].to_set, klass.invokable_methods)
  end
end

# frozen_string_literal: true

require 'test_helper'

class DropExposureTest < Minitest::Test
  include Liquid

  class ProductDrop < Liquid::Drop
    liquid_expose :title, :price

    attr_reader :internal_hits

    def initialize
      super
      @internal_hits = 0
    end

    def title
      'Widget'
    end

    def price
      9.99
    end

    # Public for internal administration use only. It must never be reachable
    # from a template just because it is public.
    def rebuild_search_index
      @internal_hits += 1
      'index rebuilt'
    end

    def method_missing(name, *args)
      super
    end
  end

  class ChildProductDrop < ProductDrop
  end

  class ChildWithOverride < ProductDrop
    def title
      'Overridden'
    end
  end

  class ChildWithRedeclaredOverride < ProductDrop
    liquid_expose :title

    def title
      'Redeclared'
    end
  end

  class ChildWithExtraExposure < ProductDrop
    liquid_expose :description

    def description
      'Extra'
    end
  end

  module CategoryMethods
    def category
      'tools'
    end
  end

  class DropWithModule < Liquid::Drop
    include CategoryMethods

    liquid_expose :category
  end

  class DropWithUnexposedModule < Liquid::Drop
    include CategoryMethods

    liquid_expose :title

    def title
      'Widget'
    end
  end

  class DropWithAlias < Liquid::Drop
    liquid_expose :display_name

    def secret_name
      'SECRET'
    end

    alias display_name secret_name
  end

  class DropWithValidAlias < Liquid::Drop
    liquid_expose :display_name

    def name
      'Widget'
    end

    alias display_name name
  end

  class DropWithVisibilityChange < Liquid::Drop
    liquid_expose :secret

    def secret
      'SECRET'
    end

    private :secret
  end

  class DropWithVisibilityRestored < Liquid::Drop
    liquid_expose :secret

    def secret
      'SECRET'
    end

    private :secret
    public :secret
  end

  class DropExposingProtectedMethod < Liquid::Drop
    liquid_expose :secret

    protected

    def secret
      'SECRET'
    end
  end

  class DynamicDrop < Liquid::Drop
    liquid_expose :title
    liquid_expose_missing

    def title
      'Widget'
    end

    def liquid_method_missing(name)
      "dynamic:#{name}"
    end

    def internal_admin
      'SECRET'
    end
  end

  class DynamicDropWithoutOptIn < Liquid::Drop
    liquid_expose :title

    def title
      'Widget'
    end

    def liquid_method_missing(name)
      "dynamic:#{name}"
    end
  end

  class DynamicDropWithNames < Liquid::Drop
    liquid_expose :title
    liquid_expose_missing :theme, :locale

    def title
      'Widget'
    end

    def liquid_method_missing(name)
      "dynamic:#{name}"
    end
  end

  class DynamicDropWithPredicate < Liquid::Drop
    liquid_expose :title
    liquid_expose_missing { |name| name.start_with?('section.') }

    def title
      'Widget'
    end

    def liquid_method_missing(name)
      "dynamic:#{name}"
    end
  end

  class RedefinableDrop < Liquid::Drop
    liquid_expose :field

    def field
      'one'
    end
  end

  class CacheDrop < Liquid::Drop
    liquid_expose :field

    def field
      'one'
    end
  end

  class LegacyAccountDrop < Liquid::Drop
    attr_reader :internal_hits

    def initialize
      super
      @internal_hits = 0
    end

    def name
      'Acme'
    end

    def plan
      'pro'
    end

    def admin_export
      @internal_hits += 1
      'EXPORTED'
    end
  end

  class MigratedAccountDrop < Liquid::Drop
    liquid_expose :name, :plan

    attr_reader :internal_hits

    def initialize
      super
      @internal_hits = 0
    end

    def name
      'Acme'
    end

    def plan
      'pro'
    end

    def admin_export
      @internal_hits += 1
      'EXPORTED'
    end
  end

  class LegacyDrop < Liquid::Drop
    def title
      'Widget'
    end

    def liquid_method_missing(name)
      "legacy:#{name}"
    end
  end

  def render(template, assigns = {})
    Liquid::Template.parse(template).render!(assigns)
  end

  def test_exposed_method_is_readable_with_dot_and_bracket_notation
    drop = ProductDrop.new

    assert_equal('Widget', render('{{ product.title }}', 'product' => drop))
    assert_equal('Widget', render('{{ product["title"] }}', 'product' => drop))
    assert_equal('9.99', render('{{ product.price }}', 'product' => drop))
    assert_equal('9.99', render('{{ product["price"] }}', 'product' => drop))
  end

  def test_internal_public_method_cannot_be_invoked_and_is_not_called
    drop = ProductDrop.new

    assert_equal('', Liquid::Template.parse('{{ product.rebuild_search_index }}').render!('product' => drop))
    assert_equal('', Liquid::Template.parse('{{ product["rebuild_search_index"] }}').render!('product' => drop))
    assert_equal('', Liquid::Template.parse('{{ product | map: "rebuild_search_index" }}').render!('product' => [drop]))
    assert_equal(0, drop.internal_hits)

    # Sanity check that the counter works when the method is called directly.
    drop.rebuild_search_index
    assert_equal(1, drop.internal_hits)
    assert_equal('', Liquid::Template.parse('{{ product.rebuild_search_index }}').render!('product' => drop))
    assert_equal(1, drop.internal_hits)
  end

  def test_internal_method_is_not_exported_by_invokable_methods
    refute(ProductDrop.invokable?('rebuild_search_index'))
    refute_includes(ProductDrop.invokable_methods, 'rebuild_search_index')
  end

  def test_unknown_method_does_not_fall_through_to_catch_all_without_opt_in
    drop = DynamicDropWithoutOptIn.new

    assert_equal('', render('{{ product.whatever }}', 'product' => drop))
    assert_equal('', render('{{ product["whatever"] }}', 'product' => drop))
  end

  def test_inheritance_keeps_explicit_exposure
    drop = ChildProductDrop.new

    assert_equal('Widget', render('{{ product.title }}', 'product' => drop))
    assert_equal('', render('{{ product.rebuild_search_index }}', 'product' => drop))
    assert_equal(0, drop.internal_hits)
  end

  def test_subclass_override_does_not_inherit_permission
    drop = ChildWithOverride.new

    assert_equal('', render('{{ product.title }}', 'product' => drop))
    assert_equal('', render('{{ product["title"] }}', 'product' => drop))
    refute(ChildWithOverride.invokable?('title'))
  end

  def test_subclass_can_redeclare_overridden_method
    drop = ChildWithRedeclaredOverride.new

    assert_equal('Redeclared', render('{{ product.title }}', 'product' => drop))
    assert_includes(ChildWithRedeclaredOverride.invokable_methods, 'title')
  end

  def test_subclass_can_add_its_own_exposures
    drop = ChildWithExtraExposure.new

    assert_equal('Widget', render('{{ product.title }}', 'product' => drop))
    assert_equal('Extra', render('{{ product.description }}', 'product' => drop))
    refute(ChildWithExtraExposure.invokable?('rebuild_search_index'))
  end

  def test_included_module_method_can_be_exposed
    drop = DropWithModule.new

    assert_equal('tools', render('{{ d.category }}', 'd' => drop))
    assert_equal('tools', render('{{ d["category"] }}', 'd' => drop))
  end

  def test_included_module_method_is_not_exposed_without_declaration
    drop = DropWithUnexposedModule.new

    assert_equal('', render('{{ d.category }}', 'd' => drop))
    refute(DropWithUnexposedModule.invokable?('category'))
  end

  def test_alias_must_be_the_declared_name
    drop = DropWithAlias.new

    assert_equal('SECRET', render('{{ d.display_name }}', 'd' => drop))
    assert_equal('', render('{{ d.secret_name }}', 'd' => drop))
  end

  def test_alias_of_an_exposed_method_is_not_exposed_without_a_declaration
    drop = DropWithValidAlias.new

    assert_equal('Widget', render('{{ d.display_name }}', 'd' => drop))
    assert_equal('', render('{{ d.name }}', 'd' => drop))
  end

  def test_visibility_change_revokes_exposure
    drop = DropWithVisibilityChange.new

    assert_equal('', render('{{ d.secret }}', 'd' => drop))
    refute(DropWithVisibilityChange.invokable?('secret'))
  end

  def test_restoring_visibility_does_not_restore_revoked_exposure
    drop = DropWithVisibilityRestored.new

    assert_equal('SECRET', render('{{ d.secret }}', 'd' => drop))

    DropWithVisibilityRestored.class_eval { private :secret }
    assert_equal('', render('{{ d.secret }}', 'd' => drop))

    DropWithVisibilityRestored.class_eval { public :secret }
    assert_equal('', render('{{ d.secret }}', 'd' => drop))

    # The declaration must be confirmed again after a revocation.
    DropWithVisibilityRestored.liquid_expose :secret
    assert_equal('SECRET', render('{{ d.secret }}', 'd' => drop))
  end

  def test_protected_method_cannot_be_exposed
    drop = DropExposingProtectedMethod.new

    assert_equal('', render('{{ d.secret }}', 'd' => drop))
    refute(DropExposingProtectedMethod.invokable?('secret'))
  end

  def test_dynamic_fields_are_denied_without_opt_in
    drop = DynamicDropWithoutOptIn.new

    assert_equal('', render('{{ d.unknown }}', 'd' => drop))
    assert_equal('', render('{{ d["unknown"] }}', 'd' => drop))
  end

  def test_dynamic_fields_work_after_explicit_opt_in
    drop = DynamicDrop.new

    assert_equal('dynamic:unknown', render('{{ d.unknown }}', 'd' => drop))
    assert_equal('dynamic:unknown', render('{{ d["unknown"] }}', 'd' => drop))
  end

  def test_dynamic_opt_in_cannot_reach_unexposed_real_methods
    drop = DynamicDrop.new

    assert_equal('', render('{{ d.internal_admin }}', 'd' => drop))
    assert_equal('', render('{{ d["internal_admin"] }}', 'd' => drop))
  end

  def test_dynamic_opt_in_can_be_limited_to_names
    drop = DynamicDropWithNames.new

    assert_equal('dynamic:theme', render('{{ d.theme }}', 'd' => drop))
    assert_equal('', render('{{ d.other }}', 'd' => drop))
  end

  def test_dynamic_opt_in_can_use_a_predicate
    drop = DynamicDropWithPredicate.new

    assert_equal('dynamic:section.header', render('{{ d["section.header"] }}', 'd' => drop))
    assert_equal('', render('{{ d.header }}', 'd' => drop))
  end

  def test_dynamic_fields_are_still_readable_from_brackets
    drop = DynamicDrop.new

    assert_equal('dynamic:top', render('{{ d.top }}', 'd' => drop))
    assert_equal('dynamic:top', render('{{ d["top"] }}', 'd' => drop))
  end

  def test_dynamic_fields_do_not_bypass_strict_variables
    template = Liquid::Template.parse('{{ d.unknown }}', error_mode: :lax)
    result = template.render({ 'd' => DynamicDropWithoutOptIn.new }, strict_variables: true)

    assert_equal('', result)
    assert_equal(1, template.errors.size)
    assert_instance_of(Liquid::UndefinedDropMethod, template.errors[0])
  end

  def test_migration_keeps_approved_fields_and_blocks_the_internal_method
    approved = '{{ account.name }}|{{ account["plan"] }}'
    internal = '{{ account.admin_export }}|{{ account["admin_export"] }}'

    legacy = LegacyAccountDrop.new
    migrated = MigratedAccountDrop.new

    assert_equal('Acme|pro', Liquid::Template.parse(approved).render!('account' => legacy))
    assert_equal('Acme|pro', Liquid::Template.parse(approved).render!('account' => migrated))

    assert_equal('EXPORTED|EXPORTED', Liquid::Template.parse(internal).render!('account' => legacy))
    assert_equal(2, legacy.internal_hits)

    assert_equal('|', Liquid::Template.parse(internal).render!('account' => migrated))
    assert_equal(0, migrated.internal_hits)
  end

  def test_legacy_drop_without_declaration_keeps_public_methods_and_catch_all
    drop = LegacyDrop.new

    assert_equal('Widget', render('{{ d.title }}', 'd' => drop))
    assert_equal('legacy:unknown', render('{{ d.unknown }}', 'd' => drop))
  end

  def test_redefining_an_exposed_method_invalidates_it_until_redeclared
    drop = RedefinableDrop.new

    assert_equal('one', render('{{ d.field }}', 'd' => drop))

    RedefinableDrop.class_eval do
      def field
        'two'
      end
    end

    assert_equal('', render('{{ d.field }}', 'd' => drop))
    refute(RedefinableDrop.invokable?('field'))

    RedefinableDrop.liquid_expose :field
    assert_equal('two', render('{{ d.field }}', 'd' => drop))
  end

  def test_invokable_methods_cache_is_refreshed_after_redeclaration
    assert_includes(CacheDrop.invokable_methods, 'field')

    CacheDrop.class_eval do
      def field
        'changed'
      end
    end

    refute_includes(CacheDrop.invokable_methods, 'field')

    CacheDrop.liquid_expose :field
    assert_includes(CacheDrop.invokable_methods, 'field')
  end

  def test_declaration_is_required_to_switch_off_legacy_behavior
    assert(ProductDrop.send(:liquid_exposure_declared?))
    refute(LegacyDrop.send(:liquid_exposure_declared?))
  end
end

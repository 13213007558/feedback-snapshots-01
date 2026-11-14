# frozen_string_literal: true

require 'test_helper'
require_relative 'pure_value_adapter_prototype'
require_relative 'host_method_probe'

class PureValueAdapterTest < Minitest::Test
  include Liquid
  include LiquidSecurityPrototype

  PREVIEW_OPTIONS = { strict_variables: true }.freeze
  DELIVERY_OPTIONS = {}.freeze

  def test_pure_value_snapshot_rejects_plain_business_objects
    error = assert_raises(RejectedValue) { PureValue.call(Fixture.object) }
    assert_match(/no pure-value adapter/, error.message)
  end

  def test_pure_value_snapshot_keeps_only_values_and_normalizes_keys
    snapshot = PureValue.call('name' => :acme, 'tags' => %w[a b], 'nested' => { count: 2 })

    assert_equal({ 'name' => 'acme', 'tags' => %w[a b], 'nested' => { 'count' => 2 } }, snapshot)
  end

  def test_pure_value_snapshot_rejects_cycles_and_non_string_keys
    cyclic = {}
    cyclic['self'] = cyclic
    assert_raises(RejectedValue) { PureValue.call(cyclic) }
    assert_raises(RejectedValue) { PureValue.call({ 1 => 'one' }) }
  end

  def test_adapter_exposes_only_named_business_fields
    adapter = BusinessRefAdapter.new(Fixture.object)

    assert_equal(Set.new(%w(name status tags updated_at to_liquid)), BusinessRefAdapter.invokable_methods)
    refute_includes(BusinessRefAdapter.invokable_methods, 'delete_all')
    refute_includes(BusinessRefAdapter.invokable_methods, 'secret_token')
    assert_equal('acme', adapter.name)
    assert_equal(%w(alpha beta).sort, adapter.tags.sort)
  end

  def test_business_object_is_only_read_through_allowlisted_adapter_methods
    object = Fixture.object
    calls = []

    object.singleton_class.class_eval do
      %i(name status tags updated_at delete_all secret_token).each do |method_name|
        define_method(method_name) do |*args|
          calls << method_name
          super(*args)
        end
      end

      define_method(:to_s) do
        calls << :to_s
        super()
      end
    end

    view = Fixture.snapshot
    view['audit'] = BusinessRefAdapter.new(object)

    output = Template.parse(<<~LIQUID).render!({ 'view' => view }, PREVIEW_OPTIONS)
      {{ view.name }}|{{ view.tags | join: "," }}|{{ view.audit.name }}|{{ view.audit | join: "," }}
    LIQUID

    assert_equal("acme|alpha,beta|acme|acme\n", output)
    assert_equal([:name, :name], calls)
    refute_includes(calls, :delete_all)
    refute_includes(calls, :secret_token)
    refute_includes(calls, :to_s)
  end

  def test_pure_snapshot_path_never_calls_the_business_object
    calls = []
    object = Fixture.object

    object.singleton_class.class_eval do
      %i(name status tags updated_at delete_all secret_token).each do |method_name|
        define_method(method_name) do |*args|
          calls << method_name
          super(*args)
        end
      end
    end

    view = Fixture.snapshot
    Template.parse('{{ view.name }}|{{ view.tags | join: "," }}').render!(
      { 'view' => view },
      PREVIEW_OPTIONS,
    )

    assert_equal([], calls)
  end

  def test_manager_methods_are_not_reachable_by_name_or_structural_protocols
    view = Fixture.snapshot
    view['audit'] = BusinessRefAdapter.new(Fixture.object)

    templates = [
      '{{ view.audit.delete_all }}',
      '{{ view.audit.secret_token }}',
      '{{ view.audit.instance_eval }}',
      '{{ view.audit.send }}',
      '{{ view.audit | map: "delete_all" }}',
      '{{ view.audit | map: "secret_token" }}',
    ]

    templates.each do |template|
      output = Template.parse(template).render!({ 'view' => view })
      assert_equal('', output, "template leaked: #{template}")
    end
  end

  def test_strict_variables_reports_missing_business_field
    view = Fixture.snapshot
    view['audit'] = BusinessRefAdapter.new(Fixture.object)

    error = assert_raises(Liquid::UndefinedDropMethod) do
      Template.parse('{{ view.audit.no_such_field }}').render!({ 'view' => view }, PREVIEW_OPTIONS)
    end
    assert_match(/undefined method no_such_field/, error.message)
  end

  def test_render_parameters_bind_snapshot_and_adapter
    view = Fixture.snapshot
    view['audit'] = BusinessRefAdapter.new(Fixture.object)
    file_system = LiquidSecurityProbe::MemoryFileSystem.new(
      'business' => '{{ business.name }}/{{ business.status }}/{{ business.tags | join: "," }}',
      'audit' => '{{ audit.name }}',
    )

    options = { strict_variables: true, registers: { file_system: file_system } }

    assert_equal(
      'acme/active/alpha,beta',
      Template.parse("{% render 'business' with view %}").render!({ 'view' => view }, options),
    )
    assert_equal(
      'acme',
      Template.parse("{% render 'audit', audit: view.audit %}").render!({ 'view' => view }, options),
    )

    error = assert_raises(Liquid::UndefinedDropMethod) do
      Template.parse("{% render 'audit', audit: view.audit.delete_all %}").render!({ 'view' => view }, options)
    end
    assert_match(/undefined method delete_all/, error.message)
  end

  def test_preview_and_delivery_render_the_same_business_values
    view = Fixture.snapshot
    view['audit'] = BusinessRefAdapter.new(Fixture.object)
    template = Template.parse('{{ view.name }}|{{ view.status }}|{{ view.audit.name }}')

    preview = template.render!({ 'view' => view }, PREVIEW_OPTIONS)
    delivery = template.render!({ 'view' => view }, DELIVERY_OPTIONS)

    assert_equal('acme|active|acme', preview)
    assert_equal(preview, delivery)
  end

  def test_filters_only_see_plain_values_or_allowlisted_adapter_fields
    view = Fixture.snapshot
    view['audit'] = BusinessRefAdapter.new(Fixture.object)

    assert_equal('acme', Template.parse('{{ view.audit | where: "name", "acme" | join: "," }}').render!({ 'view' => view }))
    assert_equal('acme', Template.parse('{{ view.audit | map: "name" | join: "," }}').render!({ 'view' => view }))
  end

  def test_plain_values_are_safe_for_conditions_and_iteration
    view = Fixture.snapshot

    assert_equal('Y', Template.parse('{% if view.tags contains "alpha" %}Y{% endif %}').render!({ 'view' => view }))

    loop_template = Template.parse(
      '{% for tag in view.tags %}{{ tag }}{% if forloop.last %}{% else %},{% endif %}{% endfor %}',
    )
    assert_equal('alpha,beta', loop_template.render!({ 'view' => view }))
  end
end

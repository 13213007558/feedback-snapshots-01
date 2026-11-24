# frozen_string_literal: true

RSpec.describe Grape::HelperCallPermission do
  let(:base_module) { Module.new { def settle = :public } }
  let(:override_module) { Module.new { def settle = :override } }
  let(:log) { [] }
  let(:policy) do
    Grape::HelperCallPermission::Policy.new.allow(:settle, scope: :billing, owner: base_module)
  end
  let(:enforcement) do
    Grape::HelperCallPermission::Enforcement.new(policy:, scope: :billing, methods: %i[settle], recorder: log)
  end
  let(:endpoint_class) do
    guard = enforcement
    base = base_module
    Class.new do
      composed = Module.new do
        include guard.helper_module
        include base
      end
      include composed
    end
  end

  describe Grape::HelperCallPermission::Policy do
    it 'requires an exact implementation selector' do
      expect { Grape::HelperCallPermission::Policy.new.allow(:settle, scope: :billing) }.to raise_error(ArgumentError, /exact owner/)
    end

    it 'rejects the same method name from another owner or scope' do
      definition = Grape::HelperCallPermission::Definition.from_method(override_module.instance_method(:settle))
      decision = policy.authorize(definition, scope: :billing)

      expect(decision).not_to be_allowed
      expect(decision.reason).to include('unapproved implementation', '#settle', 'Approved implementations')
    end

    it 'matches a source location pattern against path and line' do
      method = base_module.instance_method(:settle)
      location_pattern = Regexp.new(method.source_location.first)
      source_policy = Grape::HelperCallPermission::Policy.new.allow(:settle, scope: :source, source_location: location_pattern)
      definition = Grape::HelperCallPermission::Definition.from_method(method)

      expect(source_policy.authorize(definition, scope: :source)).to be_allowed
    end
  end

  describe 'enforcement' do
    it 'checks the definition resolved after a later override is prepended' do
      endpoint = endpoint_class.new

      expect(endpoint.settle).to eq(:public)
      expect(log.last).to include(phase: :allowed, owner: base_module)

      base_module.prepend(override_module)

      expect { endpoint.settle }.to raise_error(described_class::Denied, /unapproved implementation/)
      expect(log.last).to include(phase: :denied, owner: override_module)
    end

    it 'accepts any callable recorder' do
      calls = []
      callable = ->(entry) { calls << entry }
      guard = described_class::Enforcement.new(policy:, scope: :billing, methods: :settle, recorder: callable)
      base = base_module
      klass = Class.new { include base }
      klass.include(guard.helper_module)

      expect(klass.new.settle).to eq(:public)
      expect(calls.last[:phase]).to eq(:allowed)
    end
  end
end

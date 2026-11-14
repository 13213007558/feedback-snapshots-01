# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/freeze_time_helper'

describe 'Rack::Attack.bounded_throttle' do
  before do
    @period = 60
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  def request_for(email, ip: '1.2.3.4', tenant: 't1')
    env = Rack::MockRequest.env_for(
      "/login?email=#{Rack::Utils.escape(email)}",
      method: 'POST',
      'REMOTE_ADDR' => ip,
      'HTTP_X_TENANT' => tenant
    )
    Rack::Attack::Request.new(env)
  end

  def check(throttle, email, **options)
    request = request_for(email, **options)
    [throttle.matched_by?(request), request.env['rack.attack.throttle_data'][throttle.name]]
  end

  it 'is configurable through the public DSL' do
    Rack::Attack.bounded_throttle('login/account', limit: 2, period: @period) { |req| req.params['email'] }

    _(Rack::Attack.bounded_throttles.key?('login/account')).must_equal true
  end

  it 'limits repeated requests for one account' do
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account', { limit: 2, period: @period, buckets: 32, depth: 3 }
    ) { |req| req.params['email'] }

    within_same_period do
      _(check(throttle, 'person@example.com')[0]).must_equal false
      _(check(throttle, 'person@example.com')[0]).must_equal false
      _(check(throttle, 'person@example.com')[0]).must_equal true
    end
  end

  it 'does not create one cache key per distinct account' do
    store = Rack::Attack.cache.store
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account', { limit: 2, period: @period, buckets: 32, depth: 3 }
    ) { |req| req.params['email'] }

    within_same_period do
      1000.times { |i| check(throttle, "account-#{i}@example.com") }
    end

    _(store.instance_variable_get(:@data).size).must_be :<=, throttle.max_state_keys
  end

  it 'blocks account rotation with a tenant budget' do
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account',
      {
        strategy: :hybrid,
        limit: 2,
        period: @period,
        buckets: 32,
        depth: 3,
        budgets: {
          tenant: { limit: 5, buckets: 8, discriminator: ->(req) { req.get_header('HTTP_X_TENANT') } }
        }
      }
    ) { |req| req.params['email'] }

    within_same_period do
      results = 12.times.map { |i| check(throttle, "account-#{i}@example.com", tenant: 't1')[0] }
      _(results.count(false)).must_equal 5
      _(results.count(true)).must_equal 7
      _(check(throttle, 'other@example.com', tenant: 't2')[0]).must_equal false
    end
  end

  it 'does not pollute the sketch when the budget already blocks' do
    store = Rack::Attack.cache.store
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account',
      {
        strategy: :hybrid,
        limit: 2,
        period: @period,
        buckets: 32,
        depth: 3,
        budgets: { tenant: { limit: 2, buckets: 8, discriminator: ->(req) { 't1' } } }
      }
    ) { |req| req.params['email'] }

    within_same_period do
      2.times { |i| check(throttle, "a#{i}@example.com") }
      before_keys = store.instance_variable_get(:@data).size
      1000.times { |i| check(throttle, "flood-#{i}@example.com") }
      after_keys = store.instance_variable_get(:@data).size

      _(after_keys).must_equal before_keys
      _(check(throttle, 'popular@example.com')[1][:matched_budget]).must_equal :tenant
    end
  end

  it 'bounds a high-cardinality attack with a global budget' do
    store = Rack::Attack.cache.store
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account',
      {
        strategy: :hybrid,
        limit: 10,
        period: @period,
        buckets: 256,
        depth: 3,
        budgets: { global: { limit: 50, buckets: 1 } }
      }
    ) { |req| req.params['email'] }

    within_same_period do
      5000.times { |i| check(throttle, "flood-#{i}@example.com") }
    end

    _(store.instance_variable_get(:@data).size).must_be :<=, throttle.max_state_keys
  end

  it 'uses a bounded sketch without a trusted dimension' do
    store = Rack::Attack.cache.store
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account', { limit: 5, period: @period, buckets: 512, depth: 3, strategy: :sketch }
    ) { |req| req.params['email'] }

    within_same_period do
      2000.times { |i| check(throttle, "flood-#{i}@example.com") }
    end

    _(store.instance_variable_get(:@data).size).must_be :<=, throttle.max_state_keys
  end

  it 'stops at the first blocking budget' do
    store = Rack::Attack.cache.store
    calls = []
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account',
      {
        strategy: :hybrid,
        limit: 2,
        period: @period,
        buckets: 32,
        depth: 3,
        budgets: {
          tenant: {
            limit: 1,
            buckets: 8,
            discriminator: lambda { |req|
              calls << req.get_header('HTTP_X_TENANT')
              req.get_header('HTTP_X_TENANT')
            }
          },
          global: { limit: 100, buckets: 1 }
        }
      }
    ) { |req| req.params['email'] }

    within_same_period do
      check(throttle, 'first@example.com')
      global_key = store.instance_variable_get(:@data).keys.grep(/budget:global/).first
      _(store.read(global_key)).must_equal 1

      check(throttle, 'second@example.com')
      _(store.read(global_key)).must_equal 1
    end

    _(calls).must_include 't1'
  end

  it 'isolates sketch state by scope buckets' do
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account',
      {
        limit: 1,
        period: @period,
        buckets: 32,
        depth: 3,
        scope_buckets: 16,
        scope: ->(req) { req.get_header('HTTP_X_TENANT') }
      }
    ) { |req| req.params['email'] }

    within_same_period do
      _(check(throttle, 'person@example.com', tenant: 't1')[0]).must_equal false
      _(check(throttle, 'person@example.com', tenant: 't1')[0]).must_equal true
      _(check(throttle, 'person@example.com', tenant: 't2')[0]).must_equal false
    end
  end

  it 'expires all bounded state after the period' do
    store = Rack::Attack.cache.store
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account', { limit: 2, period: 1, buckets: 32, depth: 3 }
    ) { |req| req.params['email'] }

    Timecop.freeze(Time.at(1000)) do
      3.times { check(throttle, 'person@example.com') }
      _(check(throttle, 'person@example.com')[0]).must_equal true
    end

    Timecop.freeze(Time.at(1002)) do
      _(check(throttle, 'person@example.com')[0]).must_equal false
      _(store.instance_variable_get(:@data).size).must_be :<=, throttle.max_state_keys
    end
  end

  it 'bounds exact account keys by admitting only global-budget traffic' do
    store = Rack::Attack.cache.store
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account',
      {
        strategy: :gate,
        limit: 1,
        period: @period,
        budgets: { global: { limit: 50, buckets: 1 } }
      }
    ) { |req| req.params['email'] }

    within_same_period do
      1000.times { |i| check(throttle, "flood-#{i}@example.com") }
    end

    _(store.instance_variable_get(:@data).size).must_be :<=, throttle.max_state_keys
    _(throttle.max_state_keys).must_equal 51
  end

  it 'still applies the exact per-account limit in gate mode' do
    throttle = Rack::Attack::BoundedThrottle.new(
      'login/account',
      {
        strategy: :gate,
        limit: 1,
        period: @period,
        budgets: { global: { limit: 100, buckets: 1 } }
      }
    ) { |req| req.params['email'] }

    within_same_period do
      _(check(throttle, 'person@example.com')[0]).must_equal false
      _(check(throttle, 'person@example.com')[0]).must_equal true
      _(check(throttle, 'other@example.com')[0]).must_equal false
    end
  end

  it 'rejects invalid bounded-state options' do
    _(lambda do
      Rack::Attack::BoundedThrottle.new('x', { limit: 3, period: 60, buckets: 3 }) { |_req| 'a' }
    end).must_raise ArgumentError

    _(lambda do
      Rack::Attack::BoundedThrottle.new('x', { limit: 3, period: 60, strategy: :budget }) { |_req| 'a' }
    end).must_raise ArgumentError

    _(lambda do
      Rack::Attack::BoundedThrottle.new(
        'x', { limit: 3, period: 60, strategy: :gate, budgets: { ip: { limit: 5, period: 120,
                                                                     discriminator: ->(_r) { '1' } } } }
      ) { |_req| 'a' }
    end).must_raise ArgumentError

    _(lambda do
      Rack::Attack::BoundedThrottle.new('x', { limit: 3, period: 60, strategy: :nope }) { |_req| 'a' }
    end).must_raise ArgumentError
  end
end

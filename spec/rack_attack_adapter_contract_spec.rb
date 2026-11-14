# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/counting/harness"
require_relative "support/counting/reference_model"
require "minitest/stub_const"

# Offline fakes that stand behind the *real* store proxy implementations, so
# the adapter contract can be probed without connecting to Redis/Memcached.
module AdapterContractFakes
  # Mimics the redis gem's client: pipelined commands, and a connection
  # error that can be raised before or after the command was applied.
  class FakeRedis
    VERSION = "5.4.0"

    class BaseConnectionError < RuntimeError; end

    class Store < FakeRedis; end

    attr_reader :expire_calls

    def initialize
      @data = {}
      @expire_calls = 0
      @failure = nil
      @pipeline = nil
    end

    # Arms a one-shot connection error. With apply: true the command is
    # applied but the response is lost (unknown outcome); with apply: false
    # the command never happened (but the caller cannot tell either).
    def fail_next!(error, apply:)
      @failure = [error, apply]
    end

    def get(key, **_options)
      @data[key]
    end

    def set(key, value, **_options)
      @data[key] = value.to_s
      "OK"
    end

    def setex(key, ttl, value, **_options)
      @data[key] = value.to_s
      "OK"
    end

    def incrby(key, amount)
      command do
        @data[key] = (@data[key].to_i + amount).to_s
        record(@data[key].to_i)
      end
    end

    def expire(_key, _ttl)
      @expire_calls += 1
      record(true)
    end

    def del(*keys)
      keys.each { |key| @data.delete(key) }
      true
    end

    def pipelined
      @pipeline = []
      yield self
      @pipeline
    ensure
      @pipeline = nil
    end

    private

    def command
      failure = @failure
      @failure = nil
      return yield unless failure

      error, apply = failure
      yield if apply
      raise error
    end

    def record(value)
      @pipeline << value if @pipeline
      value
    end
  end

  # Mimics Dalli::Client: incr with an initial value, raw set, and a
  # DalliError that can be raised before or after applying.
  class FakeDalliClient
    def initialize
      @data = {}
      @failure = nil
    end

    def fail_next!(error, apply:)
      @failure = [error, apply]
    end

    def get(key)
      @data[key]
    end

    def set(key, value, _ttl = 0, raw: false)
      @data[key] = value
      true
    end

    def incr(key, amount, _ttl, initial)
      apply = lambda do
        if @data.key?(key)
          @data[key] = (@data[key].to_i + amount).to_s
        elsif initial
          @data[key] = initial.to_s
        end
        @data[key] && @data[key].to_i
      end
      failure = @failure
      @failure = nil
      if failure
        error, should_apply = failure
        apply.call if should_apply
        raise error
      end
      apply.call
    end

    def delete(key)
      @data.delete(key)
      true
    end
  end

  FakeDalli = Module.new
  FakeDalli.const_set(:Client, FakeDalliClient)
  FakeDalli.const_set(:DalliError, Class.new(StandardError))
end

# Compares every store adapter shipped in lib/ against the reference model's
# capability contract. Everything here runs offline: fakes stand in for the
# network backends, and no test sleeps.
describe "Store adapter contracts vs the reference model" do
  WINDOW_KEY = "rack::attack:#{1_700_000_000 / 30}:attack"

  def memory_store_row
    store = ActiveSupport::Cache::MemoryStore.new
    first = store.increment("probe:1", 1, expires_in: 30)
    second = store.increment("probe:1", 1, expires_in: 30)
    confirmed = store.write("probe:2", 1, expires_in: 30)

    store.increment("probe:ttl", 1, expires_in: 30)
    expired = Timecop.travel(Time.now + 31) { store.read("probe:ttl") }

    refreshed = ActiveSupport::Cache::MemoryStore.new
    refreshed.increment("k", 1, expires_in: 30)
    Timecop.travel(Time.now + 20) { refreshed.increment("k", 1, expires_in: 30) }
    still_alive = Timecop.travel(Time.now + 45) { !refreshed.read("k").nil? }

    {
      name: "ActiveSupport::Cache::MemoryStore",
      loadable_offline: true,
      atomic_increment: first == 1 && second == 2,
      ttl: expired.nil?,
      ttl_scope: still_alive ? :every_increment : :on_create,
      confirmed_write: confirmed == true,
      swallows_store_errors: false,
      unknown_outcome_possible: false # in-process: no network between caller and store
    }
  end

  def redis_proxy_row(store_class: AdapterContractFakes::FakeRedis, proxy_class: Rack::Attack::StoreProxy::RedisProxy,
                      name: "Rack::Attack::StoreProxy::RedisProxy")
    Object.stub_const(:Redis, AdapterContractFakes::FakeRedis) do
      fake = store_class.new
      proxy = proxy_class.new(fake)
      first = proxy.increment("k", 1, expires_in: 30)
      second = proxy.increment("k", 1, expires_in: 30)
      confirmed = proxy.write("k2", 1, expires_in: 30)

      fake.fail_next!(Redis::BaseConnectionError.new("timeout"), apply: true)
      swallowed = proxy.increment("k", 1, expires_in: 30).nil?

      {
        name: name,
        loadable_offline: true,
        atomic_increment: first == 1 && second == 2,
        ttl: true,
        ttl_scope: fake.expire_calls >= 2 ? :every_increment : :on_create,
        confirmed_write: !confirmed.nil? && confirmed != false,
        swallows_store_errors: swallowed,
        unknown_outcome_possible: true
      }
    end
  end

  def dalli_proxy_row
    Object.stub_const(:Dalli, AdapterContractFakes::FakeDalli) do
      fake = AdapterContractFakes::FakeDalliClient.new
      proxy = Rack::Attack::StoreProxy::DalliProxy.new(fake)
      first = proxy.increment("k", 1, expires_in: 30)
      second = proxy.increment("k", 1, expires_in: 30)
      confirmed = proxy.write("k2", 1, expires_in: 30)

      fake.fail_next!(Dalli::DalliError.new("timeout"), apply: true)
      swallowed = proxy.increment("k", 1, expires_in: 30).nil?

      {
        name: "Rack::Attack::StoreProxy::DalliProxy",
        loadable_offline: true,
        atomic_increment: first == 1 && second == 2,
        ttl: true,
        ttl_scope: :on_create, # memcached incr carries no TTL; only the initial add sets it
        confirmed_write: confirmed == true,
        swallows_store_errors: swallowed,
        unknown_outcome_possible: true
      }
    end
  end

  def offline_row(name, requirement)
    {
      name: name,
      loadable_offline: false,
      note: "backend not loadable offline (#{requirement}); contract assessed from source"
    }
  end

  def contract_rows
    [
      memory_store_row,
      redis_proxy_row,
      redis_proxy_row(
        store_class: AdapterContractFakes::FakeRedis::Store,
        proxy_class: Rack::Attack::StoreProxy::RedisStoreProxy,
        name: "Rack::Attack::StoreProxy::RedisStoreProxy"
      ),
      dalli_proxy_row,
      offline_row("Rack::Attack::StoreProxy::RedisCacheStoreProxy", "redis gem not in bundle"),
      offline_row("Rack::Attack::StoreProxy::MemCacheStoreProxy", "dalli gem not in bundle")
    ]
  end

  it "loads every proxy class shipped in lib/" do
    assert defined?(Rack::Attack::StoreProxy::RedisProxy)
    assert defined?(Rack::Attack::StoreProxy::RedisStoreProxy)
    assert defined?(Rack::Attack::StoreProxy::RedisCacheStoreProxy)
    assert defined?(Rack::Attack::StoreProxy::DalliProxy)
    assert defined?(Rack::Attack::StoreProxy::MemCacheStoreProxy)
  end

  it "cannot load the Redis/Memcached ActiveSupport backends offline" do
    assert_raises(LoadError) { require "active_support/cache/redis_cache_store" }
    assert_raises(LoadError) { require "active_support/cache/mem_cache_store" }
  end

  it "probes each loadable adapter against the capability contract" do
    rows = contract_rows.select { |row| row[:loadable_offline] }

    rows.each do |row|
      assert row[:atomic_increment], "#{row[:name]} must initialize and increment atomically"
      assert row[:confirmed_write], "#{row[:name]} must confirm writes"
    end

    memory = rows.find { |row| row[:name].include?("MemoryStore") }
    redis = rows.find { |row| row[:name].include?("RedisProxy") }
    dalli = rows.find { |row| row[:name].include?("DalliProxy") }

    assert_equal :on_create, memory[:ttl_scope]
    assert_equal :every_increment, redis[:ttl_scope],
                 "RedisProxy re-expires the key on every increment, sliding the window"
    assert_equal :on_create, dalli[:ttl_scope]

    refute memory[:swallows_store_errors]
    assert redis[:swallows_store_errors], "RedisProxy rescues connection errors into nil"
    assert dalli[:swallows_store_errors], "DalliProxy rescues DalliError into nil"
  end

  it "shows no adapter can promise the threshold under unknown-outcome faults" do
    rows = contract_rows.select { |row| row[:loadable_offline] }

    rows.each do |row|
      capabilities = { atomic_increment: row[:atomic_increment], ttl: row[:ttl] }

      fault_free = CountingHarness::ReferenceModel.promise(capabilities, faults: [], overlapped: true)
      assert fault_free.guaranteed?, "#{row[:name]} should promise the threshold when fault-free"

      timed_out = CountingHarness::ReferenceModel.promise(
        capabilities, faults: [:timeout_after], overlapped: false
      )
      refute timed_out.safety, "#{row[:name]} cannot promise safety once outcomes are unknown"
      refute timed_out.liveness, "#{row[:name]} cannot promise liveness once outcomes are unknown"
    end
  end

  it "catches RedisProxy turning an unknown outcome into a clobbering fallback write" do
    Object.stub_const(:Redis, AdapterContractFakes::FakeRedis) do
      fake = AdapterContractFakes::FakeRedis.new
      cache = Rack::Attack::Cache.new(store: fake)
      _(cache.store).must_be_instance_of Rack::Attack::StoreProxy::RedisProxy

      Timecop.freeze(Time.at(1_700_000_000)) do
        assert_equal 1, cache.count("attack", 30)

        # The INCR is applied server-side (count is really 2) but the
        # connection drops before the response arrives. The proxy rescues
        # the error into nil, Cache#do_count reads it as "key absent" and
        # overwrites the real count with 1.
        fake.fail_next!(Redis::BaseConnectionError.new("timeout"), apply: true)
        assert_equal 1, cache.count("attack", 30)
        assert_equal "1", fake.get(WINDOW_KEY), "the real count of 2 was clobbered back to 1"

        # Net effect with limit 1: two attack requests were admitted, and
        # the counter restarted — without the clobber this would read 3.
        assert_equal 2, cache.count("attack", 30)
      end
    end
  end

  it "catches RedisStoreProxy with the same unknown-outcome hazard" do
    Object.stub_const(:Redis, AdapterContractFakes::FakeRedis) do
      fake = AdapterContractFakes::FakeRedis::Store.new
      cache = Rack::Attack::Cache.new(store: fake)
      _(cache.store).must_be_instance_of Rack::Attack::StoreProxy::RedisStoreProxy

      Timecop.freeze(Time.at(1_700_000_000)) do
        assert_equal 1, cache.count("attack", 30)
        fake.fail_next!(Redis::BaseConnectionError.new("timeout"), apply: true)
        assert_equal 1, cache.count("attack", 30)
        assert_equal "1", fake.get(WINDOW_KEY)
      end
    end
  end

  it "catches DalliProxy with the same unknown-outcome hazard" do
    Object.stub_const(:Dalli, AdapterContractFakes::FakeDalli) do
      fake = AdapterContractFakes::FakeDalliClient.new
      cache = Rack::Attack::Cache.new(store: fake)
      _(cache.store).must_be_instance_of Rack::Attack::StoreProxy::DalliProxy

      Timecop.freeze(Time.at(1_700_000_000)) do
        assert_equal 1, cache.count("attack", 30)
        fake.fail_next!(Dalli::DalliError.new("timeout"), apply: true)
        assert_equal 1, cache.count("attack", 30)
        assert_equal "1", fake.get(WINDOW_KEY)
      end
    end
  end

  it "prints the adapter contract matrix" do
    rows = contract_rows
    puts "\nAdapter contract matrix (offline probes, no Redis/Memcached connections):"
    rows.each do |row|
      if row[:loadable_offline]
        puts format(
          "  %-45s atomic_incr=%-5s ttl=%-15s confirmed_write=%-5s swallows_errors=%-5s",
          row[:name], row[:atomic_increment], row[:ttl_scope], row[:confirmed_write],
          row[:swallows_store_errors]
        )
      else
        puts format("  %-45s %s", row[:name], row[:note])
      end
    end

    differences = rows.select { |row| row[:loadable_offline] }
                      .map { |row| [row[:ttl_scope], row[:swallows_store_errors]] }
                      .uniq
    assert_operator differences.length, :>, 1, "adapters genuinely differ from the model contract"
  end
end

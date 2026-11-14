# frozen_string_literal: true

require_relative "spec_helper"
require_relative "support/counting/harness"
require_relative "support/counting/reference_model"
require_relative "support/counting/generator"

# State-machine tests for the Rack::Attack::Cache counting chain.
#
# Instead of checking call counts, these tests check *how many attack
# requests get admitted* when the cache returns nil, the first write races,
# the window expires, or a timeout hits before/after the write. A reference
# model states which store capabilities suffice for the threshold promise,
# and which promises cannot exist when capabilities are missing.
describe "Rack::Attack::Cache counting state machine" do
  # A client that treats a nil increment as "over the limit" instead of
  # "key absent": keeps the safety promise under any fault, at the cost of
  # blocking some legitimate requests (liveness).
  class FailClosedCache < Rack::Attack::Cache
    private

    def do_count(key, expires_in)
      raise Rack::Attack::MissingStoreError if store.nil?

      result = store.increment(key, 1, expires_in: expires_in)
      result.nil? ? (1 << 62) : result
    end
  end

  def run_script(script, increment_style: :atomic, ttl: true, cache_class: Rack::Attack::Cache, period: 30)
    clock = CountingHarness::LogicalClock.new
    store = CountingHarness::ScriptedStore.new(clock, increment_style: increment_style, ttl: ttl)
    cache = cache_class.new(store: store)
    result = CountingHarness::Runner.new(cache, clock, period).run(script)
    [result, store]
  end

  def run_on_memory_store(script)
    clock = CountingHarness::LogicalClock.new
    cache = Rack::Attack::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    CountingHarness::Runner.new(cache, clock, 30).run(script)
  end

  def consistent?(result)
    CountingHarness::ReferenceModel.consistent?(result)
  end

  it "reproduces the reference model on a fully capable store (generated sequences)" do
    [101, 102, 103].each do |seed|
      generator = CountingHarness::Generator.new(seed, tids: [:a, :b, :c], period: 30, max_length: 9)
      100.times do
        script = generator.next
        result, = run_script(script)

        assert consistent?(result), "script: #{script.inspect} counts: #{result.counts.inspect}"
        assert_operator result.admitted(2), :<=, 2, "script: #{script.inspect}"
      end
    end
  end

  it "matches the real ActiveSupport::Cache::MemoryStore to the model (generated sequences)" do
    [201, 202].each do |seed|
      generator = CountingHarness::Generator.new(seed, tids: [:a, :b], period: 30, max_length: 9)
      100.times do
        script = generator.next
        result = run_on_memory_store(script)

        assert consistent?(result), "script: #{script.inspect} counts: #{result.counts.inspect}"
        assert_operator result.admitted(2), :<=, 2, "script: #{script.inspect}"
      end
    end
  end

  it "admits exactly the expected requests on a legal expiry sequence" do
    script = [[:request, :r1], [:request, :r2], [:request, :r3], [:tick, 31], [:request, :r4]]
    result, store = run_script(script)

    assert_equal({ r1: 1, r2: 2, r3: 3, r4: 1 }, result.counts)
    assert_operator result.counts[:r3], :>, 2, "third request in the window must be blocked"
    assert_equal 1, result.counts[:r4], "counter must restart after the window expires"
    assert_equal 1, store.keys.length, "the expired window key must be purged, not leaked"

    promise = CountingHarness::ReferenceModel.promise(
      { atomic_increment: true, ttl: true }, faults: [], overlapped: false
    )
    assert promise.guaranteed?
  end

  it "distinguishes confirmed failure from unknown outcome at the store" do
    clock = CountingHarness::LogicalClock.new
    store = CountingHarness::ScriptedStore.new(clock)
    store.increment("k", 1, expires_in: 30)

    store.arm_fault(:confirm_miss)
    assert_nil store.increment("k", 1, expires_in: 30)
    assert_equal 1, store.value_of("k"), "confirmed failure: definitely not applied"

    store.arm_fault(:timeout_before)
    assert_nil store.increment("k", 1, expires_in: 30)
    assert_equal 1, store.value_of("k"), "timeout before the write: not applied, caller cannot tell"

    store.arm_fault(:timeout_after)
    assert_nil store.increment("k", 1, expires_in: 30)
    assert_equal 2, store.value_of("k"), "timeout after the write: applied, but the caller saw nil"
  end

  it "loses the threshold after a confirmed failure on an existing key" do
    script = [[:request, :r1], [:fault, :confirm_miss], [:request, :r2], [:request, :r3]]
    result, = run_script(script)

    assert_equal({ r1: 1, r2: 1, r3: 2 }, result.counts)
    assert_equal 2, result.admitted(1), "fallback write reset the counter: 2 requests admitted with limit 1"
    refute consistent?(result)

    promise = CountingHarness::ReferenceModel.promise(
      { atomic_increment: true, ttl: true }, faults: [:confirm_miss], overlapped: false
    )
    refute promise.safety
    assert promise.liveness
  end

  it "loses the threshold after a timeout that was actually applied (unknown outcome)" do
    script = [[:request, :r1], [:fault, :timeout_after], [:request, :r2], [:request, :r3]]
    result, store = run_script(script)

    assert_equal({ r1: 1, r2: 1, r3: 2 }, result.counts)
    assert_equal 2, result.admitted(1), "clobbered counter admits 2 requests with limit 1"

    stored = store.value_of(store.keys.first)
    assert_equal 2, stored
    # Three increments were really applied (r1, r2, r3) but the stored value
    # diverged: the fallback write silently ate r2's increment.
    assert_equal 3, stored + 1, "the stored count diverges from the number of applied increments"

    promise = CountingHarness::ReferenceModel.promise(
      { atomic_increment: true, ttl: true }, faults: [:timeout_after], overlapped: false
    )
    refute promise.safety
    refute promise.liveness, "under unknown outcomes no client can promise both sides"
  end

  it "shows a fail-closed client keeps safety under faults but cannot keep liveness" do
    [:confirm_miss, :timeout_before, :timeout_after].each do |fault|
      script = [[:request, :r1], [:fault, fault], [:request, :r2], [:request, :r3]]

      default_result, = run_script(script)
      assert_operator default_result.admitted(2), :>, 2,
                      "default cache over-admits under #{fault}"

      fail_closed_result, = run_script(script, cache_class: FailClosedCache)
      assert_operator fail_closed_result.admitted(2), :<=, 2,
                      "fail-closed cache never over-admits under #{fault}"

      blocked_legitimate = fail_closed_result.counts[:r2] > 2
      assert blocked_legitimate, "fail-closed blocks legitimate requests under #{fault}: liveness is lost"
    end
  end

  it "catches overlapping first writes on a nil-on-miss store" do
    script = [[:run, :a], [:run, :b], [:run, :a], [:run, :b], [:run, :a], [:run, :b]]

    result, = run_script(script, increment_style: :nil_on_miss)
    assert_equal({ a: 1, b: 1 }, result.counts)
    assert_equal 2, result.admitted(1), "both first writes won: 2 requests admitted with limit 1"
    refute consistent?(result)

    atomic_result, = run_script(script)
    assert_equal({ a: 1, b: 2 }, atomic_result.counts)
    assert_equal 1, atomic_result.admitted(1), "an atomic increment keeps the threshold"

    promise = CountingHarness::ReferenceModel.promise(
      { atomic_increment: false, ttl: true }, faults: [], overlapped: true
    )
    refute promise.safety
  end

  it "still guarantees the threshold sequentially on a nil-on-miss store (generated sequences)" do
    generator = CountingHarness::Generator.new(303, tids: [:a, :b], period: 30, max_length: 9)
    100.times do
      script = generator.next
      result, = run_script(script, increment_style: :nil_on_miss)
      overlapped = CountingHarness::ReferenceModel.overlapped?(result.trace)

      if overlapped
        promise = CountingHarness::ReferenceModel.promise(
          { atomic_increment: false, ttl: true }, faults: [], overlapped: true
        )
        refute promise.safety, "overlapped counts on a nil-on-miss store cannot promise the threshold"
      else
        assert consistent?(result), "script: #{script.inspect} counts: #{result.counts.inspect}"
      end
    end
  end

  it "catches a deliberately broken (non-atomic) increment with a shrunk counterexample" do
    failing = nil
    [911, 912, 913].each do |seed|
      generator = CountingHarness::Generator.new(seed, tids: [:a, :b], period: 30, max_length: 10)
      200.times do
        script = generator.next
        result, = run_script(script, increment_style: :non_atomic)
        (failing = script) && break unless consistent?(result)
      end
      break if failing
    end
    refute_nil failing, "the generator must find a lost-update counterexample"

    shrinker = CountingHarness::Shrinker.new do |candidate|
      candidate_result, = run_script(candidate, increment_style: :non_atomic)
      !consistent?(candidate_result)
    end
    shrunk = shrinker.shrink(failing)

    result, = run_script(shrunk, increment_style: :non_atomic)
    puts "\nMinimized lost-update counterexample: #{shrunk.inspect}"
    puts "  broken counts: #{result.counts.inspect} (a correct chain returns 1, 2, ... per window)"

    assert_operator shrunk.length, :<=, failing.length
    tids = shrunk.select { |event| event[0] == :run || event[0] == :request }.map { |event| event[1] }.uniq
    assert_includes tids, :a, "shrinking must preserve the thread interleaving"
    assert_includes tids, :b, "shrinking must preserve the thread interleaving"
    assert_operator result.admitted(1), :>, 1, "the shrunk counterexample still over-admits"
    refute consistent?(result)
  end

  it "catches a store that ignores expiry (keys leak), keeping tick anchors while shrinking" do
    # A store that ignores expires_in does not break the threshold (the
    # window epoch is part of the key), but it leaks every window key: the
    # no-leak promise is exactly what the :ttl capability buys.
    failing = nil
    [511, 512].each do |seed|
      generator = CountingHarness::Generator.new(seed, tids: [:a, :b], period: 30, max_length: 8)
      200.times do
        script = generator.next
        next unless script.any? { |event| event[0] == :tick }

        _result, store = run_script(script, ttl: false)
        _ideal, ideal_store = run_script(script)
        if (store.keys - ideal_store.keys).any?
          failing = script
          break
        end
      end
      break if failing
    end
    refute_nil failing, "the generator must find a key-leak counterexample"

    ticks_before = failing.select { |event| event[0] == :tick }
    shrinker = CountingHarness::Shrinker.new do |candidate|
      _result, store = run_script(candidate, ttl: false)
      _ideal, ideal_store = run_script(candidate)
      (store.keys - ideal_store.keys).any?
    end
    shrunk = shrinker.shrink(failing)

    ticks_after = shrunk.select { |event| event[0] == :tick }
    assert_equal ticks_before, ticks_after, "shrinking must preserve every expiry position"
    refute_empty ticks_after

    _result, store = run_script(shrunk, ttl: false)
    _ideal, ideal_store = run_script(shrunk)
    leaked = store.keys - ideal_store.keys
    refute_empty leaked, "the shrunk counterexample still leaks window keys"
  end

  it "maps store capabilities to the promises they can support" do
    cases = [
      # capabilities, faults, overlapped, safety, liveness
      [{ atomic_increment: true, ttl: true }, [], false, true, true],
      [{ atomic_increment: true, ttl: true }, [], true, true, true],
      [{ atomic_increment: false, ttl: true }, [], false, true, true],
      [{ atomic_increment: false, ttl: true }, [], true, false, true],
      [{ atomic_increment: true, ttl: true }, [:confirm_miss], false, false, true],
      [{ atomic_increment: true, ttl: true }, [:timeout_before], false, false, false],
      [{ atomic_increment: true, ttl: true }, [:timeout_after], false, false, false],
      [{ atomic_increment: true, ttl: true }, [:write_rejected], false, false, true],
      [{ atomic_increment: true, ttl: false }, [], false, false, false]
    ]

    cases.each do |capabilities, faults, overlapped, safety, liveness|
      promise = CountingHarness::ReferenceModel.promise(
        capabilities, faults: faults, overlapped: overlapped
      )
      assert_equal safety, promise.safety, "capabilities=#{capabilities} faults=#{faults} overlapped=#{overlapped}"
      assert_equal liveness, promise.liveness, "capabilities=#{capabilities} faults=#{faults} overlapped=#{overlapped}"
    end
  end

  it "finds over-admission in generated fault sequences while fail-closed stays safe" do
    violations = 0
    fail_closed_violations = 0
    [71, 72, 73].each do |seed|
      generator = CountingHarness::Generator.new(
        seed, tids: [:a, :b, :c, :d], period: 30, max_length: 10,
        faults: [:confirm_miss, :timeout_before, :timeout_after]
      )
      150.times do
        script = generator.next
        next unless script.any? { |event| event[0] == :fault }

        result, = run_script(script)
        violations += 1 if result.admitted(2) > 2

        fail_closed_result, = run_script(script, cache_class: FailClosedCache)
        fail_closed_violations += 1 if fail_closed_result.admitted(2) > 2
      end
    end

    assert_operator violations, :>, 0, "fault sequences must expose over-admission in the default cache"
    assert_equal 0, fail_closed_violations, "fail-closed must never over-admit, whatever the fault"
  end
end

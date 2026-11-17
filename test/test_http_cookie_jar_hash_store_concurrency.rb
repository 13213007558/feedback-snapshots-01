# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))
require 'timeout'

# Deterministic concurrency tests for HTTP::CookieJar::HashStore.
#
# One thread iterates over the store (with and without a URI) while
# another thread deletes, expires (cleanup), clears or replaces
# cookies.  A Queue-based barrier parks the iterator inside the first
# yield and guarantees that the concurrent mutation is initiated while
# the iteration is in flight.  On a correctly synchronized store the
# mutation then blocks on the store monitor until the iteration has
# completed, so each iteration observes exactly one generation of
# cookies (never a mix of old and new values) and the mutation becomes
# visible entirely afterwards.
#
# Note: on CRuby the GVL additionally guarantees that the mutator runs
# uninterrupted from the +attempting+ barrier until it either blocks
# on the store monitor (fixed code) or completes the unsynchronized
# mutation (unfixed code), which makes the interleaving deterministic
# on both.  On the fixed code the monitor alone provides the ordering,
# independent of the GVL.
class TestHashStoreConcurrency < Test::Unit::TestCase
  TIMEOUT = 15

  def setup
    @store = HTTP::CookieJar::HashStore.new
    @uri = URI('http://example.com/')
  end

  def make_cookie(name, value, options = {})
    HTTP::Cookie.new({
      :name       => name,
      :value      => value,
      :domain     => 'example.com',
      :path       => '/',
      :for_domain => true,
      :expires    => Time.now + 86400,
    }.merge(options))
  end

  def add_generation(*names)
    names.each { |name| @store.add(make_cookie(name, 'gen1')) }
  end

  def identity_of(cookie)
    [cookie.domain, cookie.path, cookie.name, cookie.value]
  end

  def read_all(uri = nil)
    cookies = []
    @store.each(uri) { |cookie| cookies << identity_of(cookie) }
    cookies
  end

  # Runs +iteration+ (a lambda taking a block to yield cookies to)
  # while +mutation+ is performed by another thread.  The mutation
  # thread is released by a barrier from inside the first yield, so
  # the mutation is always initiated while the iteration is in
  # progress.  Returns the identities of the yielded cookies in
  # iteration order.  Any exception raised by the mutation thread is
  # re-raised here.
  def interleave(iteration, mutation)
    entered = Queue.new
    attempting = Queue.new
    mutated = Queue.new
    mutator = Thread.new {
      entered.pop
      attempting << true
      begin
        mutation.call
        mutated << nil
      rescue Exception => exception
        mutated << exception
      end
    }
    observed = []
    first = true
    iteration.call(->(cookie) {
      if first
        first = false
        entered << true
        attempting.pop
      end
      observed << identity_of(cookie)
    })
    error = mutated.pop
    mutator.join
    raise error if error
    observed
  end

  def test_each_with_uri_is_atomic_against_same_identity_replacement
    add_generation('c0', 'c1', 'c2')
    expected = read_all(@uri)

    observed = interleave(
      ->(block) { @store.each(@uri, &block) },
      -> { @store.add(make_cookie('c1', 'gen2')) }
    )

    assert_equal expected, observed,
      'iteration must observe a single generation, not a mix of gen1/gen2'
    assert_equal ['gen1'] * 3, observed.map { |_, _, _, value| value }.sort

    # the replacement is visible entirely afterwards
    assert_equal expected.map { |id| id[2] == 'c1' ? [id[0], id[1], id[2], 'gen2'] : id },
      read_all(@uri)
  end

  def test_each_with_uri_is_atomic_against_add_of_new_identity
    add_generation('c0', 'c1', 'c2')
    expected = read_all(@uri)

    observed = interleave(
      ->(block) { @store.each(@uri, &block) },
      -> { @store.add(make_cookie('c3', 'gen2')) }
    )

    assert_equal expected, observed
    assert_equal expected + [['example.com', '/', 'c3', 'gen2']], read_all(@uri)
  end

  def test_each_without_uri_is_atomic_against_delete
    add_generation('c0', 'c1', 'c2')
    expected = read_all

    observed = interleave(
      ->(block) { @store.each(&block) },
      -> { @store.delete(make_cookie('c2', 'gen1')) }
    )

    assert_equal expected, observed
    assert_equal expected.reject { |id| id[2] == 'c2' }, read_all
  end

  def test_each_without_uri_is_atomic_against_clear
    add_generation('c0', 'c1')
    @store.add(make_cookie('d0', 'gen1', :domain => 'www.example.org'))
    @store.add(make_cookie('d1', 'gen1', :domain => 'www.example.org'))
    expected = read_all
    assert_equal %w(c0 c1 d0 d1), expected.map { |id| id[2] }.sort

    observed = interleave(
      ->(block) { @store.each(&block) },
      -> { @store.clear }
    )

    assert_equal expected, observed
    assert_equal [], read_all
  end

  def test_each_with_uri_is_atomic_against_cleanup_of_session_cookies
    add_generation('c0', 'c1')
    @store.add(make_cookie('s0', 'gen1', :expires => nil))
    expected = read_all(@uri)
    assert_equal %w(c0 c1 s0), expected.map { |id| id[2] }.sort

    observed = interleave(
      ->(block) { @store.each(@uri, &block) },
      -> { @store.cleanup(true) } # expires session cookies
    )

    # the iteration still observes the not-yet-removed session cookie
    assert_equal expected, observed
    # cleanup took effect entirely afterwards; nothing was resurrected
    assert_equal expected.reject { |id| id[2] == 's0' }, read_all(@uri)
  end

  def test_each_with_uri_drops_expired_cookies_atomically_against_cleanup
    add_generation('c0', 'c1')
    @store.add(make_cookie('e0', 'gen1', :expires => Time.now - 3600))
    expected = read_all(@uri) # expired cookie is filtered out
    assert_equal %w(c0 c1), expected.map { |id| id[2] }.sort

    observed = interleave(
      ->(block) { @store.each(@uri, &block) },
      -> { @store.cleanup }
    )

    assert_equal expected, observed
    assert_equal expected, read_all(@uri)
    jar = @store.instance_variable_get(:@jar)
    assert_nil jar.dig('example.com', '/', 'e0'),
      'expired cookie must not be put back into the store'
  end

  def test_callback_exception_releases_the_monitor
    add_generation('c0', 'c1')

    assert_raise(RuntimeError) { @store.each { |cookie| raise 'boom' } }
    assert_raise(RuntimeError) { @store.each(@uri) { |cookie| raise 'boom' } }

    Timeout.timeout(TIMEOUT) do
      @store.add(make_cookie('c2', 'gen1'))
      assert_equal %w(c0 c1 c2), read_all.map { |id| id[2] }.sort
      @store.cleanup
      @store.clear
      assert_equal [], read_all
    end
  end

  def test_expired_cookies_are_not_resurrected_by_callback_exception
    @store.add(make_cookie('e0', 'gen1', :expires => Time.now - 3600))
    add_generation('c0')

    # the iteration deletes the expired entry, then the callback raises
    assert_raise(RuntimeError) {
      @store.each { |cookie| raise 'boom' if cookie.name == 'c0' }
    }

    Timeout.timeout(TIMEOUT) do
      assert_equal [['example.com', '/', 'c0', 'gen1']], read_all
      @store.add(make_cookie('c1', 'gen1'))
      assert_equal %w(c0 c1), read_all.map { |id| id[2] }.sort
    end
    jar = @store.instance_variable_get(:@jar)
    assert_nil jar.dig('example.com', '/', 'e0'),
      'expired cookie must not be put back into the store'
  end

  def test_reentrant_calls_from_callback_do_not_deadlock
    add_generation('c0')

    yielded = []
    Timeout.timeout(TIMEOUT) {
      @store.each { |cookie|
        yielded << cookie.name
        @store.empty?                # reentrant each without URI
        @store.each(@uri) { }        # reentrant each with URI
        @store.cleanup               # reentrant cleanup
      }
    }
    assert_equal ['c0'], yielded
    assert_equal [['example.com', '/', 'c0', 'gen1']], read_all
  end

  def test_reentrant_same_identity_replacement_from_callback
    add_generation('c0', 'c1')

    Timeout.timeout(TIMEOUT) {
      @store.each { |cookie|
        @store.add(make_cookie('c0', 'gen2')) if cookie.name == 'c0'
      }
    }
    assert_equal %w(gen1 gen2), read_all.map { |id| id[3] }.sort
  end

  def test_same_identity_replacement_keeps_a_single_entry
    @store.add(make_cookie('c0', 'gen1'))
    @store.add(make_cookie('c0', 'gen2'))

    assert_equal [['example.com', '/', 'c0', 'gen2']], read_all
  end
end

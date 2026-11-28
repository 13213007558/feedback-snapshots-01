# frozen_string_literal: true

require "test_helper"

class HTTPRetriableClockTest < Minitest::Test
  cover "HTTP::Retriable::Clock*"

  def test_now_returns_a_monotonic_numeric
    clock = HTTP::Retriable::Clock.new
    first = clock.now
    second = clock.now

    assert_kind_of Numeric, first
    assert_operator second, :>=, first
  end

  def test_sleep_with_zero_returns_without_a_real_wait
    clock = HTTP::Retriable::Clock.new

    assert_equal 0, clock.sleep(0)
  end

  def test_default_performer_clock_is_a_frozen_clock
    assert_instance_of HTTP::Retriable::Clock, HTTP::Retriable::Performer::DEFAULT_CLOCK
    assert HTTP::Retriable::Performer::DEFAULT_CLOCK.frozen?
  end
end

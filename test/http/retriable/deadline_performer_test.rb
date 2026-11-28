# frozen_string_literal: true

require "test_helper"

# Custom exception used across the deadline tests
unless defined?(DeadlineCustomException)
  class DeadlineCustomException < StandardError
  end
end

# Controllable monotonic clock. `sleep` records the requested delay without
# advancing time, so a test decides exactly when the deadline is reached.
class ManualClock
  attr_reader :sleeps

  def initialize(now = 0)
    @now = now
    @sleeps = []
  end

  def now
    @now
  end

  def sleep(seconds)
    @sleeps << seconds
    seconds
  end
end

# Verifies that retry waits honor both the server/backoff suggested delay and
# the operation deadline (lease), and that the two failure modes are told apart.
class HTTPRetriableDeadlinePerformerTest < Minitest::Test
  cover "HTTP::Retriable::Performer*"

  def request
    @request ||= HTTP::Request.new(verb: :get, uri: "http://example.com")
  end

  def make_response(status: 503, headers: {})
    HTTP::Response.new(
      status:  status,
      version: "1.1",
      headers: headers,
      body:    "Service Unavailable",
      request: request
    )
  end

  # Runs the performer with a fixed suggested delay and a manual clock.
  #
  # @return [Hash] observable outcome for the on-call dashboard
  def run_with_deadline(deadline:, delay: 10, tries: 5, retry_statuses: [503],
                        should_retry: nil, clock: @clock, on_retry: nil, &block)
    transmissions = 0
    retries = 0
    closes = 0
    mock_client = fake(close: -> { closes += 1 })
    callback = on_retry || proc { retries += 1 }

    result =
      begin
        HTTP::Retriable::Performer.new(
          delay: delay, tries: tries, retry_statuses: retry_statuses,
          should_retry: should_retry, on_retry: callback,
          deadline: deadline, clock: clock
        ).perform(mock_client, request) do
          transmissions += 1
          block ? block.call : make_response
        end
      rescue StandardError => e
        e
      end

    {
      callback_calls: retries,
      result:         result,
      transmissions:  transmissions,
      sleeps:         clock.sleeps,
      closes:         closes
    }
  end

  def setup
    super
    @clock = ManualClock.new(0)
  end

  # -- scenario 1: server suggests waiting past the lease --

  def test_server_suggested_wait_longer_than_lease_is_wait_exhaustion
    outcome = run_with_deadline(deadline: 5, delay: 10)

    assert_kind_of HTTP::DeadlineExceededError, outcome[:result]
    assert_equal 1, outcome[:transmissions]
    assert_equal 0, outcome[:callback_calls]
    assert_equal [], outcome[:sleeps]
    assert_equal 1, outcome[:closes]
  end

  def test_retry_after_header_longer_than_lease_is_wait_exhaustion
    response = make_response(headers: { "Retry-After" => "10" })

    outcome = run_with_deadline(deadline: 5, delay: 1) { response }

    assert_kind_of HTTP::DeadlineExceededError, outcome[:result]
    assert_equal 1, outcome[:transmissions]
    assert_equal 0, outcome[:callback_calls]
    assert_equal [], outcome[:sleeps]
  end

  # -- scenario 2: lease runs out while waiting for a retry --

  def test_deadline_reached_during_wait_is_wait_exhaustion
    # suggested wait (5) fits the remaining lease (10), but the clock reaches
    # the deadline during the wait before the next attempt starts
    @clock.define_singleton_method(:sleep) do |seconds|
      @sleeps << seconds
      @now += 10
      seconds
    end

    outcome = run_with_deadline(deadline: 10, delay: 5)

    assert_kind_of HTTP::DeadlineExceededError, outcome[:result]
    assert_equal 1, outcome[:transmissions]
    assert_equal 1, outcome[:callback_calls]
    assert_equal [5], outcome[:sleeps]
    assert_equal 1, outcome[:closes]
  end

  # -- scenario 3: the lease still allows an on-time retry --

  def test_retry_within_lease_succeeds_on_the_next_attempt
    attempt = 0
    outcome = run_with_deadline(deadline: 10, delay: 5) do
      attempt += 1
      attempt == 1 ? make_response : make_response(status: 200)
    end

    assert_kind_of HTTP::Response, outcome[:result]
    assert_equal 200, outcome[:result].status.to_i
    assert_equal 2, outcome[:transmissions]
    assert_equal 1, outcome[:callback_calls]
    assert_equal [5], outcome[:sleeps]
    assert_equal 1, outcome[:closes]
  end

  def test_retry_within_lease_keeps_retrying_until_success
    responses = [make_response, make_response, make_response(status: 200)]

    outcome = run_with_deadline(deadline: 100, delay: 5) { responses.shift }

    assert_kind_of HTTP::Response, outcome[:result]
    assert_equal 3, outcome[:transmissions]
    assert_equal 2, outcome[:callback_calls]
    assert_equal [5, 5], outcome[:sleeps]
  end

  # -- deadline vs service refusal stay distinct --

  def test_running_out_of_tries_is_still_out_of_retries_not_deadline
    # plenty of lease left, but only one attempt is permitted
    outcome = run_with_deadline(deadline: 1000, delay: 5, tries: 1)

    assert_kind_of HTTP::OutOfRetriesError, outcome[:result]
    refute_kind_of HTTP::DeadlineExceededError, outcome[:result]
    assert_equal 1, outcome[:transmissions]
    assert_equal 0, outcome[:callback_calls]
  end

  def test_deadline_error_is_catchable_as_out_of_retries
    outcome = run_with_deadline(deadline: 5, delay: 10)

    assert_kind_of HTTP::OutOfRetriesError, outcome[:result]
  end

  def test_deadline_error_carries_last_response_and_message
    outcome = run_with_deadline(deadline: 5, delay: 10)
    error = outcome[:result]

    assert_kind_of HTTP::Response, error.response
    assert_equal 503, error.response.status.to_i
    assert_includes error.message, "deadline exceeded"
    assert_includes error.message, "503"
  end

  def test_deadline_error_carries_exception_when_request_raised
    error = nil
    clock = ManualClock.new(0)
    mock_client = fake(close: -> {})

    begin
      HTTP::Retriable::Performer.new(
        exceptions: [DeadlineCustomException], tries: 5, delay: 10,
        deadline: 5, clock: clock
      ).perform(mock_client, request) { raise DeadlineCustomException, "boom" }
    rescue HTTP::DeadlineExceededError => e
      error = e
    end

    assert_kind_of HTTP::DeadlineExceededError, error
    assert_kind_of DeadlineCustomException, error.cause
    assert_includes error.message, "boom"
  end

  # -- boundary conditions --

  def test_wait_equal_to_remaining_lease_is_treated_as_exhausted
    outcome = run_with_deadline(deadline: 10, delay: 10)

    assert_kind_of HTTP::DeadlineExceededError, outcome[:result]
    assert_equal 0, outcome[:callback_calls]
  end

  def test_wait_shorter_than_remaining_lease_is_allowed
    @clock.define_singleton_method(:sleep) do |seconds|
      @sleeps << seconds
      @now += 5
      seconds
    end

    # remaining lease (10) exceeds the wait (5), and after waiting (now=5)
    # the deadline (10) has not been reached
    responses = [make_response, make_response(status: 200)]
    outcome = run_with_deadline(deadline: 10, delay: 5) { responses.shift }

    assert_kind_of HTTP::Response, outcome[:result]
    assert_equal 200, outcome[:result].status.to_i
    assert_equal 1, outcome[:callback_calls]
  end

  # -- custom retry predicate still vetoes --

  def test_should_retry_false_vetoes_retry_even_with_remaining_lease
    veto = ->(_req, _err, _res, _attempt) { false }
    outcome = run_with_deadline(deadline: 100, delay: 5, should_retry: veto)

    assert_kind_of HTTP::Response, outcome[:result]
    assert_equal 503, outcome[:result].status.to_i
    assert_equal 1, outcome[:transmissions]
    assert_equal 0, outcome[:callback_calls]
  end

  def test_should_retry_false_vetoes_on_exception_even_with_remaining_lease
    veto = ->(_req, _err, _res, _attempt) { false }
    outcome = run_with_deadline(deadline: 100, delay: 5, should_retry: veto) do
      raise DeadlineCustomException
    end

    assert_kind_of DeadlineCustomException, outcome[:result]
    assert_equal 1, outcome[:transmissions]
    assert_equal 0, outcome[:callback_calls]
    assert_equal 1, outcome[:closes]
  end

  # -- no deadline configured preserves original behavior --

  def test_without_deadline_retries_until_tries_are_exhausted
    outcome = run_with_deadline(deadline: nil, delay: 0, tries: 3)

    assert_kind_of HTTP::OutOfRetriesError, outcome[:result]
    refute_kind_of HTTP::DeadlineExceededError, outcome[:result]
    assert_equal 3, outcome[:transmissions]
    assert_equal 2, outcome[:callback_calls]
  end

  # -- white-box checks on the lease helpers --

  def build_performer(deadline:, now: 0)
    clock = ManualClock.new(now)
    HTTP::Retriable::Performer.new(delay: 0, deadline: deadline, clock: clock)
  end

  def test_remaining_lease_is_deadline_minus_clock_now
    performer = build_performer(deadline: 10, now: 3)

    assert_equal 7, performer.send(:remaining_lease)
  end

  def test_deadline_predicate_reflects_configuration
    assert build_performer(deadline: 10).send(:deadline?)
    refute HTTP::Retriable::Performer.new(delay: 0).send(:deadline?)
  end

  def test_before_wait_guard_is_false_without_a_deadline
    performer = HTTP::Retriable::Performer.new(delay: 0)

    refute performer.send(:deadline_exceeded_before_wait?, 999)
  end

  def test_before_wait_guard_allows_a_wait_shorter_than_the_lease
    performer = build_performer(deadline: 10, now: 0)

    refute performer.send(:deadline_exceeded_before_wait?, 9)
  end

  def test_after_wait_guard_is_false_without_a_deadline
    performer = HTTP::Retriable::Performer.new(delay: 0)

    refute performer.send(:deadline_exceeded_after_wait?)
  end

  def test_after_wait_guard_is_false_while_clock_is_before_the_deadline
    performer = build_performer(deadline: 10, now: 9)

    refute performer.send(:deadline_exceeded_after_wait?)
  end

  def test_after_wait_guard_is_true_once_clock_reaches_the_deadline
    performer = build_performer(deadline: 10, now: 10)

    assert performer.send(:deadline_exceeded_after_wait?)
  end
end

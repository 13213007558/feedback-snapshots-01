# frozen_string_literal: true

require "sidekiq"
require "minitest/autorun"
require "redis-client"
require "json"

class RecordingTransactionBackend
  Frame = Struct.new(:name, :token, :callbacks)

  attr_reader :events

  def initialize(events = [])
    @events = events
    @root = nil
    @stack = []
  end

  def current_token
    frame = @stack.last || @root
    frame&.token
  end

  def after_commit(&block)
    raise "transaction is not open" unless @stack.last || @root

    @events << "tx:enlist:#{current_token}"
    (@stack.last || @root).callbacks << block
  end

  def begin_outer(token = "outer-commit")
    @root = Frame.new(:outer, token, [])
    @stack = [@root]
    @events << "tx:begin:outer:#{token}"
  end

  def begin_savepoint(token = "savepoint-1")
    frame = Frame.new(:savepoint, token, [])
    @stack << frame
    @events << "tx:savepoint:begin:#{token}"
    frame
  end

  def rollback_savepoint
    frame = @stack.pop
    @events << "tx:savepoint:rollback:#{frame.token}"
    frame.callbacks.clear
  end

  def release_savepoint
    frame = @stack.pop
    @events << "tx:savepoint:release:#{frame.token}"
    @stack.last.callbacks.concat(frame.callbacks)
  end

  def commit_outer
    token = @root.token
    callbacks = @root.callbacks.dup
    @events << "tx:outer_commit:#{token}"
    @root = nil
    @stack.clear
    callbacks.each(&:call)
    @events << "tx:callbacks_finished:#{token}"
  end

  def rollback_outer
    @events << "tx:outer_rollback:#{@root.token}"
    @root.callbacks.clear
    @root = nil
    @stack.clear
  end
end

class RedisDouble
  attr_reader :events, :payloads

  def initialize(events)
    @events = events
    @payloads = []
    @fail_next_lpush = false
    @fail_next_bulk = false
  end

  def fail_next_lpush!
    @fail_next_lpush = true
  end

  def fail_bulk_once!
    @fail_next_bulk = true
  end

  def pipelined
    @events << "redis:pipelined"
    yield self
  end

  def sadd(key, members)
    @events << "redis:sadd:#{key}:#{Array(members).size}"
  end

  def lpush(key, values)
    values = Array(values)
    @events << "redis:lpush:#{key}:#{values.size}"
    if @fail_next_lpush || (@fail_next_bulk && values.size > 1)
      @fail_next_lpush = false
      @fail_next_bulk = false
      raise RedisClient::Error, "simulated interrupted bulk publish"
    end

    values.each do |raw_payload|
      @payloads << JSON.parse(raw_payload)
    end
  end

  def close
    @events << "redis:close"
  end
end

class PoolDouble
  attr_reader :redis

  def initialize(redis)
    @redis = redis
  end

  def with
    yield redis
  end
end

class TransactionalApprovalTest < Minitest::Test
  def setup
    @events = []
    @transaction = RecordingTransactionBackend.new(@events)
    @redis = RedisDouble.new(@events)
    @pool = PoolDouble.new(@redis)
    @config = Sidekiq::Config.new
    @standard_client = Sidekiq::Client.new(pool: @pool, config: @config)
    @client = Sidekiq::TransactionAwareClient.new(
      @transaction,
      pool: @pool,
      config: @config
    )
  end

  def test_nested_rollback_discards_only_savepoint_approval_and_commit_publishes_snapshot
    @transaction.begin_outer("commit-A")

    mutable_params = {"invoice" => {"state" => "approved-at-review"}}
    outer_item = {
      "class" => "ApprovalAcceptanceJob",
      "args" => [{"id" => "outer", "params" => mutable_params}]
    }
    outer_approval = @client.approve(outer_item)
    outer_jid = outer_approval.jid
    assert_equal 24, outer_jid.size
    assert_equal "commit-A", outer_approval.transaction_token

    @client.push(outer_approval)

    @transaction.begin_savepoint("sp-rollback")
    nested_approval = @client.approve(
      "class" => "NestedRolledBackJob",
      "args" => [{"id" => "nested"}]
    )
    assert_equal "sp-rollback", nested_approval.transaction_token
    nested_jid = @client.push(nested_approval)
    @transaction.rollback_savepoint

    batch = @client.push_approved_batch(
      "class" => "ApprovedSmallBatchJob",
      "args" => [
        [{"id" => "batch-1"}],
        [{"id" => "batch-2"}]
      ]
    )
    assert_equal "commit-A", batch.transaction_token
    assert_equal 2, batch.size
    assert_equal batch.jids, batch.to_a

    # Post-approval mutation, including nested keys added later, cannot change
    # the frozen approved payload.
    mutable_params["invoice"]["state"] = "changed-after-approval"
    mutable_params["invoice"]["post_commit"] = "injected"
    outer_item["args"][0]["params"]["invoice"]["state"] = "also-changed"

    @transaction.commit_outer

    published_jids = @redis.payloads.map { |payload| payload["jid"] }
    assert_equal [outer_jid, *batch.jids], published_jids
    refute_includes published_jids, nested_jid

    outer_payload = @redis.payloads.find { |payload| payload["jid"] == outer_jid }
    assert_equal "approved-at-review", outer_payload["args"][0]["params"]["invoice"]["state"]
    refute outer_payload["args"][0]["params"]["invoice"].key?("post_commit")

    batch_payloads = @redis.payloads.select { |payload| batch.jids.include?(payload["jid"]) }
    assert_equal 2, batch_payloads.size
    batch_payloads.each { |payload| assert_kind_of Integer, payload["enqueued_at"] }
    assert_equal(
      batch.payloads.map { |payload| JSON.parse(Sidekiq.dump_json(payload)) },
      batch_payloads.map { |payload| payload.except("enqueued_at") }
    )

    commit_index = @events.index("tx:outer_commit:commit-A")
    assert commit_index
    assert_empty @events.first(commit_index).grep(/\Aredis:/)
    assert @events.index("tx:savepoint:rollback:sp-rollback") < @events.index("tx:outer_commit:commit-A")
    assert commit_index < @events.index("redis:lpush:queue:default:1")
    assert commit_index < @events.index("redis:lpush:queue:default:2")
    assert batch.published?
    assert outer_approval.published?
  end

  def test_failed_batch_publish_reports_preallocated_ids_and_commit_fact
    @transaction.begin_outer("commit-F")
    @redis.fail_next_lpush!

    batch = @client.push_approved_batch(
      "class" => "FailedApprovedBatchJob",
      "args" => [[1], [2]]
    )
    jids = batch.jids.dup
    assert_equal 2, jids.size

    error = assert_raises(RedisClient::Error) do
      @transaction.commit_outer
    end

    assert error.is_a?(Sidekiq::ApprovalPublishFailure)
    assert_equal jids, error.jids
    assert_equal jids, error.approval_batch.jids
    assert_same batch, error.approval_batch
    assert batch.failed?
    assert_instance_of RedisClient::Error, batch.error
    assert_empty @redis.payloads

    commit_index = @events.index("tx:outer_commit:commit-F")
    failure_index = @events.index("redis:lpush:queue:default:2")
    assert commit_index < failure_index

    # Recovery can reuse the same approved payloads and pre-allocated JIDs after
    # Redis is available again. Delivery remains at-least-once if the prior
    # interruption's outcome was ambiguous.
    retried_jids = @standard_client.push_prepared_bulk(batch.payloads)
    assert_equal jids, retried_jids
    assert_equal 2, @redis.payloads.size
    assert_equal jids, @redis.payloads.map { |payload| payload["jid"] }
  end

  def test_combined_nested_rollback_commit_and_batch_failure_order
    @transaction.begin_outer("commit-combined")

    first = @client.push(
      "class" => "CommittedSingleJob",
      "args" => ["first"]
    )

    @transaction.begin_savepoint("sp-discarded")
    discarded = @client.push("class" => "DiscardedJob", "args" => ["discarded"])
    @transaction.rollback_savepoint

    batch = @client.push_approved_batch(
      "class" => "InterruptedBatchJob",
      "args" => [["a"], ["b"]]
    )
    @redis.fail_bulk_once!

    error = assert_raises(RedisClient::Error) { @transaction.commit_outer }

    assert_equal batch.jids, error.jids
    assert batch.failed?
    refute_includes error.jids, first
    refute_includes error.jids, discarded

    published_jids = @redis.payloads.map { |payload| payload["jid"] }
    assert_equal [first], published_jids
    refute_includes published_jids, discarded
    assert_empty published_jids & batch.jids

    expected_order = [
      "tx:begin:outer:commit-combined",
      "tx:enlist:commit-combined",
      "tx:savepoint:begin:sp-discarded",
      "tx:enlist:sp-discarded",
      "tx:savepoint:rollback:sp-discarded",
      "tx:enlist:commit-combined",
      "tx:outer_commit:commit-combined",
      "redis:pipelined",
      "redis:sadd:queues:1",
      "redis:lpush:queue:default:1",
      "redis:pipelined",
      "redis:sadd:queues:1",
      "redis:lpush:queue:default:2"
    ]
    assert_equal expected_order, @events
  end

  def test_released_savepoint_approval_joins_outer_commit
    @transaction.begin_outer("outer-with-release")
    @transaction.begin_savepoint("sp-release")
    jid = @client.push("class" => "ReleasedSavepointJob", "args" => ["ok"])
    @transaction.release_savepoint

    assert_empty @redis.payloads
    @transaction.commit_outer

    assert_equal [jid], @redis.payloads.map { |payload| payload["jid"] }
    assert_includes @events, "tx:savepoint:release:sp-release"
  end

  def test_outer_rollback_publishes_nothing
    @transaction.begin_outer("rolled-back")
    @client.push("class" => "RolledBackSingle", "args" => ["x"])
    @client.push_approved_batch(
      "class" => "RolledBackBatch",
      "args" => [[1], [2]]
    )

    @transaction.rollback_outer

    assert_empty @redis.payloads
    assert_empty @events.grep(/\Aredis:/)
  end

  def test_approved_batch_has_a_small_explicit_limit
    assert_equal 10, Sidekiq::TransactionAwareClient::MAX_APPROVED_BATCH_SIZE

    approved = @client.approve_batch(
      "class" => "LimitJob",
      "args" => Array.new(10) { |index| [index] }
    )
    assert_equal 10, approved.size

    error = assert_raises(ArgumentError) do
      @client.approve_batch(
        "class" => "LimitJob",
        "args" => Array.new(11) { |index| [index] }
      )
    end
    assert_match(/limited to 10/, error.message)

    assert_raises(ArgumentError) do
      @client.approve_batch(
        {"class" => "LimitJob", "args" => [[1], [2], [3]]},
        limit: 2
      )
    end
  end

  def test_ordinary_single_push_remains_immediate_control
    @transaction.begin_outer("control-single")
    item = {"class" => "OrdinarySingleJob", "args" => [{"value" => "before"}]}

    jid = @standard_client.push(item)

    assert_equal 24, jid.size
    assert_equal 1, @redis.payloads.size
    assert_equal jid, @redis.payloads.first["jid"]

    @transaction.rollback_outer

    assert_equal 1, @redis.payloads.size
    assert @events.index("redis:lpush:queue:default:1") < @events.index("tx:outer_rollback:control-single")
  end

  def test_ordinary_push_bulk_remains_immediate_and_non_transactional_control
    @transaction.begin_outer("control-bulk")

    jids = @standard_client.push_bulk(
      "class" => "OrdinaryBulkJob",
      "args" => [[1], [2], [3]]
    )

    assert_equal 3, jids.size
    assert_equal 3, @redis.payloads.size
    assert_nil @events.grep(/\Atx:enlist/).first

    @transaction.rollback_outer

    assert_equal 3, @redis.payloads.size
    assert @events.index("redis:lpush:queue:default:3") < @events.index("tx:outer_rollback:control-bulk")
  end

  def test_transaction_aware_push_bulk_defaults_to_existing_immediate_delegation
    jids = @client.push_bulk(
      "class" => "DefaultOrdinaryBulkJob",
      "args" => [[1], [2]]
    )

    assert_equal 2, jids.size
    assert_equal 2, @redis.payloads.size
    assert_nil @events.grep(/\Atx:enlist/).first
  end

  def test_transactional_push_bulk_opt_in_uses_approved_batch
    @transaction.begin_outer("opt-in")

    batch = @client.push_bulk(
      "class" => "OptInBulkJob",
      "args" => [[1], [2]],
      "transactional" => true
    )

    assert_kind_of Sidekiq::ApprovedBatch, batch
    assert_empty @redis.payloads
    @transaction.commit_outer
    assert_equal 2, @redis.payloads.size
    assert batch.published?
  end
end

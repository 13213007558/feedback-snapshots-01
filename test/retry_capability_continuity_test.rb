# frozen_string_literal: true

# Acceptance evidence for retry capability continuity.
#
# The prompt asks us to:
#
#   * put retries into a different Sidekiq queue (retry_queue routing),
#   * keep the original execution capability even though some workers have
#     wider permissions,
#   * let on-call operators approve equivalent-capability fallback queues,
#   * make rejected retries visible,
#   * use a recordable queue stand-in, fail two jobs, change one route while
#     the retries wait, then trigger redelivery, and
#   * judge the *actual executing capsule* and the *retained failure results*,
#     not merely whether a message was enqueued.
#
# This file uses only an in-memory Redis stand-in: no Redis server and no
# socket are touched. The stand-in records commands so the test can distinguish
# "a message was queued" from "a job actually ran in a capsule".

require "minitest/autorun"
require "connection_pool"
require "sidekiq"
require "sidekiq/api"
require "sidekiq/capsule"
require "sidekiq/scheduled"
require "sidekiq/processor"
require "sidekiq/fetch"

# A small, strict in-memory Redis double supporting exactly the commands used
# by the retry / scheduler / delivery paths under test.
# Wraps the double so each command issued inside `pipelined` also appends its
# result to the pipeline's result array, like redis-client does.
class ResultCollector
  def initialize(redis, results)
    @redis = redis
    @results = results
  end

  def method_missing(name, *args, &block)
    result = @redis.public_send(name, *args, &block)
    @results << result
    result
  end

  def respond_to_missing?(name, include_private = false)
    @redis.respond_to?(name) || super
  end
end

class RecordingRedis
  attr_reader :log

  def initialize
    @data = {}
    @log = []
  end

  def flushdb
    @data.clear
    @log.clear
    "OK"
  end

  def zset(key)
    @data[key] ||= []
  end

  def list(key)
    @data[key] ||= []
  end

  def zcard(key)
    zset(key).size
  end

  def llen(key)
    list(key).size
  end

  def type(key)
    value = @data[key]
    return "none" if value.nil?
    return "zset" if value.is_a?(Array) && value.all? { |e| e.is_a?(Array) && e.size == 2 }
    return "set" if value.is_a?(Set)
    "list"
  end

  def zadd(key, *args)
    entries = args.size == 1 && args.first.is_a?(Array) ? args.first : args
    raise ArgumentError, "zadd requires score/member pairs" unless entries.size.even?

    zset = zset(key)
    entries.each_slice(2) do |score, member|
      zset.reject! { |_, m| m == member }
      zset << [score.to_f, member.to_s]
      @log << [:zadd, key, score.to_f, member.to_s]
    end
    zset.sort_by!(&:first)
    entries.size / 2
  end

  def zrange(key, start, stop, *opts)
    entries = zset(key).sort_by(&:first)
    rev = opts.include?("REV")
    byscore = opts.include?("BYSCORE")
    withscores = opts.include?("withscores")

    if byscore
      lo = boundary(start)
      hi = boundary(stop)
      matched = entries.select { |score, _| score >= lo && score <= hi }
    else
      matched = entries
      matched = matched.reverse if rev
      matched = slice(matched, start, stop)
    end

    if withscores
      matched.map { |score, member| [member, score.to_s] }
    else
      matched.map { |_, member| member }
    end
  end

  def zrem(key, member)
    zset = zset(key)
    before = zset.size
    zset.reject! { |_, m| m == member.to_s }
    before - zset.size
  end

  def zpopmin(key, count = 1)
    zset = zset(key).sort_by(&:first)
    popped = zset.shift(count.to_i)
    @data[key] = zset
    popped.map { |score, member| [member, score.to_s] }
  end

  def zremrangebyscore(key, min, max)
    zset = zset(key)
    lo = boundary(min)
    hi = boundary(max)
    before = zset.size
    zset.reject! { |score, _| score >= lo && score <= hi }
    before - zset.size
  end

  def zremrangebyrank(key, start, stop)
    zset = zset(key).sort_by(&:first)
    removed = slice(zset, start, stop)
    removed.each { |entry| zset.delete(entry) }
    @data[key] = zset
    removed.size
  end

  def sadd(key, members)
    set = (@data[key] ||= Set.new)
    added = Array(members).map(&:to_s) - set.to_a
    set.merge(added)
    added.size
  end

  def smembers(key)
    @data[key].is_a?(Set) ? @data[key].to_a : []
  end

  def srem(key, members)
    return 0 unless @data[key].is_a?(Set)
    before = @data[key].size
    Array(members).each { |m| @data[key].delete(m.to_s) }
    before - @data[key].size
  end

  def scard(key)
    @data[key].is_a?(Set) ? @data[key].size : 0
  end

  def sismember(key, member)
    @data[key].is_a?(Set) && @data[key].include?(member.to_s)
  end

  def lpush(key, values)
    list = list(key)
    Array(values).each { |value| list.unshift(value) }
    @log << [:lpush, key, Array(values)]
    list.size
  end

  def lrange(key, start, stop)
    slice(list(key), start, stop)
  end

  def lpop(key)
    list(key).shift
  end

  def lindex(key, index)
    list(key)[Integer(index)]
  end

  def get(key)
    @data[key]
  end

  # The scheduler loads a Lua script once; EVALSHA is the only script call.
  def script(_subcommand, _body)
    "fake-sha"
  end

  # Only the EVALSHA call used by Scheduled::Enq and INFO are supported.
  # Like redis-client, INFO yields its raw payload to an optional block.
  def call(command, *args, &block)
    result = case command
    when "EVALSHA"
      _sha, _numkeys, key, now = args
      entries = zset(key).sort_by(&:first)
      entry = entries.find { |score, _| score <= now.to_f }
      entry && begin
        zset(key).delete(entry)
        entry[1]
      end
    when "INFO"
      "redis_version:8.0.0\r\nuptime_in_days:1\r\nconnected_clients:1\r\nused_memory_human:1M\r\n"
    else
      raise "unsupported command #{command}"
    end
    block ? block.call(result) : result
  end

  # Mirrors redis-client: the block's command return values are collected and
  # returned in order.
  def multi
    results = []
    yield ResultCollector.new(self, results)
    results
  end

  def pipelined
    results = []
    yield ResultCollector.new(self, results)
    results
  end

  def close
  end

  private

  def boundary(value)
    case value.to_s
    when "-inf" then -Float::INFINITY
    when "+inf", "inf" then Float::INFINITY
    else Float(value)
    end
  end

  # Mirrors Redis rank semantics: negative indexes are relative to the end,
  # out-of-range indexes are clamped, and a start greater than the stop yields
  # an empty result (this is what stops Sidekiq's paging loops).
  def slice(entries, start, stop)
    size = entries.size
    a = Integer(start)
    b = Integer(stop)
    a += size if a.negative?
    b += size if b.negative?
    a = 0 if a.negative?
    b = size - 1 if b >= size
    return [] if b.negative? || a > b || a >= size
    entries[a..b] || []
  end
end

class ContinuityProbeJob
  include Sidekiq::Job

  sidekiq_class_attribute :runs
  self.runs = []

  def perform(label)
    capsule = _context&.capsule
    self.class.runs << {
      label: label,
      capsule: capsule&.name,
      capability: capsule&.capability
    }
  end
end

describe "retry capability continuity" do
  before do
    ContinuityProbeJob.runs = []
    @redis = RecordingRedis.new
    @pool = ConnectionPool.new(size: 4) { @redis }

    @config = Sidekiq::Config.new
    @config.logger = Logger.new(IO::NULL)
    # Inject the in-memory stand-in as the process-wide pool.
    @config.instance_variable_set(:@redis, @pool)
    Sidekiq.instance_variable_set(:@config, @config)

    @worker = @config.capsule("worker") do |cap|
      cap.capability = "worker"
      cap.queues = %w[worker]
      cap.concurrency = 1
    end
    @backup = @config.capsule("backup") do |cap|
      cap.capability = "worker"
      cap.queues = %w[backup]
      cap.concurrency = 1
    end
    @ops = @config.capsule("ops") do |cap|
      cap.capability = "worker"
      cap.queues = %w[ops]
      cap.concurrency = 1
    end
    [@worker, @backup, @ops].each { |cap| cap.instance_variable_set(:@redis, @pool) }
  end

  after do
    Sidekiq.instance_variable_set(:@config, nil)
  end

  def fail_job(jid:, label:, retry_queue:)
    payload = Sidekiq.dump_json({
      "class" => ContinuityProbeJob.name,
      "args" => [label],
      "queue" => "worker",
      "retry" => true,
      "retry_queue" => retry_queue,
      "jid" => jid
    })

    assert_raises(Sidekiq::JobRetry::Handled) do
      Sidekiq::JobRetry.new(@worker).local(ContinuityProbeJob.new, payload, "worker") do
        raise RuntimeError, "boom #{label}"
      end
    end
  end

  def retries_by_jid
    Sidekiq::RetrySet.new.to_a.to_h { |entry| [entry["jid"], entry] }
  end

  def make_due!
    @redis.zset("retry").each { |entry| entry[0] = Time.now.to_f - 60 }
  end

  def run_in(capsule, queue)
    # Mirrors BasicFetch: the message is taken off the queue before execution.
    payload = @redis.lpop("queue:#{queue}")
    return nil unless payload

    uow = Sidekiq::BasicFetch::UnitOfWork.new("queue:#{queue}", payload, capsule)
    Sidekiq::Processor.new(capsule) { |*| }.send(:process, uow)
    payload
  end

  it "keeps original capability, honors approved equivalent fallbacks, and retains rejected retries" do
    # Two jobs fail in the worker capsule while routed to fallback queues.
    # Each records the capability of the capsule which really executed the
    # failing attempt; the route is a separate, client-supplied value.
    fail_job(jid: "a" * 24, label: "A", retry_queue: "backup")
    fail_job(jid: "b" * 24, label: "B", retry_queue: "ops")

    retries = retries_by_jid
    assert_equal 2, retries.size
    assert_equal "worker", retries["a" * 24]["capability"]
    assert_equal "worker", retries["a" * 24]["origin_queue"]
    assert_equal "backup", retries["a" * 24]["queue"]
    assert_equal "worker", retries["b" * 24]["capability"]
    assert_equal "ops", retries["b" * 24]["queue"]

    # On-call approves the equivalent-capability backup fallback for retries,
    # and separately approves ops while it is still equivalent.
    @config.approve_retry_fallback("backup", capability: "worker")
    @config.approve_retry_fallback("ops", capability: "worker")

    # While the retries wait, job B's route is changed to the ops queue, and
    # the ops capsule is upgraded to a wider, administrative capability.
    # (The point is that neither the original client route nor a string queue
    # name is trusted later.)
    @redis.zset("retry").each do |entry|
      message = Sidekiq.load_json(entry[1])
      next unless message["jid"] == "b" * 24

      message["queue"] = "ops"
      entry[1] = Sidekiq.dump_json(message)
    end
    @ops.capability = "admin"

    make_due!
    Sidekiq::Scheduled::Poller.new(@config).enqueue

    # Only the approved, equivalent retry was really redelivered. A message
    # merely being queued is not enough: the executing capsule below proves
    # the capability it actually ran with.
    assert_equal 0, Sidekiq::RetrySet.new.size
    assert_equal 1, @redis.llen("queue:backup")
    assert_equal 0, @redis.llen("queue:ops")

    run_in(@backup, "backup")

    assert_equal 1, ContinuityProbeJob.runs.size
    run = ContinuityProbeJob.runs.first
    assert_equal "A", run[:label]
    assert_equal "backup", run[:capsule], "job must run in the approved fallback capsule"
    assert_equal "worker", run[:capability], "executed with the original capability"

    # The widened route was retained, with its original failure facts plus the
    # reason it was not delivered.
    rejected = Sidekiq::RejectedSet.new.to_a
    assert_equal 1, rejected.size
    entry = rejected.first
    assert_equal "b" * 24, entry["jid"]
    assert_equal "capability_mismatch", entry["rejection_reason"]
    assert_equal ["worker"], entry["required_capability"]
    assert_equal ["admin"], entry["actual_capability"]
    assert_equal "ops", entry["rejected_queue"]
    assert_equal 0, @redis.llen("queue:ops"), "the unsafe route was never enqueued"
    assert_equal "RuntimeError", entry["error_class"]
    assert_equal "boom B", entry["error_message"]
    assert entry["failed_at"], "original failure timestamp is retained"
    assert_equal 0, entry["retry_count"]
    assert_equal "rejected", entry["status"]
    assert_equal 1, Sidekiq::Stats.new.rejected_size
  end

  it "rejects a retry enqueued under an approval that is widened before execution" do
    # Operator approves the ops fallback while both capsules are equivalent.
    @config.approve_retry_fallback("ops", capability: "worker")
    fail_job(jid: "c" * 24, label: "C", retry_queue: "ops")

    make_due!
    Sidekiq::Scheduled::Poller.new(@config).enqueue
    assert_equal 1, @redis.llen("queue:ops"), "delivery check passed while the route was equivalent"

    # The route is widened after the message is already queued. A test which
    # only inspects queue length would report success here.
    @ops.capability = "admin"
    run_in(@ops, "ops")

    assert_empty ContinuityProbeJob.runs, "the widened capsule must not execute the retry"

    # Nothing may be left pending: a rejected retry is retained once and the
    # queue message consumed. Re-polling must not create a second record.
    assert_equal 0, @redis.llen("queue:ops")
    Sidekiq::Scheduled::Poller.new(@config).enqueue
    assert_equal 1, Sidekiq::RejectedSet.new.size
    entry = Sidekiq::RejectedSet.new.to_a.first
    refute_nil entry
    assert_equal "c" * 24, entry["jid"]
    assert_equal "capability_mismatch", entry["rejection_reason"]
    assert_equal ["worker"], entry["required_capability"]
    assert_equal ["admin"], entry["actual_capability"]
    assert_equal "ops", entry["rejected_by_capsule"]
    assert_equal "ops", entry["rejected_by"], "the capsule which refused execution is recorded"
    assert_equal "RuntimeError", entry["error_class"]
    assert_equal "boom C", entry["error_message"]
  end

  it "does not widen authority for an unapproved route change" do
    fail_job(jid: "d" * 24, label: "D", retry_queue: "backup")

    # No approval exists; change the route during the wait to another
    # equivalent-capability capsule.
    @redis.zset("retry").each do |entry|
      message = Sidekiq.load_json(entry[1])
      message["queue"] = "ops"
      entry[1] = Sidekiq.dump_json(message)
    end
    make_due!
    Sidekiq::Scheduled::Poller.new(@config).enqueue

    assert_equal 0, @redis.llen("queue:ops")
    assert_equal 0, @redis.llen("queue:backup")
    entry = Sidekiq::RejectedSet.new.to_a.first
    refute_nil entry
    assert_equal "unapproved_retry_queue", entry["rejection_reason"]
    assert_equal "ops", entry["rejected_queue"]
    assert_equal "boom D", entry["error_message"]
  end

  it "does not trust a client-supplied capability on the first failure" do
    # A payload may claim any capability and origin queue. The capsule which
    # actually executed the job is authoritative, so the claim must be dropped.
    payload = Sidekiq.dump_json({
      "class" => ContinuityProbeJob.name,
      "args" => ["E"],
      "queue" => "worker",
      "retry" => true,
      "jid" => "e" * 24,
      "capability" => "admin",
      "origin_queue" => "adminq"
    })

    assert_raises(Sidekiq::JobRetry::Handled) do
      Sidekiq::JobRetry.new(@worker).local(ContinuityProbeJob.new, payload, "worker") do
        raise RuntimeError, "boom E"
      end
    end

    entry = Sidekiq::RetrySet.new.to_a.first
    assert_equal "worker", entry["capability"]
    assert_equal "worker", entry["origin_queue"]
  end

  it "leaves unclassified legacy jobs on the normal retry path" do
    # A default capsule with no declared capability must preserve the historic
    # behavior: the job retries on its queue with no capability fields.
    default = @config.default_capsule
    default.queues = %w[default]
    default.instance_variable_set(:@redis, @pool)

    payload = Sidekiq.dump_json({
      "class" => ContinuityProbeJob.name,
      "args" => ["F"],
      "queue" => "default",
      "retry" => true,
      "retry_queue" => "low",
      "jid" => "f" * 24
    })

    assert_raises(Sidekiq::JobRetry::Handled) do
      Sidekiq::JobRetry.new(default).local(ContinuityProbeJob.new, payload, "default") do
        raise RuntimeError, "boom F"
      end
    end

    entry = Sidekiq::RetrySet.new.to_a.first
    assert_equal "low", entry["queue"], "existing retry_queue routing is preserved"
    refute entry.item.key?("capability")
    refute entry.item.key?("origin_queue")
    assert_equal 0, Sidekiq::RejectedSet.new.size

    make_due!
    Sidekiq::Scheduled::Poller.new(@config).enqueue
    assert_equal 1, @redis.llen("queue:low")
    assert_equal 0, Sidekiq::RejectedSet.new.size
  end

  it "lets an operator inspect and re-approve a rejected retry" do
    fail_job(jid: "9" * 24, label: "G", retry_queue: "ops")
    make_due!
    Sidekiq::Scheduled::Poller.new(@config).enqueue

    entry = Sidekiq::RejectedSet.new.to_a.first
    refute_nil entry
    assert_equal "unapproved_retry_queue", entry["rejection_reason"]
    assert_equal "boom G", entry["error_message"]
    assert entry.failed_at

    # After approving the route, an operator can requeue the retained retry.
    # The rejection metadata is cleared; the original failure facts stay.
    @config.approve_retry_fallback("ops", capability: "worker")
    entry.retry

    assert_equal 0, Sidekiq::RejectedSet.new.size
    assert_equal 1, @redis.llen("queue:ops")
    requeued = Sidekiq.load_json(@redis.lrange("queue:ops", 0, -1).first)
    assert_equal "boom G", requeued["error_message"]
    refute requeued.key?("rejection_reason")
    refute requeued.key?("status")
    assert_equal "worker", requeued["capability"]

    run_in(@ops, "ops")
    assert_equal ["G"], ContinuityProbeJob.runs.map { |run| run[:label] }
    assert_equal "ops", ContinuityProbeJob.runs.first[:capsule]
  end
end

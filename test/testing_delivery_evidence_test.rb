# frozen_string_literal: true

# Security regression evidence for the pre-release Sidekiq testing audit.
#
# This file proves, with local connection doubles only (no Redis server), where
# a job actually ends up when the *same* job class is pushed while
# Sidekiq::Testing is in :fake or :inline mode:
#
#   * :fake   -> the job is parked in the in-memory substitute queue and the
#                business #perform is never invoked.
#   * :inline -> the job bypasses every queue and #perform is executed
#                immediately, including raising a plain exception on the
#                failing path.
#   * :disable-> the standard client delivery entry (Client#atomic_push and
#                its Redis SADD/LPUSH/ZADD commands) is really touched.
#
# The two test modes are exercised in separate threads so the thread-local
# mode switch is part of the evidence. Nothing here opens a socket: the
# "standard delivery" path is driven through an in-memory Redis double, so the
# Redis-dependent parts of the suite are not started by this acceptance.

begin
  require_relative "helper"
rescue LoadError
  $LOAD_PATH.unshift File.expand_path("../lib", __dir__)
  require "minitest/autorun"
  require "connection_pool"
  require "sidekiq"
end

require "sidekiq/test_api"

# Plain, in-memory Redis double. It only implements the surface the standard
# delivery path calls and records every command so a test can prove whether the
# real entry point was reached, without ever opening a network connection.
class RecordingRedis
  attr_reader :commands

  def initialize
    @commands = []
    @mutex = Mutex.new
  end

  def pipelined
    yield self
    @commands
  end

  def sadd(key, members)
    @mutex.synchronize { @commands << [:sadd, key, members] }
  end

  def lpush(key, payloads)
    @mutex.synchronize { @commands << [:lpush, key, payloads] }
  end

  def zadd(key, members)
    @mutex.synchronize { @commands << [:zadd, key, members] }
  end

  def close; end
end

# The single job class reused across both modes, as required by the audit.
class RegressionProbeJob
  include Sidekiq::Job

  sidekiq_class_attribute :run_log
  self.run_log = []
  @log_mutex = Mutex.new

  class << self
    def record_run(marker)
      @log_mutex.synchronize { run_log << marker }
    end

    def reset!
      @log_mutex.synchronize { run_log.clear }
    end
  end

  def perform(marker, raise_error = false)
    raise RuntimeError, "probe failure for #{marker}" if raise_error

    RegressionProbeJob.record_run(marker)
  end
end

describe "Sidekiq testing delivery evidence" do
  before do
    Sidekiq.testing!(:disable)
    Sidekiq::Queues.clear_all
    RegressionProbeJob.reset!
  end

  after do
    Sidekiq.testing!(:disable)
    Sidekiq::Queues.clear_all
    Thread.current[:sidekiq_redis_pool] = nil
  end

  # The substitute queue is process-global, so both worker threads share it.
  # Snapshot it under a mutex immediately before and after each block and keep
  # only the delta: that attributes parked jobs to the thread that pushed them
  # and keeps the two modes from contaminating each other's evidence.
  def queue_snapshot(mutex)
    mutex.synchronize { RegressionProbeJob.jobs.map { |job| job["args"].first }.dup }
  end

  # Two threads, one locked to :fake and one locked to :inline. Each captures
  # its own evidence snapshot so the modes cannot bleed into each other.
  def build_mode_threads
    evidence = {}
    delivery_double = RecordingRedis.new
    delivery_pool = ConnectionPool.new { delivery_double }
    queue_mutex = Mutex.new

    fake_thread = Thread.new do
      Sidekiq::Testing.fake! do
        before = queue_snapshot(queue_mutex)
        fake_markers = yield(:fake, delivery_pool)
        evidence[:fake] = {
          mode: Sidekiq::Testing.__test_mode,
          local_mode: Sidekiq::Testing.__local_test_mode,
          queued_markers: queue_snapshot(queue_mutex) - before,
          ran_markers: RegressionProbeJob.run_log.grep(/-fake\b/),
          delivery_commands: delivery_double.commands.size
        }
        evidence[:fake_markers] = Array(fake_markers)
      end
    end

    inline_thread = Thread.new do
      Sidekiq::Testing.inline! do
        before = queue_snapshot(queue_mutex)
        begin
          inline_markers = yield(:inline, delivery_pool)
          error = nil
        rescue RuntimeError => e
          error = e
        end
        evidence[:inline] = {
          mode: Sidekiq::Testing.__test_mode,
          local_mode: Sidekiq::Testing.__local_test_mode,
          queued_markers: queue_snapshot(queue_mutex) - before,
          ran_markers: RegressionProbeJob.run_log.grep(/-inline\b/),
          delivery_commands: delivery_double.commands.size,
          error: error
        }
        evidence[:inline_markers] = Array(inline_markers)
      end
    end

    [fake_thread, inline_thread, evidence, delivery_double]
  end

  describe "single submission (perform_async)" do
    it "parks the job in the substitute queue in fake mode and executes it inline" do
      fake_thread, inline_thread, evidence, delivery_double =
        build_mode_threads do |mode, pool|
          Thread.current[:sidekiq_redis_pool] = pool
          marker = "single-#{mode}"
          RegressionProbeJob.perform_async(marker)
          marker
        end
      fake_thread.join
      inline_thread.join

      # Fake path: substituted, queued, business code untouched.
      assert_equal :fake, evidence[:fake][:mode]
      assert_equal :fake, evidence[:fake][:local_mode]
      assert_equal ["single-fake"], evidence[:fake][:queued_markers]
      assert_empty evidence[:fake][:ran_markers]
      refute_includes RegressionProbeJob.run_log, "single-fake"

      # Inline path: executed immediately as mocked business work, never queued.
      assert_equal :inline, evidence[:inline][:mode]
      assert_equal :inline, evidence[:inline][:local_mode]
      assert_empty evidence[:inline][:queued_markers]
      assert_equal ["single-inline"], evidence[:inline][:ran_markers]
      assert_nil evidence[:inline][:error]

      # Neither testing mode reaches the standard Redis delivery entry point.
      assert_equal 0, evidence[:fake][:delivery_commands]
      assert_equal 0, evidence[:inline][:delivery_commands]
      assert_empty delivery_double.commands
    end

    it "raises a plain exception from the inline path while the fake path stays queued" do
      fake_thread, inline_thread, evidence, _delivery_double =
        build_mode_threads do |mode, pool|
          Thread.current[:sidekiq_redis_pool] = pool
          marker = "single-bad-#{mode}"
          RegressionProbeJob.perform_async(marker, true)
          marker
        end
      fake_thread.join
      inline_thread.join

      # Fake mode never executes #perform, so the failing job cannot raise and
      # simply waits in the substitute queue.
      assert_equal ["single-bad-fake"], evidence[:fake][:queued_markers]
      assert_empty evidence[:fake][:ran_markers]

      # Inline mode executes #perform and the plain exception surfaces to the
      # caller; the job is gone (not parked) because no queue is involved.
      assert_instance_of RuntimeError, evidence[:inline][:error]
      assert_equal "probe failure for single-bad-inline", evidence[:inline][:error].message
      assert_empty evidence[:inline][:queued_markers]
      assert_empty evidence[:inline][:ran_markers]
      refute_includes RegressionProbeJob.run_log, "single-bad-inline"
    end
  end

  describe "bulk submission (push_bulk)" do
    it "stores every payload in the substitute queue in fake mode and runs them inline" do
      fake_thread, inline_thread, evidence, delivery_double =
        build_mode_threads do |mode, pool|
          Thread.current[:sidekiq_redis_pool] = pool
          markers = ["bulk-#{mode}-1", "bulk-#{mode}-2"]
          Sidekiq::Client.push_bulk(
            "class" => RegressionProbeJob,
            "args" => markers.map { |marker| [marker] }
          )
          markers
        end
      fake_thread.join
      inline_thread.join

      # Fake path: both payloads parked, none executed.
      assert_equal ["bulk-fake-1", "bulk-fake-2"], evidence[:fake][:queued_markers]
      assert_empty evidence[:fake][:ran_markers]

      # Inline path: both payloads executed in order, none queued.
      assert_empty evidence[:inline][:queued_markers]
      assert_equal ["bulk-inline-1", "bulk-inline-2"], evidence[:inline][:ran_markers]
      assert_nil evidence[:inline][:error]

      assert_equal 0, evidence[:fake][:delivery_commands]
      assert_equal 0, evidence[:inline][:delivery_commands]
      assert_empty delivery_double.commands
    end

    it "stops the inline batch on the first failure while the fake batch stays intact" do
      fake_thread, inline_thread, evidence, _delivery_double =
        build_mode_threads do |mode, pool|
          Thread.current[:sidekiq_redis_pool] = pool
          markers = ["bulk-#{mode}-ok", "bulk-#{mode}-boom"]
          Sidekiq::Client.push_bulk(
            "class" => RegressionProbeJob,
            "args" => [[markers[0]], [markers[1], true]]
          )
          markers
        end
      fake_thread.join
      inline_thread.join

      # Fake mode: the whole batch is stored verbatim, nothing runs, no raise.
      assert_equal ["bulk-fake-ok", "bulk-fake-boom"], evidence[:fake][:queued_markers]
      assert_empty evidence[:fake][:ran_markers]

      # Inline mode: the first payload runs, the second raises and aborts the
      # batch, leaving an explicit record of how each job ended.
      assert_equal ["bulk-inline-ok"], evidence[:inline][:ran_markers]
      refute_includes RegressionProbeJob.run_log, "bulk-inline-boom"
      assert_instance_of RuntimeError, evidence[:inline][:error]
      assert_equal "probe failure for bulk-inline-boom", evidence[:inline][:error].message
      assert_empty evidence[:inline][:queued_markers]
    end
  end

  describe "mode after the blocks exit" do
    it "restores each thread-local mode without disturbing the global mode" do
      snapshots = {}
      threads = []

      threads << Thread.new do
        Sidekiq::Testing.fake! do
          snapshots[:fake_inside] = {
            local: Sidekiq::Testing.__local_test_mode,
            effective: Sidekiq::Testing.__test_mode
          }
        end
        snapshots[:fake_after] = {
          local: Sidekiq::Testing.__local_test_mode,
          effective: Sidekiq::Testing.__test_mode
        }
      end

      threads << Thread.new do
        Sidekiq::Testing.inline! do
          snapshots[:inline_inside] = {
            local: Sidekiq::Testing.__local_test_mode,
            effective: Sidekiq::Testing.__test_mode
          }
        end
        snapshots[:inline_after] = {
          local: Sidekiq::Testing.__local_test_mode,
          effective: Sidekiq::Testing.__test_mode
        }
      end

      threads.each(&:join)

      assert_equal :fake, snapshots[:fake_inside][:local]
      assert_equal :fake, snapshots[:fake_inside][:effective]
      assert_equal :inline, snapshots[:inline_inside][:local]
      assert_equal :inline, snapshots[:inline_inside][:effective]

      # Block-scoped modes are cleared on exit; the threads fall back to the
      # global :disable mode set in the before hook.
      assert_nil snapshots[:fake_after][:local]
      assert_equal :disable, snapshots[:fake_after][:effective]
      assert_nil snapshots[:inline_after][:local]
      assert_equal :disable, snapshots[:inline_after][:effective]

      assert Sidekiq::Testing.disabled?
      assert_nil Sidekiq::Testing.__local_test_mode
    end
  end

  describe "standard delivery entry point" do
    before do
      Sidekiq::Testing.disable!
      @recording_redis = RecordingRedis.new
      Thread.current[:sidekiq_redis_pool] = ConnectionPool.new { @recording_redis }
    end

    it "routes a single push through the real Redis commands in disable mode" do
      jid = RegressionProbeJob.perform_async("standard-single")

      refute_nil jid
      assert_equal 2, @recording_redis.commands.size
      assert_equal [:sadd, "queues", ["default"]], @recording_redis.commands[0]
      assert_equal :lpush, @recording_redis.commands[1][0]
      assert_equal "queue:default", @recording_redis.commands[1][1]
      pushed = Sidekiq.load_json(@recording_redis.commands[1][2].first)
      assert_equal "RegressionProbeJob", pushed["class"]
      assert_equal ["standard-single"], pushed["args"]
      assert_equal jid, pushed["jid"]

      # The standard entry delivers to Redis rather than running the job.
      assert_empty RegressionProbeJob.jobs
      refute_includes RegressionProbeJob.run_log, "standard-single"
      assert Sidekiq::Testing.disabled?
    end

    it "routes a bulk push through one SADD and one LPUSH carrying every payload" do
      jids = Sidekiq::Client.push_bulk(
        "class" => RegressionProbeJob,
        "args" => [["standard-bulk-1"], ["standard-bulk-2"]]
      )

      assert_equal 2, jids.size
      assert_equal 2, @recording_redis.commands.size
      assert_equal [:sadd, "queues", ["default"]], @recording_redis.commands[0]
      assert_equal :lpush, @recording_redis.commands[1][0]
      payloads = @recording_redis.commands[1][2].map { |raw| Sidekiq.load_json(raw) }
      assert_equal [["standard-bulk-1"], ["standard-bulk-2"]], payloads.map { |job| job["args"] }
      assert_equal jids, payloads.map { |job| job["jid"] }

      assert_empty RegressionProbeJob.jobs
      assert_empty RegressionProbeJob.run_log
    end
  end
end

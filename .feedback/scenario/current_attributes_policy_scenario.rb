# frozen_string_literal: true

# End-to-end, dependency-free scenario for the CurrentAttributes field
# allowlist (SEC7558). It does not need Redis, Active Job or Rails:
#
#   1. A first job is enqueued while the request context carries several
#      organization fields. Only the allowlisted fields may land in the
#      persistent job message.
#   2. The job fails its first execution; Sidekiq::JobRetry stores the exact
#      message in the retry set (captured here instead of a real Redis).
#   3. The persistence policy is narrowed before the retry runs.
#   4. The retry executes and must only expose the fields still approved,
#      even though the stored message still contains the old broad payload.
#   5. An unrelated job is processed by the same worker, in a recycled
#      thread; it must never see the first job's context.
#   6. A monitoring observer records the approved request_id on every
#      execution while the disallowed secret never appears.
#
# Run:  sh .feedback/ruby-env.sh ruby .feedback/scenario/current_attributes_policy_scenario.rb

$LOAD_PATH.unshift File.expand_path("../../../lib", __dir__)
# Local-only ActiveJob::Arguments shim (Active Job is not in the locked bundle).
$LOAD_PATH.unshift File.expand_path("shim", __dir__)

require "logger"
require "stringio"

# Active Support and its dependencies are installed system-wide but not part
# of the locked .feedback bundle; make them discoverable without disturbing
# the bundle (Sidekiq's own locked dependencies stay on the bundle path).
# Only each gem's top-level lib directory is added so framework-internal
# directories never shadow top-level requires such as `require "i18n"`.
gem_roots = (Gem.path + Gem.default_path + [
  "/opt/homebrew/lib/ruby/gems/#{RbConfig::CONFIG["ruby_version"]}",
  "/opt/homebrew/lib/ruby/gems/4.0.0"
]).uniq
gem_roots.each do |path|
  Dir.glob(File.join(path, "gems", "*", "lib")).each do |lib|
    next unless File.directory?(lib)

    $LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
  end
end
# concurrent-ruby 1.3 nests its loadable lib one level deeper.
Dir.glob("/opt/homebrew/lib/ruby/gems/*/gems/concurrent-ruby-*/lib/concurrent-ruby").each do |lib|
  $LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
end

require "active_support"
require "active_support/core_ext/string/inflections"
require "active_support/current_attributes"
require "active_job/arguments"

require "sidekiq"
require "sidekiq/middleware/current_attributes"
require "sidekiq/job_retry"

module Sec7558
  class Current < ActiveSupport::CurrentAttributes
    # Organization fields available on the first execution. The policy
    # decides which of them are allowed to be persisted and reused.
    attribute :tenant_id, :org_id, :request_id, :secret
  end

  class FailingOrganizationJob
    include Sidekiq::Job

    sidekiq_options retry: 1

    def self.failures_remaining
      @failures_remaining ||= 1
    end

    def self.failures_remaining=(value)
      @failures_remaining = value
    end

    def perform
      Sec7558.observation!(
        jid: jid,
        job: self.class.name,
        attempt: Sec7558.attempt,
        tenant_id: Sec7558::Current.tenant_id,
        org_id: Sec7558::Current.org_id,
        request_id: Sec7558::Current.request_id,
        secret: Sec7558::Current.secret
      )
      return if self.class.failures_remaining.zero?

      self.class.failures_remaining -= 1
      raise "simulated first-execution failure for jid=#{jid}"
    end
  end

  class UnrelatedJob
    include Sidekiq::Job

    sidekiq_options retry: false

    def perform
      Sec7558.observation!(
        jid: jid,
        job: self.class.name,
        attempt: Sec7558.attempt,
        tenant_id: Sec7558::Current.tenant_id,
        org_id: Sec7558::Current.org_id,
        request_id: Sec7558::Current.request_id,
        secret: Sec7558::Current.secret
      )
    end
  end

  # Stands in for the monitoring/logging pipeline: it may only correlate on
  # fields the policy approved for persistence.
  class MonitoringObserver
    include Sidekiq::ServerMiddleware

    def call(instance, job, queue)
      yield
    ensure
      Sec7558.monitoring_events << {
        jid: job["jid"],
        class: job["wrapped"] || job["class"],
        request_id: Sec7558::Current.request_id,
        secret: Sec7558::Current.secret,
        queue: queue
      }
    end
  end

  # Minimal stand-in for the Redis structures touched by JobRetry.
  class FakeRedis
    attr_reader :retry_set, :dead_set

    def initialize
      @retry_set = []
      @dead_set = []
    end

    def call(*)
      yield self if block_given?
    end

    def zadd(set, score, payload)
      target = set == "dead" ? @dead_set : @retry_set
      target << [score, payload]
    end

    def multi
      yield self
    end
  end

  class FakePool
    def initialize(connection)
      @connection = connection
    end

    def with
      yield @connection
    end
  end

  class << self
    attr_accessor :observations, :monitoring_events, :attempt, :persisted_messages, :retry_messages

    def observation!(payload)
      observations << payload
    end

    def reset!
      self.observations = []
      self.monitoring_events = []
      self.persisted_messages = []
      self.retry_messages = []
      self.attempt = 0
      Current.clear_all
      FailingOrganizationJob.failures_remaining = 1
    end
  end
end

def section(title)
  puts "\n=== #{title} ==="
end

def check(label, condition)
  status = condition ? "PASS" : "FAIL"
  puts "[#{status}] #{label}"
  raise "assertion failed: #{label}" unless condition
end

# Execute a unit of work the way a Sidekiq Processor thread does: in a fresh
# thread with a reset CurrentAttributes context (the Rails reloader does the
# reset between units of work in a real app). What the job can observe must
# therefore come solely from the persisted job message, never from leftovers.
def run_worker
  failure = nil
  thread = Thread.new do
    begin
      Sec7558::Current.reset
      yield
    ensure
      Sec7558::Current.reset
    end
  rescue => e
    failure = e
  end
  thread.join
  raise failure if failure
end

Sec7558.reset!

# ---------------------------------------------------------------------------
# Policy v1: tenant_id, org_id and request_id may be persisted; secret may not.
# ---------------------------------------------------------------------------
config_v1 = Sidekiq::Config.new
config_v1.logger = Logger.new(IO::NULL)
fake_redis_v1 = Sec7558::FakeRedis.new
config_v1.instance_variable_set(:@redis, Sec7558::FakePool.new(fake_redis_v1))

Sidekiq::CurrentAttributes.persist(
  {"Sec7558::Current" => [:tenant_id, :org_id, :request_id]},
  config_v1
)

section "1. First job enqueued with the full request context"
first_job = {
  "class" => "Sec7558::FailingOrganizationJob",
  "args" => [],
  "retry" => 1,
  "queue" => "default",
  "jid" => "jid-first-0001"
}

Sec7558::Current.tenant_id = "tenant-7"
Sec7558::Current.org_id = "org-42"
Sec7558::Current.request_id = "req-abc-123"
Sec7558::Current.secret = "super-secret-value"

config_v1.client_middleware.invoke(nil, first_job, "default", nil) {}
Sec7558.persisted_messages << Sidekiq.load_json(Sidekiq.dump_json(first_job))

persisted_cattr = Sidekiq.load_json(Sidekiq.dump_json(first_job["cattr"]))
puts "persistent job message cattr: #{persisted_cattr.inspect}"
check "persisted message keeps tenant_id", persisted_cattr["tenant_id"] == "tenant-7"
check "persisted message keeps org_id", persisted_cattr["org_id"] == "org-42"
check "persisted message keeps request_id", persisted_cattr["request_id"] == "req-abc-123"
check "persisted message never contains the secret",
  !Sidekiq.dump_json(first_job).include?("super-secret-value")

section "2. First execution fails and the job is moved into the retry set"
Sec7558.attempt = 1
job_instance = Sec7558::FailingOrganizationJob.new
job_instance.jid = first_job["jid"]
retrier_v1 = Sidekiq::JobRetry.new(config_v1)

run_worker do
  begin
    config_v1.server_middleware.invoke(job_instance, first_job, "default") do
      retrier_v1.local(job_instance, Sidekiq.dump_json(first_job), "default") do
        job_instance.perform
      end
    end
  rescue Sidekiq::JobRetry::Handled
    # expected: JobRetry turned the failure into a stored retry
  end
end

check "first execution raised and was captured", Sec7558.observations.size == 1
first_observation = Sec7558.observations.last
check "first execution saw tenant_id", first_observation[:tenant_id] == "tenant-7"
check "first execution saw org_id", first_observation[:org_id] == "org-42"
check "first execution saw request_id", first_observation[:request_id] == "req-abc-123"
check "first execution never saw the secret", first_observation[:secret].nil?
check "retry set holds one message", fake_redis_v1.retry_set.size == 1

retry_payload = fake_redis_v1.retry_set.last.last
stored_retry = Sidekiq.load_json(retry_payload)
Sec7558.retry_messages << stored_retry
puts "retry-set message cattr: #{stored_retry["cattr"].inspect}"
check "stored retry message preserves the original allowlisted payload",
  stored_retry["cattr"]["tenant_id"] == "tenant-7" &&
    stored_retry["cattr"]["org_id"] == "org-42" &&
    stored_retry["cattr"]["request_id"] == "req-abc-123"
check "stored retry message contains no secret",
  !retry_payload.include?("super-secret-value")

# ---------------------------------------------------------------------------
# Policy v2 (strategy change): org_id is no longer approved. The stored retry
# message is untouched, but every worker execution must now honor v2.
# ---------------------------------------------------------------------------
section "3. Policy narrows before the retry (org_id revoked)"
config_v2 = Sidekiq::Config.new
config_v2.logger = Logger.new(IO::NULL)
fake_redis_v2 = Sec7558::FakeRedis.new
config_v2.instance_variable_set(:@redis, Sec7558::FakePool.new(fake_redis_v2))

Sidekiq::CurrentAttributes.persist(
  {"Sec7558::Current" => [:tenant_id, :request_id]},
  config_v2
)
config_v2.server_middleware.add Sec7558::MonitoringObserver

section "4. Retry of the same job under the narrowed policy"
Sec7558.attempt = 2
retry_job = Sidekiq.load_json(Sidekiq.dump_json(stored_retry))
retry_instance = Sec7558::FailingOrganizationJob.new
retry_instance.jid = retry_job["jid"]
retrier_v2 = Sidekiq::JobRetry.new(config_v2)

run_worker do
  config_v2.server_middleware.invoke(retry_instance, retry_job, "default") do
    retrier_v2.local(retry_instance, Sidekiq.dump_json(retry_job), "default") do
      retry_instance.perform
    end
  end
end

check "retry executed successfully", Sec7558.observations.size == 2
retry_observation = Sec7558.observations.last
puts "retry execution visible fields: #{retry_observation.inspect}"
check "retry still sees tenant_id", retry_observation[:tenant_id] == "tenant-7"
check "retry still sees request_id", retry_observation[:request_id] == "req-abc-123"
check "retry loses revoked org_id", retry_observation[:org_id].nil?
check "retry never sees the secret", retry_observation[:secret].nil?
check "no new retry was scheduled on success", fake_redis_v2.retry_set.empty?

section "5. Unrelated job on the same worker, in a recycled thread"
unrelated_job = {
  "class" => "Sec7558::UnrelatedJob",
  "args" => [],
  "retry" => false,
  "queue" => "default",
  "jid" => "jid-unrelated-0002"
}

# Run in another fresh/recycled Processor thread; Current is reset both
# before and after the unit of work.
unrelated_instance = Sec7558::UnrelatedJob.new
unrelated_instance.jid = unrelated_job["jid"]
post_work_state = nil
run_worker do
  config_v2.server_middleware.invoke(unrelated_instance, unrelated_job, "default") do
    unrelated_instance.perform
  end
  # observed inside the worker thread once the middleware has unwound
  post_work_state = {
    tenant_id: Sec7558::Current.tenant_id,
    org_id: Sec7558::Current.org_id,
    request_id: Sec7558::Current.request_id,
    secret: Sec7558::Current.secret
  }
end

unrelated_observation = Sec7558.observations.last
puts "unrelated job visible fields: #{unrelated_observation.inspect}"
check "unrelated job sees no tenant_id", unrelated_observation[:tenant_id].nil?
check "unrelated job sees no org_id", unrelated_observation[:org_id].nil?
check "unrelated job sees no request_id", unrelated_observation[:request_id].nil?
check "unrelated job sees no secret", unrelated_observation[:secret].nil?
check "recycled thread keeps no context after work",
  post_work_state.values.all?(&:nil?)

section "6. Monitoring correlation on every execution"
Sec7558.monitoring_events.each { |event| puts event.inspect }
retry_monitor = Sec7558.monitoring_events.find { |event| event[:jid] == "jid-first-0001" }
unrelated_monitor = Sec7558.monitoring_events.find { |event| event[:jid] == "jid-unrelated-0002" }
check "monitoring correlates the retry with the approved request_id",
  retry_monitor && retry_monitor[:request_id] == "req-abc-123"
check "monitoring never observes the secret",
  Sec7558.monitoring_events.all? { |event| event[:secret].nil? }
check "unrelated job has no request_id to correlate",
  unrelated_monitor && unrelated_monitor[:request_id].nil?

section "7. All persistent messages"
Sec7558.persisted_messages.each { |msg| puts "enqueued: #{msg.inspect}" }
Sec7558.retry_messages.each { |msg| puts "retry:    #{msg.inspect}" }
all_payloads = (Sec7558.persisted_messages + Sec7558.retry_messages).map { |msg| Sidekiq.dump_json(msg) }
check "no persistent payload ever contains the secret",
  all_payloads.none? { |payload| payload.include?("super-secret-value") }
check "every persistent payload carries the approved request_id",
  all_payloads.all? { |payload| payload.include?("req-abc-123") }

puts "\nAll SEC7558 scenario checks passed."

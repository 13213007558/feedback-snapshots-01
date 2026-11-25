# frozen_string_literal: true

# Local, Redis-free demonstration of approval-scoped iterable job recovery.
#
# Run with:
#   ruby -Ilib examples/iterable_scope/demo.rb
#
# It uses Sidekiq::Job::Iterable::MemoryStateStore, so nothing touches Redis
# and no real jobs are enqueued. The demo pauses an enumerator at a chosen
# point and shows three things:
#
#   1. A committed iteration whose progress save failed: the next attempt
#      must not re-apply that record, and counts it as recovered.
#   2. An approval narrowed midway: the old cursor is discarded and only the
#      newly approved records are processed.
#   3. A fully legal resume within the same approval: it continues from the
#      persisted cursor without repeating committed records.
#
# Diagnostics are deliberately limited: counters and a 12-character digest of
# the approval scope. Cursors and record payloads are never printed.

require "sidekiq"
require "logger"

Sidekiq.default_configuration.logger = Logger.new(IO::NULL)

# A batch job over an approved set of record ids. Each record is processed
# once per approval; the commit ledger records the effect, and the scope
# digest records which approval authorized it.
class ApprovalScopedBatchJob
  include Sidekiq::IterableJob

  class << self
    attr_accessor :approval, :store, :processed, :pause_after, :save_fails_after,
      :narrow_after, :narrow_to, :revoke_after

    def reset!(approval:, processed: [])
      self.approval = approval
      self.processed = processed
      self.pause_after = nil
      self.save_fails_after = nil
      self.narrow_after = nil
      self.narrow_to = nil
      self.revoke_after = nil
    end
  end

  self.store = Sidekiq::Job::Iterable::MemoryStateStore.new
  self.processed = []

  def approval_scope
    self.class.approval
  end

  def iteration_commit_key(record_id)
    record_id
  end

  def iteration_state_store
    self.class.store
  end

  # Flush at every iteration so the demo is deterministic rather than timing
  # dependent.
  def iteration_state_flush_interval
    0
  end

  def build_enumerator(cursor:)
    ids = Array(self.class.approval && self.class.approval["record_ids"])
    array_enumerator(ids, cursor: cursor)
  end

  def interrupted?
    self.class.pause_after && attempt_count >= self.class.pause_after
  end

  def each_iteration(record_id)
    @_attempt_count = attempt_count + 1
    self.class.processed << record_id

    # Simulate losing the progress write right after this record's business
    # effect committed.
    if self.class.save_fails_after && @_attempt_count == self.class.save_fails_after
      self.class.store.fail_next_write!
    end

    # The approval changes while the job is running.
    if self.class.narrow_after && @_attempt_count == self.class.narrow_after
      self.class.approval = {"record_ids" => self.class.narrow_to, "ticket" => "APPROVAL-2"}
    end
    if self.class.revoke_after && @_attempt_count == self.class.revoke_after
      self.class.approval = nil
    end
  end

  private

  def attempt_count
    @_attempt_count || 0
  end
end

def run_attempt(jid)
  job = ApprovalScopedBatchJob.new
  job.jid = jid
  error = nil
  begin
    job.perform
  rescue => ex
    error = ex
  end
  [job, error]
end

def report(label, job, error, jid)
  state = ApprovalScopedBatchJob.store.read("it-#{jid}")
  puts label
  puts "  outcome:      #{error ? "#{error.class}: #{error.message}" : "quiet stop"}"
  puts "  processed:    #{ApprovalScopedBatchJob.processed.inspect}"
  puts "  diagnostics:  #{job.iteration_diagnostics.inspect}"
  puts "  resumable:    #{state["c"] && state["c"] != "null" ? "cursor present" : "no cursor"}"
  puts
end

puts "=== 1. Committed write, lost progress ==="
puts "The third record commits, then the progress save fails. The retry must"
puts "not apply it twice; it reports one recovered record instead."
puts
ApprovalScopedBatchJob.reset!(
  approval: {"record_ids" => [101, 102, 103, 104], "ticket" => "APPROVAL-1"}
)
ApprovalScopedBatchJob.save_fails_after = 3
job, error = run_attempt("batch-A")
report("attempt 1 (save fails after record 103)", job, error, "batch-A")

ApprovalScopedBatchJob.save_fails_after = nil
job, error = run_attempt("batch-A")
report("attempt 2 (same approval, honest resume)", job, error, "batch-A")

puts "=== 2. Approval narrowed midway ==="
puts "Records 201-206 were approved, then the approval shrinks to 201-202."
puts "The old cursor is discarded; the job restarts within the narrower scope."
puts
ApprovalScopedBatchJob.reset!(
  approval: {"record_ids" => [201, 202, 203, 204, 205, 206], "ticket" => "APPROVAL-1"}
)
ApprovalScopedBatchJob.narrow_after = 3
ApprovalScopedBatchJob.narrow_to = [201, 202]
job, error = run_attempt("batch-B")
report("attempt 1 (scope narrowed to 201-202 after record 203)", job, error, "batch-B")

job, error = run_attempt("batch-B")
report("attempt 2 (narrower approval)", job, error, "batch-B")

puts "=== 3. Legal resume within one approval ==="
puts "A pause at record 302 with no scope change resumes from the cursor and"
puts "never re-applies 301 or 302."
puts
ApprovalScopedBatchJob.reset!(
  approval: {"record_ids" => [301, 302, 303, 304], "ticket" => "APPROVAL-3"}
)
ApprovalScopedBatchJob.pause_after = 2
job, error = run_attempt("batch-C")
report("attempt 1 (paused after record 302)", job, error, "batch-C")

ApprovalScopedBatchJob.pause_after = nil
job, error = run_attempt("batch-C")
report("attempt 2 (same approval resumes)", job, error, "batch-C")

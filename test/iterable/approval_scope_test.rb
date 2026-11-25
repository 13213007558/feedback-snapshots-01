# frozen_string_literal: true

require_relative "../helper"
require "sidekiq/job/iterable"
require_relative "approval_scope_jobs"

describe Sidekiq::Job::Iterable::ScopeBinding do
  it "produces the same digest regardless of key order and symbol keys" do
    a = Sidekiq::Job::Iterable::ScopeBinding.digest({"ids" => [1, 2], "ticket" => "A"})
    b = Sidekiq::Job::Iterable::ScopeBinding.digest({ticket: "A", ids: [1, 2]})
    assert_equal a, b
  end

  it "changes when the approved set changes" do
    refute_equal Sidekiq::Job::Iterable::ScopeBinding.digest({"ids" => [1, 2, 3]}),
      Sidekiq::Job::Iterable::ScopeBinding.digest({"ids" => [1, 2]})
  end
end

describe "approval-scoped iterable jobs" do
  before do
    @config = reset!
    ApprovalScopedJob.reset!
  end

  it "does not re-apply a committed record when progress was not saved" do
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([1, 2, 3, 4])

    # The third record commits, then its progress write fails.
    ApprovalScopedJob.hook = lambda do |_record, count, _job|
      ApprovalScopedJob.store.fail_next_write! if count == 3
    end

    job, error = ApprovalScopedJob.attempt_with_error("commit-A")
    assert_kind_of IOError, error
    assert_equal [1, 2, 3], ApprovalScopedJob.processed
    assert_equal 3, job.iteration_diagnostics[:committed]
    assert_equal 1, job.iteration_diagnostics[:save_failures]

    # The approval is unchanged, so the retry resumes legitimately. Record 3
    # is recognized from the commit ledger and not applied twice.
    ApprovalScopedJob.hook = nil
    resumed = ApprovalScopedJob.attempt("commit-A")
    assert_equal [1, 2, 3, 4], ApprovalScopedJob.processed
    assert_equal 4, resumed.iteration_diagnostics[:processed]
    assert_equal 4, resumed.iteration_diagnostics[:iterations]
    assert_equal 4, resumed.iteration_diagnostics[:committed]
    assert_equal 1, resumed.iteration_diagnostics[:recovered]
    assert_nil resumed.iteration_diagnostics[:reason]
    assert_empty ApprovalScopedJob.store.read("it-commit-A")
  end

  it "restarts within a narrowed approval instead of reusing the old cursor" do
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([1, 2, 3, 4, 5, 6])
    ApprovalScopedJob.hook = lambda do |_record, count, job|
      job.class.approval_value = ApprovalScopedJob.approval([1, 2]) if count == 3
    end

    job, error = ApprovalScopedJob.attempt_with_error("narrow-A")
    assert_kind_of Sidekiq::Job::Interrupted, error
    assert_equal [1, 2, 3], ApprovalScopedJob.processed
    assert_equal 3, job.iteration_diagnostics[:revoked]
    assert_equal "scope_changed", job.iteration_diagnostics[:reason]

    # No resumable cursor is left for the wider approval.
    assert_equal "null", ApprovalScopedJob.store.read("it-narrow-A")["c"]

    ApprovalScopedJob.hook = nil
    resumed = ApprovalScopedJob.attempt("narrow-A")
    # Only the narrower approval runs; the old cursor did not authorize 4-6.
    assert_equal [1, 2, 3, 1, 2], ApprovalScopedJob.processed
    assert_equal 2, resumed.iteration_diagnostics[:processed]
    assert_equal 0, resumed.iteration_diagnostics[:recovered]
    assert_equal 3, resumed.iteration_diagnostics[:revoked]
    assert_equal "scope_changed", resumed.iteration_diagnostics[:reason]
  end

  it "stops without resuming when the approval is fully revoked" do
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([7, 8, 9])
    ApprovalScopedJob.hook = lambda do |_record, count, job|
      job.class.approval_value = nil if count == 2
    end

    revoked = ApprovalScopedJob.attempt("revoke-A")
    assert_equal "scope_revoked", revoked.iteration_diagnostics[:reason]
    assert_equal [7, 8], ApprovalScopedJob.processed

    state = ApprovalScopedJob.store.read("it-revoke-A")
    assert_equal "null", state["c"]

    # A later attempt has no approval and must not continue from any cursor.
    ApprovalScopedJob.hook = nil
    ApprovalScopedJob.processed = []
    still_revoked = ApprovalScopedJob.attempt("revoke-A")
    assert_equal "scope_revoked", still_revoked.iteration_diagnostics[:reason]
    assert_empty ApprovalScopedJob.processed
  end

  it "keeps redacted counters across repeated revoked attempts" do
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([61, 62, 63])
    ApprovalScopedJob.hook = lambda do |_record, count, job|
      job.class.approval_value = nil if count == 2
    end
    first = ApprovalScopedJob.attempt("revoke-B")
    assert_equal 2, first.iteration_diagnostics[:processed]

    ApprovalScopedJob.hook = nil
    ApprovalScopedJob.processed = []
    second = ApprovalScopedJob.attempt("revoke-B")
    assert_equal "scope_revoked", second.iteration_diagnostics[:reason]
    assert_equal 2, second.iteration_diagnostics[:processed]
    assert_empty ApprovalScopedJob.processed
  end

  it "keeps redacted counters across repeated revoked attempts" do
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([61, 62, 63])
    ApprovalScopedJob.hook = lambda do |_record, count, job|
      job.class.approval_value = nil if count == 2
    end
    first = ApprovalScopedJob.attempt("revoke-B")
    assert_equal 2, first.iteration_diagnostics[:processed]

    ApprovalScopedJob.hook = nil
    ApprovalScopedJob.processed = []
    second = ApprovalScopedJob.attempt("revoke-B")
    assert_equal "scope_revoked", second.iteration_diagnostics[:reason]
    assert_equal 2, second.iteration_diagnostics[:processed]
    assert_empty ApprovalScopedJob.processed
  end

  it "continues from the persisted cursor within one approval" do
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([10, 11, 12, 13])
    ApprovalScopedJob.pause_after = 2

    job, error = ApprovalScopedJob.attempt_with_error("legal-A")
    assert_kind_of Sidekiq::Job::Interrupted, error
    assert_equal [10, 11], ApprovalScopedJob.processed
    assert_equal 2, job.iteration_diagnostics[:committed]

    ApprovalScopedJob.pause_after = nil
    resumed = ApprovalScopedJob.attempt("legal-A")
    assert_equal [10, 11, 12, 13], ApprovalScopedJob.processed
    assert_equal 4, resumed.iteration_diagnostics[:processed]
    assert_equal 0, resumed.iteration_diagnostics[:recovered]
    assert_nil resumed.iteration_diagnostics[:reason]
  end

  it "does not trust a cursor saved before scope binding" do
    store = ApprovalScopedJob.store
    store.write("it-unbound-A", {"c" => "2", "ex" => 1, "diag" => Sidekiq.dump_json({"processed" => 2})})
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([21, 22, 23, 24])

    job = ApprovalScopedJob.attempt("unbound-A")
    # The old cursor is ignored; the approved scope runs from the start.
    assert_equal [21, 22, 23, 24], ApprovalScopedJob.processed
    assert_equal "unbound_progress", job.iteration_diagnostics[:reason]
  end

  it "exposes persisted diagnostics through IterableJobQuery" do
    tests = ApprovalScopedJob.store
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([51, 52, 53])
    ApprovalScopedJob.pause_after = 1
    ApprovalScopedJob.attempt_with_error("query-A")

    parsed = Sidekiq.load_json(tests.read("it-query-A")["diag"])
    assert_equal 1, parsed["processed"]
    assert_equal 12, parsed["scope"].length
    refute parsed.key?("cursor")
  end

  it "keeps cursor-only behavior for jobs without approval scopes" do
    UnscopedIterableJob.store = Sidekiq::Job::Iterable::MemoryStateStore.new
    UnscopedIterableJob.processed = []
    job = UnscopedIterableJob.new
    job.jid = "plain-A"

    job.extend(Module.new do
      def interrupted?
        true
      end
    end)

    assert_raises(Sidekiq::Job::Interrupted) { job.perform }

    state = UnscopedIterableJob.store.read("it-plain-A")
    assert state.key?("c")
    refute state.key?("sd")
    refute state.key?("diag")
  end

  it "exposes only redacted counters in diagnostics" do
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([31, 32])
    job = ApprovalScopedJob.attempt("redact-A")

    # The persisted state has no cursor (the job completed), and the only
    # remaining detail payload is counters plus a short digest.
    state = ApprovalScopedJob.store.read("it-redact-A")
    assert_empty state

    diag = job.iteration_diagnostics
    assert_equal 2, diag[:processed]
    assert_equal 2, diag[:committed]
    assert_equal 12, diag[:scope].length
    refute_includes diag.inspect, "31"
    refute_includes diag.inspect, "32"

    # An interrupted attempt keeps diagnostics but writes a null cursor.
    ApprovalScopedJob.approval_value = ApprovalScopedJob.approval([41, 42, 43])
    ApprovalScopedJob.pause_after = 1
    paused, = ApprovalScopedJob.attempt_with_error("redact-B")
    state = ApprovalScopedJob.store.read("it-redact-B")
    refute_includes state["diag"], "41"
    refute_includes state["diag"], "42"
    assert_nil paused.iteration_diagnostics[:reason]
  end
end

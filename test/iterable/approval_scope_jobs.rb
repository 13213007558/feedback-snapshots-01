# frozen_string_literal: true

require "sidekiq/job/iterable"

# A batch job whose progress is bound to an approval descriptor. Every
# processed record is appended to a shared list so tests can assert exactly
# what ran on each attempt.
class ApprovalScopedJob
  include Sidekiq::IterableJob

  class << self
    attr_accessor :store, :approval_value, :pause_after, :hook

    def processed
      @processed ||= []
    end

    def processed=(value)
      @processed = value
    end

    def reset!
      self.store = Sidekiq::Job::Iterable::MemoryStateStore.new
      self.approval_value = nil
      self.pause_after = nil
      self.hook = nil
      @processed = []
    end

    def approval(ids)
      {"record_ids" => ids, "ticket" => "ticket-#{ids.join("-")}"}
    end

    def attempt(jid)
      job = new
      job.jid = jid
      job.perform
      job
    end

    # Like +attempt+, but also returns the exception raised by a paused or
    # failed attempt so tests can inspect that job'state.
    def attempt_with_error(jid)
      job = new
      job.jid = jid
      error = nil
      begin
        job.perform
      rescue => ex
        error = ex
      end
      [job, error]
    end
  end

  def approval_scope
    self.class.approval_value
  end

  def iteration_commit_key(record_id)
    record_id
  end

  def iteration_state_store
    self.class.store
  end

  def iteration_state_flush_interval
    0
  end

  def build_enumerator(cursor:)
    ids = Array(self.class.approval_value && self.class.approval_value["record_ids"])
    array_enumerator(ids, cursor: cursor)
  end

  def interrupted?
    self.class.pause_after && attempt_count >= self.class.pause_after
  end

  def each_iteration(record_id)
    @_attempt_count = attempt_count + 1
    self.class.processed << record_id
    self.class.hook&.call(record_id, @_attempt_count, self)
  end

  private

  def attempt_count
    @_attempt_count || 0
  end
end

# A plain iterable job which does not opt into approval scopes. It must keep
# the historical cursor-only behavior.
class UnscopedIterableJob
  include Sidekiq::IterableJob

  class << self
    attr_accessor :store, :processed
  end

  def iteration_state_store
    self.class.store
  end

  def iteration_state_flush_interval
    0
  end

  def build_enumerator(cursor:)
    array_enumerator([1, 2, 3], cursor: cursor)
  end

  def each_iteration(record_id)
    (self.class.processed ||= []) << record_id
  end
end

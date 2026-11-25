# frozen_string_literal: true

require "set"

module Sidekiq
  ##
  # A retry must not gain execution privileges just because it is routed to a
  # different queue. Sidekiq records the capability of the capsule which first
  # executed a job and carries it in the retry payload. When the retry is
  # delivered, RetryPolicy compares that recorded capability with the
  # capability of the capsule which is about to execute it.
  #
  # A retry is allowed when:
  #
  # * the capsule's declared capability is exactly equivalent to the recorded
  #   capability (neither wider nor narrower), and
  # * the job is running on its original queue, or an operator has explicitly
  #   approved the target queue as a fallback for that capability.
  #
  # Approvals are deliberately separate from capability equality: a queue which
  # happens to be served by an equivalent capsule still needs an operator to
  # approve it for a capability. Approvals are evaluated at delivery time, so
  # widening a capsule during a retry's backoff window causes the retry to be
  # rejected instead of silently running with more authority.
  #
  # Approvals are mirrored in Redis so an operator approval made by one
  # process is visible to the process which later delivers the retry. If Redis
  # is unavailable the policy keeps working with its in-process approvals.
  #
  # Jobs without a recorded capability (legacy payloads) are not affected.
  class RetryPolicy
    Rejection = Data.define(:reason, :queue, :capsule, :required_capability, :actual_capability)

    CAPABILITY_SEPARATOR = ","
    FALLBACK_KEY = "sidekiq:retry_fallbacks"
    private_constant :CAPABILITY_SEPARATOR

    # Capabilities are compared as a normalized, sorted Array of Strings so
    # Symbols, Strings and comma-separated lists are all equivalent.
    #
    # @param value [String, Symbol, Array, Set, nil]
    # @return [Array<String>, nil]
    def self.normalize_capability(value)
      return nil if value.nil?

      values = case value
      when String
        value.split(CAPABILITY_SEPARATOR)
      when Array
        value.flat_map { |entry| entry.is_a?(String) ? entry.split(CAPABILITY_SEPARATOR) : [entry] }
      else
        Array(value)
      end

      values = values.map { |entry| entry.to_s.strip }.reject(&:empty?).uniq.sort
      values.empty? ? nil : values
    end

    # Strip the fields which only describe a retained rejection before the
    # job is pushed back onto a queue by an operator.
    #
    # @param job [Hash]
    # @return [Hash] the same hash
    def self.clear_rejection!(job)
      %w[status rejected_at rejection_reason required_capability
        actual_capability rejected_by_capsule rejected_queue rejected_on_queue].each do |key|
        job.delete(key)
      end
      job
    end

    # @param config [Sidekiq::Config, nil] used to persist and read approvals
    def initialize(config = nil)
      @config = config
      @mutex = Mutex.new
      @fallbacks = {}
    end

    # Approve +queue+ as a fallback for jobs whose recorded capability is
    # equivalent to +capability+. Repeat calls are idempotent.
    #
    # @param queue [String, Symbol]
    # @param capability [String, Symbol, Array]
    # @return [true]
    def approve_fallback(queue, capability:)
      key = capability_key(capability)
      raise ArgumentError, "capability is required" if key.nil?

      queue = queue.to_s
      raise ArgumentError, "queue is required" if queue.empty?

      @mutex.synchronize { (@fallbacks[key] ||= Set.new) << queue }
      persist(key, queue)
      true
    end

    # @return [Boolean] whether the approval existed and was removed
    def revoke_fallback(queue, capability:)
      key = capability_key(capability)
      return false if key.nil?

      queue = queue.to_s
      removed = @mutex.synchronize do
        set = @fallbacks[key]
        set ? !!set.delete(queue) : false
      end
      unpersist(key, queue)
      removed
    end

    # @return [Boolean]
    def approved_fallback?(queue, capability)
      key = capability_key(capability)
      return false if key.nil?

      queue = queue.to_s
      persisted = read_persisted(key)
      if persisted.nil?
        # Redis is unavailable; use this process's local approvals only.
        return @mutex.synchronize { @fallbacks.fetch(key, Set.new).include?(queue) }
      end

      @mutex.synchronize do
        (@fallbacks[key] ||= Set.new).merge(persisted)
      end
      persisted.include?(queue)
    end
    alias_method :approved?, :approved_fallback?

    # @return [Array<String>] queues approved for the given capability
    def approved_fallbacks(capability)
      key = capability_key(capability)
      return [] if key.nil?

      memory = @mutex.synchronize { @fallbacks.fetch(key, Set.new).to_a }
      persisted = read_persisted(key)
      ((persisted.nil? ? [] : persisted) | memory).sort
    end

    # Forget this process's cached view of persisted approvals. Useful for
    # tests and for long-running processes which want a fresh read.
    def clear_cache
      @mutex.synchronize { @fallbacks.clear }
      true
    end

    # Decide whether the given job may execute in +capsule+.
    #
    # @param job [Hash] the job payload
    # @param capsule [Sidekiq::Capsule]
    # @param queue [String] the queue the job was fetched from
    # @return [Rejection, nil] nil means the job is authorized
    def authorize(job, capsule:, queue:)
      required = self.class.normalize_capability(job["capability"])
      return nil if required.nil?

      actual = self.class.normalize_capability(capsule&.capability)
      on_retry = retry_payload?(job)

      # A legacy first execution in an unclassified capsule is allowed; once
      # the job has a recorded capability its retries must be classified.
      return nil if actual.nil? && !on_retry

      if actual.nil?
        return rejection(:capability_unclassified, queue, capsule, required, actual)
      end

      if actual != required
        return rejection(:capability_mismatch, queue, capsule, required, actual)
      end

      if on_retry
        target = (job["queue"] || queue).to_s
        unless queue_allowed?(job, target, required)
          return rejection(:unapproved_retry_queue, target, capsule, required, actual)
        end
      end

      nil
    end

    # Decide whether a retry may be pushed onto its target queue at all.
    #
    # A process only rejects when it can authoritatively see the capsules which
    # serve the queue, i.e. at least one of its own capsules lists the queue.
    # When every such capsule has an equivalent capability the retry may be
    # enqueued; otherwise the queue is unsafe for this job.
    #
    # @param job [Hash] the retry payload
    # @param config [Sidekiq::Config]
    # @return [Rejection, nil]
    def authorize_delivery(job, config)
      required = self.class.normalize_capability(job["capability"])
      return nil if required.nil?

      return nil unless retry_payload?(job)

      target = (job["queue"] || "").to_s
      unless queue_allowed?(job, target, required)
        return rejection(:unapproved_retry_queue, target, nil, required, nil)
      end

      serving = config.capsules.values.select { |capsule| capsule.queues.include?(target) }
      return nil if serving.empty?

      actual = serving.map { |capsule| self.class.normalize_capability(capsule.capability) }
      offending = actual.find { |caps| caps != required }
      return rejection(:capability_mismatch, target, nil, required, offending) if offending

      nil
    end

    # A retry may run on its original queue, or on a queue an operator
    # explicitly approved for the recorded capability. The configured
    # `retry_queue` is client-supplied and is therefore *not* trusted on its
    # own: it too must be approved before a retry is delivered there.
    def queue_allowed?(job, target, required)
      target == job["origin_queue"].to_s || approved_fallback?(target, required)
    end

    # Build the record persisted in the "rejected" sorted set. The original
    # failure fields (error_class, error_message, failed_at, retry_count, ...)
    # stay intact so operators can see why the retry was retained rather than
    # delivered.
    #
    # @return [Hash]
    def rejection_record(job, rejection, rejected_at:, queue: nil)
      job.merge(
        "status" => "rejected",
        "rejected_at" => rejected_at,
        "rejection_reason" => rejection.reason.to_s,
        "required_capability" => rejection.required_capability,
        "actual_capability" => rejection.actual_capability,
        "rejected_by_capsule" => rejection.capsule,
        "rejected_queue" => rejection.queue,
        "rejected_on_queue" => queue
      )
    end

    # A payload is a retry when it carries the first-execution fingerprint.
    # "origin_queue" is always recorded alongside "capability", so legacy jobs
    # (neither key) are untouched while a first-execution payload from a
    # classified capsule is still allowed to run where it is.
    def retry_payload?(job)
      !job["origin_queue"].nil?
    end

    private

    def capability_key(capability)
      normalized = self.class.normalize_capability(capability)
      normalized&.join(CAPABILITY_SEPARATOR)
    end

    def redis_key(key)
      "#{FALLBACK_KEY}:#{key}"
    end

    def persist(key, queue)
      with_redis { |conn| conn.sadd(redis_key(key), [queue]) }
    rescue StandardError
      nil
    end

    def unpersist(key, queue)
      with_redis { |conn| conn.srem(redis_key(key), [queue]) }
    rescue StandardError
      nil
    end

    # @return [Array<String>, nil] nil when Redis could not be read
    def read_persisted(key)
      with_redis { |conn| conn.smembers(redis_key(key)) }
    rescue StandardError
      nil
    end

    def with_redis
      return nil unless @config.respond_to?(:redis)
      @config.redis { |conn| yield conn }
    end

    def rejection(reason, queue, capsule, required, actual)
      Rejection.new(
        reason: reason,
        queue: queue.to_s,
        capsule: capsule&.name&.to_s,
        required_capability: required,
        actual_capability: actual
      )
    end
  end
end

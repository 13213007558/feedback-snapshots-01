# frozen_string_literal: true

require "securerandom"
require "sidekiq/client"

module Sidekiq
  # Transactional approval boundary for single jobs and capped small batches.
  # See docs/transactional-approval.md for the savepoint and publish-failure
  # contract.
  #
  # Mixed into the original exception when an after-commit approval cannot be
  # published. The original exception class is preserved so callers can still
  # rescue their usual Redis/network errors.
  module ApprovalPublishFailure
    attr_accessor :approval_batch
    alias_method :batch, :approval_batch

    def jids
      approval_batch&.jids || []
    end
    alias_method :attempted_jids, :jids

    def approved_payloads
      approval_batch&.payloads || []
    end
    alias_method :payloads, :approved_payloads

    # Redis clients do not always report whether an interrupted pipelined
    # command was executed. An empty list means "not confirmed", not "none".
    def confirmed_jids
      []
    end
  end

  # An immutable-at-approval-time job payload and its pre-allocated JID.
  class Approval
    attr_reader :jid, :payload, :transaction_token, :error

    def initialize(payload, transaction_token: nil)
      @payload = payload
      @jid = payload["jid"]
      @transaction_token = transaction_token
      @state = :approved
      @enlisted = false
    end

    def args
      payload["args"]
    end

    def [](key)
      payload[key]
    end

    def enlisted?
      @enlisted
    end

    def enlist!
      @enlisted = true
      self
    end

    def published?
      @state == :published
    end

    def failed?
      @state == :failed
    end

    def mark_published!
      @state = :published
      self
    end

    def mark_failed!(error)
      @state = :failed
      @error = error
      self
    end
  end

  # The pre-allocated JIDs are available immediately because this is an Array
  # of JIDs. The frozen approved payloads and publication state remain attached.
  class ApprovedBatch < Array
    attr_reader :approvals, :payloads, :limit, :transaction_token, :state, :error

    def initialize(approvals, limit:, transaction_token: nil)
      @approvals = approvals.freeze
      @payloads = @approvals.map(&:payload).freeze
      @limit = limit
      @transaction_token = transaction_token
      @state = :approved
      @error = nil
      super(@approvals.map(&:jid))
    end

    def jids
      to_a
    end
    alias_method :attempted_jids, :jids

    def enlisted?
      @state != :approved
    end

    def enlist!
      @state = :enlisted
      @approvals.each(&:enlist!)
      self
    end

    def published?
      @state == :published
    end

    def failed?
      @state == :failed
    end

    def mark_published!
      @state = :published
      @approvals.each(&:mark_published!)
      self
    end

    def mark_failed!(error)
      @state = :failed
      @error = error
      @approvals.each { |approval| approval.mark_failed!(error) }
      self
    end
  end

  class TransactionAwareClient
    class ImmediatePool
      def initialize(redis)
        @redis = redis
      end

      def with
        yield @redis
      end
    end

    # Transactional approvals are intentionally small. Use ordinary
    # Client#push_bulk for large imports; it keeps the existing slicing and
    # performance characteristics but is not tied to a database commit.
    DEFAULT_APPROVED_BATCH_LIMIT = 10
    MAX_APPROVED_BATCH_SIZE = 10
    MAX_TRANSACTIONAL_BATCH_SIZE = MAX_APPROVED_BATCH_SIZE

    class << self
      attr_accessor :approved_batch_limit, :backend

      def transaction_backend
        backend
      end

      def transaction_backend=(value)
        self.backend = value
      end
    end
    self.approved_batch_limit = DEFAULT_APPROVED_BATCH_LIMIT

    def initialize(backend = nil, pool: nil, config: nil, transaction_backend: nil,
      redis_client: nil, client: nil, **options)
      raw_redis = redis_client || client || options[:redis]
      @redis_client =
        if raw_redis.nil?
          Client.new(pool: pool, config: config)
        elsif raw_redis.respond_to?(:normalize_item) && raw_redis.respond_to?(:push_prepared_bulk)
          raw_redis
        elsif raw_redis.respond_to?(:pipelined)
          Client.new(pool: ImmediatePool.new(raw_redis), config: config)
        else
          raw_redis
        end
      @pool = pool || (@redis_client.respond_to?(:redis_pool) ? @redis_client.redis_pool : nil)
      explicit_backend = transaction_backend || backend || options[:backend] ||
        options[:transaction] || options[:after_commit] || self.class.backend
      @transaction_backend = explicit_backend || default_transaction_backend
    end

    def batching?
      Thread.current[:sidekiq_batch]
    end

    def push(item)
      return @redis_client.push(item) if batching?

      approval = item.is_a?(Approval) ? item : approve(item)
      return nil unless approval
      return approval.jid if approval.enlisted?

      batch = ApprovedBatch.new([approval], limit: 1, transaction_token: approval.transaction_token)
      enlist(batch) { publish_batch(batch) }
      approval.jid
    end

    # Freeze and validate the payload now. A caller may continue to mutate the
    # original Hash; those changes cannot affect the approved payload.
    def approve(item)
      raise ArgumentError, "Job must be a Hash" unless item.is_a?(Hash)

      item["jid"] ||= SecureRandom.hex(12)
      payload = @redis_client.normalize_item(deep_snapshot(item))

      chain = @redis_client.respond_to?(:middleware) ? @redis_client.middleware : nil
      if chain
        payload = chain.invoke(payload["class"], payload, payload["queue"], @pool) { payload }
      end
      return nil unless payload

      @redis_client.verify_json(payload) if @redis_client.respond_to?(:verify_json)
      deep_freeze(payload)
      Approval.new(payload, transaction_token: current_transaction_token)
    end

    # Approve a small bulk group. The return value is an Array-compatible list
    # of pre-allocated JIDs and also exposes #payloads and publication state.
    def approve_batch(items = nil, options = {})
      options ||= {}
      raise ArgumentError, "Bulk job must be a Hash with 'args'" unless items.is_a?(Hash)

      raw = stringify_top_level_keys(deep_snapshot(items))
      raw.delete("transactional")
      raw.delete("approved")
      raw.delete("atomic")
      raw.delete("approval")
      requested_limit = batch_option(options, :limit) || batch_option(options, :max) ||
        raw.delete("approved_batch_limit") || self.class.approved_batch_limit
      batch_limit = Integer(requested_limit)
      raise ArgumentError, "approved batch limit must be positive" if batch_limit <= 0
      raise ArgumentError, "approved batches are limited to #{MAX_APPROVED_BATCH_SIZE} jobs" if batch_limit > MAX_APPROVED_BATCH_SIZE

      args = raw["args"]
      raise ArgumentError, "Bulk 'args' must be an Array of Arrays" unless args.is_a?(Array)
      raise ArgumentError, "approved batches are limited to #{batch_limit} jobs (got #{args.size})" if args.size > batch_limit

      at = raw.delete("at")
      spread_interval = raw.delete("spread_interval")
      if spread_interval && (!spread_interval.is_a?(Numeric) || spread_interval <= 0)
        raise ArgumentError, "Jobs 'spread_interval' must be a positive Numeric"
      end
      if !at && spread_interval
        spread_interval = [spread_interval, 5].max
        now = Time.now.to_f
        at = Array.new(args.size) { now + (rand * spread_interval) }
      end
      at_values = normalize_at_values(at, args.size)
      raw.delete("batch_size")
      raw.delete(:batch_size)

      approvals = args.each_with_index.map do |job_args, index|
        raise ArgumentError, "Bulk arguments must be an Array of Arrays: [[1], [2]]" unless job_args.is_a?(Array)

        entry = raw.merge("args" => job_args)
        entry["at"] = at_values[index] if at_values
        approve(entry) or raise ArgumentError, "client middleware rejected job at index #{index}"
      end

      ApprovedBatch.new(approvals, limit: batch_limit, transaction_token: current_transaction_token)
    end
    alias_method :approve_bulk, :approve_batch

    def push_approved_batch(items = nil, options = {})
      options ||= {}
      batch = batch_option(options, :batch)
      batch ||= items if items.is_a?(ApprovedBatch)
      batch ||= approve_batch(items, options)
      return batch if batch.enlisted?

      enlist(batch) { publish_batch(batch) }
      batch
    end
    alias_method :push_transactional_bulk, :push_approved_batch
    alias_method :push_bulk_at_commit, :push_approved_batch
    alias_method :push_approved_bulk, :push_approved_batch
    alias_method :push_bulk_transactionally, :push_approved_batch
    alias_method :transactional_push_bulk, :push_approved_batch

    # Ordinary bulk push is unchanged unless the caller explicitly opts into a
    # transactionally approved small batch.
    def push_bulk(items = nil, options = {})
      options ||= {}
      if approved_bulk_option?(options) || approved_bulk_option?(items)
        approved_options = {}
        limit = batch_option(options, :limit) || batch_option(options, :max)
        approved_options[:limit] = limit if limit
        push_approved_batch(items, approved_options)
      else
        @redis_client.push_bulk(items)
      end
    end

    private

    def default_transaction_backend
      if defined?(::ActiveRecord)
        if ::ActiveRecord.version >= Gem::Version.new("7.2")
          ::ActiveRecord.method(:after_all_transactions_commit)
        else
          require "after_commit_everywhere"
          ::AfterCommitEverywhere.method(:after_commit)
        end
      else
        proc do
          raise ArgumentError, "A transaction_backend is required outside ActiveRecord"
        end
      end
    end

    def enlist(batch, &publish)
      batch.enlist!
      if @transaction_backend.respond_to?(:after_commit)
        @transaction_backend.after_commit(&publish)
      else
        @transaction_backend.call(&publish)
      end
    end

    def publish_batch(batch)
      @redis_client.push_prepared_bulk(batch.payloads)
      batch.mark_published!
    rescue => error
      batch.mark_failed!(error)
      annotate_failure(error, batch)
      raise
    end

    def annotate_failure(error, batch)
      if error.is_a?(ApprovalPublishFailure)
        error.approval_batch ||= batch
        return
      end

      begin
        error.extend(ApprovalPublishFailure)
        error.approval_batch = batch
      rescue StandardError
        # Some exception instances may be frozen. The batch itself still carries
        # the JIDs, payloads, and error for callers holding the returned batch.
      end
    end

    def current_transaction_token
      if @transaction_backend.respond_to?(:current_token)
        @transaction_backend.current_token
      elsif @transaction_backend.respond_to?(:transaction_id)
        @transaction_backend.transaction_id
      end
    rescue StandardError
      nil
    end

    def approved_bulk_option?(source)
      return false unless source.is_a?(Hash)

      %w[transactional transactionally approved approval atomic].any? do |key|
        source[key] || source[key.to_sym]
      end
    end

    def batch_option(options, name)
      options[name] || options[name.to_s]
    end

    def normalize_at_values(at, size)
      return nil unless at

      values = at.is_a?(Array) ? at : Array.new(size, at)
      raise ArgumentError, "Job 'at' Array must have same size as 'args' Array" if values.size != size
      raise ArgumentError, "Job 'at' must be a Numeric or an Array of Numeric timestamps" unless values.all? { |value| value.is_a?(Numeric) }

      values
    end

    def stringify_top_level_keys(hash)
      hash.each_with_object({}) do |(key, value), result|
        result[key.to_s] = value
      end
    end

    def deep_snapshot(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, item), result|
          result[deep_snapshot(key)] = deep_snapshot(item)
        end
      when Array
        value.map { |item| deep_snapshot(item) }
      when String
        value.dup
      else
        value
      end
    end

    def deep_freeze(value)
      case value
      when Hash
        value.each do |key, item|
          deep_freeze(key)
          deep_freeze(item)
        end
      when Array
        value.each { |item| deep_freeze(item) }
      end
      value.freeze
    end
  end
end

##
# Use `Sidekiq.transactional_push!` in your sidekiq.rb initializer
module Sidekiq
  def self.transactional_push!
    if defined?(::ActiveRecord) && ::ActiveRecord.version < Gem::Version.new("7.2")
      begin
        require "after_commit_everywhere"
      rescue LoadError
        raise %q(You need ActiveRecord >= 7.2 or to add `gem "after_commit_everywhere"` to your Gemfile to use Sidekiq's transactional client)
      end
    elsif !defined?(::ActiveRecord)
      begin
        require "after_commit_everywhere"
      rescue LoadError
        # ActiveRecord 7.2+ provides the callback used by the default backend.
        # Non-ActiveRecord apps can inject their own transaction backend.
      end
    end

    Sidekiq.default_job_options["client_class"] = Sidekiq::TransactionAwareClient
    unless Sidekiq::JobUtil::TRANSIENT_ATTRIBUTES.include?("client_class")
      Sidekiq::JobUtil::TRANSIENT_ATTRIBUTES << "client_class"
    end
    true
  end

  TransactionalClient = TransactionAwareClient
  TransactionalApproval = Approval
  ApprovalBatch = ApprovedBatch
  ApprovalGroup = ApprovedBatch
  TransactionalBatch = ApprovedBatch
end

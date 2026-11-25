# frozen_string_literal: true

require "json"
require_relative "iterable/enumerators"
require_relative "iterable/scope_binding"
require_relative "iterable/state_store"

module Sidekiq
  module Job
    class Interrupted < ::RuntimeError; end

    module Iterable
      include Enumerators

      # Opaque counters persisted with the iteration state. They never contain
      # record payloads, item keys or cursor values.
      DIAGNOSTIC_FIELD = "diag"
      DIAGNOSTIC_VERSION = "1"

      # @api private
      def self.included(base)
        base.extend(ClassMethods)
      end

      # @api private
      module ClassMethods
        def method_added(method_name)
          raise "#{self} is an iterable job and must not define #perform" if method_name == :perform
          super
        end
      end

      # @api private
      def initialize
        super

        @_executions = 0
        @_cursor = nil
        @_start_time = nil
        @_runtime = 0
        @_args = nil
        @_cancelled = nil
        @current_object = nil
        @_scope_digest = nil
        @_revoked_scope_digest = nil
        @_scope_reason = nil
        @_had_progress = false
        @_processed = 0
        @_iterations = 0
        @_committed = 0
        @_recovered = 0
        @_revoked_processed = 0
        @_save_failures = 0
        @_ledger = nil
        @_scope_revoked = false
      end

      # Access to the current object while iterating.
      # This value is not reset so the latest element is
      # explicitly available to cleanup/complete callbacks.
      attr_reader :current_object

      def arguments
        @_args
      end

      # The approval scope which authorizes this run, as a JSON-serializable
      # descriptor. Return nil (the default) to keep the historical behavior
      # where a cursor is not bound to an approval decision.
      #
      # When this hook is defined, Sidekiq stores a digest of the descriptor
      # with the cursor. A later attempt only resumes from that cursor when the
      # digest still matches. If the scope changed, narrowed, or the persisted
      # cursor predates scope binding, iteration restarts from the beginning of
      # the currently approved scope. The old cursor is never treated as
      # permission for the new scope.
      def approval_scope
        nil
      end

      # A stable, opaque identity for an item once its business effect has
      # been committed. Return nil (the default) to disable the commit ledger.
      #
      # Keys should be stable across attempts (for example a primary key) and
      # must not contain secrets. Only a digest is written to the ledger.
      def iteration_commit_key(_object)
        nil
      end

      # Optional custom ledger, used instead of the default ledger supplied by
      # the state store. It must respond to +committed?(key)+, +record(key)+
      # and +clear+.
      def iteration_commit_ledger
        nil
      end

      # Optional state store, used instead of Redis. Primarily useful for
      # local examples and tests where no Redis server is available.
      def iteration_state_store
        nil
      end

      # Seconds between progress checkpoints. Lower this in examples and tests
      # so interruption and scope changes are observed deterministically.
      def iteration_state_flush_interval
        STATE_FLUSH_INTERVAL
      end

      # Redacted progress diagnostics: counters and a short scope digest only.
      # Safe to expose to monitoring; it never includes the cursor or item
      # payloads.
      def iteration_diagnostics
        {
          scope: scope_prefix,
          processed: @_processed,
          iterations: @_iterations,
          committed: @_committed,
          recovered: @_recovered,
          revoked: @_revoked_processed,
          reason: @_scope_reason,
          attempts: @_executions,
          save_failures: @_save_failures
        }
      end

      # Three days is the longest period you generally need to wait for a retry to
      # execute when using the default retry scheme. We don't want to "forget" the job
      # is cancelled before it has a chance to execute and cancel itself.
      CANCELLATION_PERIOD = (3 * 86_400).to_s

      # Set a flag in Redis to mark this job as cancelled.
      # Cancellation is asynchronous and is checked at the start of iteration
      # and every 5 seconds thereafter as part of the recurring state flush.
      def cancel!
        return @_cancelled if cancelled?

        @_cancelled = state_store.cancel(iteration_key)
      end

      def cancelled?
        @_cancelled
      end

      def cursor
        @_cursor.freeze
      end

      # A hook to override that will be called when the job starts iterating.
      #
      # It is called only once, for the first time.
      #
      def on_start
      end

      # A hook to override that will be called around each iteration.
      #
      # Can be useful for some metrics collection, performance tracking etc.
      #
      def around_iteration
        yield
      end

      # A hook to override that will be called when the job resumes iterating.
      #
      def on_resume
      end

      # A hook to override that will be called each time the job is interrupted.
      #
      # This can be due to interruption or sidekiq stopping.
      #
      def on_stop
      end

      # A hook to override that will be called when the job is cancelled.
      #
      def on_cancel
      end

      # A hook to override that will be called when the job finished iterating.
      #
      def on_complete
      end

      # The enumerator to be iterated over.
      #
      # @return [Enumerator]
      #
      # @raise [NotImplementedError] with a message advising subclasses to
      #     implement an override for this method.
      #
      def build_enumerator(*)
        raise NotImplementedError, "#{self.class.name} must implement a '#build_enumerator' method"
      end

      # The action to be performed on each item from the enumerator.
      #
      # @return [void]
      #
      # @raise [NotImplementedError] with a message advising subclasses to
      #     implement an override for this method.
      #
      def each_iteration(*)
        raise NotImplementedError, "#{self.class.name} must implement an '#each_iteration' method"
      end

      def iteration_key
        "it-#{jid}"
      end

      # @api private
      def perform(*args)
        @_args = args.dup.freeze
        fetch_previous_iteration_state

        if approval_scope_enabled? && @_scope_digest.nil?
          if @_had_progress
            abandon!("scope_revoked")
          else
            logger.warn { "Iterable job has no approved scope; skipping" }
          end
          return nil
        end

        @_executions += 1
        @_start_time = mono_now

        enumerator = build_enumerator(*args, cursor: @_cursor)
        unless enumerator
          logger.info("'#build_enumerator' returned nil, skipping the job.")
          return
        end

        assert_enumerator!(enumerator)

        if @_executions == 1
          on_start
        else
          on_resume
        end

        completed = catch(:abort) do
          iterate_with_enumerator(enumerator, args)
        end

        on_stop

        if @_scope_revoked
          abandon!(@_scope_reason)
          return nil
        end

        completed = handle_completed(completed)

        if completed
          on_complete
          cleanup
        else
          reenqueue_iteration_job
        end
      end

      private

      def approval_scope_enabled?
        method(:approval_scope).owner != Sidekiq::Job::Iterable
      end

      def current_scope_digest
        scope = approval_scope
        scope.nil? ? nil : Sidekiq::Job::Iterable::ScopeBinding.digest(scope)
      end

      # A short, non-reversible label which is safe to log and display.
      def scope_prefix
        (@_scope_digest || @_revoked_scope_digest)&.slice(0, 12)
      end

      def state_store
        @_state_store ||= iteration_state_store || Sidekiq::Job::Iterable::RedisStateStore.instance
      end

      def is_cancelled?
        @_cancelled = state_store.cancelled_marker(iteration_key)
      end

      def fetch_previous_iteration_state
        state = state_store.read(iteration_key)
        @_had_progress = state.key?("c") || state.key?("sd")

        unless state.empty?
          @_executions = state["ex"].to_i
          @_runtime = state["rt"].to_f
        end

        unless approval_scope_enabled?
          @_cursor = Sidekiq.load_json(state["c"]) if state.key?("c")
          return
        end

        current = current_scope_digest
        if current.nil?
          @_scope_digest = nil
          @_revoked_scope_digest = state["sd"]
          if @_had_progress
            # Preserve redacted counters from a previous terminal stop instead
            # of erasing the only record of what already ran.
            load_diagnostics(parse_diagnostics(state))
            @_scope_reason = "scope_revoked"
          end
          return
        end

        @_scope_digest = current
        stored = state["sd"]
        diagnostics = parse_diagnostics(state)

        if state["c"] == "null"
          # There is no position to resume. A terminal revocation clears any
          # counters; a scope change keeps its counters so the redacted
          # diagnostics still explain what happened.
          reset = diagnostics.nil? || diagnostics["reason"] == "scope_revoked"
          reset_progress!
          if reset
            @_scope_reason = nil
          else
            load_diagnostics(diagnostics)
            @_scope_reason = diagnostics["reason"]
          end
          return
        end

        if state.key?("c")
          if stored.nil?
            # Progress saved before this job was scope-bound: the cursor has
            # no approval evidence, so it cannot authorize a scoped run.
            invalidate_progress!("unbound_progress", old_digest: nil, diagnostics: diagnostics)
          elsif stored != current
            # The previous approval no longer applies. Restart from the
            # approved beginning; the old cursor and its commit evidence are
            # discarded so they cannot authorize or suppress work later.
            invalidate_progress!("scope_changed", old_digest: stored, diagnostics: diagnostics)
          else
            @_cursor = Sidekiq.load_json(state["c"])
            load_diagnostics(diagnostics)
          end
        elsif stored == current
          load_diagnostics(diagnostics)
        end
      end

      def parse_diagnostics(state)
        raw = state[DIAGNOSTIC_FIELD]
        return nil if raw.nil? || raw.empty?

        parsed = Sidekiq.load_json(raw)
        parsed.is_a?(Hash) ? parsed : nil
      rescue ::JSON::ParserError
        nil
      end

      def diag_total(diagnostics)
        diagnostics ? diagnostics["processed"].to_i + diagnostics["revoked"].to_i : 0
      end

      def load_diagnostics(diagnostics)
        return unless diagnostics

        @_processed = diagnostics["processed"].to_i
        @_iterations = diagnostics["iterations"].to_i
        @_committed = diagnostics["committed"].to_i
        @_recovered = (diagnostics["recovered"] || diagnostics["skipped"]).to_i
        @_revoked_processed = diagnostics["revoked"].to_i
        @_save_failures = diagnostics["save_failures"].to_i
        @_scope_reason = diagnostics["reason"] if diagnostics["reason"]
      end

      # Drop stale position and counters, along with the commit evidence for
      # the approval which produced them. Commit evidence is only valid for
      # the approval that authorized it; a new approval starts with a clean
      # ledger, even if it covers overlapping records.
      def invalidate_progress!(reason, old_digest:, diagnostics:)
        @_revoked_processed = diag_total(diagnostics)
        purge_ledger(old_digest)
        reset_progress!
        @_scope_reason = reason
      end

      def purge_ledger(digest)
        return if digest.nil?

        state_store.ledger(iteration_key, digest).clear
      rescue => ex
        logger.warn { "Unable to clear iteration commit ledger (#{ex.class})" }
      end

      def reset_progress!
        @_cursor = nil
        @_processed = 0
        @_iterations = 0
        @_committed = 0
        @_recovered = 0
        @_ledger = nil
        @_scope_revoked = false
      end

      # Detect a scope change at a checkpoint. Returns nil when unchanged,
      # :changed when a different approval is available, and :revoked when no
      # approval remains.
      def refresh_scope_state!
        return nil unless approval_scope_enabled?

        current = current_scope_digest
        if current.nil?
          @_scope_reason = "scope_revoked"
          @_revoked_scope_digest = @_scope_digest
          return :revoked
        end
        return nil if current == @_scope_digest

        @_revoked_processed += @_processed
        purge_ledger(@_scope_digest)
        reset_progress!
        @_scope_digest = current
        @_scope_reason = "scope_changed"
        @_scope_revoked = false
        :changed
      end

      STATE_FLUSH_INTERVAL = 5 # seconds
      # we need to keep the state around as long as the job
      # might be retrying
      STATE_TTL = 30 * 24 * 60 * 60 # one month

      def iterate_with_enumerator(enumerator, arguments)
        if is_cancelled?
          on_cancel
          logger.info { "Job cancelled" }
          return true
        end

        time_limit = Sidekiq.default_configuration[:timeout]
        flush_interval = iteration_state_flush_interval || STATE_FLUSH_INTERVAL
        found_record = false
        state_flushed_at = mono_now

        enumerator.each do |object, cursor|
          found_record = true
          @_cursor = cursor
          @current_object = object

          interrupt_job = interrupted? || should_interrupt?
          if mono_now - state_flushed_at >= flush_interval || interrupt_job
            case refresh_scope_state!
            when :revoked
              logger.warn { "Approval scope was revoked during iteration; stopping" }
              @_scope_revoked = true
              return true
            when :changed
              logger.warn { "Approval scope changed; restarting from the approved beginning (scope=#{scope_prefix})" }
              flush_state
              return false
            end

            cancelled = flush_state
            state_flushed_at = mono_now
            if cancelled
              @_cancelled = true
              on_cancel
              logger.info { "Job cancelled" }
              return true
            end
          end

          return false if interrupt_job

          commit_key = iteration_commit_key(object)
          ledger = commit_key && iteration_ledger

          # A previous attempt may have committed this item and then failed
          # to persist the cursor. The commit ledger is the authority for
          # already-applied work, not the stale cursor position.
          if ledger&.committed?(commit_key)
            # The item's effect is already in place. Its iteration happened
            # before a lost progress write, so count it as an iteration but
            # not as new work in this attempt.
            @_recovered += 1
            @_iterations += 1
            @_processed += 1
            @_committed += 1
            next
          end

          verify_iteration_time(time_limit) do
            around_iteration do
              each_iteration(object, *arguments)
            rescue Exception
              begin
                flush_state
              rescue => flush_error
                logger.debug { "Progress flush failed while handling an iteration error (#{flush_error.class})" }
              end
              raise
            end
          end

          # The item's effects are committed at this point. Record them in the
          # ledger *before* the next progress checkpoint: a later attempt uses
          # the ledger, not the cursor, to tell that this item already ran.
          if ledger
            ledger.record(commit_key)
            @_committed += 1
          end
          @_iterations += 1
          @_processed += 1
        end

        logger.debug("Enumerator found nothing to iterate!") unless found_record
        true
      ensure
        @_runtime += (mono_now - @_start_time)
      end

      # The ledger records effects which were already applied under the
      # current approval. It is keyed by the approval digest, so evidence from
      # an earlier approval is never used for a new one, and by the job, so a
      # resumed attempt within the same approval can skip items whose effects
      # committed before the cursor was persisted. The ledger never authorizes
      # an item: only the approved enumerator decides what is yielded.
      def iteration_ledger
        return nil unless approval_scope_enabled? && @_scope_digest

        @_ledger ||= iteration_commit_ledger || state_store.ledger(iteration_key, @_scope_digest)
      end

      def verify_iteration_time(time_limit)
        start = mono_now
        yield
        finish = mono_now
        total = finish - start
        if total > time_limit
          logger.warn { "Iteration took longer (%.2f) than Sidekiq's shutdown timeout (%d). This can lead to job processing problems during deploys" % [total, time_limit] }
        end
      end

      def reenqueue_iteration_job
        flush_state
        if approval_scope_enabled?
          logger.debug { "Interrupting job (scope=#{scope_prefix || "none"} processed=#{@_processed} committed=#{@_committed})" }
        else
          logger.debug { "Interrupting job (cursor=#{@_cursor.inspect})" }
        end

        raise Interrupted
      end

      def assert_enumerator!(enum)
        unless enum.is_a?(Enumerator)
          raise ArgumentError, <<~MSG
            #build_enumerator must return an Enumerator, but returned #{enum.class}.
            Example:
              def build_enumerator(params, cursor:)
                active_record_records_enumerator(
                  Shop.find(params["shop_id"]).products,
                  cursor: cursor
                )
              end
          MSG
        end
      end

      def should_interrupt?
        max_iteration_runtime = Sidekiq.default_configuration[:max_iteration_runtime]
        max_iteration_runtime && (mono_now - @_start_time > max_iteration_runtime)
      end

      # Returns true when the cancellation marker is set.
      def flush_state
        key = iteration_key
        state = {
          "ex" => @_executions,
          "c" => Sidekiq.dump_json(@_cursor),
          "rt" => @_runtime
        }

        if approval_scope_enabled? && @_scope_digest
          state["sd"] = @_scope_digest
          state[DIAGNOSTIC_FIELD] = Sidekiq.dump_json(diagnostics_payload)
        end

        !state_store.write(key, state).nil?
      rescue => ex
        @_save_failures += 1
        logger.warn {
          format(
            "Iteration progress was not saved; scope=%s processed=%d committed=%d error=%s",
            scope_prefix || "unbound", @_processed, @_committed, ex.class
          )
        }
        raise
      end

      def diagnostics_payload
        payload = {
          "v" => DIAGNOSTIC_VERSION,
          "scope" => scope_prefix,
          "processed" => @_processed,
          "iterations" => @_iterations,
          "committed" => @_committed,
          "recovered" => @_recovered,
          "revoked" => @_revoked_processed,
          "reason" => @_scope_reason
        }
        payload["save_failures"] = @_save_failures if @_save_failures > 0
        payload.compact
      end

      # Terminal stop for a revoked scope. The stale cursor is replaced with
      # an explicit null, and the commit evidence for that approval is
      # discarded, so neither can be mistaken for permission for a later run.
      # Only redacted counters are retained. Called at most once per attempt.
      def abandon!(reason)
        @_scope_reason = reason
        # Persist opaque counters one last time, without a resumable cursor,
        # so operators can see what happened. The cursor is explicitly null
        # and is never used to resume.
        diagnostics = {
          "ex" => 0,
          "c" => Sidekiq.dump_json(nil),
          "rt" => @_runtime,
          DIAGNOSTIC_FIELD => Sidekiq.dump_json(diagnostics_payload)
        }
        active_digest = @_scope_digest || @_revoked_scope_digest
        diagnostics["sd"] = active_digest if active_digest
        begin
          state_store.write(iteration_key, diagnostics)
        rescue => ex
          logger.warn { "Unable to record revoked approval diagnostics (#{ex.class})" }
        end
        logger.warn {
          "Stopping iterable job with revoked approval; scope=%s processed=%d committed=%d reason=%s" %
            [scope_prefix || "unbound", @_processed, @_committed, reason]
        }
        purge_ledger(@_scope_digest || @_revoked_scope_digest)
        nil
      end

      def cleanup
        logger.debug {
          format("Completed iteration. executions=%d runtime=%.3f", @_executions, @_runtime)
        }
        begin
          @_ledger&.clear
        rescue => ex
          logger.warn { "Unable to clear iteration commit ledger (#{ex.class})" }
        end
        state_store.unlink(iteration_key)
      end

      def handle_completed(completed)
        case completed
        when nil, # someone aborted the job but wants to call the on_complete callback
             true
          true
        when false
          false
        else
          raise "Unexpected thrown value: #{completed.inspect}"
        end
      end

      def mono_now
        ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
      end
    end
  end
end

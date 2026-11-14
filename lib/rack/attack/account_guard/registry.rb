# frozen_string_literal: true

require 'securerandom'

module Rack
  class Attack
    class AccountGuard
      # Thread-safe, in-process registry of authentication failures keyed by an
      # account discriminator.
      #
      # Each failure is stamped with a strictly increasing sequence number. A
      # successful authentication only clears the failures that were recorded
      # *before* that request entered the application, so a failure recorded by
      # a request that finishes later can never be wiped by an earlier success.
      #
      # Every in-flight request registers itself in `pending`. The entry is
      # removed exactly once when the request is accounted for (failure,
      # success) or aborted (downstream exception, early body close), which
      # guarantees accounting happens once and pending state never leaks.
      class Registry
        Failure = Struct.new(:seq, :at)

        attr_reader :name

        def initialize(name, findtime:, bantime:, maxretry:)
          @name     = name
          @findtime = findtime
          @bantime  = bantime
          @maxretry = maxretry
          @mutex    = Mutex.new
          @seq      = 0
          @failures = Hash.new { |hash, key| hash[key] = [] }
          @bans     = {}
          @pending  = Hash.new { |hash, key| hash[key] = {} }
        end

        # Registers an in-flight request. Returns a request id used to settle
        # it later. Returns nil when the account is currently banned.
        def register(account)
          synchronize do
            prune(account)
            return nil if banned_locked?(account)

            id = SecureRandom.hex(8)
            @pending[account][id] = true
            id
          end
        end

        # Records a failed attempt. Returns true if the account is now banned.
        def record_failure(account, id)
          synchronize do
            remove_pending(account, id)
            prune(account)
            return true if banned_locked?(account)

            @failures[account] << Failure.new(next_seq, now)
            if @failures[account].size >= @maxretry
              @bans[account] = now + @bantime
              true
            else
              false
            end
          end
        end

        # Clears only the failures recorded up to and including `seen_seq`,
        # i.e. failures visible before this request entered the application.
        # Failures recorded by requests still in flight (or that finished after
        # this request started) are preserved. The ban is only lifted when no
        # failure remains, so a late success cannot undo a ban caused by
        # failures that happened after it started.
        def record_success(account, id, seen_seq)
          synchronize do
            remove_pending(account, id)
            prune(account)
            @failures[account].reject! { |failure| failure.seq <= seen_seq }
            @bans.delete(account) if @failures[account].empty?
            drop_account(account)
            false
          end
        end

        # Drops the pending entry without touching failure counters. Used when
        # a request cannot be classified (downstream exception or body closed
        # before it could be accounted for).
        def abort(account, id)
          synchronize do
            remove_pending(account, id)
            drop_account(account)
          end
        end

        def banned?(account)
          synchronize { banned_locked?(account) }
        end

        def failure_count(account)
          synchronize do
            prune(account)
            @failures[account].size
          end
        end

        def pending?(account, id)
          return false if id.nil?

          synchronize do
            @pending[account].key?(id)
          end
        end

        # Sequence number of the newest failure visible when a request starts.
        # A later success clears only failures up to and including this number.
        def seen_seq(account)
          synchronize do
            prune(account)
            (@failures[account].last&.seq) || 0
          end
        end

        def reset!
          synchronize do
            @failures.clear
            @bans.clear
            @pending.clear
            @seq = 0
          end
        end

        private

        def synchronize(&block)
          @mutex.synchronize(&block)
        end

        def next_seq
          @seq += 1
        end

        def now
          Time.now.to_i
        end

        def banned_locked?(account)
          ban_until = @bans[account]
          return false unless ban_until

          if ban_until > now
            true
          else
            @bans.delete(account)
            false
          end
        end

        def prune(account)
          cutoff = now - @findtime
          @failures[account].reject! { |failure| failure.at < cutoff }
          drop_account(account)
        end

        def remove_pending(account, id)
          return if id.nil?

          @pending[account].delete(id)
          @pending.delete(account) if @pending[account].empty?
        end

        def drop_account(account)
          return if @pending.key?(account)
          return if @bans.key?(account)
          return unless @failures[account].empty?

          @failures.delete(account)
        end
      end
    end
  end
end

module ROTP
  module Consumption
    # Outcome of a verification phase that has not touched the store yet.
    #
    # A successful verification yields a PendingCommit carrying the exact
    # compare-and-swap instruction. It can be held while other work happens
    # (for example two HTTP requests paused after the code check) so the
    # commits can later be interleaved to prove that only one can win.
    class PendingCommit
      attr_reader :account_id, :authenticator_id, :expected_state, :next_state

      def initialize(account_id, authenticator_id, expected_state, next_state)
        @account_id = account_id
        @authenticator_id = authenticator_id
        @expected_state = expected_state
        @next_state = next_state
        freeze
      end

      def key
        [account_id, authenticator_id]
      end
    end

    # Immutable outcome of a verification or a commit.
    #
    # status is one of:
    #   :ok        - code matched and, for a commit, the position advanced
    #   :invalid   - code did not match any acceptable OTP
    #   :replayed  - code is genuine but its position is at or behind the
    #                already-consumed position (duplicate login / clock rollback)
    #   :contended - the compare-and-swap lost to a concurrent commit
    class Result
      STATUSES = %i[ok invalid replayed contended].freeze

      attr_reader :status, :state, :pending, :detail

      def initialize(status, state: nil, pending: nil, detail: nil)
        raise ArgumentError, "unknown status #{status.inspect}" unless STATUSES.include?(status)

        @status = status
        @state = state
        @pending = pending
        @detail = detail
        freeze
      end

      def ok?
        status == :ok
      end

      def rejected?
        !ok?
      end

      def inspect
        "#<#{self.class} status=#{status} detail=#{detail.inspect} state=#{state.inspect}>"
      end
    end
  end
end

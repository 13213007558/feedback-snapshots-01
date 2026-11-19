module ROTP
  module Consumption
    # Persistence contract for anti-replay positions.
    #
    # The verifier never mutates state in place. It reads the current State
    # and advances it through an explicit compare-and-swap. Two concurrent
    # requests therefore race on a single version; exactly one swap wins and
    # the loser gets +false+ without its position being touched.
    #
    # A SQL backend expresses the same contract without any in-process lock:
    #
    #   # expected_state.version.nil?  -> the row must not exist yet
    #   INSERT INTO otp_state (account_id, authenticator_id, kind, watermark, version)
    #     VALUES (?, ?, ?, ?, 0)
    #     ON CONFLICT DO NOTHING;            -- 0 affected rows == lost the race
    #
    #   # expected_state.version is an Integer -> optimistic lock on the version
    #   UPDATE otp_state
    #     SET watermark = ?, version = version + 1
    #     WHERE account_id = ? AND authenticator_id = ? AND version = ?;
    #                                          -- 0 affected rows == lost the race
    module Store
      # @return [ROTP::Consumption::State, nil] current position, or nil when
      #   this (account, authenticator) has never consumed an OTP.
      def get(account_id, authenticator_id)
        raise NotImplementedError
      end

      # Atomically replace +expected_state+ with +next_state+.
      #
      # @param expected_state [State, nil] the state read by #get, or nil for
      #   an authenticator that does not have a row yet.
      # @param next_state [State] the state to store on a winning swap.
      # @return [Boolean] true when the position advanced, false when another
      #   commit moved it first (the caller's view was stale).
      def compare_and_swap(account_id, authenticator_id, expected_state, next_state)
        raise NotImplementedError
      end

      # Run a block so that a raised business error rolls the OTP position
      # back to what it was when the transaction opened. A normal return
      # commits. The verifier itself opens no transaction: the caller wraps
      # the OTP consumption and its own business write in one unit so the two
      # cannot commit independently.
      def transaction
        raise NotImplementedError
      end
    end
  end
end

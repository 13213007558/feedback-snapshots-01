module ROTP
  module Consumption
    # Minimum verify-and-consume adapter over ROTP.
    #
    # The adapter never relies on the time an HTTP request arrived. It stores
    # the OTP's own position - a TOTP timecode or an HOTP counter - keyed by
    # (account, authenticator), and only lets that position move forward once.
    # Verification is split from consumption so requests can be paused after
    # the code check and their commits interleaved.
    class Verifier
      INITIAL_WATERMARK = -1

      def initialize(store)
        @store = store
      end

      # Check a code without mutating any state.
      #
      # On success returns a Result whose #pending holds the compare-and-swap
      # instruction; feed it to #commit once the surrounding business work is
      # ready. A wrong code returns :invalid and leaves the store untouched;
      # a genuine code at or behind the consumed position returns :replayed.
      def verify(account_id:, authenticator_id:, otp:, code:, at: Time.now,
                 drift_behind: 0, drift_ahead: 0, retries: 0, replay_lookback: nil)
        kind = kind_for(otp)
        expected = @store.get(account_id, authenticator_id) ||
                   State.new(kind, INITIAL_WATERMARK, nil)

        ensure_kind!(expected, kind)

        matched =
          if kind == State::TOTP_KIND
            verify_totp(otp, code, expected.watermark, at, drift_behind, drift_ahead)
          else
            verify_hotp(otp, code, expected.watermark, retries, replay_lookback || retries)
          end

        return matched unless matched.is_a?(Integer)

        next_state = expected.advance(matched)
        pending = PendingCommit.new(account_id, authenticator_id, expected, next_state)
        Result.new(:ok, state: expected, pending: pending)
      end

      # Apply a PendingCommit. The compare-and-swap succeeds at most once: a
      # duplicate request whose view is stale gets :contended and no state
      # change. Call inside Store#transaction together with the business write
      # so a later business failure rolls this advance back too.
      def commit(pending)
        won = @store.compare_and_swap(
          pending.account_id,
          pending.authenticator_id,
          pending.expected_state,
          pending.next_state
        )

        if won
          Result.new(:ok, state: pending.next_state)
        else
          Result.new(:contended, state: @store.get(pending.account_id, pending.authenticator_id),
                     detail: 'position already advanced by a concurrent commit')
        end
      end

      # Convenience for the case where consuming the OTP is the only write.
      # With additional business work, call #verify and #commit explicitly
      # inside one Store#transaction instead.
      def verify_and_consume(**arguments)
        result = verify(**arguments)
        return result unless result.ok?

        @store.transaction { commit(result.pending) }
      end

      private

      def verify_totp(otp, code, watermark, at, drift_behind, drift_ahead)
        after = watermark.negative? ? nil : watermark
        matched = otp.verify(code, drift_behind: drift_behind,
                                   drift_ahead: drift_ahead,
                                   after: after, at: at)
        return matched if matched

        # Distinguish a real code that is no longer fresh from a wrong code,
        # independent of which way the wall clock moved.
        genuine = otp.verify(code, drift_behind: drift_behind,
                                   drift_ahead: drift_ahead, at: at)
        genuine ? replayed(genuine) : Result.new(:invalid, detail: 'code did not match any accepted TOTP interval')
      end

      def verify_hotp(otp, code, watermark, retries, replay_lookback)
        matched = otp.verify(code, watermark + 1, retries: retries)
        return matched if matched

        lookback_start = [watermark - replay_lookback, 0].max
        span = watermark - lookback_start
        previous = span.negative? ? nil : otp.verify(code, lookback_start, retries: span)
        previous ? replayed(previous) : Result.new(:invalid, detail: 'code did not match an accepted HOTP counter')
      end

      def replayed(position)
        Result.new(:replayed, detail: "position #{position} already consumed")
      end

      def kind_for(otp)
        case otp
        when ROTP::TOTP then State::TOTP_KIND
        when ROTP::HOTP then State::HOTP_KIND
        else raise ArgumentError, "otp must be a ROTP::TOTP or ROTP::HOTP, got #{otp.class}"
        end
      end

      def ensure_kind!(state, kind)
        raise ArgumentError, 'authenticator kind cannot change between logins' if state.kind != kind
      end
    end
  end
end

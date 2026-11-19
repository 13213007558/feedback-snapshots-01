require 'securerandom'
require 'set'

module ROTP
  # Explicit clock-skew calibration flow.
  #
  # A drifting hardware token cannot be fixed by growing the TOTP drift window
  # forever: a wide window accepts stale codes and short OTPs collide across
  # timecodes. This module instead runs a bounded, two-party challenge in which
  # consecutive device codes narrow the set of candidate offsets to exactly one
  # before the authenticator's stored settings are changed.
  module Calibration
    # Drift window searched while calibrating, expressed in timecode steps.
    DEFAULT_SEARCH_WINDOW_STEPS = 3
    # Challenge lifetime in seconds.
    DEFAULT_TTL = 300
    # Number of consecutive matching submissions required before saving.
    REQUIRED_EVIDENCE = 2

    # Persisted per-authenticator settings. `offset_steps` is the only value
    # the calibration flow is allowed to mutate.
    class Authenticator
      attr_reader :id, :account_id, :secret, :digits, :interval, :drift, :offset_steps

      def initialize(id:, account_id:, secret:, digits: OTP::DEFAULT_DIGITS,
                     interval: DEFAULT_INTERVAL, drift: 0, offset_steps: 0)
        @id = id
        @account_id = account_id
        @secret = secret
        @digits = digits
        @interval = interval
        @drift = drift
        @offset_steps = offset_steps
      end

      def totp
        TOTP.new(secret, digits: digits, interval: interval)
      end

      # Ordinary login. Never learns an offset: a successful or failed login
      # leaves `offset_steps` untouched. The calibrated offset shifts the
      # reference time, and the small fixed `drift` window handles boundary lag.
      def verify(otp, at: Time.now)
        reference = time_value(at) + offset_steps * interval
        totp.verify(otp, drift_behind: drift, drift_ahead: drift, at: reference)
      end

      def with_offset(new_offset_steps)
        self.class.new(id: id, account_id: account_id, secret: secret,
                       digits: digits, interval: interval, drift: drift,
                       offset_steps: new_offset_steps)
      end

      private

      def time_value(time)
        time.is_a?(Time) ? time.utc.to_i : time.to_i
      end
    end

    # A single calibration attempt. Bound to one account and one authenticator,
    # time limited, and replay aware: every timecode it accepts is consumed so
    # it cannot be presented a second time within the same challenge.
    class Challenge
      attr_reader :id, :account_id, :authenticator_id, :created_at, :expires_at,
                  :search_window_steps, :consumed_timecodes, :candidate_offsets,
                  :evidence_count, :completed, :saved_offset_steps

      def initialize(account_id:, authenticator_id:, now:, ttl: DEFAULT_TTL,
                     search_window_steps: DEFAULT_SEARCH_WINDOW_STEPS)
        @id = SecureRandom.hex(16)
        @account_id = account_id
        @authenticator_id = authenticator_id
        @created_at = now
        @expires_at = now + ttl
        @search_window_steps = search_window_steps
        @consumed_timecodes = Set.new
        @candidate_offsets = nil
        @evidence_count = 0
        @completed = false
        @saved_offset_steps = nil
      end

      def bound_to?(account_id, authenticator_id)
        @account_id == account_id && @authenticator_id == authenticator_id
      end

      def expired?(now)
        now >= @expires_at
      end

      def submit(authenticator, otp, at:, now: Time.now)
        return Result.build(:expired, self) if expired?(now)
        return Result.build(:challenge_closed, self) if @completed

        reference_timecode = timecode(at, authenticator.interval)
        matches = matching_timecodes(authenticator, otp, at)
        return Result.build(:invalid, self, otp: otp) if matches.empty?

        fresh = matches.reject { |timecode| @consumed_timecodes.include?(timecode) }
        if fresh.empty?
          return Result.build(:replayed, self, otp: otp, matches: matches,
                                                   reference_timecode: reference_timecode)
        end

        fresh.each { |timecode| @consumed_timecodes.add(timecode) }
        offsets = fresh.map { |timecode| timecode - reference_timecode }.sort

        if @evidence_count.zero?
          @candidate_offsets = offsets
        else
          @candidate_offsets &= offsets
        end
        @evidence_count += 1

        if @candidate_offsets.empty?
          @completed = true
          return Result.build(:inconsistent, self, otp: otp)
        end

        if @evidence_count >= REQUIRED_EVIDENCE && @candidate_offsets.one?
          @completed = true
          @saved_offset_steps = @candidate_offsets.first
          return Result.build(:calibrated, self, otp: otp)
        end

        Result.build(:more_evidence_needed, self, otp: otp,
                                               reference_timecode: reference_timecode)
      end

      private

      def matching_timecodes(authenticator, otp, at)
        window_seconds = search_window_steps * authenticator.interval
        authenticator.totp.matching_timecodes(
          otp,
          drift_behind: window_seconds,
          drift_ahead: window_seconds,
          at: at
        )
      rescue ArgumentError
        []
      end

      def timecode(time, interval)
        seconds = time.is_a?(Time) ? time.utc.to_i : time.to_i
        seconds / interval
      end
    end

    # Outcome of one challenge submission. Carries enough state for a caller to
    # explain why calibration did or did not finish.
    class Result
      STATUSES = %i[
        calibrated
        more_evidence_needed
        replayed
        invalid
        inconsistent
        expired
        challenge_closed
        binding_mismatch
        challenge_not_found
      ].freeze

      attr_reader :status, :candidate_offsets, :evidence_count, :consumed_timecodes,
                  :saved_offset_steps, :challenge_id

      def self.build(status, challenge, details = {})
        new(status,
            challenge_id: challenge.id,
            candidate_offsets: challenge.candidate_offsets,
            evidence_count: challenge.evidence_count,
            consumed_timecodes: challenge.consumed_timecodes.to_a.sort,
            saved_offset_steps: challenge.saved_offset_steps,
            details: details)
      end

      def initialize(status, challenge_id:, candidate_offsets:, evidence_count:,
                     consumed_timecodes:, saved_offset_steps:, details:)
        @status = status
        @challenge_id = challenge_id
        @candidate_offsets = candidate_offsets
        @evidence_count = evidence_count
        @consumed_timecodes = consumed_timecodes
        @saved_offset_steps = saved_offset_steps
        @details = details
      end

      def success?
        status == :calibrated
      end

      def report
        {
          status: status,
          challenge_id: challenge_id,
          evidence_count: evidence_count,
          candidate_offsets: candidate_offsets,
          consumed_timecodes: consumed_timecodes,
          saved_offset_steps: saved_offset_steps,
          explanation: explanation
        }
      end

      private

      def explanation
        case status
        when :calibrated
          "Two consecutive codes uniquely implied offset #{saved_offset_steps} " \
            'timecode step(s); the authenticator setting was updated.'
        when :more_evidence_needed
          if evidence_count == 1
            "Code #{@details[:otp].inspect} matches offsets #{candidate_offsets.inspect}. " \
              'A single correct code is insufficient because each matching timecode is a ' \
              'plausible clock offset, and short OTPs collide across timecodes. Submit the ' \
              'next consecutive code to intersect the candidates.'
          else
            "Candidates after #{evidence_count} codes remain ambiguous: " \
              "#{candidate_offsets.inspect}. Submit another consecutive code."
          end
        when :replayed
          'The submitted code only matches timecodes already consumed by this challenge; ' \
            'replayed positions are never accepted again.'
        when :invalid
          'The submitted code matches no timecode inside the calibration window.'
        when :inconsistent
          'The new code supports none of the previously observed offsets; the evidence is ' \
            'contradictory, so no offset was saved.'
        when :expired
          'The calibration challenge has passed its validity period and must be restarted.'
        when :challenge_closed
          'This challenge is already finished; start a new challenge to calibrate again.'
        when :binding_mismatch
          'The challenge belongs to another account or authenticator and cannot be used here.'
        when :challenge_not_found
          'No active calibration challenge exists for that identifier.'
        end
      end
    end

    # Coordinates challenge storage and enforces account/authenticator binding.
    class Service
      def initialize(clock: -> { Time.now })
        @clock = clock
        @challenges = {}
      end

      def start_challenge(authenticator, ttl: DEFAULT_TTL,
                          search_window_steps: DEFAULT_SEARCH_WINDOW_STEPS)
        challenge = Challenge.new(account_id: authenticator.account_id,
                                  authenticator_id: authenticator.id,
                                  now: @clock.call,
                                  ttl: ttl,
                                  search_window_steps: search_window_steps)
        @challenges[challenge.id] = challenge
      end

      def submit(challenge_id, authenticator, otp, at: @clock.call)
        challenge = @challenges[challenge_id]
        return [missing_result(challenge_id), authenticator] unless challenge
        unless challenge.bound_to?(authenticator.account_id, authenticator.id)
          return [Result.build(:binding_mismatch, challenge), authenticator]
        end

        result = challenge.submit(authenticator, otp, at: at, now: @clock.call)
        if result.success?
          calibrated = authenticator.with_offset(result.saved_offset_steps)
          [result, calibrated]
        else
          [result, authenticator]
        end
      end

      private

      def missing_result(challenge_id)
        placeholder = Struct.new(:id, :candidate_offsets, :evidence_count,
                                 :consumed_timecodes, :saved_offset_steps)
        challenge = placeholder.new(challenge_id, nil, 0, [], nil)
        Result.build(:challenge_not_found, challenge)
      end
    end
  end
end

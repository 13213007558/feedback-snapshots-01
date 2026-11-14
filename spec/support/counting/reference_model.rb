# frozen_string_literal: true

module CountingHarness
  # Reference model for the counting chain: it states explicitly which store
  # capabilities are sufficient for which promises, and which promises can
  # never be made when capabilities are missing.
  #
  # Capabilities:
  #   :atomic_increment - increment initializes a missing key (with TTL) and
  #                       returns the true count as one atomic step
  #   :nil_means_absent - a nil return from increment reliably means "key was
  #                       absent" (never a transient/unknown failure)
  #   :confirmed_write  - write's return value truthfully reports application
  #   :ttl              - the store honors expires_in
  #
  # Promises:
  #   safety   - within one window, at most +limit+ requests are admitted
  #   liveness - the first min(requests, limit) requests of a window are
  #              admitted
  module ReferenceModel
    Promise = Struct.new(:safety, :liveness, :reasons) do
      def guaranteed?
        safety && liveness
      end
    end

    module_function

    def promise(capabilities, faults:, overlapped:)
      safety = true
      liveness = true
      reasons = []

      if (faults & CountingHarness::UNKNOWN_OUTCOME_FAULTS).any?
        safety = false
        liveness = false
        reasons << "unknown outcome (timeout): nil cannot distinguish " \
                   "'not applied' from 'applied', so the fallback write " \
                   "clobbers the real count; no client strategy can keep " \
                   "both safety and liveness here"
      end

      if faults.include?(:confirm_miss)
        safety = false
        reasons << "confirmed failure: increment was not applied but reports " \
                   "nil, so the fallback write resets an existing counter to 1"
      end

      if faults.include?(:write_rejected)
        safety = false
        reasons << "first-write conflict: a rejected conditional write is " \
                   "ignored, so the increment is lost"
      end

      if overlapped && !capabilities[:atomic_increment]
        safety = false
        reasons << "overlapping first writes: without an atomic increment, " \
                   "two concurrent counts can both read nil and both write 1"
      end

      unless capabilities[:ttl]
        safety = false
        liveness = false
        reasons << "store does not honor TTL: windows never reset"
      end

      Promise.new(safety, liveness, reasons)
    end

    # Schedule-robust consistency check: within each window the returned
    # counts must be exactly the ordinals 1..n (in some order). Lost
    # updates, clobbered writes and leaked windows all violate this.
    def consistent?(result)
      by_window = Hash.new { |hash, key| hash[key] = [] }
      result.counts.each do |tid, count|
        by_window[result.windows[tid]] << count
      end
      by_window.values.all? { |counts| counts.sort == (1..counts.length).to_a }
    end

    # Two logical threads overlapped if their activity intervals in the
    # execution trace (first store op .. completion) intersect.
    def overlapped?(trace)
      intervals = {}
      trace.each_with_index do |event, index|
        next unless event[0] == :op || event[0] == :done

        tid = event[1]
        if intervals[tid]
          intervals[tid][1] = index
        else
          intervals[tid] = [index, index]
        end
      end
      intervals.values.combination(2).any? do |a, b|
        a[0] <= b[1] && b[0] <= a[1]
      end
    end
  end
end

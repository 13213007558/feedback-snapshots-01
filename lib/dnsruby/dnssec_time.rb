module Dnsruby
  # RRSIG times are 32-bit unsigned seconds since the Unix epoch, and every
  # comparison involving them uses the serial number arithmetic of RFC 1982
  # (RFC 4034 section 3.1.5). This class also provides the single civil-time
  # view used by one DNSSEC validation, so signature checks and the expiry of
  # keys learned from them cannot disagree.
  module DnssecTime # :nodoc: all
    BITS = 32
    MODULUS = 1 << BITS
    HALF = MODULUS >> 1

    # Outcomes of #signature_validity.
    VALID = :valid
    EXPIRED = :expired
    NOT_YET_VALID = :not_yet_valid
    INVALID = :invalid
    INDETERMINATE = :indeterminate

    module_function

    def normalize(value)
      value.to_i % MODULUS
    end

    # RFC 1982 section 3.2 comparison. Returns -1 when s1 sorts before s2, 0
    # when they are equal, 1 when s1 sorts after s2, and nil when the ordering
    # is undefined because the serial distance is exactly 2**31.
    def compare(s1, s2)
      first = normalize(s1)
      second = normalize(s2)
      return 0 if first == second
      distance = (second - first) % MODULUS
      return nil if distance == HALF
      distance < HALF ? -1 : 1
    end

    # Signed serial-time distance from +from+ to +to+, or nil when undefined.
    # A positive result means +to+ is later than +from+.
    def distance(from, to)
      order = compare(from, to)
      return nil if order.nil?
      return 0 if order == 0
      delta = (normalize(to) - normalize(from)) % MODULUS
      order < 0 ? delta : delta - MODULUS
    end

    # Classify +now+ against an RRSIG validity interval. Intervals that cross
    # the 32-bit wrap are handled by comparing each endpoint serially, rather
    # than treating expiration as an absolute Unix time. A pair whose order is
    # undefined is reported separately so callers can reject it explicitly.
    def signature_validity(inception, expiration, now = current)
      order = compare(inception, expiration)
      return INDETERMINATE if order.nil?
      return INVALID if order > 0

      after_inception = compare(now, inception)
      before_expiration = compare(now, expiration)
      return INDETERMINATE if after_inception.nil? || before_expiration.nil?
      return NOT_YET_VALID if after_inception < 0
      return EXPIRED if before_expiration > 0
      VALID
    end

    def valid?(inception, expiration, now = current)
      signature_validity(inception, expiration, now) == VALID
    end

    # Absolute Unix time at which a serial expiration occurs, relative to the
    # current validation view. This keeps KeyCache expiry comparable with civil
    # time while preserving the serial interpretation across the wrap.
    def expiration_time(expiration, now = current)
      delta = distance(now, expiration)
      delta && now + delta
    end

    # The absolute time view of the active validation. Nested verification and
    # trust discovery share it. Outside validation, use ordinary civil time.
    def current
      budget = defined?(ValidationBudget) && ValidationBudget.current
      budget ? budget.now : Time.now.to_i
    end
  end
end

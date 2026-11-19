module ROTP
  module Consumption
    # Persisted anti-replay position for one (account, authenticator).
    #
    # The object is immutable. Every successful compare-and-swap produces a
    # new State with a monotonically increasing +version+, which is the value
    # the store's compare-and-swap condition keys on.
    #
    # +watermark+ means:
    #   * for TOTP: the timecode * interval (a Unix timestamp) of the most
    #     recently consumed OTP. Replaying any OTP from that interval or an
    #     earlier one is rejected even if the wall clock has moved backwards.
    #   * for HOTP: the highest counter that has been consumed. Only a
    #     strictly greater counter can advance the position.
    class State
      TOTP_KIND = :totp
      HOTP_KIND = :hotp

      KINDS = [TOTP_KIND, HOTP_KIND].freeze

      attr_reader :kind, :watermark, :version

      def self.totp(watermark = -1, version: nil)
        new(TOTP_KIND, watermark, version)
      end

      def self.hotp(watermark = -1, version: nil)
        new(HOTP_KIND, watermark, version)
      end

      def initialize(kind, watermark, version)
        raise ArgumentError, "unknown kind #{kind.inspect}" unless KINDS.include?(kind)
        raise ArgumentError, 'watermark must be an Integer' unless watermark.is_a?(Integer)

        @kind = kind
        @watermark = watermark
        @version = version
        freeze
      end

      # Position that represents an authenticator that has never logged in.
      # +nil+ version marks it as "not yet persisted", which the store uses to
      # require an insert rather than an update.
      def initial?
        version.nil?
      end

      def advance(next_watermark)
        raise ArgumentError, 'positions only move forward' if next_watermark <= watermark

        self.class.new(kind, next_watermark, initial? ? 0 : version + 1)
      end

      def ==(other)
        other.is_a?(self.class) &&
          kind == other.kind &&
          watermark == other.watermark &&
          version == other.version
      end
      alias eql? ==

      def hash
        [kind, watermark, version].hash
      end

      def inspect
        "#<#{self.class} kind=#{kind} watermark=#{watermark} version=#{version.inspect}>"
      end
    end
  end
end

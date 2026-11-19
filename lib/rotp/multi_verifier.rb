module ROTP
  # Verifies a single submitted OTP against several authenticators for one
  # account without letting the amount of work (or the consumption state) be
  # controlled by how many windows an attacker asks for.
  #
  # == Design
  #
  # * Authenticator configurations are captured in a frozen snapshot when
  #   +verify+ starts. Mutating an authenticator afterwards cannot change the
  #   work performed by the call already in flight.
  # * Every candidate window is described by an explicit OTP specification:
  #   digest, digits and the time/counter unit. TOTP candidates use
  #   (timestamp / interval) as their unit, HOTP candidates use counters.
  # * All candidates draw from one shared HMAC budget. Splitting a wide
  #   window into many narrow ones therefore cannot exceed the total.
  # * The complete snapshot is searched before deciding. If more than one
  #   candidate matches, verification is ambiguous and nothing is consumed.
  # * Only a unique match is committed, through a compare-and-swap (CAS)
  #   callback, so a concurrent verification cannot double-consume a token.
  #
  # == Example
  #
  #   store = {} # authenticator id => last consumed window
  #   verifier = ROTP::MultiVerifier.new(max_hmac: 100)
  #   result = verifier.verify(
  #     "301999",
  #     authenticators,
  #     at: Time.now,
  #     consume: lambda do |auth, unit|
  #       # Must atomically move from the previously read value to +unit+.
  #       store.compare_and_set(auth.id, unit)
  #     end
  #   )
  #
  #   result.unique?        # => true
  #   result.authenticator  # => the matched authenticator
  #   result.consumed_at    # => committed timecode/counter, or nil
  #   result.hmac_count     # => actual HMAC calculations performed
  class MultiVerifier
    DEFAULT_MAX_HMAC = 100
    DEFAULT_TOTP_INTERVAL = 30

    # An authenticator as seen by a single verification call.
    #
    # @param secret [String] Base32 shared secret
    # @param type [Symbol] :totp or :hotp
    # @param digest [String] HMAC digest, e.g. 'sha1'
    # @param digits [Integer] OTP digit count
    # @param interval [Integer] TOTP period in seconds (TOTP only)
    # @param counter [Integer] HOTP counter to anchor the window on (HOTP only)
    # @param drift_behind [Integer] TOTP seconds before +at+ to include
    # @param drift_ahead [Integer] TOTP seconds after +at+ to include
    # @param retries [Integer] HOTP counters after +counter+ to include
    # @param id [Object] application identifier used when consuming
    # @param consumed_through [Integer] last consumed unit, if the caller
    #   stores it alongside the configuration. Prevents reuse before any HMAC
    #   is spent.
    # @param options [Hash] extra options passed to ROTP::TOTP/ROTP::HOTP
    def self.authenticator(secret, type: :totp, id: nil, digest: 'sha1',
                           digits: 6, interval: DEFAULT_TOTP_INTERVAL,
                           counter: 0, drift_behind: 0, drift_ahead: 0,
                           retries: 0, consumed_through: nil, **options)
      Candidate.new(
        secret: secret,
        type: type,
        id: id,
        digest: digest,
        digits: digits,
        interval: interval,
        counter: counter,
        drift_behind: drift_behind,
        drift_ahead: drift_ahead,
        retries: retries,
        consumed_through: consumed_through,
        options: options
      )
    end

    # Immutable description of one authenticator and its window.
    class Candidate
      attr_reader :secret, :type, :id, :digest, :digits, :interval,
                  :counter, :drift_behind, :drift_ahead, :retries,
                  :consumed_through, :options

      def initialize(secret:, type:, id:, digest:, digits:, interval:,
                     counter:, drift_behind:, drift_ahead:, retries:,
                     consumed_through:, options:)
        @secret = normalize_secret(secret)
        @type = normalize_type(type)
        @id = id
        @digest = normalize_digest(digest)
        @digits = integer!(digits, 'digits', min: 1, max: 10)
        @interval = integer!(interval, 'interval', min: 1)
        @counter = integer!(counter, 'counter', min: 0)
        @drift_behind = integer!(drift_behind, 'drift_behind', min: 0)
        @drift_ahead = integer!(drift_ahead, 'drift_ahead', min: 0)
        @retries = integer!(retries, 'retries', min: 0)
        @consumed_through = consumed_through.nil? ? nil : integer!(consumed_through, 'consumed_through', min: 0)
        @options = options.dup.freeze
        freeze
      end

      def totp?
        type == :totp
      end

      def hotp?
        type == :hotp
      end

      # :seconds for TOTP (consumed positions are Unix timestamps) or
      # :counter for HOTP.
      def unit
        totp? ? :seconds : :counter
      end

      # Enumerate the window lazily as [position, unit] pairs. +position+
      # seeds the HMAC and +unit+ is the value committed on a match: a Unix
      # timestamp for TOTP, a counter for HOTP. Positions at or before
      # +consumed_through+ are skipped without any HMAC work.
      #
      # No array proportional to the window size is built.
      def each_position(reference = Time.now)
        return enum_for(:each_position, reference) unless block_given?

        if totp?
          each_totp_position(reference) { |position, unit| yield position, unit }
        else
          each_hotp_position { |position, unit| yield position, unit }
        end
      end

      # Number of positions this candidate's window covers. May be very
      # large; the verifier never materializes the window.
      def window_size
        if totp?
          drift_behind.div(interval) + drift_ahead.div(interval) + 1
        else
          retries + 1
        end
      end

      def to_s
        "#<ROTP::MultiVerifier::Candidate id=#{id.inspect} type=#{type} " \
          "digest=#{digest} digits=#{digits}>"
      end

      private

      def each_totp_position(reference)
        seconds = reference.is_a?(Time) ? reference.utc.to_i : reference
        return if seconds.negative?

        start = [(seconds - drift_behind) / interval, 0].max
        finish = (seconds + drift_ahead) / interval
        (start..finish).each do |timecode|
          unit = timecode * interval
          yield timecode, unit if unused?(unit)
        end
      end

      def each_hotp_position
        (counter..counter + retries).each do |value|
          yield value, value if unused?(value)
        end
      end

      def unused?(unit)
        consumed_through.nil? || unit > consumed_through
      end

      def normalize_secret(value)
        unless value.is_a?(String) && !value.empty?
          raise ArgumentError, 'secret must be a non-empty Base32 string'
        end

        Base32.decode(value)
        value.dup.freeze
      end

      def normalize_type(value)
        normalized = value.to_s.downcase.to_sym
        return normalized if %i[totp hotp].include?(normalized)

        raise ArgumentError, "unknown OTP type: #{value.inspect}"
      end

      def normalize_digest(value)
        normalized = value.to_s.downcase
        raise ArgumentError, 'digest must not be empty' if normalized.empty?

        begin
          OpenSSL::Digest.new(normalized)
        rescue StandardError
          raise ArgumentError, "unknown digest: #{value.inspect}"
        end
        normalized
      end

      def integer!(value, name, min:, max: nil)
        unless value.is_a?(Integer) && value >= min
          raise ArgumentError, "#{name} must be an Integer >= #{min}, got #{value.inspect}"
        end
        if max && value > max
          raise ArgumentError, "#{name} must be <= #{max}, got #{value.inspect}"
        end

        value
      end
    end

    # Outcome of a verification. +status+ is one of:
    #
    # * :unique      - exactly one candidate matched and was consumed
    # * :invalid     - no candidate matched the supplied OTP
    # * :ambiguous   - more than one candidate matched; nothing consumed
    # * :exhausted   - the HMAC budget ran out before the search completed
    # * :rejected    - a parameter or configuration error
    # * :conflict    - the unique match lost the compare-and-swap race
    # * :unavailable - a unique match was found but no consume callback exists
    # * :error       - the consume callback raised; nothing is known to be
    #                  committed
    class Result
      attr_reader :status, :authenticator, :position, :unit, :hmac_count,
                  :message, :error

      def initialize(status:, authenticator: nil, position: nil, unit: nil,
                     hmac_count: 0, message: nil, error: nil)
        @status = status
        @authenticator = authenticator
        @position = position
        @unit = unit
        @hmac_count = hmac_count
        @message = message
        @error = error
        freeze
      end

      def unique?
        status == :unique
      end

      def invalid?
        status == :invalid
      end

      def ambiguous?
        status == :ambiguous
      end

      def exhausted?
        status == :exhausted
      end

      def rejected?
        status == :rejected
      end

      def conflict?
        status == :conflict
      end

      def unavailable?
        status == :unavailable
      end

      def error?
        status == :error
      end

      # Committed Unix timestamp (TOTP) or counter (HOTP) when unique.
      def consumed_at
        unit if unique?
      end

      def to_s
        "status=#{status} hmac_count=#{hmac_count}" \
          "#{position ? " position=#{position}" : ''}" \
          "#{message ? " message=#{message}" : ''}"
      end
    end

    # @param max_hmac [Integer] total HMAC operations allowed per verify call
    # @param hmac [#digest, #call, nil] optional recording/auditing backend for
    #   every HMAC this verifier performs
    attr_reader :max_hmac

    def initialize(max_hmac: DEFAULT_MAX_HMAC, hmac: nil)
      unless max_hmac.is_a?(Integer) && max_hmac >= 0
        raise ArgumentError, 'max_hmac must be an Integer >= 0'
      end

      unless hmac.nil? || hmac.respond_to?(:digest) || hmac.respond_to?(:call)
        raise ArgumentError, 'hmac must respond to #digest or #call'
      end

      @max_hmac = max_hmac
      @hmac = hmac
    end

    # Capture +authenticators+ into an immutable snapshot. Useful when the
    # same configuration is verified repeatedly and the caller wants the
    # snapshot taken once, outside the verification path.
    #
    # @raise [ArgumentError] when a configuration is malformed
    # @raise [ROTP::Base32::Base32Error] for a malformed secret
    # @return [Array<Candidate>] frozen array of frozen candidates
    def snapshot(authenticators)
      unless authenticators.respond_to?(:to_ary)
        raise ArgumentError, 'authenticators must be an Array'
      end

      Array(authenticators).map { |entry| snapshot_candidate(entry) }.freeze
    end

    # Verify +otp+ against +authenticators+ within the configured budget.
    #
    # @param otp [String] submitted OTP
    # @param authenticators [Array<Candidate, ROTP::TOTP, ROTP::HOTP>]
    # @param at [Time, Integer] reference time for TOTP windows
    # @param consume [Proc, nil] called for a unique match. A two-argument
    #   callback receives +(authenticator, unit)+; a three-argument callback
    #   receives +(authenticator, expected, unit)+ where +expected+ is the
    #   consumed value read while snapshotting. It must atomically move from
    #   +expected+ to +unit+ and return true on success. Returning false
    #   reports :conflict and consumes nothing.
    # @return [Result]
    def verify(otp, authenticators, at: Time.now, consume: nil, &block)
      consume ||= block
      unless otp.is_a?(String)
        return rejected('`otp` should be a String')
      end

      unless otp =~ /\A[0-9]+\z/
        return rejected('`otp` should contain only digits')
      end

      unless authenticators.respond_to?(:to_ary)
        return rejected('authenticators must be an Array')
      end

      unless at.is_a?(Time) || at.is_a?(Integer)
        return rejected('`at` must be a Time or a Unix timestamp')
      end

      return rejected('`at` must not be before the Unix epoch') if at.to_i.negative?

      unless consume.nil? || consume.respond_to?(:call)
        return rejected('`consume` must respond to #call')
      end

      begin
        snapshot = self.snapshot(authenticators)
      rescue ArgumentError, Base32::Base32Error => e
        return rejected(e.message, e)
      end

      return rejected('at least one authenticator is required') if snapshot.empty?

      search(snapshot, otp, at, consume)
    end

    private

    def snapshot_candidate(entry)
      case entry
      when Candidate
        Candidate.new(
          secret: entry.secret, type: entry.type, id: entry.id,
          digest: entry.digest, digits: entry.digits,
          interval: entry.interval, counter: entry.counter,
          drift_behind: entry.drift_behind, drift_ahead: entry.drift_ahead,
          retries: entry.retries, consumed_through: entry.consumed_through,
          options: entry.options
        )
      when TOTP
        Candidate.new(
          secret: entry.secret, type: :totp, id: entry.name,
          digest: entry.digest, digits: entry.digits, interval: entry.interval,
          counter: 0, drift_behind: 0, drift_ahead: 0, retries: 0,
          consumed_through: nil, options: {}
        )
      when HOTP
        Candidate.new(
          secret: entry.secret, type: :hotp, id: entry.name,
          digest: entry.digest, digits: entry.digits,
          interval: DEFAULT_TOTP_INTERVAL, counter: 0, drift_behind: 0,
          drift_ahead: 0, retries: 0, consumed_through: nil, options: {}
        )
      else
        raise ArgumentError, "unsupported authenticator: #{entry.inspect}"
      end
    end

    def search(snapshot, otp, at, consume)
      counter = HMACCounter.new(@hmac || ROTP::OTP::DEFAULT_HMAC)
      budget = Budget.new(max_hmac, counter)
      search = Search.new(snapshot, otp, at, budget)

      outcome = search.run
      return outcome if outcome

      snapshot.each do |candidate|
        matches = search.matches[candidate.object_id]
        next unless matches

        return commit(candidate, matches.first, consume, counter)
      end

      Result.new(status: :invalid, hmac_count: counter.count)
    rescue BudgetExceeded => e
      Result.new(status: :exhausted, hmac_count: counter.count, message: e.message)
    rescue ArgumentError, Base32::Base32Error => e
      Result.new(status: :rejected, hmac_count: counter.count, message: e.message, error: e)
    end

    def commit(candidate, match, consume, counter)
      unless consume
        return Result.new(
          status: :unavailable,
          authenticator: candidate,
          position: match.position,
          unit: match.unit,
          hmac_count: counter.count,
          message: 'unique match requires a consume callback to commit'
        )
      end

      accepted = invoke_consume(consume, candidate, match.unit)
      unless accepted
        return Result.new(
          status: :conflict,
          authenticator: candidate,
          position: match.position,
          unit: match.unit,
          hmac_count: counter.count,
          message: 'compare-and-swap failed; another verification consumed first'
        )
      end

      Result.new(
        status: :unique,
        authenticator: candidate,
        position: match.position,
        unit: match.unit,
        hmac_count: counter.count
      )
    rescue StandardError => e
      Result.new(
        status: :error,
        authenticator: candidate,
        position: match.position,
        unit: match.unit,
        hmac_count: counter.count,
        message: "consume callback failed: #{e.message}",
        error: e
      )
    end

    # Supports callbacks declaring either (candidate, unit) or the explicit
    # compare-and-swap form (candidate, expected, unit).
    def invoke_consume(consume, candidate, unit)
      case consume.arity
      when 1
        consume.call(candidate)
      when 2
        consume.call(candidate, unit)
      else
        consume.call(candidate, candidate.consumed_through, unit)
      end
    end

    def rejected(message, error = nil)
      Result.new(status: :rejected, message: message, error: error, hmac_count: 0)
    end

    BudgetExceeded = Class.new(StandardError)
    Match = Struct.new(:candidate, :position, :unit)

    # Counts every HMAC the search performs, regardless of which window or
    # authenticator requested it.
    class HMACCounter
      attr_reader :count

      def initialize(backend)
        @backend = backend
        @count = 0
      end

      def digest(digest_name, key, data)
        @count += 1
        if @backend.respond_to?(:digest)
          @backend.digest(digest_name, key, data)
        else
          @backend.call(digest_name, key, data)
        end
      end

      alias call digest
    end

    # Enforces one total across all candidates and windows.
    class Budget
      attr_reader :limit, :used, :backend

      def initialize(limit, counter)
        @limit = limit
        @counter = counter
        @backend = counter
        @used = 0
      end

      def spend!
        if @used >= @limit
          raise BudgetExceeded, "HMAC budget of #{@limit} exhausted"
        end

        @used += 1
      end
    end

    class Search
      attr_reader :matches

      def initialize(snapshot, otp, at, budget)
        @snapshot = snapshot
        @otp = otp
        @at = at
        @budget = budget
        @matches = {}
      end

      # @return [Result, nil] a terminal result, or nil when the search
      #   completed without a unique match.
      def run
        @snapshot.each do |candidate|
          candidate.each_position(@at) do |position, unit|
            code = generate(candidate, position)
            next unless ROTP::OTP.secure_compare(@otp, code)

            (@matches[candidate.object_id] ||= []) <<
              Match.new(candidate, position, unit)
          end
        end

        return nil if total_matches.zero?
        return nil if total_matches == 1

        Result.new(
          status: :ambiguous,
          hmac_count: @budget.used,
          message: "multiple OTP positions matched (#{total_matches})"
        )
      end

      def total_matches
        @matches.values.inject(0) { |sum, list| sum + list.size }
      end

      private

      def generate(candidate, position)
        @budget.spend!
        otp_instance(candidate).generate_otp(position)
      end

      def otp_instance(candidate)
        @instances ||= {}
        @instances[candidate.object_id] ||= begin
          options = candidate.options.merge(
            digest: candidate.digest,
            digits: candidate.digits,
            hmac: @budget.backend
          )
          if candidate.totp?
            TOTP.new(candidate.secret, options.merge(interval: candidate.interval))
          else
            HOTP.new(candidate.secret, options)
          end
        end
      end

      # Yields [position, unit] pairs one at a time. +position+ seeds the
      # HMAC; +unit+ is what gets consumed on a match. No array proportional
      # to the window size is ever built.
    end
  end
end

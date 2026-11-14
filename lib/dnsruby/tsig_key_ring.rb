module Dnsruby
  # A set of TSIG keys indexed by [key name, algorithm]. A key ring lets a
  # resolver or zone transfer client accept both the old and the new key
  # while a TSIG key is being rotated, and lets several keys share one key
  # name with different algorithms.
  #
  # The ring only holds configuration. Each exchange (a single query or one
  # multi-packet transfer) gets a TSIGKeyRing::Exchange that pins one key and
  # carries its own MAC chain state, so parallel exchanges never interfere
  # and a verification failure never falls back to another key in the ring.
  #
  #     ring = Dnsruby::TSIGKeyRing.new
  #     ring.add('key.example.', old_secret, 'hmac-sha256')
  #     ring.add('key.example.', new_secret, 'hmac-sha512')
  #     resolver.tsig = ring
  #     # ... once the server has switched over:
  #     ring.remove('key.example.', 'hmac-sha256')
  class TSIGKeyRing
    # Raised when no key in the ring matches a requested [name, algorithm]
    # pair. The message identifies the key name and algorithm only; it never
    # contains key material.
    class UnknownKeyError < KeyError
      def initialize(name, algorithm)
        super("No TSIG key in key ring for name '#{name}' algorithm '#{algorithm}'")
      end
    end

    def initialize
      @keys = {}
      @signing_preference = nil
      @lock = Mutex.new
    end

    # Adds a key to the ring. Pass either a Dnsruby::RR::TSIG or a key name,
    # the base64 secret and an optional algorithm (hmac-sha256 by default).
    # The most recently added key becomes the preferred signing identity.
    # Returns self so calls can be chained.
    def add(name, key = nil, algorithm = nil)
      tsig = name.is_a?(RR::TSIG) ? name : RR.new_from_hash(tsig_options(name, key, algorithm))
      id = identity(tsig.name, tsig.algorithm)
      @lock.synchronize do
        @keys[id] = tsig
        @signing_preference = id
      end
      tsig.warn_if_legacy_algorithm
      self
    end

    # Revokes keys from the ring. With an algorithm, removes exactly that
    # [name, algorithm] key; without one, removes every algorithm registered
    # under the name. Returns the number of keys removed.
    def remove(name, algorithm = nil)
      @lock.synchronize do
        removed = 0
        if algorithm
          id = identity(name, algorithm)
          removed = @keys.delete(id) ? 1 : 0
        else
          prefix = "#{canonical_name(name)}|"
          @keys.keys.each do |id|
            removed += 1 if id.start_with?(prefix) && @keys.delete(id)
          end
        end
        unless @keys.key?(@signing_preference)
          @signing_preference = @keys.keys.last
        end
        removed
      end
    end

    # True if the ring holds a key for the name (and algorithm, if given).
    def include?(name, algorithm = nil)
      @lock.synchronize do
        if algorithm
          @keys.key?(identity(name, algorithm))
        else
          prefix = "#{canonical_name(name)}|"
          @keys.keys.any? { |id| id.start_with?(prefix) }
        end
      end
    end

    # The [name, algorithm] identities currently in the ring.
    def identities
      @lock.synchronize { @keys.keys.sort }
    end

    # A pinned exchange for the preferred signing key (the most recently
    # added), or for an explicit [name, algorithm] when given. Raises
    # UnknownKeyError if the ring holds no matching key.
    def signing_exchange(name = nil, algorithm = nil)
      if name
        exchange(name, algorithm || RR::TSIG::DEFAULT_ALGORITHM)
      else
        id = @lock.synchronize { @signing_preference }
        raise UnknownKeyError.new('<none>', '<empty ring>') unless id
        exchange(*id.split('|', 2))
      end
    end

    # A pinned exchange for the key identified by the TSIG record carried by
    # the message. Use this to verify an incoming exchange: the first signed
    # packet selects the key, and every later packet of that exchange must
    # verify against the same key.
    def exchange_for(message)
      tsig = message.tsig
      raise ArgumentError, 'Message carries no TSIG record' unless tsig
      exchange(tsig.name, tsig.algorithm)
    end

    # A pinned exchange for an explicit [name, algorithm]. Raises
    # UnknownKeyError if the ring holds no matching key.
    def exchange(name, algorithm)
      tsig = @lock.synchronize { @keys[identity(name, algorithm)]&.dup }
      raise UnknownKeyError.new(canonical_name(name), canonical_algorithm(algorithm)) unless tsig
      Exchange.new(tsig)
    end

    def inspect
      "#<Dnsruby::TSIGKeyRing keys=[#{identities.join(', ')}]>"
    end

    private

    def tsig_options(name, key, algorithm)
      options = {
        type:  Types.TSIG,
        klass: Classes.ANY,
        name:  name,
        key:   key
      }
      options[:algorithm] = algorithm if algorithm
      options
    end

    def identity(name, algorithm)
      "#{canonical_name(name)}|#{canonical_algorithm(algorithm)}"
    end

    def canonical_name(name)
      n = name.is_a?(Name) ? name : Name.create(name)
      n = Name.create("#{n}.") unless n.absolute?
      n.to_s.downcase.sub(/\.$/, '')
    end

    def canonical_algorithm(algorithm)
      alg = algorithm.to_s.downcase.sub(/\.$/, '')
      alg = RR::TSIG::HMAC_MD5.to_s.downcase.sub(/\.$/, '') if alg == 'hmac-md5'
      alg
    end
  end

  # One pinned TSIG exchange: a single [name, algorithm] key plus the MAC
  # chain state for one conversation. Created by TSIGKeyRing; never shares
  # state with any other exchange, and never switches keys mid-exchange.
  class TSIGKeyRing
    class Exchange
      # The key name and algorithm pinned for this exchange.
      attr_reader :name, :algorithm

      def initialize(tsig) #:nodoc: all - create via TSIGKeyRing
        @tsig = tsig
        @name = tsig.name
        @algorithm = tsig.algorithm
      end

      # Signs the message with the pinned key (see RR::TSIG#apply).
      def apply(message, original_request = nil)
        @tsig.apply(message, original_request)
      end

      # Verifies a single response with the pinned key (see RR::TSIG#verify).
      def verify(query, response, response_bytes, buf = '')
        @tsig.verify(query, response, response_bytes, buf)
      end

      # Verifies the next envelope of a signed stream with the pinned key
      # (see RR::TSIG#verify_envelope). Chain state is private to this
      # exchange.
      def verify_envelope(response, response_bytes)
        @tsig.verify_envelope(response, response_bytes)
      end

      def query=(query) #:nodoc: all
        @tsig.query = query
      end

      def time_signed #:nodoc: all
        @tsig.time_signed
      end

      def time_signed=(time) #:nodoc: all
        @tsig.time_signed = time
      end

      def warn_if_legacy_algorithm #:nodoc: all
        @tsig.warn_if_legacy_algorithm
      end

      def inspect
        "#<Dnsruby::TSIGKeyRing::Exchange name=#{@name} algorithm=#{@algorithm}>"
      end
    end
  end
end

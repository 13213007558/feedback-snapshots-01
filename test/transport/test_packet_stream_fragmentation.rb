# encoding: ASCII-8BIT

require_relative '../common'
require 'timeout'
require 'digest'
require 'net/ssh/transport/packet_stream'

module Transport
  # Fragmentation-invariance tests for PacketStream.
  #
  # The core invariant: the same legitimate ciphertext must produce the same
  # sequence of authenticated messages no matter which chunk boundaries it is
  # delivered in, and a tampered packet must never leak a partial or
  # unverified payload to the connection layer.
  #
  # Everything runs locally: packets are encrypted with fixed test keys and
  # delivered through a metered in-memory socket. No external SSH server is
  # contacted. Randomness (padding bytes, chunk sizes) is driven by recorded
  # seeds so any failure can be reproduced exactly.
  class TestPacketStreamFragmentation < NetSSHTest
    include Net::SSH::Transport::Constants

    # Fixed local test key material. Never used against a real server.
    KEY_OPTIONS = { shared: "fragmentation-shared-secret", hash: "fragmentation-hash",
                    digester: OpenSSL::Digest::SHA256 }.freeze
    CIPHER_KEY = "fragmentation-cipher-key"
    CIPHER_IV  = "frag-iv"
    MAC_KEY    = "fragmentation-mac-key"
    AEAD_NONCE = ["000000000000000000000031"].pack('H*')

    # Recorded seeds: PADDING_SEED drives the random padding bytes inside
    # enqueue_packet, FRAGMENT_SEED drives the randomized fragmentation
    # strategy. Keeping them as constants makes every wire byte reproducible.
    PADDING_SEED  = 20_261_114
    FRAGMENT_SEED = 0x5EED

    # Hand-anchored message sequence: both the payloads and their order are
    # part of the test contract. REKEY_AT is the hand-anchored rekey boundary:
    # keys rotate after the second message, and SSH sequence numbers must keep
    # counting across the boundary (State#reset! does not reset them).
    PAYLOADS = ["payload-0", "payload-01", "payload-012", "payload-0123"].freeze
    REKEY_AT = 2

    MAX_POLLS = 20_000
    DELIVERY_TIMEOUT = 15

    # Errors that count as a clean rejection of a tampered packet.
    REJECT_ERRORS = [Net::SSH::Exception, OpenSSL::Cipher::CipherError].freeze

    # One row per authentication path: classic encrypt-and-MAC, EtM, AEAD.
    ALGORITHM_CASES = {
      'aes128-cbc+hmac-sha1'            => ['aes128-cbc', 'hmac-sha1'],
      'aes128-ctr+hmac-sha2-256'        => ['aes128-ctr', 'hmac-sha2-256'],
      'aes128-ctr+hmac-sha2-256-etm'    => ['aes128-ctr', 'hmac-sha2-256-etm@openssh.com'],
      'aes128-gcm@openssh.com'          => ['aes128-gcm@openssh.com', 'implicit']
    }.tap do |cases|
      if Net::SSH::Transport::ChaCha20Poly1305CipherLoader::LOADED
        cases['chacha20-poly1305@openssh.com'] = ['chacha20-poly1305@openssh.com', 'implicit']
      end
    end.freeze

    # A minimal in-memory socket stand-in, extended with PacketStream by the
    # harness. Every recv size is logged, and the harness logs read-buffer
    # occupancy after every fill, so buffer usage is asserted from data,
    # not assumed.
    class MeteredSocket
      attr_reader :recv_log, :occupancy_log

      def initialize
        @pending = +"".b
        @recv_log = []
        @occupancy_log = []
      end

      def feed(bytes)
        @pending << bytes
      end

      def recv(n)
        return "" if @pending.empty?

        data = @pending.slice!(0, n)
        @recv_log << data.bytesize
        data
      end
    end

    # A deliberately broken receiver: when MAC verification fails it publishes
    # the unverified payload anyway (early publication) instead of dropping
    # the packet. Used to prove that the no-leak criterion can actually fail.
    module EarlyPublicationMutant
      def poll_next_packet
        super
      rescue Net::SSH::Exception => e
        raise unless e.message.include?("corrupted hmac")

        content = @packet.content
        offset = server.hmac.etm ? 0 : 4
        padding_length = content.getbyte(offset)
        payload = content.byteslice(offset + 1, @packet_length - padding_length - 1)
        @packet = nil
        server.increment(@packet_length)
        Net::SSH::Packet.new(payload)
      end
    end

    ALGORITHM_CASES.each do |label, (cipher_name, mac_name)|
      slug = label.gsub(/\W/, '_')

      define_method("test_fragmentation_invariance_#{slug}") do
        wire, sizes = encrypt_payloads(cipher_name, mac_name, PAYLOADS)
        ends = packet_end_offsets(sizes)

        fragmentations(wire, sizes, cipher_name, mac_name).each do |strategy, chunks|
          stream = build_stream
          install_keys(stream.server, cipher_name, mac_name, false)
          trace = Timeout.timeout(DELIVERY_TIMEOUT) { deliver(stream, chunks) }

          assert_equal PAYLOADS, trace.map { |t| t[1] },
                       "payload sequence changed (#{label}, #{strategy})"
          assert_equal (1..PAYLOADS.length).to_a, trace.map { |t| t[0] },
                       "sequence numbers changed (#{label}, #{strategy})"
          trace.each_with_index do |(_, _, at), i|
            assert_operator at, :>=, ends[i],
                            "message #{i} published before all its bytes arrived (#{label}, #{strategy})"
          end
          assert_equal 0, stream.available, "leftover bytes (#{label}, #{strategy})"
          assert_equal chunks.map(&:bytesize), stream.recv_log,
                       "metered socket lost or merged chunks (#{label}, #{strategy})"
          assert_operator stream.occupancy_log.max || 0, :<=,
                          Net::SSH::Transport::PacketStream::PACKET_MAX_SIZE + 64,
                          "read buffer grew beyond one max packet (#{label}, #{strategy})"
        end
      end

      %w[length padding payload tag duplicate].each do |variant|
        define_method("test_tamper_#{variant}_#{slug}") do
          wire, sizes = encrypt_payloads(cipher_name, mac_name, PAYLOADS)
          tampered = tamper_wire(wire, sizes, variant)
          stream = build_stream
          install_keys(stream.server, cipher_name, mac_name, false)
          trace = []
          assert_raises(*REJECT_ERRORS, "tamper #{variant} was not rejected (#{label})") do
            Timeout.timeout(DELIVERY_TIMEOUT) { deliver(stream, bytewise(tampered), into: trace) }
          end
          assert_no_publication(trace, "#{label} tamper #{variant}")
        end
      end

      define_method("test_tamper_tag_of_last_packet_#{slug}") do
        wire, = encrypt_payloads(cipher_name, mac_name, PAYLOADS)
        tampered = flip_byte(wire, wire.bytesize - 1)
        stream = build_stream
        install_keys(stream.server, cipher_name, mac_name, false)
        trace = []
        assert_raises(*REJECT_ERRORS, "tampered tag was not rejected (#{label})") do
          Timeout.timeout(DELIVERY_TIMEOUT) { deliver(stream, bytewise(tampered), into: trace) }
        end
        # The authentic prefix is still published, in order; the tampered
        # packet contributes nothing.
        assert_equal PAYLOADS[0...-1], trace.map { |t| t[1] }, "prefix leaked or reordered (#{label})"
        assert_equal (1...PAYLOADS.length).to_a, trace.map { |t| t[0] }, "prefix sequence numbers (#{label})"
      end

      define_method("test_truncation_#{slug}") do
        wire, sizes = encrypt_payloads(cipher_name, mac_name, PAYLOADS)

        # Truncated mid-way through the first packet: nothing may be published.
        stream = build_stream
        install_keys(stream.server, cipher_name, mac_name, false)
        trace = Timeout.timeout(DELIVERY_TIMEOUT) do
          deliver(stream, bytewise(wire[0...(sizes[0] - 1)]))
        end
        assert_no_publication(trace, "#{label} truncation inside first packet")
        assert_operator stream.occupancy_log.max || 0, :<=, sizes[0],
                        "truncated packet buffered more than its own size (#{label})"

        # Only the final byte of the final packet is missing: the authentic
        # prefix is published, the incomplete tail is not, and nothing raises.
        stream = build_stream
        install_keys(stream.server, cipher_name, mac_name, false)
        trace = Timeout.timeout(DELIVERY_TIMEOUT) { deliver(stream, bytewise(wire[0...-1])) }
        assert_equal PAYLOADS[0...-1], trace.map { |t| t[1] }, "prefix before truncation (#{label})"
      end

      define_method("test_rekey_boundary_#{slug}") do
        wire, = encrypt_payloads(cipher_name, mac_name, PAYLOADS, rekey_at: REKEY_AT)

        { 'bytewise' => bytewise(wire), 'whole' => [wire] }.each do |strategy, chunks|
          stream = build_stream
          install_keys(stream.server, cipher_name, mac_name, false)
          rekeyed = false
          rekey = lambda do |count|
            next unless count == REKEY_AT && !rekeyed

            install_keys(stream.server, cipher_name, mac_name, false)
            rekeyed = true
          end
          trace = Timeout.timeout(DELIVERY_TIMEOUT) { deliver(stream, chunks, rekey: rekey) }

          assert rekeyed, "rekey never happened (#{label}, #{strategy})"
          assert_equal PAYLOADS, trace.map { |t| t[1] },
                       "message order changed across rekey (#{label}, #{strategy})"
          assert_equal (1..PAYLOADS.length).to_a, trace.map { |t| t[0] },
                       "sequence numbers must survive the rekey boundary (#{label}, #{strategy})"
        end
      end
    end

    # A packet length above PACKET_MAX_SIZE must be rejected as soon as the
    # length field is decoded: no multi-hundred-KB buffering, no huge
    # allocation, no busy loop. Delivering only the first 64 bytes has to be
    # enough for the rejection.
    def test_oversized_length_is_rejected_without_buffering
      huge = Net::SSH::Transport::PacketStream::PACKET_MAX_SIZE + 4

      crafts = {
        'aes128-cbc+hmac-sha1' => encrypt_length_block('aes128-cbc', [huge, 4].pack("NC") + ("\0" * 56)),
        'aes128-ctr+hmac-sha2-256' => encrypt_length_block('aes128-ctr', [huge, 4].pack("NC") + ("\0" * 56)),
        'aes128-ctr+hmac-sha2-256-etm' => [huge].pack("N") + ("\0" * 60),
        'aes128-gcm@openssh.com' => [huge].pack("N") + ("\0" * 60)
      }

      ALGORITHM_CASES.each do |label, (cipher_name, mac_name)|
        crafted = crafts[label]
        next unless crafted # chacha20 encrypts its length; covered by the length tamper test

        stream = build_stream
        install_keys(stream.server, cipher_name, mac_name, false)
        trace = []
        error = assert_raises(Net::SSH::Exception, "oversized length not rejected (#{label})") do
          Timeout.timeout(DELIVERY_TIMEOUT) { deliver(stream, [crafted], into: trace) }
        end
        assert_match(/bad packet length/, error.message)
        assert_no_publication(trace, "#{label} oversized length")
        assert_operator stream.recv_log.sum, :<=, 64,
                        "read more than one block before rejecting (#{label})"
        assert_operator stream.occupancy_log.max || 0, :<=, 64,
                        "buffered an oversized packet before rejecting (#{label})"
      end
    end

    # Mutation check: feed a tampered stream to the EarlyPublicationMutant and
    # verify that the very criterion used by the tamper tests flags it. If the
    # criterion could not fail, the tamper tests above would be vacuous.
    def test_early_publication_mutant_is_detected
      # [cipher, mac, tamper variant, tampered payload reaches the layer?]
      scenarios = [
        # CBC: flipping a ciphertext byte garbles the whole plaintext block,
        # so tamper the tag instead; the intact-but-unverified payload leaks.
        ['aes128-cbc', 'hmac-sha1', 'tag', false],
        # CTR+EtM: flipping a ciphertext byte flips exactly one payload byte;
        # the corrupted payload leaks.
        ['aes128-ctr', 'hmac-sha2-256-etm@openssh.com', 'payload', true]
      ]
      scenarios.each do |cipher_name, mac_name, variant, corrupted|
        label = "#{cipher_name}/#{mac_name}/#{variant}"
        wire, sizes = encrypt_payloads(cipher_name, mac_name, PAYLOADS)
        tampered = tamper_wire(wire, sizes, variant)

        stream = build_stream
        stream.singleton_class.prepend(EarlyPublicationMutant)
        install_keys(stream.server, cipher_name, mac_name, false)
        trace = Timeout.timeout(DELIVERY_TIMEOUT) { deliver(stream, bytewise(tampered)) }

        assert_equal PAYLOADS.length, trace.length,
                     "mutant should publish every packet, verified or not (#{label})"
        if corrupted
          refute_equal PAYLOADS, trace.map { |t| t[1] },
                       "mutant should publish the corrupted payload (#{label})"
        else
          assert_equal PAYLOADS[0], trace[0][1],
                       "mutant should publish the unverified payload (#{label})"
        end
        assert_raises(Minitest::Assertion,
                      "no-leak criterion failed to flag early publication (#{label})") do
          assert_no_publication(trace, label)
        end
      end
    end

    # Hand-anchored wire expectations for the fixed keys and recorded seeds:
    # exact per-packet wire sizes and a digest of the whole stream. If these
    # change, every fragmentation and tamper expectation must be re-audited.
    EXPECTED_WIRE = {
      'aes128-cbc+hmac-sha1' => [
        [52, 52, 52, 52],
        "42cf27a70f094e3e112d139d86b2299a9ce9e79414d09a92a8247ed050eec7ea"
      ],
      'aes128-ctr+hmac-sha2-256' => [
        [64, 64, 64, 64],
        "5bc39421ce81b3f664e14b0274136839ee1ba80eb88f10849553fee6c67c2c16"
      ],
      'aes128-ctr+hmac-sha2-256-etm' => [
        [52, 52, 52, 68],
        "a24af4aeb933aaea28cefd81a3fb07debe775ce6e570609510ce97a27914c1df"
      ],
      'aes128-gcm@openssh.com' => [
        [36, 36, 36, 52],
        "ac1fb5e5827ccff8345c6c3a752f77734b9bf35815f5ebe8e1a718ec17723148"
      ],
      'chacha20-poly1305@openssh.com' => [
        [36, 36, 36, 44],
        "83ea2c0609121780dd578ae1f6d68d515dd71fbb7097db664a61fadc5610422c"
      ]
    }.freeze

    def test_wire_format_anchors
      ALGORITHM_CASES.each do |label, (cipher_name, mac_name)|
        wire, sizes = encrypt_payloads(cipher_name, mac_name, PAYLOADS)
        expected_sizes, expected_digest = EXPECTED_WIRE.fetch(label)
        assert_equal expected_sizes, sizes, "packet wire sizes changed (#{label})"
        assert_equal expected_digest, Digest::SHA256.hexdigest(wire), "wire bytes changed (#{label})"
      end
    end

    private

    def build_stream
      MeteredSocket.new.extend(Net::SSH::Transport::PacketStream)
    end

    def install_keys(state, cipher_name, mac_name, encrypt)
      cipher = Net::SSH::Transport::CipherFactory.get(
        cipher_name, KEY_OPTIONS.merge(key: CIPHER_KEY, iv: CIPHER_IV, encrypt: encrypt)
      )
      hmac =
        if cipher.implicit_mac?
          cipher.implicit_mac
        else
          Net::SSH::Transport::HMAC.get(mac_name, MAC_KEY, KEY_OPTIONS)
        end
      cipher.nonce = AEAD_NONCE if hmac.respond_to?(:aead) && hmac.aead
      state.set(cipher: cipher, hmac: hmac)
    end

    # Encrypts +payloads+ into one continuous wire stream using the fixed test
    # keys. Returns [wire, packet_sizes]; packet_sizes anchors the exact wire
    # offset where each packet ends. With +rekey_at+, fresh keys are installed
    # before that packet index (sequence numbers keep counting, as in SSH).
    def encrypt_payloads(cipher_name, mac_name, payloads, rekey_at: nil)
      sender = build_stream
      install_keys(sender.client, cipher_name, mac_name, true)
      srand(PADDING_SEED)
      wire = +"".b
      sizes = []
      payloads.each_with_index do |payload, index|
        install_keys(sender.client, cipher_name, mac_name, true) if rekey_at == index
        sender.enqueue_packet(payload)
        chunk = sender.write_buffer
        sender.send(:output).clear!
        wire << chunk
        sizes << chunk.bytesize
      end
      [wire, sizes]
    end

    # Feeds +chunks+ through +stream+, polling after every fill. Returns (and
    # appends to +into+) the publication trace:
    # [[sequence_number, payload, delivered_bytes_at_publication], ...].
    def deliver(stream, chunks, into: [], rekey: nil)
      delivered = 0
      polls = 0
      chunks.each do |chunk|
        stream.feed(chunk)
        delivered += chunk.bytesize
        stream.send(:fill)
        stream.occupancy_log << stream.available
        loop do
          polls += 1
          raise "poll loop did not converge" if polls > MAX_POLLS

          packet = stream.send(:poll_next_packet)
          break unless packet

          into << [stream.server.sequence_number, packet.content, delivered]
          rekey.call(into.length) if rekey
        end
      end
      into
    end

    # The no-leak criterion shared by every tamper test (and deliberately
    # violated by EarlyPublicationMutant to prove it can fail).
    def assert_no_publication(trace, context)
      assert trace.empty?,
             "#{context}: tampered stream leaked #{trace.length} payload(s) " \
             "#{trace.map { |t| t[1].inspect }.join(', ')} to the connection layer"
    end

    def packet_end_offsets(sizes)
      sizes.inject([]) { |ends, size| ends << (ends.last || 0) + size }
    end

    def bytewise(wire)
      wire.unpack('C*').map(&:chr)
    end

    def flip_byte(wire, offset)
      tampered = wire.dup
      tampered.setbyte(offset, tampered.getbyte(offset) ^ 0x01)
      tampered
    end

    # Attack variants, always aimed at the first packet so that no authentic
    # prefix exists: length field, padding_length byte, payload body, MAC/tag,
    # and a duplicated fragment (byte 10 delivered twice, desynchronizing the
    # stream).
    def tamper_wire(wire, sizes, variant)
      case variant
      when 'length'    then flip_byte(wire, 0)
      when 'padding'   then flip_byte(wire, 4)
      when 'payload'   then flip_byte(wire, 6)
      when 'tag'       then flip_byte(wire, sizes[0] - 1)
      when 'duplicate' then wire[0..10] + wire[10..]
      else raise "unknown tamper variant #{variant}"
      end
    end

    # Deterministic fragmentation strategies. The minimal strategy cuts at the
    # smallest set of offsets that still crosses every structural boundary of
    # the first packet (length field, first cipher block, payload, MAC/tag,
    # packet boundary); the exact cut sequence is recorded in the strategy
    # label so a failure reports it.
    def fragmentations(wire, sizes, cipher_name, mac_name)
      total = wire.bytesize
      block_size = Net::SSH::Transport::CipherFactory.get_lengths(cipher_name)[1]
      block_size = 8 if block_size < 8
      mac_length = mac_length_for(cipher_name, mac_name)
      first_end = sizes[0]

      cuts = [1, 4, 5, block_size, block_size + 1,
              first_end - mac_length - 1, first_end - mac_length,
              first_end - 1, first_end, first_end + 1,
              total - 1].select { |c| c > 0 && c < total }.uniq.sort
      minimal = slice_at(wire, cuts)

      rng = Random.new(FRAGMENT_SEED)
      random_chunks = []
      offset = 0
      while offset < total
        size = 1 + rng.rand(37)
        random_chunks << wire.byteslice(offset, size)
        offset += size
      end

      {
        'whole' => [wire],
        'bytewise' => bytewise(wire),
        "block-#{block_size}" => wire.scan(/.{1,#{block_size}}/m),
        'packet-boundary' => slice_at(wire, packet_end_offsets(sizes)[0...-1]),
        "minimal-cuts-#{cuts.join(',')}" => minimal,
        "random-seed-#{FRAGMENT_SEED}" => random_chunks
      }
    end

    def slice_at(wire, cuts)
      chunks = []
      offset = 0
      cuts.each do |cut|
        chunks << wire.byteslice(offset...cut)
        offset = cut
      end
      chunks << wire.byteslice(offset..)
      chunks
    end

    def mac_length_for(cipher_name, mac_name)
      if mac_name == 'implicit'
        Net::SSH::Transport::CipherFactory.get(
          cipher_name, KEY_OPTIONS.merge(key: CIPHER_KEY, iv: CIPHER_IV, encrypt: true)
        ).mac_length
      else
        Net::SSH::Transport::HMAC.get(mac_name, MAC_KEY, KEY_OPTIONS).mac_length
      end
    end

    # Encrypts a fake first block carrying a huge packet_length, for ciphers
    # whose length field is encrypted (classic encrypt-and-MAC).
    def encrypt_length_block(cipher_name, plaintext_block)
      cipher = Net::SSH::Transport::CipherFactory.get(
        cipher_name, KEY_OPTIONS.merge(key: CIPHER_KEY, iv: CIPHER_IV, encrypt: true)
      )
      cipher.update(plaintext_block)
    end
  end
end

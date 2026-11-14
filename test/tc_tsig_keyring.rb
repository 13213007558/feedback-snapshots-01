require_relative 'spec_helper'

# Tests for Dnsruby::TSIGKeyRing: key selection by [name, algorithm], pinned
# signing identities per exchange, isolation of MAC chain state between
# single-packet queries and multi-packet transfers, rotation/revocation, and
# cross-session packet substitution.
class TsigKeyRingTest < Minitest::Test
  KEY_NAME = 'key.example.'
  OLD_SECRET = 'old-secret-aaaa'.b
  NEW_SECRET = 'new-secret-bbbb'.b
  ALT_SECRET = 'alt-secret-cccc'.b
  STRAY_SECRET = 'stray-secret-dddd'.b
  SECRETS = [OLD_SECRET, NEW_SECRET, ALT_SECRET, STRAY_SECRET].freeze

  DIGESTS = {
    'hmac-md5.sig-alg.reg.int' => 'MD5', 'hmac-sha1' => 'SHA1',
    'hmac-sha256' => 'SHA256', 'hmac-sha512' => 'SHA512'
  }.freeze

  def b64(secret)
    [secret].pack('m0')
  end

  def make_ring
    Dnsruby::TSIGKeyRing.new.tap do |ring|
      ring.add(KEY_NAME, b64(OLD_SECRET), 'hmac-sha256')
      ring.add(KEY_NAME, b64(NEW_SECRET), 'hmac-sha512')
    end
  end

  def dns_name(text)
    text.sub(/\.$/, '').split('.').map { |label| [label.bytesize].pack('C') + label }.join.b + "\0".b
  end

  # A query signed by the given exchange (which records it as the exchange's
  # query for later stream verification).
  def signed_query(exchange, id = rand(65_536))
    Dnsruby::Message.new('example.', 'A').tap do |message|
      message.header.id = id
      exchange.apply(message)
    end
  end

  # Builds a signed response wire independently of the library's TSIG code,
  # using OpenSSL directly. With chained: false the MAC covers the request
  # MAC and the full TSIG variables (first/only envelope); with chained: true
  # it covers the running chain plus the timers (later stream envelopes).
  def signed_wire(query:, secret:, algorithm:, key_name: KEY_NAME, chained: false,
      prior: nil, qname: 'example.', time: Time.now.to_i, fudge: 300)
    message = Dnsruby::Message.new(qname, 'A')
    message.header.id = query.header.id
    message.header.qr = true
    unsigned = message.encode
    timers = [time >> 32, time & 0xffff_ffff, fudge].pack('nNn')
    variables = dns_name(key_name) + [255, 0].pack('nN') + dns_name(algorithm) +
      timers + [0, 0].pack('n2')
    prefix = chained ? prior : [query.tsig.mac_size].pack('n') + query.tsig.mac
    suffix = chained ? timers : variables
    digest = DIGESTS.fetch(algorithm.sub(/\.$/, ''))
    mac = OpenSSL::HMAC.digest(digest, secret, prefix + unsigned + suffix)
    rdata = dns_name(algorithm) + timers + [mac.bytesize].pack('n') + mac +
      [query.header.id, 0, 0].pack('n3')
    wire = unsigned.dup
    wire[10, 2] = [1].pack('n')
    wire << dns_name(key_name) << [250, 255, 0, rdata.bytesize].pack('n2Nn') << rdata
    [wire, mac]
  end

  def decode(wire)
    Dnsruby::Message.decode(wire)
  end

  def refute_leaks(text)
    SECRETS.each do |secret|
      refute_includes(text, secret, 'message leaks raw key material')
      refute_includes(text, b64(secret), 'message leaks base64 key material')
    end
  end

  def test_rotation_ring_accepts_old_and_new_keys
    ring = make_ring
    old_exchange = ring.exchange(KEY_NAME, 'hmac-sha256')
    old_query = signed_query(old_exchange)
    wire, = signed_wire(query: old_query, secret: OLD_SECRET, algorithm: 'hmac-sha256')
    response = decode(wire)
    assert_equal(true, ring.exchange_for(response).verify(old_query, response, wire))
    assert(response.verified?)

    new_exchange = ring.exchange(KEY_NAME, 'hmac-sha512')
    new_query = signed_query(new_exchange)
    wire, = signed_wire(query: new_query, secret: NEW_SECRET, algorithm: 'hmac-sha512')
    response = decode(wire)
    assert_equal(true, ring.exchange_for(response).verify(new_query, response, wire))
    assert(response.verified?)
  end

  def test_same_name_different_algorithm_selects_distinct_keys
    ring = make_ring
    assert(ring.include?(KEY_NAME, 'hmac-sha256'))
    assert(ring.include?(KEY_NAME, 'hmac-sha512'))
    assert_equal(Dnsruby::RR::TSIG::HMAC_SHA512, ring.signing_exchange(KEY_NAME, 'hmac-sha512').algorithm)

    # The sha512 identity uses a different secret; a sha512-labelled response
    # made with the sha256 secret must fail, not match the other ring entry.
    exchange = ring.exchange(KEY_NAME, 'hmac-sha512')
    query = signed_query(exchange)
    wire, = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha512')
    response = decode(wire)
    assert_equal(false, ring.exchange_for(response).verify(query, response, wire))
    assert_equal(:Failed, response.tsigstate)
    assert_equal(Dnsruby::RCode::BADSIG, response.tsigerror)
  end

  def test_pinned_exchange_never_falls_back_to_another_ring_key
    ring = make_ring
    exchange = ring.exchange(KEY_NAME, 'hmac-sha256')
    query = signed_query(exchange)

    # Single-packet: a valid response signed under the other ring key is
    # rejected by the pinned exchange but accepted by a correctly selected one.
    wire, = signed_wire(query: query, secret: NEW_SECRET, algorithm: 'hmac-sha512')
    pinned_response = decode(wire)
    assert_equal(false, exchange.verify(query, pinned_response, wire))
    assert_equal(:Failed, pinned_response.tsigstate)
    assert_equal(Dnsruby::RCode::BADKEY, pinned_response.tsigerror)
    selected_response = decode(wire)
    assert_equal(true, ring.exchange_for(selected_response).verify(query, selected_response, wire))

    # Stream: after the chain starts, a packet carrying the other key's
    # identity aborts the exchange instead of switching keys.
    stream = ring.exchange(KEY_NAME, 'hmac-sha256')
    stream_query = signed_query(stream)
    first, mac = signed_wire(query: stream_query, secret: OLD_SECRET, algorithm: 'hmac-sha256')
    assert_equal(true, stream.verify_envelope(decode(first), first))
    foreign, = signed_wire(query: stream_query, secret: NEW_SECRET, algorithm: 'hmac-sha512')
    foreign_response = decode(foreign)
    assert_equal(false, stream.verify_envelope(foreign_response, foreign))
    assert_equal(:Failed, foreign_response.tsigstate)
    assert_equal(Dnsruby::RCode::BADKEY, foreign_response.tsigerror)
    # The very same packet is valid for an exchange pinned to its own key.
    fresh = ring.exchange_for(decode(foreign))
    fresh.query = stream_query
    assert_equal(true, fresh.verify_envelope(decode(foreign), foreign))
  end

  def test_parallel_exchanges_keep_independent_chain_state
    ring = make_ring
    exchange_a = ring.exchange(KEY_NAME, 'hmac-sha256')
    exchange_b = ring.exchange(KEY_NAME, 'hmac-sha256')
    query_a = signed_query(exchange_a)
    query_b = signed_query(exchange_b)

    now = Time.now.to_i
    a1, mac_a = signed_wire(query: query_a, secret: OLD_SECRET, algorithm: 'hmac-sha256', time: now)
    b1, mac_b = signed_wire(query: query_b, secret: OLD_SECRET, algorithm: 'hmac-sha256', time: now)
    a2 = Dnsruby::Message.new('a.example.').encode
    b2 = Dnsruby::Message.new('b.example.').encode
    prior_a = [mac_a.bytesize].pack('n') + mac_a + a2
    prior_b = [mac_b.bytesize].pack('n') + mac_b + b2
    a3, = signed_wire(query: query_a, secret: OLD_SECRET, algorithm: 'hmac-sha256',
      chained: true, prior: prior_a, time: now)
    b3, = signed_wire(query: query_b, secret: OLD_SECRET, algorithm: 'hmac-sha256',
      chained: true, prior: prior_b, time: now)

    # Interleave the two exchanges; each must follow only its own chain.
    assert_equal(true, exchange_a.verify_envelope(decode(a1), a1))
    assert_equal(true, exchange_b.verify_envelope(decode(b1), b1))
    middle_a = decode(a2)
    assert_equal(true, exchange_a.verify_envelope(middle_a, a2))
    assert_equal(:Intermediate, middle_a.tsigstate)
    assert_equal(true, exchange_b.verify_envelope(decode(b2), b2))
    assert_equal(true, exchange_a.verify_envelope(decode(a3), a3))
    last_b = decode(b3)
    assert_equal(true, exchange_b.verify_envelope(last_b, b3))
    assert_equal(:Verified, last_b.tsigstate)
  end

  def test_cross_session_packet_swap_aborts_mixed_chain
    ring = make_ring
    now = Time.now.to_i

    build_session = lambda do |qname, id|
      exchange = ring.exchange(KEY_NAME, 'hmac-sha256')
      query = signed_query(exchange, id)
      first, mac = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha256', time: now)
      middle = Dnsruby::Message.new(qname).encode
      prior = [mac.bytesize].pack('n') + mac + middle
      last, = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha256',
        chained: true, prior: prior, time: now)
      { exchange: exchange, query: query, first: first, middle: middle, last: last }
    end
    session_a = build_session.call('a.example.', 11_111)
    session_b = build_session.call('b.example.', 22_222)

    # Both intact chains verify end to end.
    [session_a, session_b].each do |session|
      assert_equal(true, session[:exchange].verify_envelope(decode(session[:first]), session[:first]))
      assert_equal(true, session[:exchange].verify_envelope(decode(session[:middle]), session[:middle]))
      last_message = decode(session[:last])
      assert_equal(true, session[:exchange].verify_envelope(last_message, session[:last]))
      assert_equal(:Verified, last_message.tsigstate)
    end

    # Mixed chain: A's first envelope, B's middle envelope, A's last envelope.
    # The mixed exchange reuses A's exact query, as a client whose stream is
    # spliced with packets from a parallel session would.
    mixed = ring.exchange(KEY_NAME, 'hmac-sha256')
    mixed.query = session_a[:query]
    assert_equal(true, mixed.verify_envelope(decode(session_a[:first]), session_a[:first]))
    assert_equal(true, mixed.verify_envelope(decode(session_b[:middle]), session_b[:middle]))
    mixed_last = decode(session_a[:last])
    assert_equal(false, mixed.verify_envelope(mixed_last, session_a[:last]))
    assert_equal(:Failed, mixed_last.tsigstate)
    assert_equal(Dnsruby::RCode::BADSIG, mixed_last.tsigerror)

    # Mixed chain: A's first two envelopes, then B's final envelope.
    mixed = ring.exchange(KEY_NAME, 'hmac-sha256')
    mixed.query = session_a[:query]
    assert_equal(true, mixed.verify_envelope(decode(session_a[:first]), session_a[:first]))
    assert_equal(true, mixed.verify_envelope(decode(session_a[:middle]), session_a[:middle]))
    mixed_last = decode(session_b[:last])
    assert_equal(false, mixed.verify_envelope(mixed_last, session_b[:last]))
    assert_equal(Dnsruby::RCode::BADSIG, mixed_last.tsigerror)

    # Mixed chain: B's first envelope opens A's exchange.
    mixed = ring.exchange(KEY_NAME, 'hmac-sha256')
    mixed.query = session_a[:query]
    mixed_first = decode(session_b[:first])
    assert_equal(false, mixed.verify_envelope(mixed_first, session_b[:first]))
    assert_equal(:Failed, mixed_first.tsigstate)
  end

  def test_query_and_transfer_share_config_but_not_chain_state
    ring = make_ring
    transfer = ring.exchange(KEY_NAME, 'hmac-sha256')
    transfer_query = signed_query(transfer)
    now = Time.now.to_i
    first, mac = signed_wire(query: transfer_query, secret: OLD_SECRET, algorithm: 'hmac-sha256', time: now)
    assert_equal(true, transfer.verify_envelope(decode(first), first))

    # A single-packet exchange on the same ring must not disturb the chain.
    query_exchange = ring.signing_exchange(KEY_NAME, 'hmac-sha256')
    query = signed_query(query_exchange)
    wire, = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha256')
    response = decode(wire)
    assert_equal(true, ring.exchange_for(response).verify(query, response, wire))

    middle = Dnsruby::Message.new('mid.example.').encode
    prior = [mac.bytesize].pack('n') + mac + middle
    last, = signed_wire(query: transfer_query, secret: OLD_SECRET, algorithm: 'hmac-sha256',
      chained: true, prior: prior, time: now)
    assert_equal(true, transfer.verify_envelope(decode(middle), middle))
    last_message = decode(last)
    assert_equal(true, transfer.verify_envelope(last_message, last))
    assert_equal(:Verified, last_message.tsigstate)
  end

  def test_revocation_removes_old_key_and_keeps_new_key
    ring = make_ring
    assert_equal(1, ring.remove(KEY_NAME, 'hmac-sha256'))
    refute(ring.include?(KEY_NAME, 'hmac-sha256'))
    assert(ring.include?(KEY_NAME, 'hmac-sha512'))

    old_query = signed_query(ring.exchange(KEY_NAME, 'hmac-sha512'))
    wire, = signed_wire(query: old_query, secret: OLD_SECRET, algorithm: 'hmac-sha256')
    error = assert_raises(Dnsruby::TSIGKeyRing::UnknownKeyError) do
      ring.exchange_for(decode(wire))
    end
    assert_includes(error.message, KEY_NAME.sub(/\.$/, ''))
    assert_includes(error.message, 'hmac-sha256')
    refute_leaks(error.message)

    # The surviving key still verifies.
    wire, = signed_wire(query: old_query, secret: NEW_SECRET, algorithm: 'hmac-sha512')
    response = decode(wire)
    assert_equal(true, ring.exchange_for(response).verify(old_query, response, wire))

    # Removing by name revokes every remaining algorithm for that name.
    assert_equal(1, ring.remove(KEY_NAME))
    refute(ring.include?(KEY_NAME))
    assert_raises(Dnsruby::TSIGKeyRing::UnknownKeyError) { ring.signing_exchange }
  end

  def test_inspect_and_errors_do_not_leak_key_material
    ring = make_ring
    refute_leaks(ring.inspect)
    refute_leaks(ring.signing_exchange.inspect)
    error = assert_raises(Dnsruby::TSIGKeyRing::UnknownKeyError) do
      ring.exchange('missing.example.', 'hmac-sha256')
    end
    refute_leaks(error.message)
  end

  # Minimal in-memory socket for driving ZoneTransfer without a network.
  class FakeSocket
    attr_reader :written

    def initialize
      @read = +''.b
      @written = +''.b
    end

    def feed(bytes)
      @read << bytes
    end

    def send(data, _flags)
      @written << data
      data.bytesize
    end

    def read(length)
      chunk = @read.byteslice(0, length)
      @read = @read.byteslice(chunk.bytesize..-1) || +''.b
      chunk
    end

    def eof?
      @read.empty?
    end
  end

  def frame(wire)
    [wire.bytesize].pack('n') + wire
  end

  def transfer_query(ring, qname = 'example.')
    zt = Dnsruby::ZoneTransfer.new
    zt.tsig = ring
    socket = FakeSocket.new
    query = Dnsruby::Message.new(qname, 'AXFR')
    zt.send_message(socket, query)
    [zt, socket, query]
  end

  def test_zone_transfer_accepts_old_and_new_keys_during_rotation
    ring = make_ring
    # The ring signs with the most recently added key (sha512)...
    zt, socket, query = transfer_query(ring)
    assert_equal(Dnsruby::RR::TSIG::HMAC_SHA512, query.tsig.algorithm)

    # ...but the server still answers with the old key: the transfer pins the
    # old key from the first envelope and verifies the whole chain with it.
    now = Time.now.to_i
    first, mac = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha256', time: now)
    middle = Dnsruby::Message.new('mid.example.').encode
    prior = [mac.bytesize].pack('n') + mac + middle
    last, = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha256',
      chained: true, prior: prior, time: now)
    socket.feed(frame(first) + frame(middle) + frame(last))

    assert_equal(:Verified, zt.receive_message(socket).tsigstate)
    assert_equal(:Intermediate, zt.receive_message(socket).tsigstate)
    final = zt.receive_message(socket)
    assert_equal(:Verified, final.tsigstate)
  end

  def test_zone_transfer_aborts_on_revoked_key_without_leaking_secret
    ring = make_ring
    zt, socket, query = transfer_query(ring)
    ring.remove(KEY_NAME, 'hmac-sha256')

    wire, = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha256')
    socket.feed(frame(wire))
    error = assert_raises(Dnsruby::ResolvError) { zt.receive_message(socket) }
    refute_leaks(error.message)
    assert_equal(:Failed, zt.last_tsigstate)

    # A swapped-in envelope from a parallel session aborts the same way.
    ring.add(KEY_NAME, b64(OLD_SECRET), 'hmac-sha256')
    zt_a, socket_a, query_a = transfer_query(ring)
    _zt_b, _socket_b, query_b = transfer_query(ring, 'other.example.')
    foreign, = signed_wire(query: query_b, secret: OLD_SECRET, algorithm: 'hmac-sha256')
    socket_a.feed(frame(foreign))
    assert_raises(Dnsruby::ResolvError) { zt_a.receive_message(socket_a) }
    assert_equal(:Failed, zt_a.last_tsigstate)
    assert_equal(query_a.header.id, query_a.tsig.original_id)
  end

  def test_packet_sender_check_tsig_with_ring
    ring = make_ring
    sender = Dnsruby::PacketSender.new('127.0.0.1')
    sender.tsig = ring

    exchange = ring.signing_exchange(KEY_NAME, 'hmac-sha256')
    query = signed_query(exchange)

    # A response under a key the ring does not hold fails BADKEY, pinned or not.
    wire, = signed_wire(query: query, secret: STRAY_SECRET, algorithm: 'hmac-sha256',
      key_name: 'stray.example.')
    response = decode(wire)
    error = sender.check_tsig(query, response, wire)
    assert_kind_of(Dnsruby::TsigError, error)
    assert_equal(:Failed, response.tsigstate)
    assert_equal(Dnsruby::RCode::BADKEY, response.tsigerror)
    refute_leaks(error.message)

    # A response under a held key verifies through the ring.
    wire, = signed_wire(query: query, secret: OLD_SECRET, algorithm: 'hmac-sha256')
    response = decode(wire)
    assert_equal(:okay, sender.check_tsig(query, response, wire))
    assert(response.verified?)

    # A bad MAC under a held key fails BADSIG and never tries the other key.
    wire, = signed_wire(query: query, secret: NEW_SECRET, algorithm: 'hmac-sha256')
    response = decode(wire)
    error = sender.check_tsig(query, response, wire)
    assert_kind_of(Dnsruby::TsigError, error)
    assert_equal(Dnsruby::RCode::BADSIG, response.tsigerror)
    refute_leaks(error.message)
  end

  def test_ring_accepted_as_tsig_configuration
    ring = make_ring
    assert_same(ring, Dnsruby::Resolver.get_tsig([ring]))
    resolver = Dnsruby::Resolver.new('127.0.0.1')
    resolver.tsig = ring
    assert_same(ring, resolver.tsig)
    zt = Dnsruby::ZoneTransfer.new
    zt.tsig = ring
    assert_same(ring, zt.tsig)
  end
end

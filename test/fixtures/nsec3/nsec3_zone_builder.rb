# frozen_string_literal: true

# Builds a small, fully self-contained NSEC3-signed zone in memory using an
# OpenSSL RSA key (algorithm 7, RSASHA1-NSEC3-SHA1). No external signer is
# available in this environment, so the NSEC3 chain, RRSIGs and DNSKEY are
# generated directly with Dnsruby's own encoding and hashing primitives.
require 'openssl'
require 'dnsruby'

class Nsec3ZoneBuilder
  ZONE = 'example.'
  TTL = 3600
  SALT = Dnsruby::RR::NSEC3.decode_salt('aabbccdd')
  ITERATIONS = 12
  HASH_ALG = 1
  ALGORITHM = Dnsruby::Algorithms.RSASHA1_NSEC3_SHA1

  # Original owner names represented by the authoritative NSEC3 chain.
  NAMES = %w[
    example.
    a.example.
    ns1.example.
    w.example.
    x.w.example.
    y.w.example.
    cname.example.
    empty.ent.example.
    *.w.example.
  ].freeze

  # Unsigned delegation next closer name, covered by an Opt-Out span.
  OPTOUT_NEXT_CLOSER = 'corp.example.'

  class << self
    def build
      zone = new
      zone.build
      zone
    end
  end

  attr_reader :dnskey, :key_tag, :nsec3s, :opt_out

  def initialize
    @rsa = OpenSSL::PKey::RSA.new(1024)
    @now = Time.utc(2026, 11, 14, 12).to_i
    @nsec3s = []
  end

  def build
    @dnskey = build_dnskey
    @key_tag = @dnskey.key_tag
    build_nsec3_chain
    self
  end

  def hash_binary(name)
    Dnsruby::RR::NSEC3.hash_to_binary(Dnsruby::Name.create(name), ITERATIONS, SALT, HASH_ALG)
  end

  def hash_hex(name)
    base32(hash_binary(name))
  end

  def nsec3_owner(name)
    "#{hash_hex(name)}.#{ZONE}"
  end

  def ordered_entries
    @ordered_entries ||= NAMES.map { |name| [hash_binary(name), name] }.sort_by(&:first)
  end

  def build_nsec3_chain
    entries = ordered_entries
    entries.each_with_index do |(owner_hash, original), index|
      next_hash = entries[(index + 1) % entries.length].first
      owner = "#{base32(owner_hash)}.#{ZONE}"
      @nsec3s << make_nsec3(owner, 0, next_hash, types_for(original))
    end
    build_opt_out
  end

  # NSEC3 owner/next hashes use unpadded extended-hex base32 (RFC 5155).
  def base32(binary)
    Base32.encode32hex(binary).downcase.delete('=')
  end

  def make_nsec3(owner, flags, next_hash, type_names)
    salt_text = Dnsruby::RR::NSEC3.encode_salt(SALT)
    Dnsruby::RR.create(
      "#{owner} #{TTL} IN NSEC3 #{HASH_ALG} #{flags} #{ITERATIONS} #{salt_text} " \
      "( #{base32(next_hash)} #{type_names.join(' ')} )"
    )
  end

  # The Opt-Out record reuses an existing span but sets flag 1, marking that
  # it covers one or more unsigned delegations (RFC 5155 section 6).
  def build_opt_out
    cover = @nsec3s.find { |n| n.covers_name?(OPTOUT_NEXT_CLOSER) }
    raise 'could not locate span for opt-out fixture' unless cover
    type_names = cover.types.map { |t| Dnsruby::Types === t ? t.string : t }
    @opt_out = make_nsec3(cover.name.to_s, Dnsruby::RR::NSEC3::OPT_OUT,
                          cover.next_hashed, type_names)
  end

  def types_for(name)
    base = %w[RRSIG NSEC3]
    case name
    when ZONE
      base + %w[SOA NS DNSKEY NSEC3PARAM]
    when 'ns1.example.'
      %w[A] + base
    when 'a.example.'
      %w[A] + base
    when 'w.example.'
      # A normal owner name with a wildcard child; it is not itself a
      # delegation, so its NSEC3 bitmap must not carry NS without SOA.
      %w[HINFO] + base
    when 'x.w.example.', 'y.w.example.'
      %w[MX] + base
    when 'cname.example.'
      %w[CNAME] + base
    when '*.w.example.'
      %w[MX] + base
    when 'empty.ent.example.'
      base
    else
      base
    end
  end

  def build_dnskey
    exponent = @rsa.params['e'].to_s(2)
    modulus = @rsa.params['n'].to_s(2)
    wire = if exponent.length <= 255
             exponent.length.chr + exponent + modulus
           else
             "\0" + [exponent.length].pack('n') + exponent + modulus
           end
    Dnsruby::RR.create(
      type: Dnsruby::Types.DNSKEY,
      name: ZONE,
      ttl: TTL,
      flags: 257,
      protocol: 3,
      algorithm: ALGORITHM,
      key: [wire].pack('m*')
    )
  end

  def sign_rrset(rrset, labels: nil)
    rrsig = Dnsruby::RR.create(
      type: Dnsruby::Types.RRSIG,
      name: rrset.name,
      ttl: TTL,
      type_covered: rrset.type,
      algorithm: ALGORITHM,
      labels: labels || rrset.name.labels.length,
      original_ttl: TTL,
      expiration: @now + 30 * 86_400,
      inception: @now - 3600,
      key_tag: @key_tag,
      signers_name: ZONE,
      signature: ''
    )
    data = rrsig.sig_data + canonical_data(rrset, rrsig)
    rrsig.signature = @rsa.sign(OpenSSL::Digest::SHA1.new, data)
    rrset.add(rrsig)
    rrsig
  end

  def canonical_data(rrset, rrsig)
    name = rrset.name
    if rrsig.labels < name.labels.length
      name = Dnsruby::Name.new(
        [Dnsruby::Name::Label.new('*')] + name.labels.last(rrsig.labels), true
      )
    end
    rdatas = rrset.rrs.map do |record|
      Dnsruby::MessageEncoder.new { |e| record.encode_rdata(e, true) }.to_s
    end.uniq.sort
    prefix = Dnsruby::MessageEncoder.new do |e|
      e.put_name(name, true)
      e.put_pack('nnN', rrset.type.code, rrset.klass.code, rrsig.original_ttl)
    end.to_s
    rdatas.map { |d| prefix + [d.bytesize].pack('n') + d }.join
  end

  def soa
    @soa ||= Dnsruby::RR.create(
      "#{ZONE} #{TTL} IN SOA ns1.#{ZONE} bugs.x.w.#{ZONE} 1 3600 300 3600000 3600"
    )
  end

  def rrset(records)
    set = Dnsruby::RRSet.new
    records.each { |r| set.add(r) }
    set
  end

  def responses
    {
      nxdomain: nxdomain_response,
      nodata: nodata_response,
      wildcard_nodata: wildcard_nodata_response,
      wildcard_answer: wildcard_answer_response,
      ds_nodata_secure: ds_nodata_secure_response,
      ds_nodata_optout: ds_nodata_optout_response
    }
  end

  def add_signed_nsec3(message, nsec3s)
    nsec3s.group_by(&:name).each do |_owner, records|
      set = rrset(records)
      sign_rrset(set)
      set.rrs.each { |r| message.add_authority(r) }
      set.sigs.each { |r| message.add_authority(r) }
    end
  end

  def add_soa(message)
    set = rrset([soa])
    sign_rrset(set)
    set.rrs.each { |r| message.add_authority(r) }
    set.sigs.each { |r| message.add_authority(r) }
  end

  # NXDOMAIN for a.c.x.w.example. Closest encloser x.w.example., next closer
  # c.x.w.example., plus a cover of *.x.w.example. (RFC 5155 8.4).
  def nxdomain_response
    qname = 'a.c.x.w.example.'
    encloser = 'x.w.example.'
    next_closer = 'c.x.w.example.'
    wildcard = "*.#{encloser}"
    msg = Dnsruby::Message.new
    msg.header.rcode = Dnsruby::RCode.NXDOMAIN
    msg.add_question(Dnsruby::Question.new(qname, Dnsruby::Types.A, Dnsruby::Classes.IN))
    add_soa(msg)
    add_signed_nsec3(msg, [
      nsec3_matching(encloser),
      nsec3_covering(next_closer),
      nsec3_covering(wildcard)
    ])
    msg
  end

  # Plain NODATA: ns1.example. matches an NSEC3 whose bitmap lacks MX/CNAME.
  def nodata_response
    qname = 'ns1.example.'
    msg = Dnsruby::Message.new
    msg.header.rcode = Dnsruby::RCode.NOERROR
    msg.add_question(Dnsruby::Question.new(qname, Dnsruby::Types.MX, Dnsruby::Classes.IN))
    add_soa(msg)
    add_signed_nsec3(msg, [nsec3_matching(qname)])
    msg
  end

  # Wildcard NODATA for z.w.example./AAAA: closest encloser w.example., next
  # closer z.w.example. covered, and *.w.example. matched without AAAA/CNAME.
  def wildcard_nodata_response
    qname = 'z.w.example.'
    encloser = 'w.example.'
    wildcard = "*.#{encloser}"
    msg = Dnsruby::Message.new
    msg.header.rcode = Dnsruby::RCode.NOERROR
    msg.add_question(Dnsruby::Question.new(qname, Dnsruby::Types.AAAA, Dnsruby::Classes.IN))
    add_soa(msg)
    add_signed_nsec3(msg, [
      nsec3_matching(encloser),
      nsec3_covering(qname),
      nsec3_matching(wildcard)
    ])
    msg
  end

  def wildcard_name_for(encloser)
    Dnsruby::Name.new([Dnsruby::Name::Label.new('*')] + encloser.labels, true)
  end

  # Wildcard answer for z.w.example./MX synthesised from *.w.example.
  def wildcard_answer_response
    qname = 'z.w.example.'
    encloser = Dnsruby::Name.create('w.example.')
    wildcard = wildcard_name_for(encloser)
    msg = Dnsruby::Message.new
    msg.header.rcode = Dnsruby::RCode.NOERROR
    msg.add_question(Dnsruby::Question.new(qname, Dnsruby::Types.MX, Dnsruby::Classes.IN))
    mx = Dnsruby::RR.create("#{qname} #{TTL} IN MX 10 mail.#{ZONE}")
    answer = rrset([mx])
    # Labels in the RRSIG is the wildcard's label count minus one: the
    # expanded QNAME and *.w.example. both have three labels, and the smaller
    # RRSIG count is what proves wildcard synthesis (RFC 4034 3.1.3).
    sign_rrset(answer, labels: wildcard.labels.length - 1)
    answer.rrs.each { |r| msg.add_answer(r) }
    answer.sigs.each { |r| msg.add_answer(r) }
    add_signed_nsec3(msg, [
      nsec3_matching(encloser.to_s),
      nsec3_covering(qname)
    ])
    msg
  end

  # Secure DS NODATA: matching NSEC3 for a.example. without DS/CNAME bits.
  def ds_nodata_secure_response
    qname = 'a.example.'
    msg = Dnsruby::Message.new
    msg.header.rcode = Dnsruby::RCode.NOERROR
    msg.add_question(Dnsruby::Question.new(qname, Dnsruby::Types.DS, Dnsruby::Classes.IN))
    add_soa(msg)
    add_signed_nsec3(msg, [nsec3_matching(qname)])
    msg
  end

  # Insecure delegation DS NODATA via an Opt-Out next closer cover.
  def ds_nodata_optout_response
    qname = 'opt.corp.example.'
    msg = Dnsruby::Message.new
    msg.header.rcode = Dnsruby::RCode.NOERROR
    msg.add_question(Dnsruby::Question.new(qname, Dnsruby::Types.DS, Dnsruby::Classes.IN))
    add_soa(msg)
    add_signed_nsec3(msg, [nsec3_matching(ZONE), opt_out])
    msg
  end

  def absolute(name)
    n = Dnsruby::Name.create(name)
    n.absolute? ? n : Dnsruby::Name.new(n.labels, true)
  end

  def nsec3_matching(name)
    @nsec3s.find { |n| n.matches_name?(absolute(name)) } ||
      raise("no matching NSEC3 for #{name}")
  end

  def nsec3_covering(name)
    @nsec3s.find { |n| n.covers_name?(absolute(name)) } ||
      raise("no covering NSEC3 for #{name}")
  end
end

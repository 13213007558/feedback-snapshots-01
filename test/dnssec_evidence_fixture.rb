require 'openssl'
require 'base64'
require 'dnsruby'

# Builds a small signed hierarchy entirely in memory. Keys are generated per
# process, so tests never depend on real DNS or on long-lived private keys.
module DnssecEvidenceFixture
  module_function

  KEYS = {}

  def key_for(name)
    name = Dnsruby::Name.create(name).to_s(true)
    KEYS[name] ||= begin
      private_key = OpenSSL::PKey::EC.generate('prime256v1')
      bytes = private_key.public_key.to_octet_string(:uncompressed).byteslice(1, 64)
      [private_key, Dnsruby::RR.create(
        "#{name} 300 IN DNSKEY 257 3 13 #{Base64.strict_encode64(bytes)}")]
    end
  end

  def ds_for(key, ttl: 300)
    ds = Dnsruby::RR::DS.from_key(key, 'SHA-256')
    ds.ttl = ttl
    ds
  end

  def sign(rrset, key, at:)
    private_key, _ = key_for(key.name.to_s(true))
    # RRSet#add clones and may normalise TTLs, so read them from a stable copy.
    ttl = rrset.rrs.map(&:ttl).min
    signature = Dnsruby::RR.create(
      name: rrset.name, type: 'RRSIG', ttl: ttl,
      type_covered: rrset.type, algorithm: 13, labels: rrset.name.labels.length,
      original_ttl: ttl, expiration: at.to_i + 7 * 24 * 3600, inception: at.to_i - 7 * 24 * 3600,
      key_tag: key.key_tag, signers_name: key.name)
    # canonical_rrset_data prefixes the canonical name/type/class/ttl and
    # length-prefixes each sorted RDATA, so the signature input is exactly that.
    name = rrset.name
    prefix = Dnsruby::MessageEncoder.new do |encoder|
      encoder.put_name(name, true)
      encoder.put_pack('nnN', rrset.type.code, rrset.klass.code, signature.original_ttl)
    end.to_s
    rdatas = rrset.rrs.map do |rr|
      Dnsruby::MessageEncoder.new { |encoder| rr.encode_rdata(encoder, true) }.to_s
    end
    data = prefix + rdatas.uniq.sort.map { |rdata| [rdata.bytesize].pack('n') + rdata }.join
    der = private_key.dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(signature.sig_data + data))
    # DER INTEGER drops leading zero octets; the DNSSEC wire form is two
    # fixed-width unsigned integers, so encode the octets directly.
    signature.signature = OpenSSL::ASN1.decode(der).value.map do |integer|
      value = integer.value
      # DER may prepend 0x00 to keep the integer positive; trim it only then.
      size = 32
      if value.to_s(2).bytesize > size
        value & ((1 << (size * 8)) - 1)
      else
        value
      end.to_s(2).rjust(size, "\0")
    end.join
    signature
  end

  def signed(rr, key, at:)
    signed_rrset([rr], key, at: at)
  end

  def signed_rrset(rrs, key, at:)
    rrset = Dnsruby::RRSet.new(rrs)
    signature = sign(rrset, key, at: at)
    rrset.add(signature)
    # RRSet#add clones the signature and may cap its TTL to the covered set;
    # restore the signed original so ``sigs`` is byte-identical to the input.
    idx = rrset.rrs.length
    rrset.instance_variable_get(:@rrs)[idx] = signature
    rrset
  end

  def zone_keys(name)
    _, key = key_for(name)
    Dnsruby::RRSet.new([key])
  end
end

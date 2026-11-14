# --
# Copyright 2007 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'
require 'openssl'
require 'base64'

class TestSSHFPVerify < Minitest::Test
  include Dnsruby

  ZONE = 'example.'
  HOST = "host.#{ZONE}"

  def setup
    @rsa = OpenSSL::PKey::RSA.generate(1024)
    exponent = @rsa.e.to_s(2)
    key_bytes = [exponent.bytesize].pack('C') + exponent + @rsa.n.to_s(2)
    @dnskey = RR.create("#{ZONE} 300 IN DNSKEY 256 3 8 #{Base64.strict_encode64(key_bytes)}")
    @verifier = SSHFPVerifier.new(@dnskey)
  end

  def field(data)
    [data.bytesize].pack('N') + data
  end

  #  Build a wire-format SSH key blob and its OpenSSH public key line.
  def ssh_key(type = 'ssh-rsa', seed = 'host-key')
    blob = case type
           when 'ssh-ed25519'
             field('ssh-ed25519') + field(Digest::SHA256.digest(seed))
           when 'ecdsa-sha2-nistp256'
             field('ecdsa-sha2-nistp256') + field('nistp256') + field(Digest::SHA256.digest(seed) + "\x04")
           else
             field('ssh-rsa') + field("\x01\x00\x01") + field(Digest::SHA256.digest(seed) * 4)
           end
    ["#{type} #{Base64.strict_encode64(blob)}", blob]
  end

  def sshfp(name, alg, fptype, blob)
    fp = fptype == 1 ? Digest::SHA1.digest(blob) : Digest::SHA256.digest(blob)
    RR.create("#{name} 300 IN SSHFP #{alg} #{fptype} #{fp.unpack1('H*')}")
  end

  def sign(rrs, type_string, rsa = @rsa, ttl = 300)
    now = Time.now.to_i
    name = rrs.first.name
    sig = RR.create(name: name, type: 'RRSIG', ttl: ttl,
      type_covered: type_string, algorithm: 8, labels: name.labels.length,
      original_ttl: ttl, expiration: now + 3600, inception: now - 60,
      key_tag: @dnskey.key_tag, signers_name: ZONE)
    rdatas = rrs.map { |r| MessageEncoder.new { |e| r.encode_rdata(e, true) }.to_s }.uniq.sort
    prefix = MessageEncoder.new { |e|
      e.put_name(name, true)
      e.put_pack('nnN', Types.new(type_string).code, Classes::IN, ttl)
    }.to_s
    canonical = rdatas.map { |d| prefix + [d.bytesize].pack('n') + d }.join
    sig.signature = rsa.sign(OpenSSL::Digest::SHA256.new, sig.sig_data + canonical)
    sig
  end

  def signed_message(qname, records_by_type, rsa = @rsa)
    msg = Message.new(qname, 'SSHFP')
    records_by_type.each do |type, rrs|
      rrs.each { |rr| msg.add_answer(rr) }
      msg.add_answer(sign(rrs, type, rsa))
    end
    msg
  end

  def test_verified_rsa_sha256_and_sha1
    key_line, blob = ssh_key('ssh-rsa')
    records = [sshfp(HOST, 1, 2, blob), sshfp(HOST, 1, 1, blob)]
    msg = signed_message(HOST, 'SSHFP' => records)
    result = @verifier.verify(HOST, key_line, msg)
    assert(result.verified?, "expected verified, got #{result}")
    assert_equal(:verified, result.code)
    assert_equal(HOST, result.canonical_name)
    assert_equal(Types::SSHFP, result.record.type)
  end

  def test_verified_ed25519
    key_line, blob = ssh_key('ssh-ed25519')
    msg = signed_message(HOST, 'SSHFP' => [sshfp(HOST, 6, 2, blob)])
    result = @verifier.verify(HOST, key_line, msg)
    assert(result.verified?, "expected verified, got #{result}")
  end

  def test_known_hosts_line_accepted
    key_line, blob = ssh_key('ssh-ed25519')
    msg = signed_message(HOST, 'SSHFP' => [sshfp(HOST, 6, 2, blob)])
    result = @verifier.verify(HOST, "example.com #{key_line} comment", msg)
    assert(result.verified?, "expected verified, got #{result}")
  end

  def test_cname_chain_followed
    key_line, blob = ssh_key('ssh-rsa')
    cname = RR.create("alias.#{ZONE} 300 IN CNAME #{HOST}")
    msg = signed_message("alias.#{ZONE}",
      'CNAME' => [cname], 'SSHFP' => [sshfp(HOST, 1, 2, blob)])
    result = @verifier.verify("alias.#{ZONE}", key_line, msg)
    assert(result.verified?, "expected verified, got #{result}")
    assert_equal(HOST, result.canonical_name)
  end

  def test_rotation_any_matching_record_verifies
    key_line, blob = ssh_key('ssh-rsa')
    _, old_blob = ssh_key('ssh-rsa', 'old-key')
    records = [sshfp(HOST, 1, 2, old_blob), sshfp(HOST, 1, 2, blob)]
    msg = signed_message(HOST, 'SSHFP' => records)
    result = @verifier.verify(HOST, key_line, msg)
    assert(result.verified?, "expected verified, got #{result}")
  end

  def test_wrong_host_not_authenticated
    key_line, blob = ssh_key('ssh-rsa')
    other = "other.#{ZONE}"
    msg = signed_message(other, 'SSHFP' => [sshfp(other, 1, 2, blob)])
    result = @verifier.verify(HOST, key_line, msg)
    refute(result.verified?)
    assert_equal(:query_mismatch, result.code)
  end

  def test_sshfp_at_unrelated_owner_not_authenticated
    key_line, blob = ssh_key('ssh-rsa')
    other = "other.#{ZONE}"
    #  Question is for the requested host, but the only SSHFP RRSet belongs
    #  to a different owner name.
    msg = signed_message(HOST, 'SSHFP' => [sshfp(other, 1, 2, blob)])
    result = @verifier.verify(HOST, key_line, msg)
    refute(result.verified?)
    assert_equal(:no_records, result.code)
    assert_match(/other\.example/, result.reason)
  end

  def test_swapped_key_not_authenticated
    _, blob = ssh_key('ssh-rsa')
    attacker_line, = ssh_key('ssh-rsa', 'attacker-key')
    msg = signed_message(HOST, 'SSHFP' => [sshfp(HOST, 1, 2, blob)])
    result = @verifier.verify(HOST, attacker_line, msg)
    refute(result.verified?)
    assert_equal(:key_mismatch, result.code)
  end

  def test_secure_label_without_signatures_not_authenticated
    key_line, blob = ssh_key('ssh-rsa')
    msg = Message.new(HOST, 'SSHFP')
    msg.add_answer(sshfp(HOST, 1, 2, blob))
    #  A SECURE label on the object is not proof: no RRSIGs, no trust.
    msg.security_level = Message::SecurityLevel.SECURE
    result = @verifier.verify(HOST, key_line, msg)
    refute(result.verified?)
    assert_equal(:insecure, result.code)
  end

  def test_bogus_signature_not_authenticated
    key_line, blob = ssh_key('ssh-rsa')
    msg = signed_message(HOST, { 'SSHFP' => [sshfp(HOST, 1, 2, blob)] },
      OpenSSL::PKey::RSA.generate(1024))
    result = @verifier.verify(HOST, key_line, msg)
    refute(result.verified?)
    assert_equal(:bogus, result.code)
  end

  def test_bogus_label_on_valid_message_ignored
    key_line, blob = ssh_key('ssh-rsa')
    msg = signed_message(HOST, 'SSHFP' => [sshfp(HOST, 1, 2, blob)])
    msg.security_level = Message::SecurityLevel.BOGUS
    result = @verifier.verify(HOST, key_line, msg)
    assert(result.verified?, "expected verified, got #{result}")
  end

  def test_unsupported_fingerprint_type
    key_line, blob = ssh_key('ssh-rsa')
    msg = signed_message(HOST, 'SSHFP' => [sshfp(HOST, 1, 3, blob)])
    result = @verifier.verify(HOST, key_line, msg)
    refute(result.verified?)
    assert_equal(:unsupported, result.code)
    assert_match(/fingerprint type/, result.reason)
  end

  def test_key_type_must_match_record_algorithm
    #  SSHFP record covers an RSA key; the presented key is Ed25519.
    _, rsa_blob = ssh_key('ssh-rsa')
    ed_line, = ssh_key('ssh-ed25519')
    msg = signed_message(HOST, 'SSHFP' => [sshfp(HOST, 1, 2, rsa_blob)])
    result = @verifier.verify(HOST, ed_line, msg)
    refute(result.verified?)
    assert_equal(:unsupported, result.code)
    assert_match(/other key algorithms/, result.reason)
  end

  def test_unknown_key_type_explained
    _, blob = ssh_key('ssh-rsa')
    msg = signed_message(HOST, 'SSHFP' => [sshfp(HOST, 1, 2, blob)])
    weird = "ssh-xyz #{Base64.strict_encode64(field('ssh-xyz') + field('abc'))}"
    result = @verifier.verify(HOST, weird, msg)
    refute(result.verified?)
    assert_equal(:unsupported, result.code)
    assert_match(/ssh-xyz/, result.reason)
  end

  def test_cname_loop_reported
    cname = RR.create("alias.#{ZONE} 300 IN CNAME alias.#{ZONE}")
    msg = signed_message("alias.#{ZONE}", 'CNAME' => [cname])
    key_line, = ssh_key('ssh-rsa')
    result = @verifier.verify("alias.#{ZONE}", key_line, msg)
    refute(result.verified?)
    assert_equal(:cname_loop, result.code)
  end

  def test_trust_anchor_required
    assert_raises(ArgumentError) { SSHFPVerifier.new(nil) }
    assert_raises(ArgumentError) { SSHFPVerifier.new([]) }
  end

  def test_ds_trust_anchor_with_dnskey_in_message
    key_line, blob = ssh_key('ssh-rsa')
    digest = OpenSSL::Digest::SHA256.digest(MessageEncoder.new { |e|
      e.put_name(@dnskey.name, true)
      @dnskey.encode_rdata(e, true)
    }.to_s)
    ds = RR.create("#{ZONE} 300 IN DS #{@dnskey.key_tag} 8 2 #{digest.unpack1('H*')}")
    msg = signed_message(HOST,
      'DNSKEY' => [@dnskey], 'SSHFP' => [sshfp(HOST, 1, 2, blob)])
    result = SSHFPVerifier.new(ds).verify(HOST, key_line, msg)
    assert(result.verified?, "expected verified, got #{result}")
  end
end

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
require 'base64'
require 'digest/sha1'
require 'digest/sha2'

module Dnsruby
  #  Offline SSHFP verification (RFC 4255, RFC 6594, RFC 7479, RFC 8709).
  #
  #  Binds three inputs together before a host key is trusted:
  #
  #  * the hostname the caller asked for,
  #  * the DNSSEC validation material (a response Message plus trust anchors),
  #  * the SSH public key actually received from the server.
  #
  #  The verifier performs its own cryptographic DNSSEC validation of the
  #  supplied message with the supplied trust anchors. The security_level
  #  label already attached to a Message is never consulted - a SECURE tag
  #  on an object is not proof. No network traffic is generated.
  #
  #  The SSHFP RRSet must be owned by the canonical end of the (verified)
  #  CNAME chain starting at the requested hostname, and a matching record
  #  must carry the algorithm of the presented key and a supported
  #  fingerprint type. Every other outcome is reported with an explanatory
  #  Result#code and Result#reason.
  #
  #  Example :
  #    verifier = Dnsruby::SSHFPVerifier.new(trust_anchor_dnskey)
  #    result = verifier.verify("www.example.com", ssh_public_key_line, response)
  #    if result.verified?
  #      # host key authenticated
  #    else
  #      warn "#{result.code}: #{result.reason}"
  #    end
  class SSHFPVerifier
    #  The outcome of a verification attempt. #verified? is only true when
    #  the requested hostname, the DNSSEC chain and the presented SSH key
    #  all line up on a single SSHFP record.
    class Result
      #  One of :verified, :query_mismatch, :insecure, :bogus, :cname_loop,
      #  :no_records, :unsupported or :key_mismatch
      attr_reader :code
      #  Human-readable explanation of the outcome
      attr_reader :reason
      #  The hostname verification was requested for
      attr_reader :hostname
      #  The owner name of the SSHFP RRSet after following any CNAME chain
      attr_reader :canonical_name
      #  The SSHFP record which authenticated the key (nil unless verified)
      attr_reader :record

      def initialize(code, reason, hostname, canonical_name = nil, record = nil) #:nodoc: all
        @code = code
        @reason = reason
        @hostname = hostname
        @canonical_name = canonical_name
        @record = record
      end

      def verified?
        @code == :verified
      end

      def to_s
        "[#{@code}] #{@reason}"
      end
    end

    #  OpenSSH key type string => SSHFP algorithm number (RFC 4255, RFC 7479,
    #  RFC 8709)
    KEY_TYPES = {
      'ssh-rsa' => RR::SSHFP::Algorithms::RSA,
      'ssh-dss' => RR::SSHFP::Algorithms::DSS,
      'ecdsa-sha2-nistp256' => RR::SSHFP::Algorithms::ECDSA,
      'ssh-ed25519' => RR::SSHFP::Algorithms::ED25519
    }.freeze

    #  SSHFP fingerprint types this verifier can compute
    FINGERPRINT_DIGESTS = {
      RR::SSHFP::FpTypes::SHA1 => Digest::SHA1,
      RR::SSHFP::FpTypes::SHA256 => Digest::SHA256
    }.freeze

    MAX_CNAME_CHAIN = 16

    #  trust_anchors may be a single Dnsruby::RR (DNSKEY or DS), an Array of
    #  them, or an RRSet of DNSKEYs. At least one anchor is required -
    #  without one, no message can ever be authenticated.
    def initialize(trust_anchors)
      anchors = trust_anchors.is_a?(Array) ? trust_anchors : [trust_anchors]
      anchors = anchors.compact
      if anchors.empty? || anchors.any? { |a| !(RR::DNSKEY === a) && !(RR::DS === a) && !(RRSet === a) }
        raise ArgumentError.new("SSHFPVerifier requires at least one DNSKEY or DS trust anchor")
      end
      @trust_anchors = trust_anchors
    end

    #  Verify that +ssh_key+ (an OpenSSH public key line, as produced by
    #  ssh-keyscan or stored in known_hosts) is authenticated for +hostname+
    #  by the DNSSEC-signed +message+ (a Dnsruby::Message, e.g. the response
    #  to an SSHFP query).
    #
    #  Returns a Result; check Result#verified?.
    def verify(hostname, ssh_key, message)
      raise ArgumentError.new("Expected a Dnsruby::Message") unless Message === message
      name = Name.create(hostname)
      name.absolute = true
      hostname = name.to_s(true)

      alg_code, blob, key_type = self.class.parse_ssh_key(ssh_key)
      unless alg_code
        return Result.new(:unsupported,
          "SSH key type '#{key_type}' has no SSHFP algorithm mapping", hostname)
      end

      question = message.question()[0]
      unless question
        return Result.new(:bogus, "Response has no question section", hostname)
      end
      unless question.qname.canonical == name.canonical
        return Result.new(:query_mismatch,
          "Response answers #{question.qname} but verification was requested for #{hostname}", hostname)
      end
      unless [Types::SSHFP, Types::ANY].include?(question.qtype)
        return Result.new(:query_mismatch,
          "Response is for query type #{question.qtype}, not SSHFP", hostname)
      end

      if message.rrsets(Types::RRSIG).empty?
        return Result.new(:insecure,
          "Response carries no RRSIG records; SSHFP data cannot be authenticated", hostname)
      end

      #  Cryptographically validate the whole message against the configured
      #  trust anchors. The message's own security_level is deliberately
      #  ignored - a SECURE label on an object is not proof.
      verifier = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)
      begin
        verifier.verify(message, @trust_anchors)
      rescue VerifyError => e
        return Result.new(:bogus, "DNSSEC validation failed: #{e.message}", hostname)
      end

      target, error = follow_cname_chain(message, name, hostname)
      return error if error
      canonical = target.to_s(true)

      sshfp_rrset = message.answer.rrset(target, Types::SSHFP)
      if sshfp_rrset.rrs.empty?
        others = message.answer.rrsets(Types::SSHFP).map { |rs| rs.name.to_s(true) }.uniq
        detail = others.empty? ?
          "no SSHFP records are present in the response" :
          "SSHFP records are only present for other owner name(s): #{others.join(', ')}"
        return Result.new(:no_records,
          "No SSHFP RRSet owned by #{canonical} (#{detail})", hostname, canonical)
      end

      match_records(sshfp_rrset, alg_code, blob, key_type, hostname, canonical)
    end

    #  Convenience one-shot interface :
    #  SSHFPVerifier.verify(hostname, ssh_key, message, trust_anchors)
    def self.verify(hostname, ssh_key, message, trust_anchors)
      new(trust_anchors).verify(hostname, ssh_key, message)
    end

    #  Parse an OpenSSH public key line ("ssh-ed25519 AAAA... comment", with
    #  or without a leading known_hosts host field) into
    #  [sshfp_algorithm_code, key_blob, key_type_string]. The algorithm code
    #  is nil when the key type has no SSHFP mapping.
    def self.parse_ssh_key(ssh_key)
      tokens = ssh_key.to_s.strip.split(/\s+/)
      index = tokens.index { |t| t =~ /\A(ssh-|ecdsa-)/ }
      if index.nil? || tokens[index + 1].nil?
        raise ArgumentError.new("Not an OpenSSH public key line")
      end
      outer_type = tokens[index]
      begin
        blob = Base64.strict_decode64(tokens[index + 1])
      rescue ArgumentError
        raise ArgumentError.new("Invalid base64 in SSH public key")
      end
      #  The blob's own type string is what the fingerprint authenticates,
      #  so prefer it over the outer token.
      inner_type = nil
      if blob.bytesize >= 4
        length = blob.unpack("N")[0]
        inner_type = blob[4, length] if length && blob.bytesize >= 4 + length
      end
      key_type = inner_type || outer_type
      [KEY_TYPES[key_type], blob, key_type]
    end

    private

    def follow_cname_chain(message, name, hostname)
      target = name
      seen = {}
      loop do
        cname_rrset = message.answer.rrset(target, Types::CNAME)
        return [target, nil] if cname_rrset.rrs.empty?
        if seen.length >= MAX_CNAME_CHAIN
          return [nil, Result.new(:cname_loop,
            "CNAME chain from #{hostname} exceeds #{MAX_CNAME_CHAIN} hops", hostname)]
        end
        seen[target.canonical.to_s] = true
        target = cname_rrset.rrs[0].domainname
        target.absolute = true
        if seen[target.canonical.to_s]
          return [nil, Result.new(:cname_loop,
            "CNAME chain from #{hostname} loops back to #{target}", hostname)]
        end
      end
    end

    def match_records(sshfp_rrset, alg_code, blob, key_type, hostname, canonical)
      mismatched = 0
      unsupported_fptypes = []
      other_algorithms = 0
      sshfp_rrset.rrs.each do |rr|
        unless rr.alg.code == alg_code
          other_algorithms += 1
          next
        end
        digest_class = FINGERPRINT_DIGESTS[rr.fptype.code]
        unless digest_class
          unsupported_fptypes.push(rr.fptype.code)
          next
        end
        if digest_class.digest(blob) == rr.fp
          return Result.new(:verified,
            "SSHFP record for #{canonical} authenticates the presented #{key_type} key",
            hostname, canonical, rr)
        end
        mismatched += 1
      end

      if mismatched > 0
        return Result.new(:key_mismatch,
          "#{mismatched} verified SSHFP record(s) for #{canonical} cover #{key_type} keys, " \
          "but none matches the presented key", hostname, canonical)
      end
      reasons = []
      unless unsupported_fptypes.empty?
        reasons.push("record(s) with unsupported fingerprint type(s) #{unsupported_fptypes.uniq.join(', ')}")
      end
      if other_algorithms > 0
        reasons.push("#{other_algorithms} record(s) for other key algorithms")
      end
      detail = reasons.empty? ? "no usable records" : reasons.join(" and ")
      Result.new(:unsupported,
        "No usable SSHFP record for the presented #{key_type} key at #{canonical}: #{detail}",
        hostname, canonical)
    end
  end
end

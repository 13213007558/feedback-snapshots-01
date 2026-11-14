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

require 'openssl'
require 'digest'
require 'dnsruby/name'
require 'dnsruby/resource/resource'

module Dnsruby
  # Offline DANE (TLSA) authentication of a TLS peer.
  #
  # This module never sends any DNS queries.  The caller is responsible for
  # obtaining the TLSA records and, crucially, for proving their DNSSEC
  # validation state before handing them in.  Per RFC 6698 section 4, only a
  # TLSA RRset whose validation state is SECURE may be used to authenticate a
  # peer; an insecure, indeterminate or bogus RRset is unusable and can never
  # turn into a successful authentication here.
  #
  # The four certificate usages of RFC 6698 / RFC 7671 are handled:
  #
  # * PKIX-TA(0) - the chain must pass PKIX validation against the caller's
  #   trust store and contain a CA certificate matching the TLSA record.
  # * PKIX-EE(1) - the chain must pass PKIX validation and the leaf
  #   certificate must match the TLSA record.
  # * DANE-TA(2) - a chain element matching the TLSA record is the trust
  #   anchor; the rest of the chain is validated to that anchor without using
  #   the caller's PKIX trust store.
  # * DANE-EE(3) - only the leaf certificate is matched.  No chain
  #   validation, name check or expiry check is performed.
  #
  # Selector Cert(0)/SPKI(1) and matching types Full(0), SHA-256(1) and
  # SHA-512(2) are supported.  Any other field value makes the individual
  # association unusable rather than being silently ignored or trusted.
  module DANE
    # PKIX-TA certificate usage (RFC 6698 section 2.1.1).
    PKIX_TA = 0
    # PKIX-EE certificate usage (RFC 6698 section 2.1.1).
    PKIX_EE = 1
    # DANE-TA certificate usage (RFC 6698 section 2.1.1).
    DANE_TA = 2
    # DANE-EE certificate usage (RFC 6698 section 2.1.1).
    DANE_EE = 3

    # Full certificate selector.
    SELECTOR_CERT = 0
    # SubjectPublicKeyInfo selector.
    SELECTOR_SPKI = 1

    # Exact match on the selected content.
    MATCHING_FULL = 0
    # SHA-256 digest of the selected content.
    MATCHING_SHA2_256 = 1
    # SHA-512 digest of the selected content.
    MATCHING_SHA2_512 = 2

    # Raised for bad arguments to the entry point.  A rejected argument never
    # degrades into a successful verification.
    class ArgumentError < ::ArgumentError; end

    # Raised when peer authentication fails.  The attached Result explains
    # which associations were considered and why none authenticated the peer.
    class VerificationError < StandardError
      attr_reader :result

      def initialize(message, result)
        super(message)
        @result = result
      end
    end

    # A raw association whose RDATA could not be constructed as a TLSA RR.
    # It carries the parsed fields far enough for classification to explain
    # why it is unusable; it can never authenticate a peer.
    class UnusableAssociation
      attr_accessor :name
      attr_reader :usage, :selector, :matching_type, :databin

      def initialize(usage, selector, matching_type, databin)
        @usage = usage
        @selector = selector
        @matching_type = matching_type
        @databin = databin
      end

      def rdata_to_string
        "#{@usage} #{@selector} #{@matching_type} #{@databin&.unpack1('H*')}"
      end
    end

    # Caller-controlled trust settings for an offline verification.
    #
    # +trust_store+:: an OpenSSL::X509::Store used for the PKIX path
    #   validation required by usages PKIX-TA(0) and PKIX-EE(1).  When nil a
    #   new store is created; add anchors through +trusted_certs+ or enable
    #   +system_ca+ to load the platform default roots.
    # +trusted_certs+:: OpenSSL::X509::Certificate objects trusted as PKIX
    #   anchors for usages 0/1.
    # +system_ca+:: whether OpenSSL::X509::Store#set_default_paths is
    #   called on a newly created store.
    # +verify_time+:: the time used for validity-period and PKIX checks
    #   (defaults to Time.now).  DANE-EE(3) always ignores expiry.
    # +check_name+:: when true (the default) PKIX usages and DANE-TA(2)
    #   require the service name to appear in the leaf certificate, per
    #   RFC 7671 sections 5.2 and 5.3.  DANE-EE(3) never performs a name
    #   check.
    class TrustConfig
      attr_accessor :trust_store, :trusted_certs, :system_ca, :verify_time, :check_name

      def initialize(trust_store: nil, trusted_certs: nil, system_ca: false,
                     verify_time: nil, check_name: true)
        @trust_store = trust_store
        @trusted_certs = trusted_certs || []
        @system_ca = system_ca
        @verify_time = verify_time
        @check_name = check_name
      end
    end

    # The outcome of an offline verification.
    #
    # +authenticated?+ reports the final decision.  On success +matched+ is
    # the TLSA record that actually authenticated the peer; the same record
    # is included in +usable+.  +unusable+ pairs (unknown field values,
    # malformed association data or a query name mismatch) are returned with
    # a reason so callers can audit why an association was ignored.
    class Result
      attr_reader :service, :port, :matched, :usable, :unusable, :failure_reason

      def initialize(service, port)
        @service = service
        @port = port
        @authenticated = false
        @matched = nil
        @usable = []
        @unusable = []
        @failure_reason = nil
      end

      def authenticated?
        @authenticated
      end

      # Records that were well formed and had a say in the decision.
      def associations
        @usable
      end

      # Pairs of [TLSA record, reason string] rejected before matching.
      def unusable_associations
        @unusable
      end

      def succeed(record)
        @authenticated = true
        @matched = record
        self
      end

      def fail(reason)
        @authenticated = false
        @failure_reason = reason
        self
      end

      def add_usable(record)
        @usable << record
      end

      def add_unusable(record, reason)
        @unusable << [record, reason]
      end

      def record_failure(reason)
        @failure_reason = reason
      end

      def inspect
        "#<Dnsruby::DANE::Result service=#{@service} port=#{@port} " \
          "authenticated=#{@authenticated} matched=#{@matched&.rdata_to_string} " \
          "usable=#{@usable.length} unusable=#{@unusable.length}>"
      end
    end

    class << self
      # Build the TLSA query name for a service, e.g. +_443._tcp.example.com+
      # for service +example.com+, port 443 and the default TCP transport.
      # Per RFC 6698 section 3 the port label is the decimal port number and
      # transport labels come from the IANA service label registry.
      def tlsa_name(service, port, transport = 'tcp')
        service_name = validate_service(service)
        port_int = validate_port(port)
        transport = transport.to_s.downcase
        raise DANE::ArgumentError, "unsupported transport: #{transport.inspect}" unless %w[tcp udp sctp].include?(transport)

        Dnsruby::Name.create("_#{port_int}._#{transport}.#{service_name}")
      end

      # Offline verification entry point.
      #
      # +service+:: the reference service name (TLSA base domain), e.g.
      #   "www.example.com".
      # +port+:: the service port number (1..65535).
      # +tlsa_records+:: TLSA associations the caller has already validated
      #   with DNSSEC.  Each element is a Dnsruby::RR::IN::TLSA or a Hash of
      #   +:usage+, +:selector+, +:matching_type+ and +:data+ (or
      #   +:databin+).  They must be asserted SECURE through +verified+.
      # +chain+:: the peer certificate chain, leaf first, as
      #   OpenSSL::X509::Certificate objects or PEM/DER strings.  It must
      #   contain at least a leaf certificate.
      # +trust_config+:: an optional TrustConfig controlling PKIX anchors,
      #   name and time checks.
      # +transport+:: transport label for the expected query name (default
      #   "tcp").
      # +verified+:: +true+ asserts that every element of +tlsa_records+
      #   comes from a DNSSEC-validated SECURE response; an Array aligned
      #   with +tlsa_records+ allows per-record assertions; a
      #   Dnsruby::Message::SecurityLevel value is accepted only when SECURE.
      #   Anything else (including the default +false+) is refused, because
      #   an unverified association must never authenticate a peer.
      #
      # Returns a Result on success and raises DANE::VerificationError when
      # the peer cannot be authenticated.  Invalid arguments raise
      # DANE::ArgumentError.
      def verify(service:, port:, tlsa_records:, chain:, trust_config: nil,
                 transport: 'tcp', verified: false)
        service_name = validate_service(service)
        port_int = validate_port(port)
        trust = trust_config || TrustConfig.new
        unless trust.is_a?(TrustConfig)
          raise DANE::ArgumentError, 'trust_config must be a Dnsruby::DANE::TrustConfig'
        end

        records = build_records(tlsa_records, verified)
        certificates = build_chain(chain)
        expected_name = tlsa_name(service_name, port_int, transport)
        result = Result.new(service_name, port_int)

        classify_records(records, expected_name, result)

        if result.usable.empty?
          reason = 'no usable verified TLSA associations'
          raise VerificationError.new(
            "no usable verified TLSA associations for #{service_name} port #{port_int}",
            result.fail(reason)
          )
        end

        evaluate(result, certificates, service_name, trust)
      end

      private

      def validate_service(service)
        unless service.is_a?(::String) && !service.strip.empty?
          raise DANE::ArgumentError, 'service must be a non-empty String'
        end

        service
      end

      def validate_port(port)
        port_int = Integer(port)
      rescue ::ArgumentError, TypeError
        raise DANE::ArgumentError, "port must be an integer, got #{port.inspect}"
      else
        unless (1..65535).include?(port_int)
          raise DANE::ArgumentError, "port must be between 1 and 65535, got #{port_int}"
        end

        port_int
      end

      def build_records(tlsa_records, verified)
        raise DANE::ArgumentError, 'tlsa_records must be an Array' unless tlsa_records.is_a?(::Array)
        raise DANE::ArgumentError, 'tlsa_records must not be empty' if tlsa_records.empty?

        flags = verified_flags(tlsa_records, verified)

        tlsa_records.each_with_index.map do |entry, index|
          record = coerce_record(entry)
          unless flags[index]
            raise DANE::ArgumentError,
                  "unverified TLSA record #{record.rdata_to_string.inspect} cannot authenticate a peer"
          end
          record
        end
      end

      def verified_flags(records, verified)
        case verified
        when true
          Array.new(records.length, true)
        when false, nil
          Array.new(records.length, false)
        when ::Array
          unless verified.length == records.length
            raise DANE::ArgumentError, 'verified array length must match tlsa_records'
          end

          verified.map { |flag| flag == true }
        else
          # Accept Message::SecurityLevel::SECURE (numeric value 2) without
          # requiring the message subsystem to have been loaded.
          if defined?(Dnsruby::Message::SecurityLevel::SECURE) &&
             verified == Dnsruby::Message::SecurityLevel::SECURE
            Array.new(records.length, true)
          else
            raise DANE::ArgumentError,
                  "verified must be true, a per-record array or SecurityLevel::SECURE, got #{verified.inspect}"
          end
        end
      end

      def coerce_record(entry)
        case entry
        when Dnsruby::RR::IN::TLSA
          entry
        when Hash
          hash = entry
          usage = fetch_field(hash, :usage)
          selector = fetch_field(hash, :selector)
          matching_type = fetch_field(hash, :matching_type)
          databin = hash[:databin]
          if databin.nil?
            data = hash[:data]
            raise DANE::ArgumentError, 'TLSA hash requires :data or :databin' if data.nil?

            databin = parse_hex(data)
          end
          begin
            record = Dnsruby::RR::IN::TLSA.new([usage, selector, matching_type, databin])
          rescue StandardError
            # Keep the raw fields so classification can report the exact
            # reason the association is unusable.
            record = UnusableAssociation.new(usage, selector, matching_type, databin)
          end
          record.name = hash[:name] if hash[:name]
          record
        else
          raise DANE::ArgumentError,
                "each TLSA record must be a Dnsruby::RR::IN::TLSA or Hash, got #{entry.class}"
        end
      end

      def fetch_field(hash, key)
        raise DANE::ArgumentError, "TLSA hash requires :#{key}" unless hash.key?(key)

        hash[key]
      end

      def parse_hex(data)
        hex = data.to_s.gsub(/\s+/, '')
        raise DANE::ArgumentError, 'TLSA association data must be hexadecimal' unless hex.match?(/\A\h*\z/)

        [hex].pack('H*')
      end

      def build_chain(chain)
        raise DANE::ArgumentError, 'chain must be an Array' unless chain.is_a?(::Array)
        raise DANE::ArgumentError, 'chain must contain at least the leaf certificate' if chain.empty?

        chain.map { |entry| coerce_certificate(entry) }
      end

      def coerce_certificate(entry)
        case entry
        when OpenSSL::X509::Certificate
          entry
        when ::String
          begin
            OpenSSL::X509::Certificate.new(entry)
          rescue StandardError => e
            raise DANE::ArgumentError, "invalid certificate in chain: #{e.message}"
          end
        else
          raise DANE::ArgumentError,
                "chain entries must be OpenSSL::X509::Certificate or PEM/DER String, got #{entry.class}"
        end
      end

      def classify_records(records, expected_name, result)
        records.each do |record|
          reason = unusable_reason(record, expected_name)
          if reason
            result.add_unusable(record, reason)
          else
            result.add_usable(record)
          end
        end
      end

      def unusable_reason(record, expected_name)
        unless record.is_a?(Dnsruby::RR::IN::TLSA) || record.is_a?(UnusableAssociation)
          return 'not a TLSA record'
        end
        unless [PKIX_TA, PKIX_EE, DANE_TA, DANE_EE].include?(record.usage)
          return "unsupported certificate usage #{record.usage}"
        end
        unless [SELECTOR_CERT, SELECTOR_SPKI].include?(record.selector)
          return "unsupported selector #{record.selector}"
        end
        unless [MATCHING_FULL, MATCHING_SHA2_256, MATCHING_SHA2_512].include?(record.matching_type)
          return "unsupported matching type #{record.matching_type}"
        end
        if record.databin.nil? || record.databin.empty?
          return 'empty certificate association data'
        end
        if (record.matching_type == MATCHING_SHA2_256 && record.databin.bytesize != 32) ||
           (record.matching_type == MATCHING_SHA2_512 && record.databin.bytesize != 64)
          return "malformed digest length for matching type #{record.matching_type}"
        end
        if record.name && !record.name.to_s.empty? && !same_name?(record.name, expected_name)
          return "record owner #{record.name} does not match TLSA query name #{expected_name}"
        end

        nil
      end

      def same_name?(left, right)
        Dnsruby::Name.create(left.to_s).downcase == Dnsruby::Name.create(right.to_s).downcase
      rescue StandardError
        false
      end

      def evaluate(result, chain, service, trust)
        result.usable.each do |record|
          next unless record_matches_usage_position?(record, chain)
          next unless chain_checks_pass?(record, chain, service, trust, result)

          return result.succeed(record)
        end

        reason = result.failure_reason || 'no verified TLSA association matched the peer certificate chain'
        raise VerificationError.new(reason, result.fail(reason))
      end

      # DANE-EE(3) and PKIX-EE(1) match only the leaf certificate.  PKIX-TA
      # (0) matches a CA certificate in the path (RFC 6698 2.1.1: the
      # association is found among the certification paths, not the end
      # entity), while DANE-TA(2) may name any chain element as its anchor.
      def record_matches_usage_position?(record, chain)
        candidates = case record.usage
                     when PKIX_EE, DANE_EE then [chain.first]
                     when PKIX_TA then chain[1..]
                     else chain
                     end
        candidates.any? { |certificate| association_matches?(record, certificate) }
      end

      def association_matches?(record, certificate)
        selected = selected_content(record.selector, certificate)
        case record.matching_type
        when MATCHING_FULL
          secure_compare(selected, record.databin)
        when MATCHING_SHA2_256
          secure_compare(Digest::SHA256.digest(selected), record.databin)
        when MATCHING_SHA2_512
          secure_compare(Digest::SHA512.digest(selected), record.databin)
        else
          false
        end
      end

      def selected_content(selector, certificate)
        case selector
        when SELECTOR_CERT then certificate.to_der
        when SELECTOR_SPKI then certificate.public_key.to_der
        end
      end

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        OpenSSL.fixed_length_secure_compare(left, right)
      rescue StandardError
        left == right
      end

      def chain_checks_pass?(record, chain, service, trust, result)
        case record.usage
        when DANE_EE
          # RFC 7671 section 5.1: name checks, expiry and chain validation
          # are deliberately not applied for DANE-EE.
          true
        when PKIX_EE
          pkix_valid?(record, chain, service, trust, result, leaf_only: true)
        when PKIX_TA
          pkix_valid?(record, chain, service, trust, result, leaf_only: false)
        when DANE_TA
          dane_ta_valid?(record, chain, service, trust, result)
        else
          false
        end
      end

      # Usages 0 and 1 require a normal PKIX certification path against the
      # caller's trust store, plus the service name check (RFC 7671 5.3/5.4).
      # PKIX-TA additionally requires the matched certificate to be part of
      # the validated path.
      def pkix_valid?(record, chain, service, trust, result, leaf_only:)
        store = build_store(trust)
        store.time = trust.verify_time || Time.now
        unless store.verify(chain.first, chain[1..])
          result.record_failure("PKIX path validation failed: #{store.error_string}")
          return false
        end

        if trust.check_name && !hostname_matches?(chain.first, service)
          result.record_failure("leaf certificate does not match service name #{service}")
          return false
        end

        if leaf_only
          unless association_matches?(record, chain.first)
            result.record_failure('PKIX-EE association does not match the leaf certificate')
            return false
          end
        elsif chain.none? { |certificate| association_matches?(record, certificate) }
          result.record_failure('PKIX-TA association does not match any certificate in the validated path')
          return false
        end

        true
      end

      # Usage 2: the TLSA-matched chain element is the trust anchor.  Every
      # certificate from the leaf up to that anchor must be signed by its
      # issuer and within its validity period, without any reliance on the
      # caller's PKIX store (RFC 6698 2.1.1, RFC 7671 5.2).  Unlike
      # DANE-EE(3), expiry is enforced (RFC 7671 5.2 requires timely
      # certificate replacement with DANE-TA).  The anchor itself must be
      # present in the chain, as required for digest and SPKI associations.
      def dane_ta_valid?(record, chain, service, trust, result)
        anchor_index = chain.index { |certificate| association_matches?(record, certificate) }
        unless anchor_index
          result.record_failure('DANE-TA association does not match any certificate in the chain')
          return false
        end

        sub_chain = chain[0..anchor_index]
        unless path_signed_to_anchor?(sub_chain)
          result.record_failure('chain does not verify to the DANE-TA anchor')
          return false
        end

        verify_time = trust.verify_time || Time.now
        expired = sub_chain.find { |certificate| !within_validity?(certificate, verify_time) }
        if expired
          result.record_failure("certificate #{expired.subject} is not valid at the verification time")
          return false
        end

        if trust.check_name && !hostname_matches?(chain.first, service)
          result.record_failure("leaf certificate does not match service name #{service}")
          return false
        end

        true
      end

      def within_validity?(certificate, time)
        certificate.not_before <= time && time <= certificate.not_after
      end

      def path_signed_to_anchor?(sub_chain)
        sub_chain.each_cons(2).all? { |certificate, issuer| issued_by?(certificate, issuer) }
      end

      def issued_by?(certificate, issuer)
        certificate.issuer == issuer.subject && certificate.verify(issuer.public_key)
      rescue StandardError
        false
      end

      def build_store(trust)
        store = trust.trust_store || OpenSSL::X509::Store.new
        store.set_default_paths if trust.system_ca && trust.trust_store.nil?
        trust.trusted_certs.each { |certificate| store.add_cert(certificate) }
        store
      end

      def hostname_matches?(certificate, hostname)
        if OpenSSL::SSL.respond_to?(:verify_certificate_identity)
          OpenSSL::SSL.verify_certificate_identity(certificate, hostname)
        else
          OpenSSL::SSL.verify_hostname(hostname, certificate)
        end
      rescue StandardError
        false
      end
    end
  end
end

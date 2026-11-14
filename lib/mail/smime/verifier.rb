# encoding: utf-8
# frozen_string_literal: true

require 'openssl'
require 'mail/smime/mime_entity'
require 'mail/smime/result'

module Mail
  module SMIME
    # Verifies a detached S/MIME signature carried by multipart/signed.
    #
    # Callers supply the exact message octets and their trust configuration.
    # The verifier slices the received bytes itself and never routes the
    # entity through Mail::Message#encoded or any other normalising
    # serialiser. Outer headers (From, To, Subject, ...) are outside the
    # signature and are never reported as authenticated identity.
    class Verifier
      DIGEST_OIDS = {
        '1.2.840.113549.2.5' => 'MD5',
        '1.3.14.3.2.26' => 'SHA1',
        '2.16.840.1.101.3.4.2.4' => 'SHA224',
        '2.16.840.1.101.3.4.2.1' => 'SHA256',
        '2.16.840.1.101.3.4.2.2' => 'SHA384',
        '2.16.840.1.101.3.4.2.3' => 'SHA512'
      }.freeze

      # signature algorithm OID => [family, digest override]
      #
      # Absent attributes, a nil digest means the value from the SignerInfo
      # digestAlgorithm is authoritative. A non-nil value pins the digest the
      # signature OID implies and must agree with the SignerInfo.
      SIGNATURE_OIDS = {
        # rsaEncryption carries no digest; use the SignerInfo digest.
        '1.2.840.113549.1.1.1' => [:rsa, nil],
        '1.2.840.113549.1.1.4' => [:rsa, 'MD5'],
        '1.2.840.113549.1.1.5' => [:rsa, 'SHA1'],
        '1.2.840.113549.1.1.11' => [:rsa, 'SHA256'],
        '1.2.840.113549.1.1.12' => [:rsa, 'SHA384'],
        '1.2.840.113549.1.1.13' => [:rsa, 'SHA512'],
        '1.2.840.113549.1.1.14' => [:rsa, 'SHA224'],
        '1.2.840.113549.1.1.10' => [:pss, nil],
        '1.2.840.10045.4.1' => [:ec, 'SHA1'],
        '1.2.840.10045.4.3.2' => [:ec, 'SHA256'],
        '1.2.840.10045.4.3.3' => [:ec, 'SHA384'],
        '1.2.840.10045.4.3.4' => [:ec, 'SHA512'],
        '1.3.101.112' => [:ed25519, nil],
        '1.3.101.113' => [:ed448, nil],
        '2.16.840.1.101.3.4.3.2' => [:dsa, 'SHA256']
      }.freeze

      OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
      OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
      OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
      OID_ID_DATA = '1.2.840.113549.1.7.1'

      def initialize(trust: nil)
        @trust = trust
      end

      # raw_source is a String of the exact bytes as received, or any object
      # exposing those bytes through #raw_source. Returns a
      # Mail::SMIME::VerificationResult.
      def verify(raw_source)
        source = extract_raw_source(raw_source)
        entity = MimeEntity.new(source)
        signed_content = entity.signed_content
        signature_body = entity.signature_part_body

        if entity.part_count < 2
          return failure(:missing_signature, signed_content, entity, signature_body,
                         'multipart/signed has no separate signature part')
        end

        if entity.part_count > 2
          return failure(:unexpected_part_count, signed_content, entity, signature_body,
                         'multipart/signed must contain exactly two body parts')
        end

        unless entity.protocol_valid?
          return failure(:unsupported_protocol, signed_content, entity, signature_body,
                         "protocol is #{entity.protocol.inspect}, expected #{MimeEntity::DEFAULT_PROTOCOL}")
        end

        signature_type = entity.signature_part_content_type
        if signature_type && !signature_type.empty? &&
           !signature_type.match?(%r{\Aapplication/(?:x-)?pkcs7-signature\b}i)
          return failure(:invalid_signature_part, signed_content, entity, signature_body,
                         "signature part has Content-Type #{signature_type.inspect}")
        end

        der = decode_signature_body(signature_body)
        if der.nil?
          return failure(:invalid_signature_part, signed_content, entity, signature_body,
                         'signature part is not base64-encoded CMS data')
        end

        begin
          cms = OpenSSL::PKCS7.new(der)
        rescue OpenSSL::PKCS7::PKCS7Error, OpenSSL::ASN1::ASN1Error => e
          return failure(:invalid_cms, signed_content, entity, signature_body,
                         "cannot parse CMS SignedData: #{e.message}", error: e)
        end

        unless cms.type == :signed && cms.detached?
          return failure(:invalid_signature_part, signed_content, entity, signature_body,
                         'CMS object is not a detached SignedData signature')
        end

        signer_infos = parse_signer_infos(der)
        certificates = cms.certificates || []

        if signer_infos.empty? && !cms.signers.empty?
          return failure(:invalid_cms, signed_content, entity, signature_body,
                         'cannot read SignerInfo structures from the CMS object')
        end

        signers = signer_infos.map do |info|
          verify_signer(info, certificates, signed_content)
        end

        reason =
          if signers.empty?
            :no_signers
          elsif signers.none?(&:valid?)
            :no_trusted_signer
          end

        VerificationResult.new(
          signed_content: signed_content,
          signers: signers,
          reason: reason,
          protocol: entity.protocol,
          micalg: entity.micalg,
          signature_part_body: signature_body
        )
      rescue MimeEntity::ParseError => e
        failure(e.reason, ''.b, nil, nil, e.message, error: e)
      end

      private

      def extract_raw_source(value)
        return value unless value.respond_to?(:raw_source)

        value.raw_source
      end

      def failure(reason, signed_content, entity, signature_body, message, error: nil)
        VerificationResult.new(
          signed_content: signed_content,
          signers: [],
          reason: reason,
          protocol: entity&.protocol,
          micalg: entity&.micalg,
          signature_part_body: signature_body,
          error: error || StandardError.new(message)
        )
      end

      def decode_signature_body(body)
        text = body.to_s.dup.force_encoding(Encoding::BINARY)
        compact = text.gsub(/\s+/, '')
        return nil if compact.empty?
        return nil unless compact.match?(%r{\A[A-Za-z0-9+/]*={0,2}\z})

        der = compact.unpack1('m')
        return nil if der.empty?

        der.force_encoding(Encoding::BINARY)
      rescue ArgumentError
        nil
      end

      # OpenSSL::PKCS7 exposes only issuer/serial. Re-parse the DER to reach
      # the digest algorithm, signed attributes and signature value.
      def parse_signer_infos(der)
        sequence = OpenSSL::ASN1.decode(der)
        signed_data = sequence.value[1].value[0]
        signer_set = signed_data.value.last
        return [] unless signer_set.is_a?(OpenSSL::ASN1::Set)

        signer_set.value.map { |signer_info| parse_signer_info(signer_info) }
      rescue OpenSSL::ASN1::ASN1Error
        []
      end

      def parse_signer_info(signer_info)
        values = signer_info.value
        digest_identifier = values[2]

        index = 3
        attributes = nil
        if values[index] && values[index].tag_class == :CONTEXT_SPECIFIC && values[index].tag == 0
          attributes = values[index]
          index += 1
        end

        {
          sid: values[1],
          digest_oid: digest_identifier.value[0].oid,
          digest_algorithm: digest_for(digest_identifier.value[0].oid),
          signature_identifier: values[index],
          signature: values[index + 1] && values[index + 1].value,
          attributes: attributes
        }
      end

      def digest_for(oid)
        name = DIGEST_OIDS[oid]
        return nil unless name

        OpenSSL::Digest.new(name)
      rescue RuntimeError, OpenSSL::Digest::DigestError
        nil
      end

      def verify_signer(info, certificates, signed_content)
        certificate = find_certificate(info, certificates)
        signed_time = attribute_signed_time(info)
        common = {
          certificate: certificate,
          signed_time: signed_time,
          digest_algorithm: info && info[:digest_algorithm] && info[:digest_algorithm].name,
          signature_algorithm: info && info[:signature_identifier] &&
            info[:signature_identifier].value[0].oid
        }

        if certificate.nil?
          return SignerResult.new(
            status: :signer_not_found,
            reason: 'no certificate in the CMS object matches this signer',
            **common
          )
        end

        if info.nil? || info[:digest_algorithm].nil?
          return SignerResult.new(
            status: :unsupported,
            reason: 'unsupported or unreadable digest algorithm',
            **common
          )
        end

        family, signature_digest = signature_algorithm(info[:signature_identifier])
        unless family
          return SignerResult.new(
            status: :unsupported,
            reason: 'unsupported signature algorithm',
            **common
          )
        end

        if signature_digest && signature_digest != info[:digest_algorithm].name
          return SignerResult.new(
            status: :unsupported,
            reason: "signature algorithm digest #{signature_digest} does not match " \
                    "SignerInfo digest #{info[:digest_algorithm].name}",
            **common
          )
        end

        check = signature_verifies?(certificate, info, family, signature_digest, signed_content)
        unless check[:ok]
          return SignerResult.new(
            status: check[:status],
            reason: check[:reason],
            error: check[:error],
            **common
          )
        end

        trust = chain_valid?(certificate, certificates)
        if trust[:ok]
          SignerResult.new(status: :valid, reason: nil, **common)
        else
          SignerResult.new(
            status: :untrusted,
            reason: trust[:reason],
            error: trust[:error],
            **common
          )
        end
      end

      def attribute_signed_time(info)
        return nil unless info && info[:attributes]

        attribute = signed_attribute_value(info[:attributes], OID_SIGNING_TIME)
        attribute && attribute.value
      end

      def find_certificate(info, certificates)
        sid = info && info[:sid]

        if sid && sid.tag_class == :UNIVERSAL && sid.tag == 16
          issuer_name = sid.value[0]
          serial = sid.value[1].value
          certificates.find do |certificate|
            certificate.issuer.to_der == issuer_name.to_der && certificate.serial == serial
          end
        elsif sid && sid.tag_class == :CONTEXT_SPECIFIC && sid.tag == 0
          key_id = sid.value[0].value
          certificates.find do |certificate|
            extension = certificate.extensions.find { |e| e.oid == 'subjectKeyIdentifier' }
            extension && extension.value.to_s.delete(':').downcase == key_id.unpack1('H*')
          end
        end
      end

      def signature_algorithm(identifier)
        return [nil, nil] unless identifier && identifier.value[0]

        SIGNATURE_OIDS[identifier.value[0].oid]
      end

      def signature_verifies?(certificate, info, family, signature_digest, signed_content)
        signature = info[:signature]
        return { ok: false, status: :invalid, reason: 'signer has no signature value' } if signature.nil?

        digest = info[:digest_algorithm]
        signed_attributes = info[:attributes]

        if signed_attributes
          content_type = signed_attribute_value(signed_attributes, OID_CONTENT_TYPE)
          if content_type && content_type.oid != OID_ID_DATA
            return { ok: false, status: :invalid,
                     reason: 'content-type attribute is not id-data' }
          end

          message_digest = signed_attribute_value(signed_attributes, OID_MESSAGE_DIGEST)
          if message_digest.nil?
            return { ok: false, status: :invalid, reason: 'signed attributes lack messageDigest' }
          end
          if message_digest.value != digest.digest(signed_content)
            return { ok: false, status: :digest_mismatch,
                     reason: 'messageDigest does not match the signed content' }
          end
        end

        data = signed_attributes ? signed_attributes_der(signed_attributes) : signed_content

        begin
          verified =
            case family
            when :rsa, :ec, :dsa
              certificate.public_key.verify(digest, signature, data)
            when :pss
              pss_verify(certificate, info[:signature_identifier], digest, signature, data)
            when :ed25519, :ed448
              certificate.public_key.verify(nil, signature, data)
            end
        rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::ECError, OpenSSL::PKey::DSAError => e
          return { ok: false, status: :invalid, reason: 'signature verification raised', error: e }
        end

        if verified
          { ok: true }
        else
          { ok: false, status: :invalid, reason: 'signature does not verify' }
        end
      end

      def signed_attribute_value(attributes, oid)
        attribute = attributes.value.find do |candidate|
          candidate.tag_class == :UNIVERSAL && candidate.tag == 16 &&
            candidate.value[0].oid == oid
        end
        return nil unless attribute

        values = attribute.value[1]
        values && values.value[0]
      end

      # OpenSSL exposes signed attributes as [0] IMPLICIT. The signature
      # covers the DER encoding of a UNIVERSAL SET OF Attribute, so re-tag
      # the already-decoded structure without touching the raw octets.
      def signed_attributes_der(attributes)
        copy = attributes.dup
        copy.tag_class = :UNIVERSAL
        copy.tag = OpenSSL::ASN1::SET
        copy.to_der
      end

      def pss_verify(certificate, identifier, digest, signature, data)
        params = identifier.value[1]
        hash_name = digest.name
        salt_length = :auto
        mgf1_hash = hash_name

        if params && params.value.is_a?(Array)
          hash_algorithm = params.value[0]
          if hash_algorithm.is_a?(OpenSSL::ASN1::Sequence)
            hash_name = DIGEST_OIDS[hash_algorithm.value[0].oid] || hash_name
          end
          mask_algorithm = params.value[1]
          if mask_algorithm.is_a?(OpenSSL::ASN1::Sequence)
            mgf_digest = mask_algorithm.value[0]
            mgf_hash = DIGEST_OIDS[mgf_digest.oid] || mgf1_hash
          end
          salt = params.value[2]
          salt_length = salt.value.to_i if salt.is_a?(OpenSSL::ASN1::Integer)
        end

        certificate.public_key.verify_pss(
          hash_name, signature, data,
          salt_length: salt_length, mgf1_hash: mgf_hash
        )
      rescue ArgumentError
        false
      end

      # Verify the signer certificate against the caller's trust store, using
      # the certificates carried in the CMS object as untrusted intermediates.
      def chain_valid?(certificate, certificates)
        store = build_store
        untrusted = certificates.reject { |candidate| candidate.to_der == certificate.to_der }

        # Store#verify returns false on failure in current Ruby/OpenSSL
        # versions and raises in others; handle both.
        return { ok: true } if store.verify(certificate, untrusted)

        reason = store.error_string
        reason = "certificate chain does not verify (#{reason})" if reason && !reason.empty?
        { ok: false, reason: reason || 'certificate chain does not verify' }
      rescue OpenSSL::X509::StoreError => e
        { ok: false, reason: "certificate chain does not verify: #{e.message}", error: e }
      end

      # Accepts:
      #   * an OpenSSL::X509::Store (used directly)
      #   * an Array of certificates or PEM strings (trust anchors)
      #   * a Hash with :certificates, :certificate_files,
      #     :certificate_directories, :default_paths, :crls, :flags,
      #     :time and :purpose
      def build_store
        return @trust if @trust.is_a?(OpenSSL::X509::Store)

        options =
          case @trust
          when Hash then @trust
          when Array then { certificates: @trust }
          when nil then {}
          else
            if @trust.respond_to?(:to_pem) || @trust.is_a?(String)
              { certificates: [@trust] }
            else
              raise ArgumentError, "unsupported trust configuration: #{@trust.class}"
            end
          end

        store = OpenSSL::X509::Store.new

        Array(options[:certificates]).each do |certificate|
          store.add_cert(to_certificate(certificate))
        end

        Array(options[:certificate_files]).each { |path| store.add_file(path.to_s) }
        Array(options[:certificate_directories]).each { |path| store.add_path(path.to_s) }

        store.set_default_paths if options[:default_paths]

        Array(options[:crls]).each { |crl| store.add_crl(to_crl(crl)) }

        store.flags = options[:flags] if options[:flags]
        store.time = options[:time] if options[:time]
        store.purpose = options[:purpose] if options[:purpose]
        store
      end

      def to_certificate(value)
        return value if value.is_a?(OpenSSL::X509::Certificate)

        text = value.to_s
        if !text.include?('-----BEGIN') && File.file?(text)
          return OpenSSL::X509::Certificate.new(File.binread(text))
        end

        OpenSSL::X509::Certificate.new(text)
      end

      def to_crl(value)
        return value if value.is_a?(OpenSSL::X509::CRL)

        OpenSSL::X509::CRL.new(value.to_s)
      end
    end
  end
end

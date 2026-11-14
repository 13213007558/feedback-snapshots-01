# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'openssl'
require 'tmpdir'

RSpec.describe Mail::SMIME do
  # Build a small local PKI. Nothing here touches the network.
  def build_ca(name = 'Mail SMIME Test CA')
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = OpenSSL::BN.new(rand(1 << 32).to_s)
    cert.subject = OpenSSL::X509::Name.new([['CN', name]])
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 3600
    cert.not_after = Time.now + 86_400
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign,digitalSignature', true))
    cert.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash'))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    [key, cert]
  end

  def build_leaf(ca_key, ca_cert, email, name = 'Alice', not_before: Time.now - 3600,
                 not_after: Time.now + 86_400, serial: nil)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial || OpenSSL::BN.new(rand(1 << 32).to_s)
    cert.subject = OpenSSL::X509::Name.new([['CN', name], ['emailAddress', email]])
    cert.issuer = ca_cert.subject
    cert.public_key = key.public_key
    cert.not_before = not_before
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = ca_cert
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
    cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature,keyEncipherment', true))
    cert.add_extension(factory.create_extension('extendedKeyUsage', 'emailProtection'))
    cert.add_extension(factory.create_extension('subjectAltName', "email:#{email}"))
    cert.add_extension(factory.create_extension('subjectKeyIdentifier', 'hash'))
    cert.add_extension(factory.create_extension('authorityKeyIdentifier', 'keyid:always', false))
    cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
    [key, cert]
  end

  # Returns the exact octets an S/MIME sender would put on the wire for a
  # detached signature over +entity+. The signature covers +entity+ verbatim.
  def signed_message(entity, key, cert, extra_parts: [], boundary: 'smime-boundary-1',
                     protocol: 'application/pkcs7-signature', outer_headers: nil, micalg: 'sha-256',
                     sign_data: nil, signature_body: nil)
    pkcs7 = OpenSSL::PKCS7.sign(cert, key, sign_data || entity, [], OpenSSL::PKCS7::DETACHED)
    # PKCS7.sign hashes the exact bytes given to it; the helper never asks
    # Mail to re-encode the entity.
    signature = signature_body || base64_body(pkcs7.to_der)

    headers = Array(outer_headers).dup
    headers << 'MIME-Version: 1.0'
    headers << %(Content-Type: multipart/signed; protocol="#{protocol}"; micalg=#{micalg}; boundary="#{boundary}")

    body = "#{headers.join("\r\n")}\r\n\r\n"
    body << "This is an S/MIME signed message\r\n\r\n"
    body << "--#{boundary}\r\n"
    body << entity
    extra_parts.each do |part|
      body << "\r\n--#{boundary}\r\n"
      body << part
    end
    body << "\r\n--#{boundary}\r\n"
    body << "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n"
    body << "Content-Transfer-Encoding: base64\r\n"
    body << "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n\r\n"
    body << signature
    body << "\r\n--#{boundary}--\r\n"
    body.b
  end

  def base64_body(der)
    [der].pack('m0').scan(/.{1,64}/).join("\r\n")
  end

  # OpenSSL::PKCS7.sign in this Ruby always uses SHA-256, so build a
  # detached SignedData object by hand when a test needs another digest.
  def build_detached_cms(data, key, cert, digest_name: 'SHA512')
    digest_oid = {
      'SHA1' => '1.3.14.3.2.26',
      'SHA256' => '2.16.840.1.101.3.4.2.1',
      'SHA512' => '2.16.840.1.101.3.4.2.3'
    }.fetch(digest_name)

    digest = OpenSSL::Digest.new(digest_name)
    attributes = OpenSSL::ASN1::Set.new([
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.9.3'),
        OpenSSL::ASN1::Set.new([OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.7.1')])
      ]),
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.9.4'),
        OpenSSL::ASN1::Set.new([OpenSSL::ASN1::OctetString.new(digest.digest(data))])
      ])
    ])
    signature = key.sign(digest, attributes.to_der)

    signer_info = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(1),
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1.decode(cert.issuer.to_der),
        OpenSSL::ASN1::Integer.new(cert.serial)
      ]),
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(digest_oid)]),
      OpenSSL::ASN1::ASN1Data.new(attributes.value, 0, :CONTEXT_SPECIFIC),
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.1.1')]),
      OpenSSL::ASN1::OctetString.new(signature)
    ])

    signed_data = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(1),
      OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(digest_oid)])]),
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.7.1')]),
      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1.decode(cert.to_der)], 0, :CONTEXT_SPECIFIC),
      OpenSSL::ASN1::Set.new([signer_info])
    ])

    OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.7.2'),
      OpenSSL::ASN1::ASN1Data.new([signed_data], 0, :CONTEXT_SPECIFIC)
    ]).to_der
  end

  # Merge independently produced CMS SignedData objects so the fixture has
  # two genuine SignerInfos (this Ruby's PKCS7#add_signer writes an empty
  # signature value).
  def merge_signatures(pkcs7_objects)
    signer_infos = []
    certificates = []
    base = nil

    pkcs7_objects.each do |pkcs7|
      content_info = OpenSSL::ASN1.decode(pkcs7.to_der)
      signed_data = content_info.value[1].value[0]
      base ||= content_info
      signed_data.value.each do |node|
        if node.tag_class == :CONTEXT_SPECIFIC && node.tag == 0
          certificates.concat(node.value)
        elsif node.tag_class == :UNIVERSAL && node.tag == 17 &&
              node.value.first.is_a?(OpenSSL::ASN1::Sequence) &&
              node.value.first.value[0].is_a?(OpenSSL::ASN1::Integer)
          signer_infos.concat(node.value)
        end
      end
    end

    signed_data = base.value[1].value[0]
    signed_data.value = signed_data.value.map do |node|
      if node.tag_class == :CONTEXT_SPECIFIC && node.tag == 0
        OpenSSL::ASN1::ASN1Data.new(certificates, 0, :CONTEXT_SPECIFIC)
      elsif node.tag_class == :UNIVERSAL && node.tag == 17 &&
            node.value.first.is_a?(OpenSSL::ASN1::Sequence) &&
            node.value.first.value[0].is_a?(OpenSSL::ASN1::Integer)
        OpenSSL::ASN1::Set.new(signer_infos)
      else
        node
      end
    end

    base.to_der
  end

  def entity(body = "Hello signed world!\r\n", content_type: 'text/plain; charset=us-ascii')
    "Content-Type: #{content_type}\r\nContent-Transfer-Encoding: 7bit\r\n\r\n#{body}".b
  end

  def parse_signature_part(message)
    # Extract the DER from the second part for the tamper tests.
    match = message.match(/Content-Transfer-Encoding: base64\r\n\r\n(.*?)\r\n--/m)
    match[1].gsub(/\s+/, '').unpack1('m')
  end

  before(:all) do
    @ca_key, @ca_cert = build_ca
    @leaf_key, @leaf_cert = build_leaf(@ca_key, @ca_cert, 'alice@example.com', 'Alice')
    @other_ca_key, @other_ca_cert = build_ca('Unrelated CA')
    @other_leaf_key, @other_leaf_cert = build_leaf(@other_ca_key, @other_ca_cert, 'mallory@example.com', 'Mallory')
  end

  let(:trust) { { certificates: [@ca_cert] } }

  describe 'a well-formed multipart/signed message' do
    it 'returns the exact received entity bytes and a valid signer' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      mail = Mail::Message.new(raw)

      result = mail.verify_smime(trust: trust)

      expect(result).to be_valid
      expect(result.reason).to be_nil
      expect(result.protocol).to eq 'application/pkcs7-signature'
      expect(result.micalg).to eq 'sha-256'
      expect(result.signed_content).to eq entity
      expect(result.signed_content.encoding).to eq Encoding::BINARY
      expect(result.signers.size).to eq 1
      expect(result.signers.first).to be_valid
      expect(result.signers.first.email_addresses).to eq ['alice@example.com']
      expect(result.signer_email_addresses).to eq ['alice@example.com']
    end

    it 'verifies the same bytes that were signed, not Mail re-encoded output' do
      # Deliberately unusual but legal bytes: folded header, extra whitespace,
      # two trailing CRLFs in the body. Re-encoding would normalise these.
      unusual = "Content-Type: text/plain;\r\n charset=us-ascii\r\nX-Kept:  spaced\r\n\r\nLine one  \r\n\r\n".b
      raw = signed_message(unusual, @leaf_key, @leaf_cert)

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result).to be_valid
      expect(result.signed_content).to eq unusual
      expect(result.signed_content).not_to eq Mail::Message.new(raw).parts.first.encoded
    end

    it 'reports every signer independently' do
      raw_entity = entity("Two signers\r\n")
      first = OpenSSL::PKCS7.sign(@leaf_cert, @leaf_key, raw_entity, [], OpenSSL::PKCS7::DETACHED)
      second = OpenSSL::PKCS7.sign(@other_leaf_cert, @other_leaf_key, raw_entity, [], OpenSSL::PKCS7::DETACHED)

      raw = signed_message(raw_entity, @leaf_key, @leaf_cert,
                           signature_body: base64_body(merge_signatures([first, second])))

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result.signers.size).to eq 2
      expect(result.signers.map(&:email_addresses)).to contain_exactly(
        ['alice@example.com'], ['mallory@example.com']
      )
      expect(result.signers.map(&:status)).to contain_exactly(:valid, :untrusted)
      expect(result).not_to be_valid
      expect(result.any_trusted_signer?).to be true
      expect(result.signer_email_addresses).to eq ['alice@example.com']
    end

    it 'can be verified directly through Mail::SMIME.verify' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      result = Mail::SMIME.verify(raw, trust: trust)
      expect(result).to be_valid
      expect(result.signed_content).to eq entity
    end

    it 'detects multipart/signed messages' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      expect(Mail::Message.new(raw)).to be_smime_signed
      expect(Mail::Message.new("Content-Type: text/plain\r\n\r\nhi")).not_to be_smime_signed
    end

    it 'verifies a nested multipart/signed part from the part bytes' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      outer = "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
              "--outer\r\n" + raw + "\r\n--outer--\r\n"
      mail = Mail::Message.new(outer)
      signed_part = mail.parts.first

      expect(signed_part).to be_smime_signed
      expect(signed_part.verify_smime(trust: trust)).to be_valid
    end

    it 'accepts the legacy application/x-pkcs7-signature alias' do
      raw = signed_message(entity, @leaf_key, @leaf_cert,
                           protocol: 'application/x-pkcs7-signature')
      expect(Mail::Message.new(raw).verify_smime(trust: trust)).to be_valid
    end
  end

  describe 'content tampering' do
    it 'fails when the signed body is changed' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      tampered = raw.sub('Hello signed world!', 'Hello attacked world!')
      expect(tampered).not_to eq raw

      result = Mail::Message.new(tampered).verify_smime(trust: trust)

      expect(result).not_to be_valid
      expect(result.signed_content).to eq "Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHello attacked world!\r\n"
      expect(result.signers.first.status).to eq :digest_mismatch
      expect(result.reason).to eq :no_trusted_signer
    end

    it 'fails when the content is re-encoded with different line endings' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      tampered = raw.gsub("\r\n", "\n")

      result = Mail::Message.new(tampered).verify_smime(trust: trust)

      expect(result).not_to be_valid
      expect(result.signers.first.status).to eq :digest_mismatch
    end
  end

  describe 'unprotected outer headers' do
    it 'does not treat a changed outer From as authenticated identity' do
      raw = signed_message(entity("Signed body\r\n"), @leaf_key, @leaf_cert,
                           outer_headers: ['From: alice@example.com', 'Subject: signed'])
      changed = raw.sub('From: alice@example.com', 'From: attacker@evil.example')

      result = Mail::Message.new(changed).verify_smime(trust: trust)

      expect(result).to be_valid, 'the signed entity is untouched, so its signature stays valid'
      expect(result.signed_content).not_to include('From:')
      expect(result.signer_email_addresses).to eq ['alice@example.com']
      expect(Mail::Message.new(changed).from.to_s).to include('attacker@evil.example')
    end

    it 'keeps a valid signature when only outer Subject/From change' do
      raw = signed_message(entity("Body\r\n"), @leaf_key, @leaf_cert,
                           outer_headers: ['From: alice@example.com', 'Subject: original'])
      changed = raw.sub('Subject: original', 'Subject: invoice attached')
                 .sub('From: alice@example.com', 'From: billing@evil.example')

      result = Mail::Message.new(changed).verify_smime(trust: trust)

      expect(result).to be_valid
      expect(result.signer_email_addresses).to eq ['alice@example.com']
      expect(changed).not_to include('Subject: original')
    end

    it 'cannot be used to claim the outer From when no signature is present' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      unsigned = raw.sub(/--smime-boundary-1\r\nContent-Type: application\/pkcs7-signature.*\z/m, '')
      result = Mail::Message.new(unsigned).verify_smime(trust: trust)
      expect(result).not_to be_valid
      expect(result.reason).to eq :missing_signature
      expect(result.signer_email_addresses).to eq []
    end
  end

  describe 'extra parts and malformed layout' do
    it 'rejects an additional unsigned part inserted before the signature' do
      injected = "Content-Type: text/plain\r\n\r\nInjected unsigned content".b
      raw = signed_message(entity, @leaf_key, @leaf_cert, extra_parts: [injected])

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result).not_to be_valid
      expect(result.reason).to eq :unexpected_part_count
      expect(result.signers).to be_empty
      expect(result.signed_content).to eq entity
    end

    it 'rejects a multipart/signed with only the signature part' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      signature_only = "--smime-boundary-1\r\n" + raw.split("--smime-boundary-1\r\n", 2).last
      # Rebuild with a single part by dropping the signed entity.
      single = "MIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: application/pkcs7-signature\r\n\r\nZm9v\r\n--b1--\r\n".b
      result = Mail::Message.new(single).verify_smime(trust: trust)
      expect(result).not_to be_valid
      expect(result.reason).to eq :missing_signature
    end
  end

  describe 'protocol and structure mismatches' do
    it 'distinguishes an unsupported protocol parameter from a bad signature' do
      raw = signed_message(entity, @leaf_key, @leaf_cert, protocol: 'application/pgp-signature')

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result).not_to be_valid
      expect(result.reason).to eq :unsupported_protocol
      expect(result.signed_content).to eq entity
    end

    it 'rejects a message that is not multipart/signed' do
      result = Mail::SMIME.verify("Content-Type: text/plain\r\n\r\nhello".b, trust: trust)
      expect(result).not_to be_valid
      expect(result.reason).to eq :not_multipart_signed
    end

    it 'rejects a multipart/signed without a boundary parameter' do
      raw = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"\r\n\r\nbody".b
      result = Mail::SMIME.verify(raw, trust: trust)
      expect(result).not_to be_valid
      expect(result.reason).to eq :missing_boundary
    end

    it 'rejects a signature part that is not base64 CMS data' do
      broken = signed_message(entity, @leaf_key, @leaf_cert, signature_body: 'not-base64!!!')

      result = Mail::Message.new(broken).verify_smime(trust: trust)

      expect(result).not_to be_valid
      expect(result.reason).to eq :invalid_signature_part
    end
  end

  describe 'a message produced by the OpenSSL smime command' do
    let(:raw) { read_raw_fixture('emails', 'smime', 'openssl_signed.eml') }
    let(:certificate) { OpenSSL::X509::Certificate.new(read_raw_fixture('emails', 'smime', 'openssl_signer.pem')) }

    it 'verifies its legacy x-pkcs7 protocol and mixed LF/CRLF framing' do
      result = Mail::SMIME.verify(raw, trust: [certificate])

      expect(result).to be_valid
      expect(result.protocol).to eq 'application/x-pkcs7-signature'
      expect(result.signed_content).to eq(
        "Content-Type: text/plain; charset=us-ascii\r\n\r\nHello signed world!\r\n".b
      )
      expect(result.signer_email_addresses).to eq ['alice@example.com']
    end

    it 'fails when the fixture body is altered' do
      tampered = raw.sub('Hello signed world!', 'Hello altered world!')
      result = Mail::SMIME.verify(tampered, trust: [certificate])

      expect(result).not_to be_valid
      expect(result.signers.first.status).to eq :digest_mismatch
    end

    it 'leaves the signature valid when only the unprotected outer From is prepended' do
      changed = raw.sub("MIME-Version: 1.0", "From: mallory@evil.example\r\nMIME-Version: 1.0")
      result = Mail::SMIME.verify(changed, trust: [certificate])

      expect(result).to be_valid
      expect(result.signed_content).not_to include('From:')
      expect(result.signer_email_addresses).to eq ['alice@example.com']
    end
  end

  describe 'signature algorithms and digest checks' do
    it 'verifies a SHA-512 signature' do
      data = entity("SHA-512 body\r\n")
      der = build_detached_cms(data, @leaf_key, @leaf_cert, digest_name: 'SHA512')
      raw = signed_message(data, @leaf_key, @leaf_cert, signature_body: base64_body(der))

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result).to be_valid
      expect(result.signers.first.digest_algorithm).to eq 'SHA512'
    end

    it 'rejects data that differs from the messageDigest signed attribute' do
      data = entity("Original body\r\n")
      pkcs7 = OpenSSL::PKCS7.sign(@leaf_cert, @leaf_key, data, [], OpenSSL::PKCS7::DETACHED)
      # Sign the original bytes but place different bytes in the message.
      raw = signed_message(entity("Replaced body\r\n"), @leaf_key, @leaf_cert,
                           signature_body: base64_body(pkcs7.to_der))

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result).not_to be_valid
      expect(result.signers.first.status).to eq :digest_mismatch
      expect(result.reason).to eq :no_trusted_signer
    end

    it 'distinguishes an expired signer certificate' do
      key, cert = build_leaf(@ca_key, @ca_cert, 'expired@example.com', 'Expired',
                             not_before: Time.now - 7200, not_after: Time.now - 3600)
      raw = signed_message(entity, key, cert)

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result.signers.first.status).to eq :untrusted
      expect(result.signers.first.reason).to include('certificate chain')
      expect(result.structure_valid?).to be true
    end

    it 'distinguishes a signer whose certificate is absent from the CMS object' do
      data = entity
      pkcs7 = OpenSSL::PKCS7.sign(@leaf_cert, @leaf_key, data, [], OpenSSL::PKCS7::DETACHED)
      # Strip the certificates [0] element from the SignedData while keeping
      # the signer and signature intact.
      content_info = OpenSSL::ASN1.decode(pkcs7.to_der)
      signed_data = content_info.value[1].value[0]
      signed_data.value.reject! { |node| node.tag_class == :CONTEXT_SPECIFIC && node.tag == 0 }
      raw = signed_message(data, @leaf_key, @leaf_cert,
                           signature_body: base64_body(content_info.to_der))

      result = Mail::Message.new(raw).verify_smime(trust: trust)

      expect(result).not_to be_valid
      expect(result.signers.first.status).to eq :signer_not_found
      expect(result.structure_valid?).to be true
    end
  end

  describe 'certificate trust' do
    it 'reports an untrusted signer separately from a bad signature' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)

      result = Mail::Message.new(raw).verify_smime(trust: { certificates: [@other_ca_cert] })

      expect(result).not_to be_valid
      expect(result.reason).to eq :no_trusted_signer
      expect(result.structure_valid?).to be true
      expect(result.signers.size).to eq 1
      expect(result.signers.first.status).to eq :untrusted
      expect(result.signers.first.reason).to include('certificate chain')
      expect(result.signers.first.email_addresses).to eq ['alice@example.com']
      expect(result.signer_email_addresses).to eq []
    end

    it 'does not accept a signature made by the wrong leaf under a trusted CA' do
      raw = signed_message(entity, @other_leaf_key, @other_leaf_cert)
      result = Mail::Message.new(raw).verify_smime(trust: trust)
      expect(result.signers.first.status).to eq :untrusted
      expect(result).not_to be_valid
    end

    it 'reports untrusted when no trust anchors are supplied' do
      raw = signed_message(entity, @leaf_key, @leaf_cert)
      result = Mail::Message.new(raw).verify_smime(trust: {})
      expect(result.signers.first.status).to eq :untrusted
      expect(result).not_to be_valid
    end

    it 'loads trust anchors from a PEM file' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'ca.pem')
        File.write(path, @ca_cert.to_pem)
        raw = signed_message(entity, @leaf_key, @leaf_cert)
        result = Mail::Message.new(raw).verify_smime(trust: { certificate_files: [path] })
        expect(result).to be_valid
      end
    end
  end
end

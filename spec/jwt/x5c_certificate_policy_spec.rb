# frozen_string_literal: true

RSpec.describe 'x5c certificate policy' do
  # A server-provided root, an intermediate and a leaf that is allowed to sign
  # client credentials (login tokens). All timestamps are relative to +now+.
  let(:now) { Time.at(Time.now.to_i) }
  let(:root_key) { generate_key }
  let(:intermediate_key) { generate_key }
  let(:leaf_key) { generate_key }
  let(:attacker_key) { generate_key }

  let(:root_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake Root CA') }
  let(:intermediate_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake-ca/CN=Fake Intermediate CA') }
  let(:leaf_dn) { OpenSSL::X509::Name.parse('/DC=org/DC=fake/CN=Login Credential Signer') }

  let(:root_certificate) do
    certificate(root_dn, root_key, 1, ca: true, not_before: now - 7200, not_after: now + 7200)
  end
  let(:intermediate_certificate) do
    certificate(
      intermediate_dn,
      intermediate_key,
      2,
      issuer: root_certificate,
      issuer_key: root_key,
      ca: true,
      not_before: now - 7200,
      not_after: now + 7200
    )
  end
  let(:leaf_certificate) do
    certificate(
      leaf_dn,
      leaf_key.public_key,
      3,
      issuer: intermediate_certificate,
      issuer_key: intermediate_key,
      eku: 'clientAuth',
      not_before: now - 7200,
      not_after: now + 3600
    )
  end

  let(:intermediate_crl) do
    issue_crl(issuer: intermediate_certificate, issuer_key: intermediate_key, last_update: now - 7200, next_update: now + 7200)
  end
  let(:root_crl) do
    issue_crl(issuer: root_certificate, issuer_key: root_key, last_update: now - 7200, next_update: now + 7200)
  end
  let(:crls) { [intermediate_crl, root_crl] }
  let(:x5c_header) { [encode_certificate(leaf_certificate), encode_certificate(intermediate_certificate)] }

  subject(:key_finder) { JWT::X5cKeyFinder.new([root_certificate], crls) }

  describe 'trusted chain with acceptable purpose and current evidence' do
    it 'returns the leaf public key' do
      key = key_finder.from(x5c_header, purpose: :client_auth, at_time: now)

      expect(key).to be_a(OpenSSL::PKey::RSA)
      expect(key.to_der).to eq(leaf_certificate.public_key.to_der)
      expect(key.to_der).not_to eq(intermediate_certificate.public_key.to_der)
    end

    it 'returns the leaf public key when the chain is passed as parsed certificates' do
      key = key_finder.from([leaf_certificate, intermediate_certificate], purpose: :client_auth, at_time: now)

      expect(key.to_der).to eq(leaf_certificate.public_key.to_der)
    end
  end

  describe 'trusted chain with a non-matching purpose' do
    it 'rejects the certificate even though the chain itself is valid' do
      expect do
        key_finder.from(x5c_header, purpose: :server_auth, at_time: now)
      end.to raise_error(JWT::CertificatePurposeError) do |error|
        expect(error.reason).to eq(:unsuitable_certificate_purpose)
        expect(error.openssl_error).to eq(OpenSSL::X509::V_ERR_INVALID_PURPOSE)
        expect(error.current_certificate.subject.to_s).to eq(leaf_dn.to_s)
        expect(error.message).to include('unsuitable certificate purpose')
      end
    end

    it 'keeps the default purpose permissive when the caller does not ask for one' do
      key = key_finder.from(x5c_header, at_time: now)

      expect(key.to_der).to eq(leaf_certificate.public_key.to_der)
    end
  end

  describe 'revocation evidence' do
    it 'accepts valid evidence that does not list the certificate' do
      key = key_finder.from(x5c_header, purpose: :client_auth, at_time: now)

      expect(key.to_der).to eq(leaf_certificate.public_key.to_der)
    end

    it 'rejects a certificate listed as revoked' do
      crl = issue_crl(
        revoked: [[leaf_certificate.serial, now - 60]],
        issuer: intermediate_certificate,
        issuer_key: intermediate_key,
        last_update: now - 7200,
        next_update: now + 7200
      )
      finder = JWT::X5cKeyFinder.new([root_certificate], [crl, root_crl])

      expect do
        finder.from(x5c_header, purpose: :client_auth, at_time: now)
      end.to raise_error(JWT::CertificateRevokedError) { |error| expect(error.reason).to eq(:certificate_revoked) }
    end

    it 'does not treat missing evidence as a pass' do
      finder = JWT::X5cKeyFinder.new([root_certificate], nil)

      expect do
        finder.from(x5c_header, purpose: :client_auth, at_time: now)
      end.to raise_error(JWT::CertificateRevocationDataMissingError) do |error|
        expect(error.reason).to eq(:revocation_data_missing)
      end
    end

    it 'rejects evidence that has expired at the requested verification time' do
      expired_crl = issue_crl(
        issuer: intermediate_certificate,
        issuer_key: intermediate_key,
        last_update: now - 7200,
        next_update: now - 60
      )
      finder = JWT::X5cKeyFinder.new([root_certificate], [expired_crl, root_crl])

      expect do
        finder.from(x5c_header, purpose: :client_auth, at_time: now)
      end.to raise_error(JWT::CertificateRevocationDataExpiredError) do |error|
        expect(error.reason).to eq(:revocation_data_expired)
        expect(error.openssl_error).to eq(OpenSSL::X509::V_ERR_CRL_HAS_EXPIRED)
      end
    end

    it 'rejects evidence that is not yet valid at the requested verification time' do
      future_crl = issue_crl(
        issuer: intermediate_certificate,
        issuer_key: intermediate_key,
        last_update: now + 60,
        next_update: now + 7200
      )
      finder = JWT::X5cKeyFinder.new([root_certificate], [future_crl, root_crl])

      expect do
        finder.from(x5c_header, purpose: :client_auth, at_time: now)
      end.to raise_error(JWT::CertificateRevocationDataExpiredError) do |error|
        expect(error.reason).to eq(:revocation_data_not_yet_valid)
      end
    end

    it 'only skips revocation checks when the caller explicitly opts out' do
      finder = JWT::X5cKeyFinder.new([root_certificate], nil)

      key = finder.from(x5c_header, purpose: :client_auth, at_time: now, revocation: :none)

      expect(key.to_der).to eq(leaf_certificate.public_key.to_der)
    end

    it 'distinguishes an expired CRL from a revoked certificate' do
      expired_crl = issue_crl(
        issuer: intermediate_certificate,
        issuer_key: intermediate_key,
        last_update: now - 7200,
        next_update: now - 60
      )
      finder = JWT::X5cKeyFinder.new([root_certificate], [expired_crl, root_crl])

      error = nil
      begin
        finder.from(x5c_header, purpose: :client_auth, at_time: now)
      rescue JWT::CertificateVerificationError => e
        error = e
      end

      expect(error).to be_a(JWT::CertificateRevocationDataExpiredError)
      expect(error).not_to be_a(JWT::CertificateRevokedError)
      expect(error.reason).to eq(:revocation_data_expired)
    end
  end

  describe 'chain of trust' do
    it 'rejects a chain that does not end at a server-provided root' do
      other_root_key = generate_key
      other_root = certificate(OpenSSL::X509::Name.parse('/DC=org/DC=other/CN=Other Root'), other_root_key, 9, ca: true)
      finder = JWT::X5cKeyFinder.new([other_root], crls)

      expect do
        finder.from(x5c_header, purpose: :client_auth, at_time: now)
      end.to raise_error(JWT::CertificateChainError) do |error|
        expect(error.reason).to eq(:untrusted_chain)
      end
    end

    it 'does not promote a root shipped in the x5c header to a trust anchor' do
      rogue_root_key = generate_key
      rogue_intermediate_key = generate_key
      rogue_leaf_key = generate_key
      rogue_root = certificate(
        OpenSSL::X509::Name.parse('/DC=org/DC=evil/CN=Rogue Root'),
        rogue_root_key,
        10,
        ca: true,
        not_before: now - 7200,
        not_after: now + 7200
      )
      rogue_intermediate = certificate(
        OpenSSL::X509::Name.parse('/DC=org/DC=evil/CN=Rogue Intermediate'),
        rogue_intermediate_key,
        11,
        issuer: rogue_root,
        issuer_key: rogue_root_key,
        ca: true,
        not_before: now - 7200,
        not_after: now + 7200
      )
      rogue_leaf = certificate(
        OpenSSL::X509::Name.parse('/DC=org/DC=evil/CN=Rogue Leaf'),
        rogue_leaf_key.public_key,
        12,
        issuer: rogue_intermediate,
        issuer_key: rogue_intermediate_key,
        eku: 'clientAuth',
        not_before: now - 7200,
        not_after: now + 7200
      )
      rogue_header = [rogue_leaf, rogue_intermediate, rogue_root].map { |certificate| encode_certificate(certificate) }
      finder = JWT::X5cKeyFinder.new([root_certificate], crls)

      expect do
        finder.from(rogue_header, purpose: :client_auth, at_time: now)
      end.to raise_error(JWT::CertificateChainError) do |error|
        expect(error.reason).to eq(:untrusted_chain)
      end
    end

    it 'rejects an expired certificate at the requested verification time' do
      later = now + 5400

      expect do
        key_finder.from(x5c_header, purpose: :client_auth, at_time: later)
      end.to raise_error(JWT::CertificateTimeError) do |error|
        expect(error.reason).to eq(:certificate_expired)
      end
    end
  end

  describe 'policy isolation' do
    it 'does not let per-call CRLs leak into the shared store' do
      finder = JWT::X5cKeyFinder.new([root_certificate], nil)

      with_crls = Array.new(8) do
        Thread.new do
          finder.from(x5c_header, purpose: :client_auth, at_time: now, crls: crls).to_der
        end
      end
      without_crls = Array.new(8) do
        Thread.new do
          finder.from(x5c_header, purpose: :client_auth, at_time: now)
        rescue JWT::CertificateRevocationDataMissingError => e
          e.reason
        end
      end

      expect(with_crls.map(&:value)).to all(eq(leaf_certificate.public_key.to_der))
      expect(without_crls.map(&:value)).to all(eq(:revocation_data_missing))
    end

    it 'keeps time and purpose decisions independent across concurrent calls' do
      finder = JWT::X5cKeyFinder.new([root_certificate], crls)
      cases = [
        ['client-now', { purpose: :client_auth, at_time: now }, :ok],
        ['server-now', { purpose: :server_auth, at_time: now }, :unsuitable_certificate_purpose],
        ['client-later', { purpose: :client_auth, at_time: now + 5400 }, :certificate_expired],
        ['client-earlier', { purpose: :client_auth, at_time: now - 3600 }, :ok]
      ]

      results = Array.new(40) do |index|
        Thread.new do
          label, options, _expected = cases[index % cases.size]
          begin
            finder.from(x5c_header, **options)
            [label, :ok]
          rescue JWT::CertificateVerificationError => e
            [label, e.reason]
          end
        end
      end.map(&:value)

      expected = cases.to_h { |label, _options, reason| [label, reason] }
      expect(results.group_by(&:first).transform_values { |entries| entries.map(&:last).uniq }).to eq(
        expected.transform_values { |reason| [reason] }
      )
    end
  end

  describe 'JWT signature verification' do
    let(:payload) { { 'sub' => 'user-123', 'scope' => 'login' } }
    let(:x5c_parameter) do
      {
        root_certificates: [root_certificate],
        crls: crls,
        purpose: :client_auth,
        at_time: now
      }
    end

    def encode_token(signing_key)
      JWT.encode(payload, signing_key, 'RS256', 'x5c' => x5c_header)
    end

    it 'uses the selected leaf public key to verify the token signature' do
      decoded, header = JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: x5c_parameter)

      expect(decoded).to eq(payload)
      expect(header['x5c']).to eq(x5c_header)
    end

    it 'fails signature verification when the token was signed by another key' do
      expect do
        JWT.decode(encode_token(attacker_key), nil, true, algorithms: ['RS256'], x5c: x5c_parameter)
      end.to raise_error(JWT::VerificationError) do |error|
        expect(error).not_to be_a(JWT::CertificateVerificationError)
        expect(error.message).to eq('Signature verification failed')
      end
    end

    it 'rejects a correctly signed token when the certificate purpose does not match' do
      parameter = x5c_parameter.merge(purpose: :server_auth)

      expect do
        JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)
      end.to raise_error(JWT::CertificatePurposeError)
    end

    it "rejects a correctly signed token when the revocation evidence has expired" do
      expired_crl = issue_crl(
        issuer: intermediate_certificate,
        issuer_key: intermediate_key,
        last_update: now - 7200,
        next_update: now - 60
      )
      parameter = x5c_parameter.merge(crls: [expired_crl, root_crl])

      expect do
        JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)
      end.to raise_error(JWT::CertificateRevocationDataExpiredError)
    end

    it 'rejects a correctly signed token when revocation evidence is missing' do
      parameter = x5c_parameter.reject { |key, _| key == :crls }

      expect do
        JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)
      end.to raise_error(JWT::CertificateRevocationDataMissingError)
    end

    it 'rejects a correctly signed token when the certificate is revoked' do
      crl = issue_crl(
        revoked: [[leaf_certificate.serial, now - 60]],
        issuer: intermediate_certificate,
        issuer_key: intermediate_key,
        last_update: now - 7200,
        next_update: now + 7200
      )
      parameter = x5c_parameter.merge(crls: [crl, root_crl])

      expect do
        JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)
      end.to raise_error(JWT::CertificateRevokedError)
    end

    it 'evaluates certificate and CRL time windows at the requested at_time' do
      later = now + 5400
      valid_later_crl = issue_crl(
        issuer: intermediate_certificate,
        issuer_key: intermediate_key,
        last_update: later - 3600,
        next_update: later + 3600
      )
      later_root_crl = issue_crl(
        issuer: root_certificate,
        issuer_key: root_key,
        last_update: later - 3600,
        next_update: later + 3600
      )
      parameter = x5c_parameter.merge(at_time: later, crls: [valid_later_crl, later_root_crl])

      expect do
        JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)
      end.to raise_error(JWT::CertificateTimeError)

      parameter = x5c_parameter.merge(at_time: now)
      decoded, = JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)
      expect(decoded).to eq(payload)
    end

    it 'accepts a caller-provided verification time as an epoch value' do
      parameter = x5c_parameter.merge(at_time: now.to_i)

      decoded, = JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)

      expect(decoded).to eq(payload)
    end

    it 'accepts string option names in the x5c parameter' do
      parameter = {
        'root_certificates' => [root_certificate],
        'crls' => crls,
        'purpose' => 'client_auth',
        'at_time' => now
      }

      decoded, = JWT.decode(encode_token(leaf_key), nil, true, algorithms: ['RS256'], x5c: parameter)

      expect(decoded).to eq(payload)
    end
  end

  describe 'option validation' do
    it 'rejects an unknown purpose' do
      expect do
        key_finder.from(x5c_header, purpose: :email_signer)
      end.to raise_error(ArgumentError, /Unknown certificate purpose/)
    end

    it 'rejects an unknown revocation policy' do
      expect do
        key_finder.from(x5c_header, revocation: :maybe)
      end.to raise_error(ArgumentError, /Unknown revocation policy/)
    end

    it 'rejects unknown policy keys instead of silently ignoring them' do
      expect do
        key_finder.from(x5c_header, purpse: :client_auth)
      end.to raise_error(ArgumentError, /Unknown x5c policy option/)
    end
  end

  private

  def generate_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def encode_certificate(certificate)
    Base64.strict_encode64(certificate.to_der)
  end

  def certificate(subject, key, serial, issuer: nil, issuer_key: nil, ca: false, eku: nil, not_before: Time.now - 7200, not_after: Time.now + 7200)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = subject
    cert.issuer = (issuer || cert).subject
    cert.public_key = key
    cert.not_before = not_before
    cert.not_after = not_after

    extension_factory = OpenSSL::X509::ExtensionFactory.new
    extension_factory.subject_certificate = cert
    extension_factory.issuer_certificate = issuer || cert

    if ca
      cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:TRUE', true))
      cert.add_extension(extension_factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    else
      cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:FALSE', true))
      cert.add_extension(extension_factory.create_extension('keyUsage', 'digitalSignature', true))
      cert.add_extension(extension_factory.create_extension('extendedKeyUsage', eku, false)) if eku
    end

    cert.sign(issuer_key || key, 'sha256')
    cert
  end

  def issue_crl(issuer:, issuer_key:, last_update:, next_update:, revoked: [])
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = last_update
    crl.next_update = next_update

    revoked.each do |serial, time|
      entry = OpenSSL::X509::Revoked.new
      entry.serial = serial
      entry.time = time
      crl.add_revoked(entry)
    end

    crl.add_extension(OpenSSL::X509::Extension.new('crlNumber', OpenSSL::ASN1::Integer(1)))
    crl.sign(issuer_key, 'sha256')
    crl
  end
end

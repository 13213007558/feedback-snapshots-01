# frozen_string_literal: true

RSpec.describe JWT::Token do
  let(:payload) { { 'pay' => 'load' } }
  let(:header) { {} }

  subject(:token) { described_class.new(payload: payload, header: header) }

  describe '#sign!' do
    it 'signs the token' do
      token.sign!(algorithm: 'HS256', key: 'secret')

      expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'HS256', key: 'secret')).to be(true)
    end

    context 'when the header was inspected for auditing before it was completed' do
      let(:payload) { { 'sub' => 'audit-subject' } }
      let(:header) { { 'kid' => 'audit-key' } }

      it 'signs exactly the header that is reported after signing' do
        audited_header = token.encoded_header

        token.header['typ'] = 'JWT'
        token.sign!(algorithm: 'HS256', key: 'secret')

        verifier = JWT::EncodedToken.new(token.jwt)
        verifier.verify!(signature: { algorithm: 'HS256', key: 'secret' })

        expect(audited_header).not_to eq(token.encoded_header)
        expect(verifier.header).to eq('kid' => 'audit-key', 'typ' => 'JWT', 'alg' => 'HS256')
        expect(verifier.header).to eq(token.header)
        expect(verifier.payload).to eq(token.payload)
        expect(verifier.signing_input).to eq(token.signing_input)
        expect(token.jwt.split('.').first).to eq(token.encoded_header)
        expect(JWT.decode(token.jwt, 'secret', true, algorithm: 'HS256'))
          .to eq([token.payload, token.header])
      end
    end

    context 'when a nested payload value is changed after it was encoded' do
      let(:payload) { { 'nested' => { 'role' => 'reader' } } }

      it 'signs the current nested value instead of the earlier encoding' do
        earlier_payload = token.encoded_payload
        earlier_signing_input = token.signing_input

        token.payload['nested']['role'] = 'admin'
        token.sign!(algorithm: 'HS256', key: 'secret')

        verifier = JWT::EncodedToken.new(token.jwt)
        verifier.verify!(signature: { algorithm: 'HS256', key: 'secret' })

        expect(token.encoded_payload).not_to eq(earlier_payload)
        expect(token.signing_input).not_to eq(earlier_signing_input)
        expect(verifier.payload).to eq('nested' => { 'role' => 'admin' })
        expect(verifier.payload).to eq(token.payload)
      end
    end

    context 'when the signing input was read before signing' do
      it 'does not sign the earlier snapshot after the header changes' do
        earlier_signing_input = token.signing_input

        token.header['kid'] = 'added-after-reading'
        token.sign!(algorithm: 'HS256', key: 'secret')

        verifier = JWT::EncodedToken.new(token.jwt)
        verifier.verify!(signature: { algorithm: 'HS256', key: 'secret' })

        expect(token.signing_input).not_to eq(earlier_signing_input)
        expect(token.signing_input).to eq(verifier.signing_input)
        expect(verifier.header).to eq('kid' => 'added-after-reading', 'alg' => 'HS256')
      end
    end

    context 'when signing fails before the signature is produced' do
      it 'leaves the token editable so corrected parameters can be retried' do
        original_header = token.encoded_header

        expect { token.sign!(algorithm: 'ES256', key: 'secret') }
          .to raise_error(JWT::EncodeError, /It has to be an OpenSSL::PKey::EC instance/)

        expect(token.signed?).to be(false)
        expect(token.encoded_header).to eq(original_header)
        expect(token.header).to eq({})
        expect(token.signature).to be_nil
        expect { token.jwt }.to raise_error(JWT::EncodeError, 'Token is not signed')

        token.sign!(algorithm: 'HS256', key: 'secret')

        verifier = JWT::EncodedToken.new(token.jwt)
        verifier.verify!(signature: { algorithm: 'HS256', key: 'secret' })

        expect(token.header).to eq('alg' => 'HS256')
        expect(verifier.header).to eq('alg' => 'HS256')
        expect(JWT.decode(token.jwt, 'secret', true, algorithm: 'HS256')).to eq([payload, { 'alg' => 'HS256' }])
      end
    end

    context 'when signing fails because the key is rejected' do
      before { JWT.configuration.decode.enforce_hmac_key_length = true }

      after { JWT.configuration.reset! }

      it 'does not poison a retry with the same algorithm and a corrected key' do
        token.header['kid'] = 'hmac-key'

        expect { token.sign!(algorithm: 'HS256', key: 'short') }
          .to raise_error(JWT::EncodeError, 'HMAC key must be at least 32 bytes for HS256 algorithm')

        expect(token.signed?).to be(false)
        expect(token.header).to eq('kid' => 'hmac-key')

        token.sign!(algorithm: 'HS256', key: 'a-sufficiently-long-hmac-secret-1234')

        verifier = JWT::EncodedToken.new(token.jwt)
        verifier.verify!(signature: { algorithm: 'HS256', key: 'a-sufficiently-long-hmac-secret-1234' })

        expect(verifier.header).to eq('kid' => 'hmac-key', 'alg' => 'HS256')
        expect(verifier.payload).to eq(payload)
      end
    end

    context 'when signed twice' do
      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
      end

      it 'raises' do
        expect { token.sign!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::EncodeError)
      end
    end

    context 'when RSA JWK is given as key' do
      let(:jwk) { JWT::JWK::RSA.new(OpenSSL::PKey::RSA.new(2048), alg: 'RS256') }

      it 'signs the token' do
        token.sign!(key: jwk, algorithm: []) # any algorithm is fine here

        expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'RS256', key: jwk.verify_key)).to be(true)
      end

      context 'with algorithm provided in sign call' do
        it 'signs the token' do
          token.sign!(algorithm: %w[RS256 RS512], key: jwk)

          expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: 'RS256', key: jwk.verify_key)).to be(true)
        end
      end

      context 'with mismatching algorithm provided in sign call' do
        it 'signs the token' do
          expect { token.sign!(algorithm: %w[RS384 RS512], key: jwk) }.to raise_error(JWT::EncodeError, 'Provided JWKs do not support one of the specified algorithms: RS384, RS512')
        end
      end
    end

    context 'when string key is given but not algorithm' do
      it 'raises an error' do
        expect { token.sign!(key: 'secret') }.to raise_error(ArgumentError, /missing keyword/)
      end
    end
  end

  context 'when EC JWK is given as key' do
    let(:jwk) { JWT::JWK::EC.new(test_pkey('ec384-private.pem')) }

    it 'signs the token' do
      token.sign!(key: jwk, algorithm: [])

      expect(JWT::EncodedToken.new(token.jwt).valid_signature?(algorithm: [], key: jwk)).to be(true)
    end
  end

  describe '#jwt' do
    context 'when token is signed' do
      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
      end

      it 'returns a signed and encoded token' do
        expect(token.jwt).to eq('eyJhbGciOiJIUzI1NiJ9.eyJwYXkiOiJsb2FkIn0.UEhDY1Qlj29ammxuVRA_-gBah4qTy5FngIWg0yEAlC0')
        expect(JWT.decode(token.jwt, 'secret', true, algorithm: 'HS256')).to eq([{ 'pay' => 'load' }, { 'alg' => 'HS256' }])
      end
    end

    context 'when token is not signed' do
      it 'returns a signed and encoded token' do
        expect { token.jwt }.to raise_error(JWT::EncodeError)
      end
    end

    context 'when alg is given in header' do
      let(:header) { { 'alg' => 'HS123' } }

      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
      end

      it 'returns a signed and encoded token' do
        expect(JWT::EncodedToken.new(token.jwt).header).to eq({ 'alg' => 'HS123' })
      end
    end

    context 'when the payload or header is edited after signing' do
      let(:original_payload) { { 'nested' => { 'role' => 'reader' } } }
      let(:payload) { original_payload }
      let(:header) { { 'kid' => 'signed-key' } }

      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
      end

      it 'freezes the signed snapshot and keeps the rendered token unchanged' do
        jwt = token.jwt

        expect { token.header['typ'] = 'JWT' }.to raise_error(FrozenError)
        expect { token.payload['nested']['role'] = 'admin' }.to raise_error(FrozenError)
        expect(token.jwt).to eq(jwt)
        expect(token.header).to eq('kid' => 'signed-key', 'alg' => 'HS256')
        expect(token.payload).to eq('nested' => { 'role' => 'reader' })
      end

      it 'does not freeze or mutate the hash given by the caller' do
        original_payload['nested']['role'] = 'admin'
        original_payload['added'] = true

        expect(token.payload).to eq('nested' => { 'role' => 'reader' })
        expect(JWT::EncodedToken.new(token.jwt).unverified_payload).to eq('nested' => { 'role' => 'reader' })
      end
    end
  end

  describe '#detach_payload!' do
    context 'before token is signed' do
      it 'detaches the payload' do
        token.detach_payload!
        token.sign!(algorithm: 'HS256', key: 'secret')
        expect(token.jwt).to eq('eyJhbGciOiJIUzI1NiJ9..UEhDY1Qlj29ammxuVRA_-gBah4qTy5FngIWg0yEAlC0')
      end

      it 'does not change the signing input' do
        signing_input = token.signing_input
        token.detach_payload!

        expect(token.signing_input).to eq(signing_input)
        expect(token.encoded_payload).to eq('eyJwYXkiOiJsb2FkIn0')
      end
    end

    context 'after the token has been rendered' do
      before do
        token.sign!(algorithm: 'HS256', key: 'secret')
        token.jwt
      end

      it 'detaches the payload' do
        token.detach_payload!
        expect(token.jwt).to eq('eyJhbGciOiJIUzI1NiJ9..UEhDY1Qlj29ammxuVRA_-gBah4qTy5FngIWg0yEAlC0')
      end

      it 'detaches the payload from #to_s' do
        token.detach_payload!
        expect(token.to_s).to eq('eyJhbGciOiJIUzI1NiJ9..UEhDY1Qlj29ammxuVRA_-gBah4qTy5FngIWg0yEAlC0')
      end

      it 'keeps the encoded payload available' do
        token.detach_payload!
        expect(token.encoded_payload).to eq('eyJwYXkiOiJsb2FkIn0')
      end

      it 'keeps the signature and signing input unchanged' do
        signature = token.signature
        signing_input = token.signing_input

        token.detach_payload!

        expect(token.signature).to eq(signature)
        expect(token.signing_input).to eq(signing_input)
        expect(token.detached?).to be(true)
      end

      it 'can be detached again without changing the result' do
        token.detach_payload!
        jwt = token.jwt
        token.detach_payload!

        expect(token.jwt).to eq(jwt)
      end
    end
  end

  describe '#verify_claims!' do
    context 'when required_claims is passed' do
      it 'raises error' do
        expect { token.verify_claims!(required: ['exp']) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
      end
    end
  end

  describe '#valid_claims?' do
    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      context 'when claim is valid' do
        it 'returns true' do
          expect(token.valid_claims?(exp: { leeway: 1000 })).to be(true)
        end
      end

      context 'when claim is invalid' do
        it 'returns true' do
          expect(token.valid_claims?(:exp)).to be(false)
        end
      end
    end
  end

  describe '#claim_errors' do
    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      context 'when claim is valid' do
        it 'returns empty array' do
          expect(token.claim_errors(exp: { leeway: 1000 })).to be_empty
        end
      end

      context 'when claim is invalid' do
        it 'returns array with error objects' do
          expect(token.claim_errors(:exp).map(&:message)).to eq(['Signature has expired'])
        end
      end
    end
  end
end

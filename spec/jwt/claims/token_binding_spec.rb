# frozen_string_literal: true

RSpec.describe JWT::Claims::TokenBinding do
  let(:access_token) { 'raw-access-token' }
  let(:authorization_code) { 'raw-authorization-code' }
  let(:required) { %i[at_hash c_hash] }
  let(:options) { { access_token: access_token, code: authorization_code, required: required } }

  # Local samples signed with different algorithms and different digests.
  samples = [
    { algorithm: 'HS256', key_fixture: :hmac, digest: 'SHA256', cross_digest: 'SHA512' },
    { algorithm: 'RS256', key_fixture: 'rsa-2048-private.pem', digest: 'SHA256', cross_digest: 'SHA384' },
    { algorithm: 'ES384', key_fixture: 'ec384-private.pem', digest: 'SHA384', cross_digest: 'SHA256' },
    { algorithm: 'PS512', key_fixture: 'rsa-2048-private.pem', digest: 'SHA512', cross_digest: 'SHA256' }
  ]

  def sample_key(key_fixture)
    return 'h' * 64 if key_fixture == :hmac

    test_pkey(key_fixture)
  end

  def half_hash(value, digest)
    full_digest = OpenSSL::Digest.new(digest).digest(value)
    JWT::Base64.url_encode(full_digest.byteslice(0, full_digest.bytesize / 2))
  end

  def signed_sample(algorithm:, key:, digest:, access_token:, code:, header: {})
    payload = {
      'at_hash' => half_hash(access_token, digest),
      'c_hash' => half_hash(code, digest)
    }
    token = JWT::Token.new(payload: payload, header: header).tap do |unsigned|
      unsigned.sign!(algorithm: algorithm, key: key)
    end
    [token.jwt, payload]
  end

  def verify_binding(jwt, key, algorithm, binding_options = options)
    token = JWT::EncodedToken.new(jwt)
    token.verify_signature!(algorithm: algorithm, key: key)
    token.verify_claims!(token_binding: binding_options)
    token
  end

  describe '#verify!' do
    samples.each do |sample|
      context "when the token is signed with #{sample[:algorithm]}" do
        let(:key) { sample_key(sample[:key_fixture]) }
        let(:jwt) { signed_sample(algorithm: sample[:algorithm], key: key, digest: sample[:digest], access_token: access_token, code: authorization_code).first }

        it 'passes when both bindings match' do
          token = verify_binding(jwt, key, sample[:algorithm])
          expect(token.payload['at_hash']).to eq(half_hash(access_token, sample[:digest]))
        end

        it 'fails when the bindings were derived with another algorithm' do
          cross_jwt = signed_sample(algorithm: sample[:algorithm], key: key, digest: sample[:cross_digest], access_token: access_token, code: authorization_code).first

          expect do
            verify_binding(cross_jwt, key, sample[:algorithm])
          end.to raise_error(JWT::InvalidTokenBindingError, 'Invalid at_hash token binding')
        end

        it 'fails when the access token and code values are swapped' do
          swapped_jwt = signed_sample(algorithm: sample[:algorithm], key: key, digest: sample[:digest], access_token: authorization_code, code: access_token).first

          expect do
            verify_binding(swapped_jwt, key, sample[:algorithm])
          end.to raise_error(JWT::InvalidTokenBindingError)
        end
      end
    end

    context 'when only one binding kind is required' do
      let(:jwt) { signed_sample(algorithm: 'HS256', key: 'h' * 64, digest: 'SHA256', access_token: access_token, code: authorization_code).first }
      let(:required) { %i[at_hash] }

      it 'ignores a claim that was not requested' do
        tampered = JWT::Token.new(payload: { 'at_hash' => half_hash(access_token, 'SHA256'), 'c_hash' => 'not-checked' })
                                .tap { |token| token.sign!(algorithm: 'HS256', key: 'h' * 64) }

        expect { verify_binding(tampered.jwt, 'h' * 64, 'HS256') }.not_to raise_error
      end
    end

    context 'when the claim is missing' do
      it 'raises instead of skipping the check' do
        payload = { 'c_hash' => half_hash(authorization_code, 'SHA256') }
        jwt = JWT::Token.new(payload: payload).tap { |token| token.sign!(algorithm: 'HS256', key: 'h' * 64) }.jwt

        expect do
          verify_binding(jwt, 'h' * 64, 'HS256')
        end.to raise_error(JWT::InvalidTokenBindingError, 'Missing at_hash claim in the token')
      end
    end

    context 'when the claim is malformed' do
      ['', 123, ['value'], { 'value' => true }].each do |malformed|
        it "raises for #{malformed.inspect}" do
          payload = { 'at_hash' => malformed, 'c_hash' => half_hash(authorization_code, 'SHA256') }
          jwt = JWT::Token.new(payload: payload).tap { |token| token.sign!(algorithm: 'HS256', key: 'h' * 64) }.jwt

          expect { verify_binding(jwt, 'h' * 64, 'HS256') }.to raise_error(JWT::InvalidTokenBindingError)
        end
      end
    end

    context 'when the payload is not an object' do
      it 'raises instead of skipping the check' do
        jwt = JWT::Token.new(payload: 'not-a-hash').tap { |token| token.sign!(algorithm: 'HS256', key: 'h' * 64) }.jwt

        expect { verify_binding(jwt, 'h' * 64, 'HS256') }.to raise_error(JWT::InvalidTokenBindingError, 'Cannot verify at_hash without a payload object')
      end
    end

    context 'when the algorithm that verified the signature has no binding hash' do
      let(:custom_algorithm) do
        Class.new do
          include JWT::JWA::SigningAlgorithm

          def initialize
            @alg = 'CUSTOM'
          end

          def sign(*)
            'signature'
          end

          def verify(*)
            true
          end
        end.new
      end

      it 'raises an unsupported algorithm error' do
        jwt = JWT::Token.new(payload: { 'at_hash' => 'value' }).tap { |token| token.sign!(algorithm: custom_algorithm, key: 'secret') }.jwt
        token = JWT::EncodedToken.new(jwt)
        token.verify_signature!(algorithm: custom_algorithm, key: 'secret')

        expect do
          token.verify_claims!(token_binding: options)
        end.to raise_error(JWT::UnsupportedTokenBindingAlgorithmError, 'No token binding hash mapping for signing algorithm CUSTOM')
      end

      it 'raises for the none algorithm' do
        jwt = JWT.encode({ 'at_hash' => 'value' }, nil, 'none')

        expect do
          JWT.decode(jwt, nil, true, algorithm: 'none', token_binding: options)
        end.to raise_error(JWT::UnsupportedTokenBindingAlgorithmError, 'No token binding hash mapping for signing algorithm none')
      end
    end

    context 'when the alg header disagrees with the verified algorithm' do
      let(:jwt) do
        signed_sample(algorithm: 'HS384', key: 'h' * 64, digest: 'SHA384', access_token: access_token, code: authorization_code, header: { 'alg' => 'HS256' }).first
      end

      it 'derives the digest from the verified algorithm' do
        token = JWT::EncodedToken.new(jwt)
        expect(token.header['alg']).to eq('HS256')

        token.verify_signature!(algorithm: %w[HS256 HS384], key: 'h' * 64)
        expect(token.verified_jwa.alg).to eq('HS384')
        expect { token.verify_claims!(token_binding: options) }.not_to raise_error
      end

      it 'does not accept a digest computed from the alg header' do
        header_derived = signed_sample(algorithm: 'HS384', key: 'h' * 64, digest: 'SHA256', access_token: access_token, code: authorization_code, header: { 'alg' => 'HS256' }).first

        expect do
          verify_binding(header_derived, 'h' * 64, %w[HS256 HS384])
        end.to raise_error(JWT::InvalidTokenBindingError)
      end
    end

    context 'without a successful signature verification' do
      let(:jwt) { signed_sample(algorithm: 'HS256', key: 'h' * 64, digest: 'SHA256', access_token: access_token, code: authorization_code).first }

      it 'cannot conclude the binding before the signature is checked' do
        expect do
          JWT::EncodedToken.new(jwt).verify_claims!(token_binding: options)
        end.to raise_error(JWT::InvalidTokenBindingError, 'Token bindings can only be verified after a successful signature verification')
      end

      it 'cannot conclude the binding after a failed signature check' do
        token = JWT::EncodedToken.new(jwt)

        expect { token.verify_signature!(algorithm: 'HS256', key: 'wrong-key') }.to raise_error(JWT::VerificationError)
        expect(token.verified_jwa).to be_nil
        expect { token.verify_claims!(token_binding: options) }.to raise_error(JWT::InvalidTokenBindingError, 'Token bindings can only be verified after a successful signature verification')
      end

      it 'cannot conclude the binding after a later failed signature check' do
        token = JWT::EncodedToken.new(jwt)
        token.verify_signature!(algorithm: 'HS256', key: 'h' * 64)
        expect(token.verified_jwa).not_to be_nil

        expect(token.valid_signature?(algorithm: 'RS256', key: test_pkey('rsa-2048-private.pem'))).to be(false)
        expect { token.verify_claims!(token_binding: options) }.to raise_error(JWT::InvalidTokenBindingError)
      end
    end
  end

  describe 'byte semantics' do
    let(:encoded_access_token) { 'a%2Bb%2Fc%3D' }

    it 'does not URL decode the supplied raw value' do
      jwt = signed_sample(algorithm: 'HS256', key: 'h' * 64, digest: 'SHA256', access_token: encoded_access_token, code: authorization_code).first

      expect do
        verify_binding(jwt, 'h' * 64, 'HS256', options.merge(access_token: 'a+b/c='))
      end.to raise_error(JWT::InvalidTokenBindingError)
    end

    it 'hashes the exact bytes of non-ASCII values' do
      raw_value = 'tökén'
      jwt = signed_sample(algorithm: 'HS256', key: 'h' * 64, digest: 'SHA256', access_token: raw_value, code: authorization_code).first
      token = verify_binding(jwt, 'h' * 64, 'HS256', options.merge(access_token: raw_value))

      expect(token.payload['at_hash']).to eq(half_hash(raw_value, 'SHA256'))
    end
  end

  describe 'caller supplied values' do
    let(:jwt) { signed_sample(algorithm: 'HS256', key: 'h' * 64, digest: 'SHA256', access_token: access_token, code: authorization_code).first }
    let(:token) { JWT::EncodedToken.new(jwt).tap { |encoded| encoded.verify_signature!(algorithm: 'HS256', key: 'h' * 64) } }

    def binding_errors(binding_options)
      token.verify_claims!(token_binding: binding_options)
    rescue JWT::InvalidTokenBindingError => e
      e
    end

    it 'requires the required kinds to be given explicitly' do
      expect(binding_errors({ access_token: access_token, code: authorization_code })).to have_attributes(message: 'The required token binding kinds must be given explicitly')
    end

    it 'requires at least one kind' do
      expect(binding_errors(options.merge(required: []))).to have_attributes(message: 'At least one token binding kind is required')
    end

    it 'rejects unsupported kinds' do
      expect(binding_errors(options.merge(required: %i[nonce]))).to have_attributes(message: 'Unsupported token binding kind(s): nonce')
    end

    it 'rejects unknown options' do
      expect(binding_errors(options.merge(access_tokn: access_token))).to have_attributes(message: 'Unknown token binding option(s): access_tokn')
    end

    it 'rejects non-symbolisable option names' do
      expect(binding_errors(options.merge(1 => access_token))).to have_attributes(message: 'Unknown token binding option(s): 1')
    end

    it 'rejects an option given under both a string and a symbol key' do
      expect(binding_errors(options.merge('access_token' => access_token))).to have_attributes(message: 'Duplicate token binding option: access_token')
    end

    it 'requires the raw value for every required kind' do
      expect(binding_errors(options.merge(access_token: nil))).to have_attributes(message: 'Missing raw access_token value for at_hash token binding')
      expect(binding_errors(options.reject { |key, _| key == :code })).to have_attributes(message: 'Missing raw code value for c_hash token binding')
    end

    [123, ['value'], { 'value' => true }, ''].each do |invalid|
      it "rejects #{invalid.inspect} as a raw value" do
        expect(binding_errors(options.merge(access_token: invalid))).to be_a(JWT::InvalidTokenBindingError)
      end
    end

    it 'rejects options that are not a Hash' do
      expect { token.verify_claims!(token_binding: 'access-token') }.to raise_error(JWT::InvalidTokenBindingError, 'Token binding options must be a Hash')
    end
  end

  describe 'claims API without a verified signature' do
    it 'rejects binding from the payload only API' do
      expect do
        JWT::Claims.verify_payload!({ 'at_hash' => 'value' }, token_binding: options)
      end.to raise_error(JWT::InvalidTokenBindingError, 'Token bindings can only be verified after a successful signature verification')
    end

    it 'reports the problem through the payload predicate API' do
      errors = JWT::Claims.payload_errors({ 'at_hash' => 'value' }, token_binding: options)

      expect(errors.map(&:message)).to eq(['Token bindings can only be verified after a successful signature verification'])
    end
  end
end

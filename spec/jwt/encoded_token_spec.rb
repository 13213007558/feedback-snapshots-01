# frozen_string_literal: true

RSpec.describe JWT::EncodedToken do
  let(:payload) { { 'pay' => 'load' } }
  let(:header) { {} }
  let(:encoded_token) { JWT::Token.new(payload: payload, header: header).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.jwt }
  let(:detached_payload_token) do
    JWT::Token.new(payload: payload).tap do |t|
      t.detach_payload!
      t.sign!(algorithm: 'HS256', key: 'secret')
    end
  end

  subject(:token) { described_class.new(encoded_token) }

  describe '#unverified_payload' do
    it { expect(token.unverified_payload).to eq(payload) }

    context 'when payload is detached' do
      let(:encoded_token) { detached_payload_token.jwt }

      context 'when payload provided in separate' do
        before { token.encoded_payload = detached_payload_token.encoded_payload }
        it { expect(token.unverified_payload).to eq(payload) }
      end

      context 'when payload is not provided' do
        it 'raises decode error' do
          expect { token.unverified_payload }.to raise_error(JWT::MalformedTokenError, 'Encoded payload is empty')
        end
      end
    end

    context 'when payload is not encoded and the b64 crit is enabled' do
      subject(:token) { described_class.new(encoded_token) }
      let(:encoded_token) { 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature' }
      before { token.encoded_payload = '{"foo": "bar"}' }

      it 'handles the payload encoding' do
        expect(token.unverified_payload).to eq({ 'foo' => 'bar' })
      end
    end

    context 'when token is the empty string' do
      let(:encoded_token) { '' }

      it 'raises decode error' do
        expect { token.unverified_payload }.to raise_error(JWT::MalformedTokenError, 'Invalid segment encoding')
      end
    end
  end

  describe '#payload' do
    context 'when token is verified using #valid?' do
      before do
        token.valid?(signature: { algorithm: 'HS256', key: 'secret' })
      end

      it { expect(token.payload).to eq(payload) }
    end

    context 'when token is verified using #verify_signature! and #verify_claims!' do
      before do
        token.verify_signature!(algorithm: 'HS256', key: 'secret')
        token.verify_claims!
      end

      it { expect(token.payload).to eq(payload) }
    end

    context 'when token is checked using #valid_signature? and #valid_claims?' do
      before do
        token.valid_signature?(algorithm: 'HS256', key: 'secret')
        token.valid_claims?
      end

      it { expect(token.payload).to eq(payload) }
    end

    context 'when token is verified using #verify_signature!' do
      before { token.verify_signature!(algorithm: 'HS256', key: 'secret') }

      it 'raises an error' do
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token claims before accessing the payload')
      end
    end

    context 'when token is verified using #valid_signature? but is not valid' do
      before { token.valid_signature?(algorithm: 'HS256', key: 'wrong') }

      it 'raises an error' do
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')
      end
    end

    context 'when token is not verified' do
      it 'raises an error' do
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')
      end
    end
  end

  describe '#encoded_payload=' do
    let(:other_payload) { { 'other' => 'payload' } }
    let(:other_encoded_payload) do
      JWT::Token.new(payload: other_payload).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.encoded_payload
    end

    context 'when token has been verified' do
      before { token.verify!(signature: { algorithm: 'HS256', key: 'secret' }) }

      it 'requires the token to be verified again' do
        token.encoded_payload = other_encoded_payload

        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token signature before accessing the payload')
      end

      it 'discards the previously decoded payload' do
        token.encoded_payload = other_encoded_payload

        expect(token.unverified_payload).to eq(other_payload)
      end

      it 'does not verify against the previous signing input' do
        token.encoded_payload = other_encoded_payload

        expect { token.verify!(signature: { algorithm: 'HS256', key: 'secret' }) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when the payload is reassigned to a matching payload' do
      let(:encoded_token) { detached_payload_token.jwt }

      before do
        token.encoded_payload = detached_payload_token.encoded_payload
        token.verify!(signature: { algorithm: 'HS256', key: 'secret' })
        token.encoded_payload = detached_payload_token.encoded_payload
      end

      it 'requires the claims to be verified again' do
        token.verify_signature!(algorithm: 'HS256', key: 'secret')

        expect { token.payload }.to raise_error(JWT::DecodeError, 'Verify the token claims before accessing the payload')
      end

      it 'can be verified again' do
        token.verify!(signature: { algorithm: 'HS256', key: 'secret' })

        expect(token.payload).to eq(payload)
      end
    end
  end

  describe 'verification state transitions' do
    let(:payload) { { 'iss' => 'issuer', 'pay' => 'load' } }

    def trusted_payload_readable?(token)
      token.payload
      true
    rescue JWT::TokenError
      false
    end

    it 'only grants trusted payload access after signature and claims checks on unchanged contents' do
      expect(trusted_payload_readable?(token)).to be(false)

      expect(token.valid_signature?(algorithm: 'HS256', key: 'wrong')).to be(false)
      expect(trusted_payload_readable?(token)).to be(false)

      token.verify_signature!(algorithm: 'HS256', key: 'secret')
      expect(trusted_payload_readable?(token)).to be(false)

      expect(token.valid_claims?(iss: 'not-the-issuer')).to be(false)
      expect(trusted_payload_readable?(token)).to be(false)

      # The default exp check passes, but it does not cover the failed issuer
      # check and must not make the payload readable.
      expect(token.valid_claims?).to be(true)
      expect(trusted_payload_readable?(token)).to be(false)

      expect(token.valid_claims?(iss: 'issuer')).to be(true)
      expect(trusted_payload_readable?(token)).to be(true)

      # A later failing check revokes the earlier result.
      expect(token.valid_signature?(algorithm: 'HS256', key: 'wrong')).to be(false)
      expect(trusted_payload_readable?(token)).to be(false)

      # Signature and claims both have to be established again.
      token.verify_signature!(algorithm: 'HS256', key: 'secret')
      expect(trusted_payload_readable?(token)).to be(false)

      token.verify_claims!(iss: 'issuer')
      expect(trusted_payload_readable?(token)).to be(true)
    end

    it 'does not let a weaker claim check clear an earlier claim failure' do
      token.verify_signature!(algorithm: 'HS256', key: 'secret')

      expect { token.verify_claims!(iss: 'not-the-issuer') }.to raise_error(JWT::InvalidIssuerError)

      token.verify_claims!({})
      expect(trusted_payload_readable?(token)).to be(false)

      token.verify_claims!(iss: 'issuer')
      expect(trusted_payload_readable?(token)).to be(true)
    end

    it 'does not let a more permissive time check clear an earlier failure' do
      expired = { 'exp' => Time.now.to_i - 10, 'iss' => 'issuer' }
      signed = JWT::Token.new(payload: expired).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.jwt
      token = described_class.new(signed)

      token.verify_signature!(algorithm: 'HS256', key: 'secret')

      expect(token.valid_claims?(exp: {})).to be(false)
      expect(trusted_payload_readable?(token)).to be(false)

      # The token is inside the leeway window, but a check that permits a
      # longer window is weaker than the check that failed and cannot clear it.
      expect(token.valid_claims?(exp: { leeway: 1000 })).to be(true)
      expect(trusted_payload_readable?(token)).to be(false)

      token.verify_claims!(exp: { leeway: 1000 })
      expect(trusted_payload_readable?(token)).to be(false)
    end

    it 'allows claims to be checked before the signature, still gating payload access on both' do
      token.verify_claims!(iss: 'issuer')
      expect(trusted_payload_readable?(token)).to be(false)

      token.verify_signature!(algorithm: 'HS256', key: 'secret')
      expect(trusted_payload_readable?(token)).to be(true)
    end

    it 'does not treat diagnostic reads as verification' do
      token.verify_signature!(algorithm: 'HS256', key: 'secret')

      token.header
      token.claim_errors
      token.unverified_payload

      expect(trusted_payload_readable?(token)).to be(false)

      expect(token.valid_claims?(iss: 'not-the-issuer')).to be(false)
      token.header
      token.claim_errors
      token.unverified_payload

      expect(trusted_payload_readable?(token)).to be(false)
    end

    it 'invalidates a verified detached payload when it is replaced and accepts it after re-verification' do
      detached = JWT::Token.new(payload: payload).tap do |t|
        t.detach_payload!
        t.sign!(algorithm: 'HS256', key: 'secret')
      end
      other = JWT::Token.new(payload: { 'iss' => 'other', 'pay' => 'other' }).tap do |t|
        t.detach_payload!
        t.sign!(algorithm: 'HS256', key: 'secret')
      end

      detached_token = described_class.new(detached.jwt)
      detached_token.encoded_payload = detached.encoded_payload
      detached_token.verify!(signature: { algorithm: 'HS256', key: 'secret' })
      expect(trusted_payload_readable?(detached_token)).to be(true)

      detached_token.encoded_payload = other.encoded_payload
      expect(trusted_payload_readable?(detached_token)).to be(false)
      expect { detached_token.verify_signature!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      expect(trusted_payload_readable?(detached_token)).to be(false)

      detached_token.encoded_payload = detached.encoded_payload
      detached_token.verify!(signature: { algorithm: 'HS256', key: 'secret' })
      expect(detached_token.payload).to eq(payload)
    end

    it 'discards a signature result when a key finder replaces the detached payload during verification' do
      detached = JWT::Token.new(payload: payload).tap do |t|
        t.detach_payload!
        t.sign!(algorithm: 'HS256', key: 'secret')
      end
      replacement = JWT::Token.new(payload: { 'pay' => 'replacement' }).tap do |t|
        t.detach_payload!
        t.sign!(algorithm: 'HS256', key: 'secret')
      end

      detached_token = described_class.new(detached.jwt)
      detached_token.encoded_payload = detached.encoded_payload

      key_finder = lambda do |candidate|
        candidate.encoded_payload = replacement.encoded_payload
        'secret'
      end

      expect(detached_token.valid_signature?(algorithm: 'HS256', key_finder: key_finder)).to be(false)
      expect(trusted_payload_readable?(detached_token)).to be(false)
      expect(detached_token.unverified_payload).to eq({ 'pay' => 'replacement' })
    end

    it 'does not let a header read before verification change the algorithm that is verified' do
      read_header = token.header
      read_header['alg'] = 'none'

      expect(token.valid_signature?(algorithm: 'HS256', key: 'secret')).to be(true)

      token.verify_claims!(iss: 'issuer')
      expect(token.payload).to eq(payload)
    end

    it 'does not carry a signature result across a payload change made by a key finder' do
      detached = JWT::Token.new(payload: payload).tap do |t|
        t.detach_payload!
        t.sign!(algorithm: 'HS256', key: 'secret')
      end

      detached_token = described_class.new(detached.jwt)
      detached_token.encoded_payload = detached.encoded_payload

      key_finder = lambda do |candidate|
        candidate.encoded_payload = detached.encoded_payload
        'secret'
      end

      expect(detached_token.valid_signature?(algorithm: 'HS256', key_finder: key_finder)).to be(false)
      expect { detached_token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')
    end
  end

  describe 'object ownership' do
    let(:payload) { { 'data' => { 'roles' => ['admin', { 'scope' => 'read' }] } } }

    it 'does not let changes to a returned payload change what was verified' do
      token.verify!(signature: { algorithm: 'HS256', key: 'secret' })

      copy = token.payload
      copy['data']['roles'] << 'root'
      copy['data']['roles'][1]['scope'].replace('write')
      copy['data']['roles'][1]['scope'] = 'write'
      copy.delete('data')

      expect(token.payload).to eq(payload)
      expect(token.unverified_payload).to eq(payload)
    end

    it 'does not let changes to the diagnostic payload change what a later verification accepts' do
      diagnostic = token.unverified_payload
      diagnostic['data']['roles'] << 'root'
      diagnostic['data']['roles'][1].delete('scope')

      token.verify!(signature: { algorithm: 'HS256', key: 'secret' })

      expect(token.payload).to eq(payload)
    end

    it 'does not let changes to a returned header change the decoded header' do
      header = { 'crit' => ['b64'], 'nested' => { 'key' => ['value'] } }
      encoded = JWT::Token.new(payload: payload, header: header).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.jwt
      token = described_class.new(encoded)

      copy = token.header
      copy['crit'] << 'other'
      copy['nested']['key'][0].replace('changed')
      copy['nested'].delete('key')

      expect(token.header).to eq(header.merge('alg' => 'HS256'))
    end

    it 'does not observe later changes to the original token string' do
      original = encoded_token.dup
      token = described_class.new(original)

      original.replace('tampered')

      expect(token.jwt).to eq(encoded_token)
      token.verify!(signature: { algorithm: 'HS256', key: 'secret' })
      expect(token.payload).to eq(payload)
    end

    it 'returns copies of the encoded segments' do
      token.verify!(signature: { algorithm: 'HS256', key: 'secret' })
      signing_input = token.signing_input

      token.jwt << '.tampered'
      token.encoded_header << '.tampered'
      token.encoded_payload << '.tampered'
      token.encoded_signature << '.tampered'
      token.signature << '.tampered'

      expect(token.signing_input).to eq(signing_input)
      expect(token.payload).to eq(payload)
    end

    it 'does not share state with a copy' do
      token.verify!(signature: { algorithm: 'HS256', key: 'secret' })
      copy = token.dup
      copy.encoded_payload = JWT::Token.new(payload: { 'pay' => 'other' }).tap { |t| t.sign!(algorithm: 'HS256', key: 'secret') }.encoded_payload

      expect(token.payload).to eq(payload)
      expect { copy.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')
    end

    it 'does not observe later changes to an assigned detached payload' do
      detached = JWT::Token.new(payload: payload).tap do |t|
        t.detach_payload!
        t.sign!(algorithm: 'HS256', key: 'secret')
      end
      other = JWT::Token.new(payload: { 'pay' => 'other' }).tap do |t|
        t.detach_payload!
        t.sign!(algorithm: 'HS256', key: 'secret')
      end

      segment = detached.encoded_payload.dup
      token = described_class.new(detached.jwt)
      token.encoded_payload = segment

      segment.replace(other.encoded_payload)

      token.verify!(signature: { algorithm: 'HS256', key: 'secret' })
      expect(token.payload).to eq(payload)
    end
  end

  describe '#header' do
    it { expect(token.header).to eq({ 'alg' => 'HS256' }) }

    context 'when token is the empty string' do
      let(:encoded_token) { '' }

      it 'raises decode error' do
        expect { token.header }.to raise_error(JWT::MalformedTokenError, 'Invalid segment encoding')
      end
    end

    ['[]', 'null', '"header"', '1', 'true', 'false'].each do |json|
      context "when the header is the JSON value #{json}" do
        let(:encoded_token) { "#{JWT::Base64.url_encode(json)}.#{JWT::Base64.url_encode('{}')}.signature" }

        it 'raises decode error' do
          expect { token.header }.to raise_error(JWT::MalformedTokenError, 'Token header not a JSON object')
        end

        it 'raises decode error when verifying the signature' do
          expect { token.verify_signature!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::MalformedTokenError, 'Token header not a JSON object')
        end

        it 'raises decode error when reading the payload' do
          expect { token.unverified_payload }.to raise_error(JWT::MalformedTokenError, 'Token header not a JSON object')
        end
      end
    end
  end

  describe '#signature' do
    it { expect(token.signature).to be_a(String) }
  end

  describe '#signing_input' do
    it { expect(token.signing_input).to eq('eyJhbGciOiJIUzI1NiJ9.eyJwYXkiOiJsb2FkIn0') }
  end

  describe '#verify_signature!' do
    context 'when key is valid' do
      it 'does not raise' do
        expect(token.verify_signature!(algorithm: 'HS256', key: 'secret')).to eq(nil)
      end
    end

    context 'when key is invalid' do
      it 'raises an error' do
        expect { token.verify_signature!(algorithm: 'HS256', key: 'wrong') }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when key is an array with one valid entry' do
      it 'does not raise' do
        expect(token.verify_signature!(algorithm: 'HS256', key: %w[wrong secret])).to eq(nil)
      end
    end

    context 'when algorithm is an empty array' do
      it 'raises an error' do
        expect { token.verify_signature!(key: 'secret', algorithm: []) }.to raise_error(JWT::VerificationError, 'No algorithm provided')
      end
    end

    context 'when algorithm is not given' do
      it 'raises an error' do
        expect { token.verify_signature!(key: 'secret') }.to raise_error(ArgumentError, /missing keyword/)
      end
    end

    context 'when header has invalid alg value' do
      let(:header) { { 'alg' => 'HS123' } }

      it 'does not raise' do
        expect(token.header).to eq(header)
        expect(token.verify_signature!(algorithm: 'HS256', key: 'secret')).to eq(nil)
      end
    end

    ['.extra', '.'].each do |suffix|
      context "when the token is followed by #{suffix.inspect}" do
        subject(:token) { described_class.new("#{encoded_token}#{suffix}") }

        it 'raises decode error' do
          expect { token.verify_signature!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::MalformedTokenError, 'Too many segments')
        end

        it 'raises decode error from #valid_signature?' do
          expect { token.valid_signature?(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::MalformedTokenError, 'Too many segments')
        end

        it 'raises decode error from #valid? and #verify!' do
          signature = { algorithm: 'HS256', key: 'secret' }

          expect { token.valid?(signature: signature) }.to raise_error(JWT::MalformedTokenError, 'Too many segments')
          expect { token.verify!(signature: signature) }.to raise_error(JWT::MalformedTokenError, 'Too many segments')
        end

        it 'does not call the key finder' do
          key_finder = ->(_token) { raise 'key finder should not be called' }

          expect { token.verify_signature!(algorithm: 'HS256', key_finder: key_finder) }.to raise_error(JWT::MalformedTokenError, 'Too many segments')
        end

        it 'does not make the payload available' do
          token.verify_claims!

          expect { token.verify_signature!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::MalformedTokenError)
          expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')
        end
      end
    end

    context 'when payload is detached' do
      let(:encoded_token) { detached_payload_token.jwt }

      context 'when payload provided in separate' do
        before { token.encoded_payload = detached_payload_token.encoded_payload }
        it 'does not raise' do
          expect(token.verify_signature!(algorithm: 'HS256', key: 'secret')).to eq(nil)
        end
      end

      context 'when payload is not provided' do
        it 'raises VerificationError' do
          expect { token.verify_signature!(algorithm: 'HS256', key: 'secret') }.to raise_error(JWT::VerificationError, 'Signature verification failed')
        end
      end
    end

    context 'when key_finder is given' do
      it 'uses key provided by keyfinder' do
        expect(token.verify_signature!(algorithm: 'HS256', key_finder: ->(_token) { 'secret' })).to eq(nil)
      end

      it 'can utilize an array provided by keyfinder' do
        expect(token.verify_signature!(algorithm: 'HS256', key_finder: ->(_token) { %w[wrong secret] })).to eq(nil)
      end

      it 'accepts the token when one of several algorithms is allowed' do
        expect(token.verify_signature!(algorithm: %w[RS256 HS256], key_finder: ->(_token) { 'secret' })).to eq(nil)
      end

      it 'accepts algorithm names given as symbols and in a different case' do
        expect(token.verify_signature!(algorithm: :HS256, key_finder: ->(_token) { 'secret' })).to eq(nil)
        expect(token.verify_signature!(algorithm: 'hs256', key_finder: ->(_token) { 'secret' })).to eq(nil)
      end

      it 'accepts a custom algorithm object' do
        custom = Class.new do
          include JWT::JWA::SigningAlgorithm

          def alg
            'CUSTOM'
          end

          def sign(*)
            'signature'
          end

          def verify(*)
            true
          end
        end.new
        custom_token = JWT::Token.new(payload: payload).tap { |t| t.sign!(algorithm: custom, key: 'secret') }.jwt

        expect(described_class.new(custom_token).verify_signature!(algorithm: custom, key_finder: ->(_token) { 'secret' })).to eq(nil)
      end

      it 'reports an unknown algorithm as a configuration error' do
        expect { token.verify_signature!(algorithm: 'FOO', key_finder: ->(_token) { 'secret' }) }.to raise_error(JWT::VerificationKeyError, 'Algorithm not supported')
      end

      it 'does not load the JWKS through the JWK key finder' do
        loader = double('jwks loader')
        expect(loader).not_to receive(:call)

        expect { token.verify_signature!(algorithm: 'RS256', key_finder: JWT::JWK::KeyFinder.new(jwks: loader)) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end

      context 'when the token algorithm is not allowed' do
        let(:key_finder) { ->(_token) { raise 'key finder should not be called' } }

        it 'raises without calling the key finder' do
          expect { token.verify_signature!(algorithm: 'RS256', key_finder: key_finder) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
        end

        it 'is reported as invalid without calling the key finder' do
          expect(token.valid_signature?(algorithm: %w[RS256 RS512], key_finder: key_finder)).to eq(false)
          expect(token.valid?(signature: { algorithm: 'RS256', key_finder: key_finder })).to eq(false)
        end

        it 'clears an earlier successful verification' do
          token.verify_signature!(algorithm: 'HS256', key: 'secret')
          token.verify_claims!
          expect(token.payload).to eq(payload)

          expect(token.valid_signature?(algorithm: 'RS256', key_finder: key_finder)).to eq(false)
          expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')
        end
      end

      [{}, { 'alg' => nil }, { 'alg' => [] }, { 'alg' => 123 }, { 'alg' => true }, { 'alg' => {} }].each do |invalid_header|
        context "when the token header is #{invalid_header}" do
          let(:encoded_token) do
            encoded = JWT::Base64.url_encode(JSON.generate(invalid_header))
            "#{encoded}.#{JWT::Base64.url_encode('{}')}.signature"
          end

          it 'raises without calling the key finder' do
            key_finder = ->(_token) { raise 'key finder should not be called' }
            expect { token.verify_signature!(algorithm: 'RS256', key_finder: key_finder) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
          end
        end
      end

      context 'when no algorithm is given and the key finder provides a JWK' do
        let(:jwk) { JWT::JWK.new(test_pkey('rsa-2048-private.pem'), alg: 'RS256') }
        let(:encoded_token) do
          JWT::Token.new(payload: payload)
                    .tap { |t| t.sign!(algorithm: 'RS256', key: jwk.signing_key) }
                    .jwt
        end

        it 'uses the JWK for verification' do
          expect(token.verify_signature!(algorithm: [], key_finder: ->(_token) { jwk })).to eq(nil)
        end
      end
    end

    context 'when neither key or key_finder is given' do
      it 'raises an ArgumentError' do
        expect { token.verify_signature!(algorithm: 'HS256') }.to raise_error(ArgumentError, 'Provide either key or key_finder, not both or neither')
      end
    end

    context 'when both key or key_finder is given' do
      it 'raises an ArgumentError' do
        expect { token.verify_signature!(algorithm: 'HS256', key: 'key', key_finder: 'finder') }.to raise_error(ArgumentError, 'Provide either key or key_finder, not both or neither')
      end
    end

    context 'when payload is not encoded' do
      let(:encoded_token) { 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY' }
      before { token.encoded_payload = '$.02' }

      let(:key) { Base64.urlsafe_decode64('AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow') }

      it 'does not raise' do
        expect(token.verify_signature!(algorithm: 'HS256', key: key)).to eq(nil)
      end
    end

    context 'when JWT::KeyFinder is used as a key_finder' do
      let(:jwk) { JWT::JWK.new(test_pkey('rsa-2048-private.pem')) }
      let(:encoded_token) do
        JWT::Token.new(payload: payload, header: { kid: jwk.kid })
                  .tap { |t| t.sign!(algorithm: 'RS256', key: jwk.signing_key) }
                  .jwt
      end

      it 'uses the keys provided by the JWK key finder' do
        key_finder = JWT::JWK::KeyFinder.new(jwks: JWT::JWK::Set.new(jwk))
        expect(token.verify_signature!(algorithm: 'RS256', key_finder: key_finder)).to eq(nil)
      end
    end

    context 'when RSA JWK is given as a key' do
      let(:jwk) { JWT::JWK.new(test_pkey('rsa-2048-private.pem'), alg: 'RS256') }
      let(:encoded_token) do
        JWT::Token.new(payload: payload)
                  .tap { |t| t.sign!(algorithm: 'RS256', key: jwk.signing_key) }
                  .jwt
      end

      context 'with empty algorithm array provided' do
        it 'uses the JWK for verification' do
          expect(token.verify_signature!(key: jwk, algorithm: [])).to eq(nil)
        end
      end

      context 'with algorithms supported by key provided' do
        it 'uses the JWK for verification' do
          expect(token.verify_signature!(algorithm: %w[RS256 RS512], key: jwk)).to eq(nil)
        end
      end

      context 'with algorithms not supported by key provided' do
        it 'raises JWT::VerificationKeyError' do
          expect { token.verify_signature!(algorithm: %w[RS384 RS512], key: jwk) }.to raise_error(JWT::VerificationKeyError, 'Provided JWKs do not support one of the specified algorithms: RS384, RS512')
        end
      end
    end
  end

  describe '#verify_claims!' do
    context 'when required_claims is passed' do
      it 'raises error' do
        expect { token.verify_claims!(required: ['exp']) }.to raise_error(JWT::MissingRequiredClaim, 'Missing required claim exp')
      end
    end

    context 'exp claim' do
      let(:payload) { { 'exp' => Time.now.to_i - 10, 'pay' => 'load' } }

      it 'verifies the exp' do
        token.verify_claims!(required: ['exp'])
        expect { token.verify_claims!(exp: {}) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        token.verify_claims!(exp: { leeway: 1000 })
      end

      context 'when no claims are provided' do
        it 'raises ExpiredSignature error' do
          expect { token.verify_claims! }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claim validation skips verifying the exp claim' do
        it 'does not raise' do
          expect { token.verify_claims!({}) }.not_to raise_error
        end
      end

      context 'when claims given as symbol' do
        it 'validates the claim' do
          expect { token.verify_claims!(:exp) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claims given as a list of symbols' do
        it 'validates the claim' do
          expect { token.verify_claims!(:exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when claims given as a list of symbols and hashes' do
        it 'validates the claim' do
          expect { token.verify_claims!({ exp: { leeway: 1000 }, nbf: {} }, :exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
        end
      end

      context 'when payload is detached' do
        let(:encoded_token) { detached_payload_token.jwt }
        context 'when payload provided in separate' do
          before { token.encoded_payload = detached_payload_token.encoded_payload }
          it 'raises claim verification error' do
            expect { token.verify_claims!(:exp, :nbf) }.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
          end
        end
        context 'when payload is not provided' do
          it 'raises decode error' do
            expect { token.verify_claims!(:exp, :nbf) }.to raise_error(JWT::MalformedTokenError, 'Encoded payload is empty')
          end
        end
      end
    end

    context 'when header contains crits header' do
      let(:header) { { crit: ['b64'] } }

      context 'when expected crits are missing' do
        it 'raises an error' do
          expect { token.verify_claims!(crit: ['other']) }.to raise_error(JWT::InvalidCritError, 'Crit header missing expected values: other')
        end
      end

      context 'when expected crits are present' do
        it 'passes verification' do
          expect { token.verify_claims!(crit: ['b64']) }.not_to raise_error
        end
      end
    end
  end

  context '#verify!' do
    context 'when key is valid' do
      it 'does not raise' do
        expect(token.verify!(signature: { algorithm: 'HS256', key: 'secret' })).to eq(nil)
      end
    end

    context 'when key is invalid' do
      it 'raises an error' do
        expect { token.verify!(signature: { algorithm: 'HS256', key: 'wrong' }) }.to raise_error(JWT::VerificationError, 'Signature verification failed')
      end
    end

    context 'when claims are invalid' do
      let(:payload) { { 'pay' => 'load', exp: Time.now.to_i - 1000 } }

      it 'raises an error' do
        expect do
          token.verify!(signature: { algorithm: 'HS256', key: 'secret' },
                        claims: { exp: { leeway: 900 } })
        end.to raise_error(JWT::ExpiredSignature, 'Signature has expired')
      end
    end
  end

  context '#valid?' do
    context 'when key is valid' do
      it 'returns true' do
        expect(token.valid?(signature: { algorithm: 'HS256', key: 'secret' })).to be(true)
      end
    end

    context 'when key is invalid' do
      it 'returns false' do
        expect(token.valid?(signature: { algorithm: 'HS256', key: 'wrong' })).to be(false)
      end
    end

    context 'when claims are provided as an array' do
      it 'returns true' do
        expect(
          token.valid?(signature: { algorithm: 'HS256', key: 'secret' }, claims: [:exp])
        ).to be(true)
      end
    end

    context 'when claims are invalid' do
      let(:payload) { { 'pay' => 'load', exp: Time.now.to_i - 1000 } }

      it 'returns false' do
        expect(
          token.valid?(signature: { algorithm: 'HS256', key: 'secret' },
                       claims: { exp: { leeway: 900 } })
        ).to be(false)
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

      context 'when no claims are provided' do
        it 'validates the exp claim and returns false' do
          expect(token.valid_claims?).to be(false)
        end
      end

      context 'when claim validation skips verifying the exp claim' do
        it 'returns true' do
          expect(token.valid_claims?({})).to be(true)
        end
      end
    end

    context 'when payload is detached and not provided' do
      let(:encoded_token) { detached_payload_token.jwt }

      it 'returns false instead of raising' do
        expect(token.valid_claims?(:exp)).to be(false)
      end
    end

    context 'when payload is not valid JSON' do
      let(:encoded_token) do
        header_segment = Base64.urlsafe_encode64('{"alg":"HS256"}', padding: false)
        payload_segment = Base64.urlsafe_encode64('not json', padding: false)
        signature = Base64.urlsafe_encode64(OpenSSL::HMAC.digest('SHA256', 'secret', "#{header_segment}.#{payload_segment}"), padding: false)
        [header_segment, payload_segment, signature].join('.')
      end

      it 'returns false instead of raising' do
        expect(token.valid_claims?(:exp)).to be(false)
      end

      it 'makes #valid? return false even though the signature is valid' do
        expect(token.valid_signature?(algorithm: 'HS256', key: 'secret')).to be(true)
        expect(token.valid?(signature: { algorithm: 'HS256', key: 'secret' })).to be(false)
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

    context 'when payload is detached and not provided' do
      let(:encoded_token) { detached_payload_token.jwt }

      it 'reports the decoding problem instead of raising' do
        expect(token.claim_errors(:exp).map(&:message)).to eq(['Encoded payload is empty'])
      end
    end
  end

  describe 'integration use-cases' do
    context 'simple verify HS256 with defaults' do
      let(:payload) { { 'pay' => 'load', 'iss' => 'issuer' } }
      let(:encoded_token) do
        JWT::Token.new(payload: payload)
                  .tap { |t| t.sign!(algorithm: 'HS256', key: 'secret_signing_key') }
                  .jwt
      end

      it 'protects the user from unverified payload access' do
        token = described_class.new(encoded_token)

        expect(token.unverified_payload).to eq({ 'pay' => 'load', 'iss' => 'issuer' })
        expect(token.header).to eq({ 'alg' => 'HS256' })

        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')

        expect(token.valid_signature?(algorithm: 'HS256', key: 'invalid_signing_key')).to be(false)
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')

        expect(token.valid_signature?(algorithm: 'HS256', key: 'secret_signing_key')).to be(true)
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token claims before accessing the payload')

        expect(token.valid_claims?(iss: 'not-the-issuer')).to be(false)
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token claims before accessing the payload')

        # A weaker check that does not cover the failed issuer check cannot
        # make the payload readable.
        expect(token.valid_claims?).to be(true)
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token claims before accessing the payload')

        expect(token.valid_claims?(iss: 'issuer')).to be(true)
        expect(token.payload).to eq({ 'pay' => 'load', 'iss' => 'issuer' })

        token = described_class.new(encoded_token)

        expect(token.valid?(signature: { algorithm: 'HS256', key: 'invalid_signing_key' })).to be(false)
        expect { token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')

        expect(token.valid?(signature: { algorithm: 'HS256', key: 'secret_signing_key' })).to be(true)
        expect(token.payload).to eq({ 'pay' => 'load', 'iss' => 'issuer' })
      end
    end
  end
end

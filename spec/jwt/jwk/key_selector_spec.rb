# frozen_string_literal: true

RSpec.describe JWT::JWK::KeySelector do
  let(:keypair)       { test_pkey('rsa-2048-private.pem') }
  let(:other_keypair) { OpenSSL::PKey::RSA.generate(2048) }
  let(:jwk)           { JWT::JWK.new(keypair, kid: 'rotation-kid') }
  let(:other_jwk)     { JWT::JWK.new(other_keypair, kid: 'rotation-kid') }
  let(:algorithm)     { 'RS256' }
  let(:payload)       { { 'data' => 'something' } }
  let(:token) do
    JWT::EncodedToken.new(JWT.encode(payload, jwk.signing_key, algorithm, kid: jwk.kid))
  end

  def selector(jwks, **overrides)
    described_class.new({ jwks: jwks, algorithms: [algorithm] }.merge(overrides))
  end

  describe '#call' do
    context 'with a single matching key' do
      let(:jwks) { { keys: [jwk.export] } }

      it 'returns its verification key and verifies the token' do
        returned_key = selector(jwks).call(token)
        expect(token.valid_signature?(algorithm: algorithm, key: returned_key)).to eq(true)
      end

      it 'is unchanged by unrelated keys placed before the match' do
        jwks[:keys].unshift(kid: 'other', kty: 'oct', k: 'secret')
        expect(selector(jwks).call(token)).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'when the same public key is published twice under one kid' do
      let(:jwks) { { keys: [jwk.export, jwk.export] } }

      it 'treats the duplicates as one candidate and verifies the token' do
        expect(selector(jwks).call(token)).to be_a(OpenSSL::PKey::RSA)
      end

      it 'reaches the same conclusion when the JWKS order is swapped' do
        reversed = { keys: jwks[:keys].reverse }
        expect(selector(jwks).call(token)).to be_a(OpenSSL::PKey::RSA)
        expect(selector(reversed).call(token)).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'when different public keys share the kid' do
      let(:jwks) { { keys: [jwk.export, other_jwk.export] } }

      it 'verifies when only one of the distinct keys can verify the token' do
        expect(selector(jwks).call(token)).to be_a(OpenSSL::PKey::RSA)
      end

      it 'does not depend on the order of the JWKS' do
        reversed = { keys: jwks[:keys].reverse }

        expect(selector(jwks).call(token)).to be_a(OpenSSL::PKey::RSA)
        expect(selector(reversed).call(token)).to be_a(OpenSSL::PKey::RSA)
      end

      context 'and several distinct keys can verify the same token' do
        let(:algorithm_a) { build_custom_algorithm('CUSTOM-A') }
        let(:algorithm_b) { build_custom_algorithm('CUSTOM-B') }
        let(:signed_token) do
          JWT::EncodedToken.new(JWT.encode(payload, jwk.signing_key, algorithm_a, kid: 'rotation-kid'))
        end
        let(:jwks) do
          first = jwk.export.merge(alg: 'CUSTOM-A')
          second = other_jwk.export.merge(alg: 'CUSTOM-B')
          { keys: [first, second] }
        end

        def selector(jwks, **overrides)
          described_class.new({ jwks: jwks }.merge(overrides))
        end

        it 'rejects with an ambiguity error instead of choosing a key' do
          key_selector = selector(jwks, algorithms: [algorithm_a, algorithm_b])
          expect { key_selector.call(signed_token) }.to raise_error(
            JWT::AmbiguousKeyError, /2 distinct keys matching kid rotation-kid verify the token/
          )
        end

        it 'rejects identically when the JWKS order is swapped' do
          reversed = { keys: jwks[:keys].reverse }
          build_selector = ->(set) { selector(set, algorithms: [algorithm_a, algorithm_b]).call(signed_token) }

          expect { build_selector.call(jwks) }.to raise_error(JWT::AmbiguousKeyError)
          expect { build_selector.call(reversed) }.to raise_error(JWT::AmbiguousKeyError)
        end
      end

      context 'and no distinct key can verify the token' do
        let(:foreign_token) do
          JWT::EncodedToken.new(JWT.encode(payload, other_jwk.signing_key, algorithm, kid: 'rotation-kid'))
        end
        let(:jwks) { { keys: [jwk.export] } }

        it 'reports that no matching key verifies the token' do
          expect { selector(jwks).call(foreign_token) }.to raise_error(
            JWT::SignatureError, /No key matching kid rotation-kid verifies the token/
          )
        end
      end
    end

    context 'when no candidate fits the caller constraints' do
      let(:ec_jwk) { JWT::JWK.new(test_pkey('ec256-private.pem'), kid: jwk.kid) }

      it 'rejects a key type that cannot run the algorithm' do
        jwks = { keys: [ec_jwk.export] }
        expect { selector(jwks).call(token) }.to raise_error(
          JWT::VerificationKeyError, /No compatible public key for kid rotation-kid/
        )
      end

      it 'rejects an algorithm declared on the JWK that is not allowed' do
        jwks = { keys: [jwk.export.merge(alg: 'RS512')] }
        expect { selector(jwks).call(token) }.to raise_error(JWT::VerificationKeyError)
      end

      it 'ignores encryption keys and keys without the verify key operation' do
        jwks = { keys: [jwk.export.merge(use: 'enc'), jwk.export.merge(key_ops: %w[sign])] }
        expect { selector(jwks).call(token) }.to raise_error(JWT::VerificationKeyError)
      end

      it 'keeps keys advertised for signature verification' do
        jwks = { keys: [jwk.export.merge(use: 'sig', key_ops: ['verify'])] }
        expect(selector(jwks).call(token)).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'when there are too many candidates' do
      let(:many_token) do
        JWT::EncodedToken.new(JWT.encode(payload, jwk.signing_key, algorithm, kid: 'shared-kid'))
      end
      let(:shared_jwks) do
        { keys: Array.new(6) { jwk.export.merge(kid: 'shared-kid') } }
      end

      it 'raises a configuration error before attempting any signature' do
        verifications = 0
        allow_any_instance_of(JWT::JWA::Rsa).to receive(:verify) { verifications += 1 }
        key_selector = selector(shared_jwks, max_candidates: 5)

        expect { key_selector.call(many_token) }.to raise_error(
          JWT::TooManyCandidateKeys,
          /6 compatible key candidates for kid shared-kid exceed the limit of 5/
        )
        expect(verifications).to eq(0)
      end

      it 'honours a custom candidate limit' do
        expect(selector(shared_jwks, max_candidates: 6).call(many_token)).to be_a(OpenSSL::PKey::RSA)
      end

      it 'counts only candidates passing the algorithm and usage filters' do
        keys = [jwk.export.merge(kid: 'shared-kid', use: 'enc')] +
               Array.new(5) { jwk.export.merge(kid: 'shared-kid') }
        jwks = { keys: keys }
        expect(selector(jwks, max_candidates: 5).call(many_token)).to be_a(OpenSSL::PKey::RSA)
      end

      it 'applies the limit to the compatible candidates before deduplication' do
        keys = Array.new(6) { jwk.export.merge(kid: 'shared-kid') }
        jwks = { keys: keys }
        expect { selector(jwks, max_candidates: 5).call(many_token) }.to raise_error(JWT::TooManyCandidateKeys)
        expect(selector(jwks, max_candidates: 6).call(many_token)).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'when the kid is missing from the token' do
      let(:jwks) { { keys: [jwk.export] } }
      let(:token_without_kid) do
        JWT::EncodedToken.new(JWT.encode(payload, jwk.signing_key, algorithm))
      end

      it 'rejects by default' do
        expect { selector(jwks).call(token_without_kid) }.to raise_error(
          JWT::SignatureError, 'No key id (kid) or x5t found from token headers'
        )
      end

      it 'matches every key when nil kids are allowed' do
        key_selector = selector(jwks, allow_nil_kid: true)
        expect(key_selector.call(token_without_kid)).to be_a(OpenSSL::PKey::RSA)
      end

      it 'uses the algorithm declared on the JWK when no algorithm constraint is given' do
        key_with_alg = JWT::JWK.new(keypair, kid: 'alg-kid', alg: algorithm)
        alg_token = JWT::EncodedToken.new(JWT.encode(payload, keypair, algorithm, kid: 'alg-kid'))
        key_selector = described_class.new(jwks: { keys: [key_with_alg.export] })
        expect(key_selector.call(alg_token)).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'when the token kid has an invalid type' do
      let(:invalid_kid_token) do
        header = JWT::Base64.url_encode(JSON.generate(alg: algorithm, kid: 5))
        payload_segment = JWT::Base64.url_encode(JSON.generate(payload))
        JWT::EncodedToken.new("#{header}.#{payload_segment}.signature")
      end

      it 'raises a malformed token error' do
        expect { selector({ keys: [jwk.export] }).call(invalid_kid_token) }.to raise_error(
          JWT::MalformedTokenError, 'Invalid type for kid header parameter'
        )
      end
    end

    context 'when a candidate JWK cannot be materialized' do
      it 'skips the unusable JWK instead of bubbling up the JWK error' do
        jwk_with_unknown_alg = jwk.export.merge(alg: 'NOT-A-REAL-ALG')
        jwks = { keys: [jwk_with_unknown_alg, jwk.export] }

        expect(selector(jwks).call(token)).to be_a(OpenSSL::PKey::RSA)
      end

      it 'reports a signature error when the only candidate fails to verify' do
        allow_any_instance_of(JWT::JWA::Rsa).to receive(:verify).and_raise(JWT::VerificationError, 'boom')
        jwks = { keys: [jwk.export] }

        expect { selector(jwks).call(token) }.to raise_error(
          JWT::SignatureError, /No key matching kid/
        )
      end
    end

    context 'when the JWKS is provided by a loader' do
      it 'calls the loader a second time with invalidation when nothing matches' do
        calls = []
        loader = lambda do |options|
          calls << options
          options[:invalidate] ? { keys: [jwk.export] } : { keys: [] }
        end

        expect(selector(loader).call(token)).to be_a(OpenSSL::PKey::RSA)
        expect(calls.last).to include(invalidate: true, kid_not_found: true)
      end
    end

    context 'error message safety' do
      let(:rsa_jwk) { JWT::JWK.new(keypair, kid: 'priv-kid', alg: 'RS256') }

      it 'keeps private key material out of configuration and verification errors' do
        private_export = rsa_jwk.export(include_private: true)
        private_components = private_export.values_at(:d, :p, :q, :dp, :dq, :qi).compact

        expect do
          selector({ keys: [private_export] }, algorithms: ['RS512']).call(token)
        end.to raise_error(JWT::VerificationKeyError) { |error| assert_no_private_material(error, private_components) }

        shared = { keys: Array.new(6) { private_export.merge(kid: 'shared-kid') } }
        many_token = JWT::EncodedToken.new(JWT.encode(payload, jwk.signing_key, algorithm, kid: 'shared-kid'))
        expect do
          selector(shared, max_candidates: 5).call(many_token)
        end.to raise_error(JWT::TooManyCandidateKeys) { |error| assert_no_private_material(error, private_components) }
      end

      it 'never includes the shared secret of an HMAC key in errors' do
        secret = 'a-very-secret-hmac-value'
        encoded_secret = JWT::Base64.url_encode(secret)
        hmac_export = JWT::JWK.new(secret, kid: 'hmac-kid').export(include_private: true)
        hmac_token = JWT::EncodedToken.new(JWT.encode(payload, secret, 'HS256', kid: 'hmac-kid'))
        jwks = { keys: [hmac_export] }

        expect do
          selector(jwks, algorithms: ['RS256']).call(hmac_token)
        end.to raise_error(JWT::VerificationKeyError) do |error|
          expect(error.message).not_to include(secret)
          expect(error.message).not_to include(encoded_secret)
        end

        shared = { keys: Array.new(6) { hmac_export.merge(kid: 'shared-hmac') } }
        shared_token = JWT::EncodedToken.new(JWT.encode(payload, secret, 'HS256', kid: 'shared-hmac'))
        expect do
          selector(shared, algorithms: ['HS256'], max_candidates: 5).call(shared_token)
        end.to raise_error(JWT::TooManyCandidateKeys) do |error|
          expect(error.message).not_to include(secret)
          expect(error.message).not_to include(encoded_secret)
        end
      end

      def assert_no_private_material(error, private_components)
        private_components.each { |component| expect(error.message).not_to include(component) }
        expect(error.message).not_to include('BEGIN')
      end
    end
  end

  describe 'through JWT.decode' do
    let(:jwks) { { keys: [jwk.export, other_jwk.export] } }
    let(:encoded_token) { JWT.encode(payload, jwk.signing_key, algorithm, kid: jwk.kid) }

    it 'decodes regardless of the position of the verifying key' do
      key_selector = described_class.new(jwks: jwks, algorithms: [algorithm])
      decoded, _header = JWT.decode(encoded_token, nil, true,
                                    algorithms: [algorithm], jwk_key_finder: key_selector)
      expect(decoded).to eq(payload)

      reversed = described_class.new(jwks: { keys: jwks[:keys].reverse }, algorithms: [algorithm])
      decoded, _header = JWT.decode(encoded_token, nil, true,
                                    algorithms: [algorithm], jwk_key_finder: reversed)
      expect(decoded).to eq(payload)
    end

    it 'works directly as an EncodedToken key finder' do
      key_selector = described_class.new(jwks: jwks, algorithms: [algorithm])
      expect(token.verify_signature!(algorithm: algorithm, key_finder: key_selector)).to eq(nil)
    end
  end

  describe 'legacy single key callback stability' do
    let(:encoded_token) { JWT.encode(payload, jwk.signing_key, algorithm, kid: jwk.kid) }

    it 'keeps the order dependent behaviour of the plain jwks option unchanged' do
      jwks = { keys: [jwk.export, other_jwk.export] }
      decoded, _header = JWT.decode(encoded_token, nil, true, algorithms: [algorithm], jwks: jwks)
      expect(decoded).to eq(payload)

      swapped = { keys: jwks[:keys].reverse }
      expect do
        JWT.decode(encoded_token, nil, true, algorithms: [algorithm], jwks: swapped)
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end
  end

  def build_custom_algorithm(name)
    Class.new do
      include JWT::JWA::SigningAlgorithm

      define_method(:initialize) do
        @alg = name
      end

      def sign(data:, signing_key:)
        'signature'
      end

      def verify(**_kwargs)
        true
      end
    end.new
  end
end

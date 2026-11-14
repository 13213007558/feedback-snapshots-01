# frozen_string_literal: true

RSpec.describe JWT::Policy::IdentityVerifier do
  let(:secret) { 'a-very-long-shared-secret-key-for-hmac' }
  let(:issuer) { 'https://issuer.example' }
  let(:algorithm) { 'HS256' }

  let(:login_typ) { 'login+jwt' }
  let(:api_typ) { 'api+jwt' }
  let(:login_aud) { 'web-app' }
  let(:api_aud) { 'api-gateway' }

  let(:login_payload) do
    { 'iss' => issuer, 'aud' => login_aud, 'sub' => 'user-1', 'nonce' => 'abc', 'exp' => Time.now.to_i + 300 }
  end
  let(:api_payload) do
    { 'iss' => issuer, 'aud' => api_aud, 'sub' => 'user-1', 'scope' => 'read', 'exp' => Time.now.to_i + 300 }
  end

  def encode_token(payload, typ, key = secret, alg = algorithm, extra_headers = {})
    JWT.encode(payload, key, alg, { 'typ' => typ }.merge(extra_headers))
  end

  let(:login_token) { encode_token(login_payload, login_typ) }
  let(:api_token) { encode_token(api_payload, api_typ) }

  subject(:verifier) do
    described_class.new do |register|
      register.policy(
        purpose: :login,
        issuers: issuer,
        algorithms: algorithm,
        typ: login_typ,
        audience: login_aud,
        required_claims: %w[sub nonce],
        key: secret
      )
      register.policy(
        purpose: :api,
        issuers: issuer,
        algorithms: algorithm,
        typ: api_typ,
        audience: api_aud,
        required_claims: %w[sub],
        key: secret
      )
    end
  end

  describe '#verify on the matching purpose' do
    it 'returns a usable identity for the login token' do
      identity = verifier.verify(login_token, purpose: :login)

      expect(identity).to be_a(JWT::Policy::VerifiedIdentity)
      expect(identity.purpose).to eq(:login)
      expect(identity.subject).to eq('user-1')
      expect(identity.payload).to eq(login_payload)
      expect(identity.header['typ']).to eq(login_typ)
      expect(identity.policy.purpose).to eq(:login)
    end

    it 'returns a usable identity for the API token' do
      identity = verifier.verify(api_token, purpose: :api)

      expect(identity.purpose).to eq(:api)
      expect(identity.subject).to eq('user-1')
      expect(identity.payload).to eq(api_payload)
    end

    context 'with a JWK set key source' do
      subject(:verifier) do
        rsa = test_pkey('rsa-2048-private.pem')
        jwk = JWT::JWK.new(rsa)
        jwks = { keys: [jwk.export] }

        described_class.new do |register|
          register.policy(
            purpose: :login,
            issuers: issuer,
            algorithms: 'RS256',
            typ: login_typ,
            audience: login_aud,
            required_claims: %w[sub],
            jwks: jwks
          )
        end
      end

      let(:rsa_token) do
        rsa = test_pkey('rsa-2048-private.pem')
        encode_token(login_payload, login_typ, rsa, 'RS256', 'kid' => JWT::JWK.new(rsa).kid)
      end

      it 'resolves the key from the configured set and verifies' do
        identity = verifier.verify(rsa_token, purpose: :login)
        expect(identity.subject).to eq('user-1')
      end
    end
  end

  describe 'cross-purpose delivery' do
    it 'rejects an API token presented to the login endpoint' do
      expect { verifier.verify(api_token, purpose: :login) }
        .to raise_error(JWT::InvalidTypError, /Expected .*login\+jwt.* received api\+jwt/)
    end

    it 'rejects a login token presented to the API endpoint' do
      expect { verifier.verify(login_token, purpose: :api) }
        .to raise_error(JWT::InvalidTypError, /Expected .*api\+jwt.* received login\+jwt/)
    end

    it 'rejects when only the audience differs but typ matches the wrong purpose' do
      swapped = encode_token(api_payload.merge('aud' => login_aud), api_typ)
      expect { verifier.verify(swapped, purpose: :login) }
        .to raise_error(JWT::InvalidTypError)
    end
  end

  describe 'individual constraint failures' do
    it 'rejects an untrusted issuer before any key lookup' do
      fetch_calls = 0
      loader = ->(options) { fetch_calls += 1; { keys: [] } }
      policy_verifier = described_class.new do |register|
        register.policy(
          purpose: :login, issuers: issuer, algorithms: algorithm,
          typ: login_typ, audience: login_aud, required_claims: %w[sub], jwks: loader
        )
      end
      evil = encode_token(login_payload.merge('iss' => 'https://evil.example'), login_typ)

      expect { policy_verifier.verify(evil, purpose: :login) }
        .to raise_error(JWT::InvalidIssuerError, /trusted|issuer.example/)
      expect(fetch_calls).to eq(0)
    end

    it 'rejects a disallowed algorithm' do
      none_like = encode_token(login_payload, login_typ, secret, 'HS384')
      expect { verifier.verify(none_like, purpose: :login) }
        .to raise_error(JWT::IncorrectAlgorithm, /HS256/)
    end

    it 'rejects a missing typ header' do
      token = JWT.encode(login_payload, secret, algorithm)
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::InvalidTypError, /<none>/)
    end

    it 'rejects a wrong audience' do
      token = encode_token(login_payload.merge('aud' => 'someone-else'), login_typ)
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::InvalidAudError)
    end

    it 'rejects a missing required claim' do
      token = encode_token(login_payload.reject { |k| k == 'nonce' }, login_typ)
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::MissingRequiredClaim, /nonce/)
    end

    it 'rejects an expired token' do
      token = encode_token(login_payload.merge('exp' => Time.now.to_i - 10), login_typ)
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::ExpiredSignature)
    end

    it 'rejects a token that is not yet valid (nbf)' do
      token = encode_token(login_payload.merge('nbf' => Time.now.to_i + 300), login_typ)
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::ImmatureSignature)
    end

    it 'rejects a token with an invalid signature' do
      token = encode_token(login_payload, login_typ, 'a-different-secret-value')
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::VerificationError)
    end

    it 'rejects a malformed token' do
      expect { verifier.verify('not-a-jwt', purpose: :login) }
        .to raise_error(JWT::MalformedTokenError)
    end

    it 'rejects an unknown purpose without consulting the token' do
      expect { verifier.verify(login_token, purpose: :not_registered) }
        .to raise_error(JWT::UnknownPurposeError, /not_registered/)
    end
  end

  describe 'unverified token cannot choose the key source' do
    it 'rejects a jku header without performing a fetch' do
      token = encode_token(login_payload, login_typ, secret, algorithm, 'jku' => 'https://evil.example/keys')
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::VerificationKeyError, /jku/)
    end

    it 'rejects an x5u header' do
      token = encode_token(login_payload, login_typ, secret, algorithm, 'x5u' => 'https://evil.example/cert')
      expect { verifier.verify(token, purpose: :login) }
        .to raise_error(JWT::VerificationKeyError, /x5u/)
    end
  end

  describe '#valid?' do
    it 'is true for a matching token' do
      expect(verifier.valid?(login_token, purpose: :login)).to be(true)
    end

    it 'is false for a cross-purpose token' do
      expect(verifier.valid?(api_token, purpose: :login)).to be(false)
    end
  end

  describe 'legacy JWT.decode compatibility' do
    it 'still returns the payload/header array and is unaffected by the new layer' do
      payload, header = JWT.decode(login_token, secret, true, algorithms: [algorithm])
      expect(payload['sub']).to eq('user-1')
      expect(header['alg']).to eq(algorithm)
    end
  end
end

RSpec.describe JWT::Policy::Registry do
  let(:secret) { 'a-very-long-shared-secret-key-for-hmac' }

  def policy(purpose, typ, audience, overrides = {})
    JWT::Policy::VerificationPolicy.new(
      purpose: purpose,
      issuers: 'iss',
      algorithms: 'HS256',
      typ: typ,
      audience: audience,
      key: secret,
      **overrides
    )
  end

  subject(:registry) { described_class.new }

  it 'stores and fetches policies by purpose' do
    p = policy(:login, 'login+jwt', 'web')
    registry.register(p)
    expect(registry.fetch(:login)).to be(p)
  end

  it 'raises when registering the same purpose twice' do
    registry.register(policy(:login, 'login+jwt', 'web'))
    expect { registry.register(policy(:login, 'other+jwt', 'web2')) }
      .to raise_error(JWT::PolicyError, /already registered/)
  end

  it 'raises a diagnostic error when two policies fully overlap instead of silently keeping the first' do
    registry.register(policy(:login, 'shared+jwt', 'shared'))
    expect { registry.register(policy(:api, 'shared+jwt', 'shared')) }
      .to raise_error(JWT::PolicyError, /:login and :api overlap on every discriminator/)
  end

  it 'allows policies that differ in at least one discriminator dimension' do
    registry.register(policy(:login, 'login+jwt', 'shared'))
    expect { registry.register(policy(:api, 'api+jwt', 'shared')) }.not_to raise_error
  end

  it 'treats array-valued constraints as overlapping on shared members' do
    registry.register(policy(:login, %w[t1 t2], 'shared'))
    expect { registry.register(policy(:api, 't2', 'shared')) }
      .to raise_error(JWT::PolicyError, /overlap/)
  end

  it 'raises UnknownPurposeError for an unregistered purpose' do
    expect { registry.fetch(:missing) }
      .to raise_error(JWT::UnknownPurposeError, /missing/)
  end
end

RSpec.describe JWT::Policy::VerificationPolicy do
  let(:secret) { 'a-very-long-shared-secret-key-for-hmac' }

  it 'normalizes scalar constraints into arrays' do
    p = described_class.new(purpose: :x, issuers: 'iss', algorithms: 'HS256',
                            typ: 't', audience: 'a', key: secret)
    expect(p.issuers).to eq(['iss'])
    expect(p.algorithms).to eq(['HS256'])
    expect(p.types).to eq(['t'])
    expect(p.audiences).to eq(['a'])
  end

  it 'requires an issuer' do
    expect do
      described_class.new(purpose: :x, issuers: [], algorithms: 'HS256', typ: 't', audience: 'a', key: secret)
    end.to raise_error(JWT::PolicyError, /issuers/)
  end

  it 'requires an algorithm' do
    expect do
      described_class.new(purpose: :x, issuers: 'iss', algorithms: [], typ: 't', audience: 'a', key: secret)
    end.to raise_error(JWT::PolicyError, /algorithms/)
  end

  it 'requires a typ' do
    expect do
      described_class.new(purpose: :x, issuers: 'iss', algorithms: 'HS256', typ: [], audience: 'a', key: secret)
    end.to raise_error(JWT::PolicyError, /typ/)
  end

  it 'requires an audience' do
    expect do
      described_class.new(purpose: :x, issuers: 'iss', algorithms: 'HS256', typ: 't', audience: [], key: secret)
    end.to raise_error(JWT::PolicyError, /audience/)
  end

  it 'requires either a static key or a jwks source' do
    expect do
      described_class.new(purpose: :x, issuers: 'iss', algorithms: 'HS256', typ: 't', audience: 'a')
    end.to raise_error(JWT::PolicyError, /static :key or a :jwks source/)
  end

  it 'exposes jwk options for a loader-backed policy' do
    loader = ->(_opts) { { keys: [] } }
    p = described_class.new(purpose: :x, issuers: 'iss', algorithms: 'HS256',
                            typ: 't', audience: 'a', jwks: loader, allow_nil_kid: true)
    expect(p).to be_jwks
    expect(p.jwk_options[:jwks]).to be(loader)
    expect(p.jwk_options[:allow_nil_kid]).to be(true)
  end
end

RSpec.describe JWT::Policy::TypVerifier do
  it 'passes when the header typ is accepted' do
    expect { described_class.new(expected_types: 'login+jwt').verify!(header: { 'typ' => 'login+jwt' }) }.not_to raise_error
  end

  it 'passes when the typ is one of several accepted values' do
    expect { described_class.new(expected_types: %w[a b]).verify!(header: { 'typ' => 'b' }) }.not_to raise_error
  end

  it 'raises when the typ does not match' do
    expect { described_class.new(expected_types: 'login+jwt').verify!(header: { 'typ' => 'api+jwt' }) }
      .to raise_error(JWT::InvalidTypError, /login\+jwt.*api\+jwt/)
  end

  it 'raises when the typ header is absent' do
    expect { described_class.new(expected_types: 'login+jwt').verify!(header: {}) }
      .to raise_error(JWT::InvalidTypError, /<none>/)
  end
end

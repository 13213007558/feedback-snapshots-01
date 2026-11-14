# frozen_string_literal: true

# Boundary tests for the key_finder callback contract.
#
# These tests pin down exactly which unverified inputs reach a key finder
# callback (for example a database query), how many times it is called, and
# which verification phase runs afterwards. A parsed header/payload is NOT
# trusted data: the callback always runs before the signature is verified.
RSpec.describe 'key_finder callback boundary' do
  let(:secret) { 'secret' }
  let(:store) { SpecSupport::CountingKeyStore.new('good-kid' => secret) }
  let(:payload) { { 'sub' => '123', 'exp' => Time.now.to_i + 3600 } }

  def token_with(header, payload_segment: JWT::Base64.url_encode(JSON.generate(payload)), signature: 'sig')
    "#{JWT::Base64.url_encode(JSON.generate(header))}.#{payload_segment}.#{JWT::Base64.url_encode(signature)}"
  end

  let(:valid_token) { JWT.encode(payload, secret, 'HS256', { kid: 'good-kid' }) }
  let(:forged_token) { JWT.encode(payload, 'attacker-secret', 'HS256', { kid: 'good-kid' }) }

  shared_examples 'a guarded callback boundary' do
    it 'queries exactly once and succeeds for a valid token with an allowed algorithm' do
      expect(result).to eq(payload)
      expect(store.queries).to eq(['good-kid'])
    end

    it 'never queries for a header that is not valid JSON' do
      token = "#{JWT::Base64.url_encode('not json')}.#{JWT::Base64.url_encode('{}')}.c2ln"
      expect { attempt(token) }.to raise_error(JWT::MalformedTokenError)
      expect(store.query_count).to eq(0)
    end

    it 'never queries for a header that is not a JSON object' do
      token = "#{JWT::Base64.url_encode(JSON.generate(['HS256']))}.#{JWT::Base64.url_encode('{}')}.c2ln"
      expect { attempt(token) }.to raise_error(JWT::MalformedTokenError, 'Token header not a JSON object')
      expect(store.query_count).to eq(0)
    end

    it 'never queries when the algorithm is not in the allowlist' do
      token = JWT.encode(payload, secret, 'HS512', { kid: 'good-kid' })
      expect { attempt(token) }.to raise_error(error_class)
      expect(store.query_count).to eq(0)
    end

    it 'never queries for the none algorithm when it is not allowed' do
      expect { attempt(token_with({ 'alg' => 'none', 'kid' => 'good-kid' }, signature: '')) }
        .to raise_error(error_class)
      expect(store.query_count).to eq(0)
    end

    it 'never queries when the alg header is missing' do
      expect { attempt(token_with({ 'kid' => 'good-kid' })) }.to raise_error(error_class)
      expect(store.query_count).to eq(0)
    end

    it 'never queries for a token with too many segments' do
      expect { attempt("#{valid_token}.extra") }.to raise_error(JWT::MalformedTokenError)
      expect(store.query_count).to eq(0)
    end

    it 'passes abnormal kid types to the callback as raw unverified data' do
      [nil, 12_345, ['good-kid'], { '$gt' => '' }, true].each do |kid|
        store.queries.clear
        expect { attempt(token_with({ 'alg' => 'HS256', 'kid' => kid })) }.to raise_error(JWT::Error)
        expect(store.queries).to eq([kid])
      end
    end

    it 'queries exactly once for an invalid signature and does not trust the payload' do
      expect { attempt(forged_token) }.to raise_error(JWT::VerificationError)
      expect(store.queries).to eq(['good-kid'])
    end

    it 'queries exactly once when the kid is unknown and the store returns nil' do
      token = JWT.encode(payload, secret, 'HS256', { kid: 'unknown-kid' })
      expect { attempt(token) }.to raise_error(JWT::Error)
      expect(store.queries).to eq(['unknown-kid'])
    end
  end

  describe 'legacy JWT.decode interface' do
    # Contract: the block receives (header) or (header, payload) depending on
    # arity, both unverified. It runs after segment count, header JSON and alg
    # allowlist checks, but before signature and claims verification.
    # Returning nil/empty raises JWT::SignatureError; a raised error propagates.
    let(:error_class) { JWT::IncorrectAlgorithm }

    def attempt(token)
      JWT.decode(token, nil, true, algorithm: 'HS256') do |header|
        store.fetch(header['kid']) || raise(JWT::SignatureError, 'No verification key available')
      end
    end

    def result
      attempt(valid_token).first
    end

    it_behaves_like 'a guarded callback boundary'

    it 'delivers the raw unverified header to the callback before signature verification' do
      events = []
      JWT.decode(valid_token, nil, true, algorithm: 'HS256') do |header|
        events << [:callback, header]
        events << [:signature_verified_yet, false] # callback runs before signature check
        store.fetch(header['kid'])
      end
      expect(events.first).to eq([:callback, { 'alg' => 'HS256', 'kid' => 'good-kid' }])
    end

    it 'propagates an error raised by the callback and returns no payload' do
      expect do
        JWT.decode(valid_token, nil, true, algorithm: 'HS256') { raise IOError, 'database is down' }
      end.to raise_error(IOError, 'database is down')
    end

    it 'raises JWT::SignatureError when the callback returns nil' do
      expect do
        JWT.decode(valid_token, nil, true, algorithm: 'HS256') { nil }
      end.to raise_error(JWT::SignatureError, 'No verification key available')
    end

    it 'fails verification when the callback returns an incompatible key' do
      expect do
        JWT.decode(valid_token, nil, true, algorithm: 'HS256') { OpenSSL::PKey::RSA.generate(2048).public_key }
      end.to raise_error(JWT::Error)
    end

    it 'parses the payload before an arity-2 callback runs, rejecting malformed payloads early' do
      token = token_with({ 'alg' => 'HS256', 'kid' => 'good-kid' }, payload_segment: '!!!')
      expect do
        JWT.decode(token, nil, true, algorithm: 'HS256') { |_header, payload| store.fetch(payload) }
      end.to raise_error(JWT::Base64DecodeError)
      expect(store.query_count).to eq(0)
    end

    it 'may still invoke an arity-1 callback for a malformed payload (parsed is not trusted)' do
      token = token_with({ 'alg' => 'HS256', 'kid' => 'good-kid' }, payload_segment: '!!!')
      expect do
        JWT.decode(token, nil, true, algorithm: 'HS256') { |header| store.fetch(header['kid']) }
      end.to raise_error(JWT::Error)
      expect(store.queries).to eq(['good-kid'])
    end
  end

  describe 'JWT::EncodedToken object interface' do
    # Contract: key_finder receives the JWT::EncodedToken and runs after
    # segment count, header JSON, alg allowlist and signature-segment checks,
    # but before the signature itself is verified. #payload stays inaccessible
    # until both signature and claims are verified.
    let(:error_class) { JWT::VerificationError }

    def attempt(token)
      encoded_token = JWT::EncodedToken.new(token)
      encoded_token.verify_signature!(algorithm: 'HS256', key_finder: ->(t) { store.fetch(t.header['kid']) })
      encoded_token.verify_claims!
      encoded_token.payload
    end

    def result
      attempt(valid_token)
    end

    it_behaves_like 'a guarded callback boundary'

    it 'runs the callback before the signature is verified' do
      events = []
      encoded_token = JWT::EncodedToken.new(valid_token)
      encoded_token.verify_signature!(algorithm: 'HS256', key_finder: lambda { |t|
        events << [:callback, t.header['kid']]
        store.fetch(t.header['kid'])
      })
      events << [:signature_verified]
      expect(events).to eq([[:callback, 'good-kid'], [:signature_verified]])
    end

    it 'never queries for a token without a signature segment' do
      token = valid_token.split('.')[0..1].join('.')
      encoded_token = JWT::EncodedToken.new(token)
      expect do
        encoded_token.verify_signature!(algorithm: 'HS256', key_finder: ->(t) { store.fetch(t.header['kid']) })
      end.to raise_error(JWT::VerificationError)
      expect(store.query_count).to eq(0)
    end

    it 'keeps the payload unreadable when the callback raises' do
      encoded_token = JWT::EncodedToken.new(valid_token)
      expect do
        encoded_token.verify_signature!(algorithm: 'HS256', key_finder: ->(_t) { raise IOError, 'database is down' })
      end.to raise_error(IOError, 'database is down')
      expect { encoded_token.payload }.to raise_error(JWT::TokenError)
    end

    it 'keeps the payload unreadable when the callback returns nil' do
      encoded_token = JWT::EncodedToken.new(valid_token)
      expect do
        encoded_token.verify_signature!(algorithm: 'HS256', key_finder: ->(_t) { nil })
      end.to raise_error(JWT::VerificationError)
      expect { encoded_token.payload }.to raise_error(JWT::TokenError)
    end

    it 'keeps the payload unreadable when the callback returns an incompatible key' do
      encoded_token = JWT::EncodedToken.new(valid_token)
      expect do
        encoded_token.verify_signature!(algorithm: 'HS256', key_finder: ->(_t) { OpenSSL::PKey::RSA.generate(2048).public_key })
      end.to raise_error(JWT::Error)
      expect { encoded_token.payload }.to raise_error(JWT::TokenError)
    end

    it 'keeps the payload unreadable after a failed verification with a valid key' do
      encoded_token = JWT::EncodedToken.new(forged_token)
      expect do
        encoded_token.verify_signature!(algorithm: 'HS256', key_finder: ->(t) { store.fetch(t.header['kid']) })
      end.to raise_error(JWT::VerificationError)
      expect { encoded_token.payload }.to raise_error(JWT::TokenError, 'Verify the token signature before accessing the payload')
    end

    it 'keeps the payload unreadable when only the signature is verified but claims are not' do
      encoded_token = JWT::EncodedToken.new(valid_token)
      encoded_token.verify_signature!(algorithm: 'HS256', key_finder: ->(t) { store.fetch(t.header['kid']) })
      expect { encoded_token.payload }.to raise_error(JWT::TokenError, 'Verify the token claims before accessing the payload')
    end
  end

  describe 'JWKS loader query amplification' do
    it 'rejects abnormal kid types without hitting the loader' do
      loader_calls = []
      loader = ->(options) { loader_calls << options and { keys: [] } }
      token = token_with({ 'alg' => 'HS256', 'kid' => { '$gt' => '' } })
      expect { JWT.decode(token, nil, true, algorithm: 'HS256', jwks: loader) }
        .to raise_error(JWT::MalformedTokenError, 'Invalid type for kid header parameter')
      expect(loader_calls).to eq([])
    end

    it 'documents the invalidation retry: an unknown kid triggers two loader calls' do
      loader_calls = []
      loader = ->(options) { loader_calls << options and { keys: [] } }
      token = JWT.encode(payload, secret, 'HS256', { kid: 'unknown-kid' })
      expect { JWT.decode(token, nil, true, algorithm: 'HS256', jwks: loader) }
        .to raise_error(JWT::SignatureError)
      expect(loader_calls.size).to eq(2)
      expect(loader_calls.last).to include(invalidate: true, kid_not_found: true)
    end
  end
end

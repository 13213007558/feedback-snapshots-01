# frozen_string_literal: true

RSpec.describe JWT::StrictKeyFinder do
  let(:secret) { 'secret' }
  let(:payload) { { 'sub' => '123' } }
  let(:loader_calls) { [] }
  let(:loader) { ->(kid) { loader_calls << kid and { 'good-kid' => secret }[kid] } }
  let(:finder) { described_class.new(&loader) }

  def token_with(header, signature: 'sig')
    "#{JWT::Base64.url_encode(JSON.generate(header))}.#{JWT::Base64.url_encode(JSON.generate(payload))}.#{JWT::Base64.url_encode(signature)}"
  end

  it 'requires a loader block' do
    expect { described_class.new }.to raise_error(ArgumentError, 'Provide a key loader block')
  end

  describe '#call with an EncodedToken' do
    it 'passes a String kid to the loader exactly once and returns the key' do
      token = JWT::EncodedToken.new(JWT.encode(payload, secret, 'HS256', { kid: 'good-kid' }))
      expect(finder.call(token)).to eq(secret)
      expect(loader_calls).to eq(['good-kid'])
    end

    it 'rejects a token without a signature segment before loading' do
      token = JWT::EncodedToken.new(token_with({ 'alg' => 'HS256', 'kid' => 'good-kid' }).sub(/\.[^.]*$/, ''))
      expect { finder.call(token) }.to raise_error(JWT::MalformedTokenError, 'Token is missing a signature segment')
      expect(loader_calls).to eq([])
    end

    it 'allows an unsigned token when the alg is none' do
      token = JWT::EncodedToken.new(token_with({ 'alg' => 'none', 'kid' => 'good-kid' }, signature: '').sub(/\.[^.]*$/, ''))
      expect { finder.call(token) }.not_to raise_error
      expect(loader_calls).to eq(['good-kid'])
    end

    [12_345, ['good-kid'], { '$gt' => '' }, true].each do |kid|
      it "rejects a non-String kid (#{kid.inspect}) before loading" do
        token = JWT::EncodedToken.new(token_with({ 'alg' => 'HS256', 'kid' => kid }))
        expect { finder.call(token) }.to raise_error(JWT::MalformedTokenError, 'Invalid type for kid header parameter')
        expect(loader_calls).to eq([])
      end
    end

    it 'rejects a missing kid before loading' do
      token = JWT::EncodedToken.new(token_with({ 'alg' => 'HS256' }))
      expect { finder.call(token) }.to raise_error(JWT::SignatureError, 'No key id (kid) found in token header')
      expect(loader_calls).to eq([])
    end

    context 'with allow_nil_kid' do
      let(:finder) { described_class.new(allow_nil_kid: true, &loader) }

      it 'passes nil to the loader' do
        token = JWT::EncodedToken.new(token_with({ 'alg' => 'HS256' }))
        finder.call(token)
        expect(loader_calls).to eq([nil])
      end
    end

    context 'with kid_format' do
      let(:finder) { described_class.new(kid_format: /\A[\w-]+\z/, &loader) }

      it 'rejects a kid not matching the format before loading' do
        token = JWT::EncodedToken.new(token_with({ 'alg' => 'HS256', 'kid' => '1 OR 1=1' }))
        expect { finder.call(token) }
          .to raise_error(JWT::SignatureError, 'Key id (kid) in token header does not match the expected format')
        expect(loader_calls).to eq([])
      end

      it 'accepts a kid matching the format' do
        token = JWT::EncodedToken.new(token_with({ 'alg' => 'HS256', 'kid' => 'good-kid' }))
        expect(finder.call(token)).to eq(secret)
      end
    end
  end

  describe 'integration with JWT::EncodedToken#verify_signature!' do
    it 'verifies a valid token' do
      token = JWT::EncodedToken.new(JWT.encode(payload, secret, 'HS256', { kid: 'good-kid' }))
      expect(token.verify_signature!(algorithm: 'HS256', key_finder: finder)).to eq(nil)
      expect(loader_calls).to eq(['good-kid'])
    end

    it 'does not query when the algorithm is not allowed' do
      token = JWT::EncodedToken.new(JWT.encode(payload, secret, 'HS512', { kid: 'good-kid' }))
      expect do
        token.verify_signature!(algorithm: 'HS256', key_finder: finder)
      end.to raise_error(JWT::VerificationError)
      expect(loader_calls).to eq([])
    end
  end

  describe 'integration with the legacy JWT.decode interface' do
    it 'verifies a valid token via #to_proc' do
      token = JWT.encode(payload, secret, 'HS256', { kid: 'good-kid' })
      decoded, = JWT.decode(token, nil, true, algorithm: 'HS256', &finder)
      expect(decoded).to eq(payload)
      expect(loader_calls).to eq(['good-kid'])
    end

    it 'rejects an abnormal kid without querying' do
      token = token_with({ 'alg' => 'HS256', 'kid' => { '$gt' => '' } })
      expect { JWT.decode(token, nil, true, algorithm: 'HS256', &finder) }
        .to raise_error(JWT::MalformedTokenError, 'Invalid type for kid header parameter')
      expect(loader_calls).to eq([])
    end
  end
end

# frozen_string_literal: true

RSpec.describe Faraday::Request::DigestVerification do
  let(:app) { double('app') }
  let(:body) { '{"name":"YK"}' }
  let(:approved) { Digest::SHA256.hexdigest(body) }

  def env_for(request_body, headers = {})
    Faraday::Env.from(
      method: :post,
      body: request_body,
      url: Faraday::Utils.URI('http://example.test/uploads'),
      request_headers: Faraday::Utils::Headers.new(headers)
    )
  end

  def build_middleware(options = {})
    described_class.new(app, options)
  end

  describe 'unit-level behavior' do
    it 'passes a small string body through when the digest matches' do
      middleware = build_middleware(approved_digest: approved)
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(body))
    end

    it 'raises DigestMismatchError and does not call the app when the digest differs' do
      middleware = build_middleware(approved_digest: Digest::SHA256.hexdigest('other'))
      expect(app).not_to receive(:call)

      expect { middleware.call(env_for(body)) }
        .to raise_error(Faraday::DigestMismatchError)
    end

    it 'is a transparent pass-through when no approved digest is configured' do
      middleware = build_middleware
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(body))
    end

    it 'skips verification when a callable approved digest resolves to nil' do
      middleware = build_middleware(approved_digest: ->(_env) { nil })
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(body))
    end

    it 'accepts a callable approved digest based on the env' do
      middleware = build_middleware(approved_digest: ->(env) { Digest::SHA256.hexdigest(env.body) })
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(body))
    end

    it 'accepts an upcase or raw binary approved digest' do
      middleware = build_middleware(approved_digest: approved.upcase)
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(body))
    end

    it 'accepts the raw binary (packed) form of the approved digest' do
      raw = Digest::SHA256.digest(body)
      middleware = build_middleware(approved_digest: raw)
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(body))
    end

    it 'verifies an empty string body against its own digest' do
      empty_digest = Digest::SHA256.hexdigest('')
      middleware = build_middleware(approved_digest: empty_digest)
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(''))
    end

    it 'supports a custom digest algorithm' do
      md5 = Digest::MD5.hexdigest(body)
      middleware = build_middleware(approved_digest: md5, algorithm: Digest::MD5)
      expect(app).to receive(:call).with(an_instance_of(Faraday::Env))

      middleware.call(env_for(body))
    end

    it 'verifies a rewindable streaming upload and rewinds it for the adapter' do
      stream = StringIO.new(body)
      middleware = build_middleware(approved_digest: approved)
      expect(app).to receive(:call) do |env|
        expect(env.body.pos).to eq(0)
        expect(env.body.read).to eq(body)
      end

      middleware.call(env_for(stream))
      stream.rewind
      expect(stream.read).to eq(body)
      stream.close
    end

    it 'raises UnverifiableBodyError for a stream that cannot be rewound' do
      stream = double('unrewindable stream', read: body)
      middleware = build_middleware(approved_digest: approved)
      expect(app).not_to receive(:call)

      expect { middleware.call(env_for(stream)) }
        .to raise_error(Faraday::UnverifiableBodyError)
    end

    it 'raises UnverifiableBodyError for a body that is neither a string nor a stream' do
      middleware = build_middleware(approved_digest: approved)
      expect(app).not_to receive(:call)

      expect { middleware.call(env_for(Object.new)) }
        .to raise_error(Faraday::UnverifiableBodyError)
    end

    it 'raises UnverifiableBodyError for a nil body with an approved digest' do
      middleware = build_middleware(approved_digest: approved)
      expect(app).not_to receive(:call)

      expect { middleware.call(env_for(nil)) }
        .to raise_error(Faraday::UnverifiableBodyError)
    end

    it 'derives both failures from the common DigestVerificationError' do
      mismatch = Faraday::DigestMismatchError.new
      unverifiable = Faraday::UnverifiableBodyError.new
      expect(mismatch).to be_a(Faraday::DigestVerificationError)
      expect(unverifiable).to be_a(Faraday::DigestVerificationError)
    end
  end

  describe 'with the Test adapter' do
    def read_body(request_body)
      if request_body.respond_to?(:read)
        request_body.rewind if request_body.respond_to?(:rewind)
        request_body.read
      else
        request_body.to_s
      end
    end

    def build_connection(approved_digest, extra_middleware = nil)
      Faraday.new do |builder|
        extra_middleware&.call(builder)
        builder.request :digest_verification, approved_digest: approved_digest
        builder.adapter :test do |stub|
          stub.post('/uploads') { |env| [200, {}, read_body(env[:body])] }
        end
      end
    end

    it 'allows an ordinarily JSON-encoded body whose final digest is approved' do
      approved = Digest::SHA256.hexdigest('{"a":1}')
      conn = Faraday.new do |builder|
        builder.request :json
        builder.request :digest_verification, approved_digest: approved
        builder.adapter :test do |stub|
          stub.post('/uploads') { |env| [200, {}, read_body(env[:body])] }
        end
      end

      response = conn.post('/uploads', { a: 1 }, 'Content-Type' => 'application/json')
      expect(response.status).to eq(200)
      expect(response.body).to eq('{"a":1}')
    end

    it 'blocks a reconstructed body whose digest differs from the approved version' do
      approved = Digest::SHA256.hexdigest('{"a":1}')
      conn = Faraday.new do |builder|
        builder.request :json
        builder.request :digest_verification, approved_digest: approved
        builder.adapter :test do |stub|
          stub.post('/uploads') { |env| [200, {}, read_body(env[:body])] }
        end
      end

      expect { conn.post('/uploads', { a: 2 }, 'Content-Type' => 'application/json') }
        .to raise_error(Faraday::DigestMismatchError)
    end

    it 'does not let unapproved data reach the adapter' do
      approved = Digest::SHA256.hexdigest('{"a":1}')
      sent_bodies = []
      conn = Faraday.new do |builder|
        builder.request :json
        builder.request :digest_verification, approved_digest: approved
        builder.adapter :test do |stub|
          stub.post('/uploads') do |env|
            sent_bodies << read_body(env[:body])
            [200, {}, '']
          end
        end
      end

      expect { conn.post('/uploads', { tampered: true }, 'Content-Type' => 'application/json') }
        .to raise_error(Faraday::DigestMismatchError)
      expect(sent_bodies).to be_empty
    end

    it 'verifies a StringIO streaming upload end to end' do
      approved = Digest::SHA256.hexdigest(body)
      conn = build_connection(approved)
      stream = StringIO.new(body)

      response = conn.post('/uploads', stream)
      expect(response.status).to eq(200)
      expect(response.body).to eq(body)
    end

    it 'blocks an unverifiable non-rewindable stream before the adapter' do
      sent_bodies = []
      conn = Faraday.new do |builder|
        builder.request :digest_verification, approved_digest: approved
        builder.adapter :test do |stub|
          stub.post('/uploads') do |env|
            sent_bodies << env[:body]
            [200, {}, '']
          end
        end
      end

      stream = Object.new
      def stream.read(*)
        'chunk'
      end

      expect { conn.post('/uploads', stream) }
        .to raise_error(Faraday::UnverifiableBodyError)
      expect(sent_bodies).to be_empty
    end

    it 'sends normally when no digest is approved even if middleware stays in the stack' do
      conn = build_connection(nil)
      response = conn.post('/uploads', body)
      expect(response.status).to eq(200)
      expect(response.body).to eq(body)
    end

    it 'checks the url-encoded body produced by another request middleware' do
      encoded = Faraday::Utils.build_nested_query(name: 'YK')
      approved = Digest::SHA256.hexdigest(encoded)
      sent_bodies = []
      conn = Faraday.new do |builder|
        builder.request :url_encoded
        builder.request :digest_verification, approved_digest: approved
        builder.adapter :test do |stub|
          stub.post('/uploads') do |env|
            sent_bodies << read_body(env[:body])
            [200, {}, '']
          end
        end
      end

      conn.post('/uploads', name: 'YK')
      expect(sent_bodies).to eq([encoded])

      expect { conn.post('/uploads', name: 'tampered') }
        .to raise_error(Faraday::DigestMismatchError)
    end
  end
end

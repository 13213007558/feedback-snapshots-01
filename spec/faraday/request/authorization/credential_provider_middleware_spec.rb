# frozen_string_literal: true

RSpec.describe Faraday::Request::Authorization do
  # Controllable provider. Each lookup bumps a counter and is allowed to
  # flip from approved to denied between attempts via `deny_after`.
  let(:provider_class) do
    Class.new(Faraday::Request::Authorization::CredentialProvider) do
      attr_reader :env_seen, :results

      def initialize(deny_after: nil)
        super()
        @deny_after = deny_after
        @lookup = 0
        @env_seen = []
        @results = []
      end

      def fetch_credential(env, state)
        @env_seen << env
        @lookup += 1
        result =
          if @deny_after && @lookup > @deny_after
            Faraday::Request::Authorization::CredentialResult
              .denied('credential rotated', version: state.version)
          else
            Faraday::Request::Authorization::CredentialResult
              .approved("v-credential-#{state.version || 1}", version: state.version || 42)
          end
        @results << result
        result
      end
    end
  end

  let(:provider) { provider_class.new }

  let(:conn) do
    Faraday.new do |b|
      b.request :authorization, 'Bearer', provider
      b.adapter :test do |stub|
        stub.get('/auth-echo') do |env|
          [200, {}, env[:request_headers]['Authorization']]
        end
      end
    end
  end

  describe 'approved credential' do
    it 'sets the Authorization header from the provider result' do
      response = conn.get('/auth-echo')
      expect(response.body).to eq('Bearer v-credential-1')
    end

    it 'consults the provider once for a single request and marks an outbound attempt' do
      conn.get('/auth-echo')

      state = provider.request_state(provider.request_ids.first)
      expect(state.fetch_count).to eq(1)
      expect(state).to be_outbound_attempted
      expect(provider.env_seen.size).to eq(1)
    end

    it 'passes the request env to the provider' do
      conn.get('/auth-echo')
      expect(provider.env_seen.first).to be_a(Faraday::Env)
    end
  end

  describe 'retry reconfirmation' do
    # Simulates a retry middleware re-running the stack with the same env.
    def run_twice(middleware, env)
      middleware.on_request(env)
      middleware.on_request(env)
    end

    it 'reconsults the provider and keeps one stable request id on retry' do
      app = double('app', call: double(on_complete: nil))
      middleware = described_class.new(app, 'Bearer', provider)
      env = Faraday::Env.new(:get, nil, Faraday::Utils::URI('http://example.com/x'),
                             Faraday::RequestOptions.new, Faraday::Utils::Headers.new, {})

      run_twice(middleware, env)

      session = env[Faraday::Request::Authorization::CredentialProvider::ENV_SESSION_KEY]
      state = provider.request_state(session.request_id)
      expect(state.fetch_count).to eq(2)
      expect(provider.request_ids).to contain_exactly(session.request_id)
    end

    it 'reuses the version pinned by the first attempt for the retry' do
      app = double('app', call: double(on_complete: nil))
      middleware = described_class.new(app, 'Bearer', provider)
      env = Faraday::Env.new(:get, nil, Faraday::Utils::URI('http://example.com/x'),
                             Faraday::RequestOptions.new, Faraday::Utils::Headers.new, {})

      run_twice(middleware, env)

      expect(provider.results.map(&:version)).to eq([42, 42])
      expect(provider.request_state(provider.request_ids.first).version).to eq(42)
      expect(env.request_headers['Authorization']).to eq('Bearer v-credential-42')
    end

    it 'blocks the retry when the provider no longer approves the request' do
      revoking = provider_class.new(deny_after: 1)
      app = double('app', call: double(on_complete: nil))
      middleware = described_class.new(app, 'Bearer', revoking)
      env = Faraday::Env.new(:get, nil, Faraday::Utils::URI('http://example.com/x'),
                             Faraday::RequestOptions.new, Faraday::Utils::Headers.new, {})

      middleware.on_request(env)
      first_header = env.request_headers['Authorization']

      expect do
        middleware.on_request(env)
      end.to raise_error(described_class::CredentialDeniedError, 'credential rotated')

      session = env[Faraday::Request::Authorization::CredentialProvider::ENV_SESSION_KEY]
      state = revoking.request_state(session.request_id)
      expect(state.fetch_count).to eq(2)
      expect(session).to be_denied
      # The retry never produced a new outbound header; the first one stands.
      expect(env.request_headers['Authorization']).to eq(first_header)
    end

    it 'keeps refusing after a denial without consulting the provider again' do
      always_deny = provider_class.new(deny_after: 0)
      app = double('app', call: double(on_complete: nil))
      middleware = described_class.new(app, 'Bearer', always_deny)
      env = Faraday::Env.new(:get, nil, Faraday::Utils::URI('http://example.com/x'),
                             Faraday::RequestOptions.new, Faraday::Utils::Headers.new, {})

      expect { middleware.on_request(env) }
        .to raise_error(described_class::CredentialDeniedError)
      expect { middleware.on_request(env) }
        .to raise_error(described_class::CredentialDeniedError,
                        'credential provider already denied this request')

      session = env[Faraday::Request::Authorization::CredentialProvider::ENV_SESSION_KEY]
      state = always_deny.request_state(session.request_id)
      expect(state.fetch_count).to eq(1)
      expect(state).not_to be_outbound_attempted
    end
  end

  describe 'denial' do
    let(:provider) { provider_class.new(deny_after: 0) }

    it 'raises and sends no Authorization header' do
      expect { conn.get('/auth-echo') }
        .to raise_error(described_class::CredentialDeniedError)

      state = provider.request_state(provider.request_ids.first)
      expect(state).to be_denied
      expect(state).not_to be_outbound_attempted
    end

    it 'never calls the downstream app, so nothing goes out after denial' do
      app = double('app')
      expect(app).not_to receive(:call)
      middleware = described_class.new(app, 'Bearer', provider)
      env = Faraday::Env.new(:get, nil, Faraday::Utils::URI('http://example.com/x'),
                             Faraday::RequestOptions.new, Faraday::Utils::Headers.new, {})

      expect { middleware.call(env) }
        .to raise_error(described_class::CredentialDeniedError)
      expect(env.request_headers).not_to include('Authorization')
    end
  end

  describe 'precedence' do
    it 'does not call the provider when the request already sets the header' do
      conn.get('/auth-echo', nil, authorization: 'OAuth oauth_token')

      expect(provider.request_ids).to be_empty
    end

    it 'keeps static string credentials working without involving a provider' do
      static = Faraday.new do |b|
        b.request :authorization, 'Bearer', 'static-token'
        b.adapter :test do |stub|
          stub.get('/auth-echo') { |env| [200, {}, env[:request_headers]['Authorization']] }
        end
      end

      expect(static.get('/auth-echo').body).to eq('Bearer static-token')
    end

    it 'keeps callable credentials working' do
      callable_conn = Faraday.new do |b|
        b.request :authorization, 'Bearer', -> { 'from-proc' }
        b.adapter :test do |stub|
          stub.get('/auth-echo') { |env| [200, {}, env[:request_headers]['Authorization']] }
        end
      end

      expect(callable_conn.get('/auth-echo').body).to eq('Bearer from-proc')
    end
  end

  describe 'distinct requests' do
    it 'gives each request its own session and request id' do
      conn.get('/auth-echo')
      conn.get('/auth-echo')

      expect(provider.request_ids.size).to eq(2)
      provider.request_ids.each do |id|
        expect(provider.request_state(id).fetch_count).to eq(1)
      end
    end
  end
end

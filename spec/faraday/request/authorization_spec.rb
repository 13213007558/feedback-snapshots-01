# frozen_string_literal: true

RSpec.describe Faraday::Request::Authorization do
  let(:conn) do
    Faraday.new do |b|
      b.request :authorization, auth_type, *auth_config
      b.adapter :test do |stub|
        stub.get('/auth-echo') do |env|
          [200, {}, env[:request_headers]['Authorization']]
        end
      end
    end
  end

  shared_examples 'does not interfere with existing authentication' do
    context 'and request already has an authentication header' do
      let(:response) { conn.get('/auth-echo', nil, authorization: 'OAuth oauth_token') }

      it 'does not interfere with existing authorization' do
        expect(response.body).to eq('OAuth oauth_token')
      end
    end
  end

  let(:response) { conn.get('/auth-echo') }

  describe 'basic_auth' do
    let(:auth_type) { :basic }

    context 'when passed correct params' do
      let(:auth_config) { %w[aladdin opensesame] }

      it { expect(response.body).to eq('Basic YWxhZGRpbjpvcGVuc2VzYW1l') }

      include_examples 'does not interfere with existing authentication'
    end

    context 'when passed very long values' do
      let(:auth_config) { ['A' * 255, ''] }

      it { expect(response.body).to eq("Basic #{'QUFB' * 85}Og==") }

      include_examples 'does not interfere with existing authentication'
    end
  end

  describe 'authorization' do
    let(:auth_type) { :Bearer }

    context 'when passed a string' do
      let(:auth_config) { ['custom'] }

      it { expect(response.body).to eq('Bearer custom') }

      include_examples 'does not interfere with existing authentication'
    end

    context 'when passed a proc' do
      let(:auth_config) { [-> { 'custom_from_proc' }] }

      it { expect(response.body).to eq('Bearer custom_from_proc') }

      include_examples 'does not interfere with existing authentication'
    end

    context 'when passed a callable' do
      let(:callable) { double('Callable Authorizer', call: 'custom_from_callable') }
      let(:auth_config) { [callable] }

      it { expect(response.body).to eq('Bearer custom_from_callable') }

      include_examples 'does not interfere with existing authentication'
    end

    context 'with an argument' do
      let(:response) { conn.get('/auth-echo', nil, 'middle' => 'crunchy surprise') }

      context 'when passed a proc' do
        let(:auth_config) { [proc { |env| "proc #{env.request_headers['middle']}" }] }

        it { expect(response.body).to eq('Bearer proc crunchy surprise') }

        include_examples 'does not interfere with existing authentication'
      end

      context 'when passed a lambda' do
        let(:auth_config) { [->(env) { "lambda #{env.request_headers['middle']}" }] }

        it { expect(response.body).to eq('Bearer lambda crunchy surprise') }

        include_examples 'does not interfere with existing authentication'
      end

      context 'when passed a callable with an argument' do
        let(:callable) do
          Class.new do
            def call(env)
              "callable #{env.request_headers['middle']}"
            end
          end.new
        end
        let(:auth_config) { [callable] }

        it { expect(response.body).to eq('Bearer callable crunchy surprise') }

        include_examples 'does not interfere with existing authentication'
      end
    end

    context 'when passed too many arguments' do
      let(:auth_config) { %w[baz foo] }

      it { expect { response }.to raise_error(ArgumentError) }

      include_examples 'does not interfere with existing authentication'
    end
  end

  describe 'restricting credentials to approved targets' do
    let(:approved_origin) { 'https://api.example.com' }
    let(:other_origin) { 'https://unauthenticated.example.com' }

    let(:conn) do
      Faraday.new(approved_origin) do |b|
        b.request :authorization, 'Bearer', 'secret-token', only: only
        b.adapter :test do |stub|
          stub.get(/.*/) do |env|
            [200, {}, env[:request_headers]['Authorization'].to_s]
          end
        end
      end
    end

    let(:only) { approved_origin }

    it 'adds credentials to a request on the approved host' do
      expect(conn.get('/profile').body).to eq('Bearer secret-token')
    end

    it 'does not add credentials to a request retargeted at another host' do
      expect(conn.get("#{other_origin}/public").body).to eq('')
    end

    it 'decides from the final url handed to the adapter, not the configured prefix' do
      expect(conn.get("#{other_origin}/public").body).to eq('')
      expect(conn.get("#{approved_origin}/profile").body).to eq('Bearer secret-token')
    end

    context 'with a relative path target' do
      let(:only) { '/private' }

      it 'adds credentials to an approved relative path on the configured host' do
        expect(conn.get('/private/items').body).to eq('Bearer secret-token')
      end

      it 'does not add credentials to a path outside the approved prefix' do
        expect(conn.get('/public/items').body).to eq('')
      end
    end

    context 'with a regexp target' do
      let(:only) { %r{\Ahttps://api\.example\.com/v2/} }

      it 'adds credentials when the final url matches' do
        expect(conn.get('/v2/items').body).to eq('Bearer secret-token')
      end

      it 'does not add credentials when the final url does not match' do
        expect(conn.get('/v1/items').body).to eq('')
      end
    end

    context 'with several approved targets' do
      let(:only) { [approved_origin, other_origin] }

      it 'adds credentials to every approved target' do
        expect(conn.get("#{approved_origin}/profile").body).to eq('Bearer secret-token')
        expect(conn.get("#{other_origin}/public").body).to eq('Bearer secret-token')
      end

      it 'withholds credentials from a target that is not approved' do
        expect(conn.get('https://elsewhere.example.com/path').body).to eq('')
      end
    end

    context 'with an origin plus path prefix target' do
      let(:only) { "#{approved_origin}/private" }

      it 'adds credentials only to the approved path on the approved origin' do
        expect(conn.get("#{approved_origin}/private/items").body).to eq('Bearer secret-token')
        expect(conn.get("#{approved_origin}/public/items").body).to eq('')
      end

      it 'does not treat a look-alike host as the approved origin' do
        expect(conn.get('https://api.example.com.evil.com/private').body).to eq('')
      end

      it 'compares scheme and port in addition to the host' do
        expect(conn.get('http://api.example.com/private').body).to eq('')
        expect(conn.get('https://api.example.com:8443/private').body).to eq('')
      end

      it 'treats the default port as equivalent to an omitted port' do
        expect(conn.get('https://api.example.com:443/private').body).to eq('Bearer secret-token')
      end
    end

    context 'when the request already carries an authorization header' do
      it 'does not add automatic credentials to an unapproved target' do
        response = conn.get("#{other_origin}/public", nil, authorization: 'Bearer caller-supplied')
        expect(response.body).to eq('Bearer caller-supplied')
      end
    end

    context 'when the connection is duplicated' do
      it 'keeps restricting credentials on the duplicate' do
        duplicate = conn.dup
        expect(duplicate.get("#{approved_origin}/profile").body).to eq('Bearer secret-token')
        expect(duplicate.get("#{other_origin}/public").body).to eq('')
      end
    end

    context 'with a credential callback' do
      let(:conn) do
        Faraday.new(approved_origin) do |b|
          b.request :authorization, 'Bearer', ->(env) { "token-for-#{env.url.host}" }, only: only
          b.adapter :test do |stub|
            stub.get(/.*/) do |env|
              [200, {}, env[:request_headers]['Authorization'].to_s]
            end
          end
        end
      end

      it 'still invokes the callback for approved requests' do
        expect(conn.get('/profile').body).to eq('Bearer token-for-api.example.com')
      end

      it 'does not invoke the callback or add credentials for other targets' do
        expect(conn.get("#{other_origin}/public").body).to eq('')
      end
    end
  end
end

# frozen_string_literal: true

# Two adapters that record the env they receive. They stand in for a real
# adapter so the examples can show exactly which proxy each request carried
# to the adapter boundary.
RSpec.describe 'Proxy-required requests' do
  # Records every env it receives and completes with a plain 200 response.
  class RecordingAdapter < Faraday::Adapter
    class << self
      attr_accessor :calls

      def reset!
        self.calls = []
      end
    end

    def call(env)
      super
      self.class.calls << env
      save_response(env, 200, 'ok', {})
      @app.call(env)
    end
  end

  # A recording adapter that refuses to run without a proxy, mimicking an
  # adapter that can only reach the outside world through an approved proxy.
  class ApprovedProxyRecordingAdapter < RecordingAdapter
    class MissingProxy < StandardError; end

    def call(env)
      raise MissingProxy, 'no proxy reached the adapter' if env.request.proxy.nil?

      super
    end
  end

  before do
    RecordingAdapter.reset!
    ApprovedProxyRecordingAdapter.reset!
  end

  let(:calls) { RecordingAdapter.calls }
  let(:managed_calls) { ApprovedProxyRecordingAdapter.calls }

  def connection(adapter, options = {})
    Faraday.new('http://example.com', options) do |f|
      f.adapter adapter
    end
  end

  def proxy_hosts(envs = calls)
    envs.map { |env| env.request.proxy&.host }
  end

  describe 'an explicit approved proxy' do
    it 'reaches the adapter with the declared connection proxy' do
      response = connection(ApprovedProxyRecordingAdapter, proxy: 'http://approved.proxy:8080')
                 .get('/') { |req| req.options.proxy_required = true }

      expect(response.status).to eq(200)
      expect(proxy_hosts(managed_calls)).to eq(['approved.proxy'])
    end

    it 'reaches the adapter with a proxy declared for the request' do
      response = connection(ApprovedProxyRecordingAdapter).get('/') do |req|
        req.options.proxy_required = true
        req.options.proxy = 'http://request.proxy:9090'
      end

      expect(response.status).to eq(200)
      expect(proxy_hosts(managed_calls)).to eq(['request.proxy'])
    end
  end

  describe 'a connection that requires a proxy for every request' do
    it 'uses its declared proxy' do
      response = connection(ApprovedProxyRecordingAdapter,
                            proxy: 'http://approved.proxy:8080', proxy_required: true).get('/')

      expect(response.status).to eq(200)
      expect(proxy_hosts(managed_calls)).to eq(['approved.proxy'])
    end

    it 'fails instead of using the environment proxy' do
      with_env 'http_proxy' => 'http://env.proxy:3128' do
        expect do
          connection(ApprovedProxyRecordingAdapter, proxy_required: true).get('/')
        end.to raise_error(Faraday::ProxyRequiredError)
      end

      expect(managed_calls).to be_empty
    end
  end

  describe 'a request without an approved proxy' do
    it 'fails before the adapter sees it, even when the environment has a proxy' do
      with_env 'http_proxy' => 'http://env.proxy:3128' do
        expect do
          connection(ApprovedProxyRecordingAdapter)
            .get('/') { |req| req.options.proxy_required = true }
        end.to raise_error(Faraday::ProxyRequiredError)
      end

      expect(managed_calls).to be_empty
    end

    it 'fails before the adapter sees it when there is no proxy at all' do
      expect do
        connection(ApprovedProxyRecordingAdapter)
          .get('/') { |req| req.options.proxy_required = true }
      end.to raise_error(Faraday::ProxyRequiredError)

      expect(managed_calls).to be_empty
    end
  end

  describe 'a regular direct request' do
    it 'reaches the adapter without a proxy' do
      response = connection(RecordingAdapter).get('/')

      expect(response.status).to eq(200)
      expect(calls.map { |env| env.request.proxy }).to eq([nil])
    end

    it 'still uses the environment proxy when it is not managed' do
      with_env 'http_proxy' => 'http://env.proxy:3128' do
        connection(RecordingAdapter).get('/')
      end

      expect(proxy_hosts).to eq(['env.proxy'])
    end
  end

  describe 'proxy settings across requests' do
    it 'does not carry a request proxy into the next request' do
      conn = connection(RecordingAdapter)

      conn.get('/') { |req| req.options.proxy = 'http://first.proxy:8080' }
      conn.get('/')
      conn.get('/') { |req| req.options.proxy = 'http://third.proxy:8080' }

      expect(proxy_hosts).to eq(['first.proxy', nil, 'third.proxy'])
    end

    it 'does not let a request mutate the connection proxy' do
      conn = connection(RecordingAdapter, proxy: 'http://default.proxy:8080')

      conn.get('/') { |req| req.options.proxy.port = 9090 }
      conn.get('/')

      expect(calls.map { |env| env.request.proxy.port }).to eq([9090, 8080])
      expect(conn.proxy.port).to eq(8080)
    end

    it 'does not treat an inferred environment proxy as approved for later requests' do
      with_env 'http_proxy' => 'http://env.proxy:3128' do
        conn = connection(ApprovedProxyRecordingAdapter)

        expect do
          conn.get('/') { |req| req.options.proxy_required = true }
        end.to raise_error(Faraday::ProxyRequiredError)

        conn.get('/') do |req|
          req.options.proxy_required = true
          req.options.proxy = 'http://ok.proxy:1'
        end

        expect(proxy_hosts(managed_calls)).to eq(['ok.proxy'])
      end
    end
  end
end

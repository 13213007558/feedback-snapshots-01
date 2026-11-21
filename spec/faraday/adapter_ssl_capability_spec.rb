# frozen_string_literal: true

RSpec.describe 'SSL capability check' do
  # Adapter double that declares support for the strict TLS configuration
  # required by the connection (custom CA + client certificate).
  let(:strict_adapter) do
    Class.new(Faraday::Adapter) do
      supports_ssl_options :verify, :verify_hostname, :ca_file, :ca_path,
                           :client_cert, :client_key

      class << self
        def calls
          @calls ||= []
        end
      end

      def call(env)
        super
        self.class.calls << env
        save_response(env, 200, 'strict ok')
      end
    end
  end

  # Adapter double that only supports basic certificate verification.
  let(:basic_adapter) do
    Class.new(Faraday::Adapter) do
      supports_ssl_options :verify

      class << self
        def calls
          @calls ||= []
        end
      end

      def call(env)
        super
        self.class.calls << env
        save_response(env, 200, 'basic ok')
      end
    end
  end

  let(:ssl_options) do
    { ca_file: '/path/to/ca.pem', client_cert: '/path/to/cert.pem' }
  end

  def build_connection(adapter)
    Faraday.new('https://example.com', ssl: ssl_options) do |f|
      f.adapter adapter
    end
  end

  context 'with default configuration (no requirement declared)' do
    it 'uses any adapter without checks, as before' do
      conn = build_connection(basic_adapter)
      expect(conn.get('/').body).to eq('basic ok')
      expect(basic_adapter.calls.size).to eq(1)
    end
  end

  context 'when the connection requires strict TLS support' do
    it 'allows requests through an adapter declaring support' do
      conn = build_connection(strict_adapter)
      conn.require_ssl_support :ca_file, :client_cert

      expect(conn.get('/').body).to eq('strict ok')
      expect(strict_adapter.calls.size).to eq(1)
    end

    it 'rejects before connecting when the adapter only supports basic verification' do
      conn = build_connection(basic_adapter)
      conn.require_ssl_support :ca_file, :client_cert

      expect { conn.get('/') }.to raise_error(
        Faraday::AdapterCapabilityError, /:ca_file, :client_cert/
      )
      expect(basic_adapter.calls).to be_empty
    end

    it 'checks at request time, so an adapter swapped in later is re-validated' do
      conn = build_connection(strict_adapter)
      conn.require_ssl_support :ca_file, :client_cert

      # The app replaces the underlying adapter at runtime, before the
      # first request locks the middleware stack.
      conn.builder.adapter basic_adapter

      expect { conn.get('/') }.to raise_error(Faraday::AdapterCapabilityError)
      expect(basic_adapter.calls).to be_empty
    end

    it 'keeps the requirement on duplicated connections' do
      conn = build_connection(basic_adapter)
      conn.require_ssl_support :ca_file, :client_cert

      expect { conn.dup.get('/') }.to raise_error(Faraday::AdapterCapabilityError)
      expect(basic_adapter.calls).to be_empty
    end
  end

  describe Faraday::Adapter do
    it 'declares no SSL support by default' do
      expect(Faraday::Adapter.supported_ssl_options).to eq([])
      expect(Faraday::Adapter.new.supports_ssl_config?(:verify)).to be(false)
    end

    it 'inherits declared SSL support to subclasses' do
      subclass = Class.new(strict_adapter)
      expect(subclass.supported_ssl_options).to include(:ca_file, :client_cert)
      expect(subclass.new.supports_ssl_config?(:ca_file, :client_cert)).to be(true)
    end
  end
end

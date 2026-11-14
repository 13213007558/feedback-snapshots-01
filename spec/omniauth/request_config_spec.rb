require 'helper'

describe OmniAuth::RequestConfig do
  let(:attributes) do
    {
      :tenant => 'acme',
      :version => 3,
      :overrides => {
        :client_id => 'acme-id',
        'client_secret' => 'acme-secret',
        :client_options => {'authorize_url' => 'https://acme.idp.example/authorize'}
      }
    }
  end

  let(:config) { described_class.new(attributes) }

  describe OmniAuth::RequestConfig::Error do
    it 'uses the message key as the message when no detail is given' do
      error = described_class.new(:stale_request_config)
      expect(error.message).to eq('stale_request_config')
      expect(error.message_key).to eq(:stale_request_config)
    end

    it 'includes the detail in the message when given' do
      expect(described_class.new(:unallowed_override, 'nope').message).to eq('unallowed_override (nope)')
    end
  end

  describe '.assign and .fetch' do
    it 'stores a built config in the env' do
      env = {}
      expect(described_class.assign(env, attributes)).to be_a(described_class)
      expect(described_class.fetch(env).tenant).to eq('acme')
    end

    it 'returns nil when no config is assigned' do
      expect(described_class.fetch({})).to be_nil
    end
  end

  describe '#initialize' do
    it 'requires a tenant from the verified context' do
      expect { described_class.new({}) }.to raise_error(OmniAuth::RequestConfig::Error, /missing_tenant/)
      expect { described_class.new(:tenant => nil) }.to raise_error(OmniAuth::RequestConfig::Error, /missing_tenant/)
      expect { described_class.new(:tenant => '') }.to raise_error(OmniAuth::RequestConfig::Error, /missing_tenant/)
    end

    it 'exposes the message key for the strategy to fail with' do
      error = nil
      begin
        described_class.new({})
      rescue OmniAuth::RequestConfig::Error => e
        error = e
      end
      expect(error.message_key).to eq(:missing_tenant)
    end

    it 'rejects overrides that decide routing or dispatch' do
      %i[name path_prefix request_path callback_path setup setup_path origin_param skip_info].each do |key|
        expect { described_class.new(:tenant => 'acme', :overrides => {key => 'x'}) }
          .to raise_error(OmniAuth::RequestConfig::Error, /unallowed_override.*#{key}/)
      end
    end

    it 'accepts every allowed override, with string or symbol keys' do
      overrides = described_class::ALLOWED_OVERRIDES.each_with_object({}) { |key, hash| hash[key.to_sym] = 'value' }
      config = described_class.new(:tenant => 'acme', :overrides => overrides)
      expect(config.keys.sort).to eq(described_class::ALLOWED_OVERRIDES.sort)
    end

    it 'freezes itself and its overrides' do
      expect(config).to be_frozen
      expect(config.to_h).not_to be_frozen
      expect { config.instance_variable_get(:@overrides)['client_id'] = 'late' }.to raise_error(FrozenError)
    end

    it 'keeps a private copy the caller cannot change afterwards' do
      overrides = {:client_options => {'authorize_url' => 'https://acme.example/'}}
      config = described_class.new(:tenant => 'acme', :overrides => overrides)
      overrides[:client_id] = 'late'
      overrides[:client_options]['authorize_url'] = 'https://evil.example/'

      expect(config['client_id']).to be_nil
      expect(config['client_options']).to eq('authorize_url' => 'https://acme.example/')
    end

    it 'deep-freezes array values against later mutation' do
      overrides = {:authorize_params => {:scope => %w[email profile]}}
      config = described_class.new(:tenant => 'acme', :overrides => overrides)
      overrides[:authorize_params][:scope] << 'admin'

      expect(config['authorize_params'][:scope]).to eq(%w[email profile])
      expect { config['authorize_params'][:scope] << 'admin' }.to raise_error(FrozenError)
    end
  end

  describe '#[]' do
    it 'reads overrides with string or symbol keys' do
      expect(config[:client_id]).to eq('acme-id')
      expect(config['client_secret']).to eq('acme-secret')
      expect(config[:missing]).to be_nil
    end
  end

  describe '#to_h' do
    it 'returns a mutable deep copy' do
      copy = config.to_h
      copy['client_id'] = 'changed'
      copy['client_options']['authorize_url'] = 'https://evil.example/'

      expect(config['client_id']).to eq('acme-id')
      expect(config['client_options']['authorize_url']).to eq('https://acme.idp.example/authorize')
    end
  end

  describe '#inspect' do
    it 'redacts sensitive values, recursively, and keeps the rest' do
      config = described_class.new(:tenant => 'acme', :overrides => {
        :client_id => 'acme-id',
        :client_secret => 'acme-secret',
        :token_params => {:token => 'tok-value'},
        :authorize_params => {:other => 'visible'},
        :client_options => {'password' => 'pw-value', 'site' => 'https://acme.example'}
      })

      text = config.inspect
      expect(text).to include('acme-id', 'visible', 'https://acme.example')
      expect(text).not_to include('acme-secret', 'tok-value', 'pw-value')
    end

    it 'does not leak secrets through the default string conversion' do
      expect(config.to_s).not_to include('acme-secret')
    end
  end

  describe 'session binding' do
    let(:session) { {} }

    it 'binds only the tenant and version, never the overrides' do
      config.bind(session)
      expect(described_class.pending(session)).to eq('tenant' => 'acme', 'version' => '3')
      expect(session.inspect).not_to include('acme-secret')
    end

    it 'verifies a config matching the binding' do
      config.bind(session)
      expect { described_class.verify!(session, described_class.new(:tenant => 'acme', :version => 3)) }.not_to raise_error
    end

    it 'verifies when neither side uses versions' do
      described_class.new(:tenant => 'acme').bind(session)
      expect { described_class.verify!(session, described_class.new(:tenant => 'acme')) }.not_to raise_error
    end

    it 'raises when the tenant differs' do
      config.bind(session)
      expect { described_class.verify!(session, described_class.new(:tenant => 'evil', :version => 3)) }
        .to raise_error(OmniAuth::RequestConfig::Error, /request_config_tenant_mismatch/)
    end

    it 'raises when the version changed between request and callback' do
      config.bind(session)
      expect { described_class.verify!(session, described_class.new(:tenant => 'acme', :version => 4)) }
        .to raise_error(OmniAuth::RequestConfig::Error, /stale_request_config/)
    end

    it 'raises when a config is assigned without a request-phase binding' do
      expect { described_class.verify!(session, config) }
        .to raise_error(OmniAuth::RequestConfig::Error, /unbound_request_config/)
    end

    it 'raises when a binding exists but no config is assigned' do
      config.bind(session)
      expect { described_class.verify!(session, nil) }
        .to raise_error(OmniAuth::RequestConfig::Error, /missing_request_config/)
    end

    it 'passes when neither a binding nor a config exists' do
      expect { described_class.verify!(session, nil) }.not_to raise_error
    end

    it 'ignores a binding that is not a hash' do
      session[described_class::SESSION_KEY] = 'junk'
      expect(described_class.pending(session)).to be_nil
      expect { described_class.verify!(session, nil) }.not_to raise_error
    end

    it 'consumes the binding on conclude' do
      config.bind(session)
      described_class.conclude(session)
      expect(described_class.pending(session)).to be_nil
    end
  end
end

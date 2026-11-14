require 'helper'
require 'timeout'

# A strategy that reads its per-tenant credentials through
# #effective_options, the way a multi-tenant OAuth2 strategy would.
# Its default nested client_options are shared by every instance, which
# is exactly what the request config must isolate each request from.
class TenantStrategy
  include OmniAuth::Strategy

  option :name, 'test'
  option :client_id, 'global-id'
  option :client_secret, 'global-secret'
  option :client_options, {'authorize_url' => 'https://global.idp.example/authorize'}

  def request_phase
    options = effective_options
    env['captured.request_options'] = options
    env['captured.same_as_options'] = options.equal?(self.options)
    # Mutating the returned copy must not leak anywhere.
    options['client_options']['authorize_url'] = "https://mutated.example/#{options['client_id']}"
    redirect "#{effective_options['client_options']['authorize_url']}?client_id=#{effective_options['client_id']}"
  end

  def callback_phase
    env['captured.callback_options'] = effective_options
    env['omniauth.auth'] = {'provider' => name}
    call_app!
  end
end

# The top-level describe is OmniAuth::Strategy rather than
# OmniAuth::RequestConfig so mutant keeps selecting every
# OmniAuth::Strategy example for the strategy subjects.
describe OmniAuth::Strategy, 'request configuration' do
  let(:app) { lambda { |_env| [200, {}, ['OK']] } }
  let(:setup_lambda) { lambda { |_env| } }
  let(:strategy) { TenantStrategy.new(app, :setup => setup_lambda) }

  around do |example|
    validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil
    example.run
  ensure
    OmniAuth.config.request_validation_phase = validation_phase
  end

  def request_env(session = {}, tenant = 'acme')
    Rack::MockRequest.env_for('http://app.example/auth/test', :method => 'POST', 'rack.session' => session).tap do |env|
      env['app.verified_tenant'] = tenant
    end
  end

  def callback_env(session = {}, tenant = 'acme', query = '')
    Rack::MockRequest.env_for("http://app.example/auth/test/callback#{query}", 'rack.session' => session).tap do |env|
      env['app.verified_tenant'] = tenant
    end
  end

  def assign_verified(env, version)
    OmniAuth::RequestConfig.assign(env,
      :tenant => env.fetch('app.verified_tenant'),
      :version => version,
      :overrides => {
        :client_id => "#{env.fetch('app.verified_tenant')}-id",
        :client_secret => "#{env.fetch('app.verified_tenant')}-secret",
        :client_options => {'authorize_url' => "https://#{env.fetch('app.verified_tenant')}.idp.example/authorize"}
      }
    )
  end

  context 'with no request config assigned' do
    it 'makes effective_options the strategy options themselves' do
      env = request_env
      strategy.call(env)
      expect(env['captured.same_as_options']).to be true
    end
  end

  context 'request phase' do
    let(:setup_lambda) { lambda { |env| assign_verified(env, 1) } }

    it 'binds the tenant and version into the session, never the overrides' do
      session = {}
      response = strategy.call(request_env(session))

      expect(response[1]['Location']).to eq('https://acme.idp.example/authorize?client_id=acme-id')
      expect(OmniAuth::RequestConfig.pending(session)).to eq('tenant' => 'acme', 'version' => '1')
      expect(session.inspect).not_to include('acme-secret')
    end

    it 'merges the overrides into a fresh copy for the request only' do
      env = request_env
      strategy.call(env)

      captured = env['captured.request_options']
      expect(captured['client_id']).to eq('acme-id')
      expect(captured['client_secret']).to eq('acme-secret')
      # The request phase's mutation stays inside its own copy.
      expect(captured['client_options']['authorize_url']).to eq('https://mutated.example/acme-id')
      expect(env['captured.same_as_options']).to be false
    end

    it 'leaves the instance options, the class defaults, and the global config untouched' do
      defaults_before = TenantStrategy.default_options.to_hash
      strategy.call(request_env)

      expect(strategy.options['client_id']).to eq('global-id')
      expect(strategy.options['client_options']['authorize_url']).to eq('https://global.idp.example/authorize')
      expect(TenantStrategy.default_options.to_hash).to eq(defaults_before)
      expect(TenantStrategy.default_options['client_options']['authorize_url']).to eq('https://global.idp.example/authorize')
      expect(OmniAuth.config.path_prefix).to eq('/auth')
    end

    it 'fails cleanly when the config selects an option that may not be overridden' do
      session = {}
      bad_setup = lambda do |env|
        OmniAuth::RequestConfig.assign(env, :tenant => 'acme', :overrides => {:callback_path => '/evil'})
      end
      env = request_env(session)
      TenantStrategy.new(app, :setup => bad_setup).call(env)

      expect(env['omniauth.error.type']).to eq(:unallowed_override)
      expect(OmniAuth::RequestConfig.pending(session)).to be_nil
      expect(OmniAuth::RequestConfig.fetch(env)).to be_nil
    end

    it 'fails cleanly when the setup phase raises' do
      session = {}
      raising_setup = lambda { |_env| raise ArgumentError, 'no such tenant' }
      env = request_env(session)
      TenantStrategy.new(app, :setup => raising_setup).call(env)

      expect(env['omniauth.error'].message).to eq('no such tenant')
      expect(OmniAuth::RequestConfig.pending(session)).to be_nil
      expect(OmniAuth::RequestConfig.fetch(env)).to be_nil
    end
  end

  context 'callback phase' do
    let(:setup_lambda) { lambda { |env| assign_verified(env, 1) } }

    it 'runs the callback with the request-phase tenant when the config matches' do
      session = {}
      strategy.call(request_env(session))
      env = callback_env(session)
      strategy.call(env)

      expect(env['omniauth.auth']).to eq('provider' => 'test')
      expect(env['captured.callback_options']['client_id']).to eq('acme-id')
      expect(OmniAuth::RequestConfig.pending(session)).to be_nil
    end

    it 'fails when the tenant configuration changed between request and callback' do
      session = {}
      version = {:current => 1}
      versioned_setup = lambda { |env| assign_verified(env, version[:current]) }
      versioned_strategy = TenantStrategy.new(app, :setup => versioned_setup)

      versioned_strategy.call(request_env(session))
      expect(OmniAuth::RequestConfig.pending(session)).to eq('tenant' => 'acme', 'version' => '1')

      version[:current] = 2 # the tenant rotated its credentials while the user was away

      env = callback_env(session)
      versioned_strategy.call(env)

      expect(env['omniauth.error.type']).to eq(:stale_request_config)
      expect(env['omniauth.error'].message).not_to include('acme-secret')
      expect(env['captured.callback_options']).to be_nil
      expect(OmniAuth::RequestConfig.pending(session)).to be_nil
    end

    it 'cannot be redirected to another tenant by a forged query parameter' do
      session = {}
      # The safe pattern: the callback reloads the tenant named by the
      # verified request-phase binding, ignoring the query string.
      safe_setup = lambda do |env|
        marker = OmniAuth::RequestConfig.pending(env['rack.session'])
        tenant = marker ? marker['tenant'] : env.fetch('app.verified_tenant')
        OmniAuth::RequestConfig.assign(env,
          :tenant => tenant,
          :version => 1,
          :overrides => {:client_id => "#{tenant}-id", :client_secret => "#{tenant}-secret"})
      end
      safe_strategy = TenantStrategy.new(app, :setup => safe_setup)

      safe_strategy.call(request_env(session))
      env = callback_env(session, 'acme', '?tenant=evil')
      safe_strategy.call(env)

      expect(env['omniauth.error']).to be_nil
      expect(env['captured.callback_options']['client_id']).to eq('acme-id')
    end

    it 'fails closed when the callback re-selects the tenant from a query parameter' do
      session = {}
      # The unsafe pattern the mechanism refuses: re-selecting the
      # tenant from a forgeable query parameter at the callback.
      unsafe_setup = lambda do |env|
        tenant = Rack::Request.new(env).params['tenant'] || env.fetch('app.verified_tenant')
        OmniAuth::RequestConfig.assign(env, :tenant => tenant, :version => 1, :overrides => {:client_id => "#{tenant}-id"})
      end
      unsafe_strategy = TenantStrategy.new(app, :setup => unsafe_setup)

      unsafe_strategy.call(request_env(session))
      env = callback_env(session, 'acme', '?tenant=evil')
      unsafe_strategy.call(env)

      expect(env['omniauth.error.type']).to eq(:request_config_tenant_mismatch)
      expect(env['captured.callback_options']).to be_nil
      expect(OmniAuth::RequestConfig.pending(session)).to be_nil
    end

    it 'fails when a config is assigned without a request-phase binding' do
      env = callback_env({})
      strategy.call(env)

      expect(env['omniauth.error.type']).to eq(:unbound_request_config)
    end

    it 'fails when the request phase bound a tenant but the callback assigns nothing' do
      session = {}
      request_only_setup = lambda do |env|
        assign_verified(env, 1) if env['PATH_INFO'] == '/auth/test'
      end
      request_only_strategy = TenantStrategy.new(app, :setup => request_only_setup)

      request_only_strategy.call(request_env(session))
      env = callback_env(session)
      request_only_strategy.call(env)

      expect(env['omniauth.error.type']).to eq(:missing_request_config)
      expect(OmniAuth::RequestConfig.pending(session)).to be_nil
    end

    it 'fails closed when two tenants share a provider name and a session' do
      session = {}
      strategy.call(request_env(session, 'acme'))
      strategy.call(request_env(session, 'globex'))

      env = callback_env(session, 'acme')
      strategy.call(env)
      expect(env['omniauth.error.type']).to eq(:request_config_tenant_mismatch)
      expect(OmniAuth::RequestConfig.pending(session)).to be_nil

      env = callback_env(session, 'globex')
      strategy.call(env)
      expect(env['omniauth.error.type']).to eq(:unbound_request_config)

      strategy.call(request_env(session, 'globex'))
      env = callback_env(session, 'globex')
      strategy.call(env)
      expect(env['omniauth.auth']).to eq('provider' => 'test')
    end
  end

  context 'with two requests paused in the middle of setup' do
    it 'keeps their configurations, including nested options, isolated' do
      entered = Queue.new
      release = Queue.new
      pausing_setup = lambda do |env|
        assign_verified(env, 1)
        entered << env.fetch('app.verified_tenant')
        release.pop # paused in the middle of setup
      end
      strategy_a = TenantStrategy.new(app, :setup => pausing_setup)
      strategy_b = TenantStrategy.new(app, :setup => pausing_setup)
      env_a = request_env({}, 'acme')
      env_b = request_env({}, 'globex')

      threads = [Thread.new { strategy_a.call(env_a) }, Thread.new { strategy_b.call(env_b) }]
      # Wait until both requests are paused inside the setup phase.
      entered_tenants = Timeout.timeout(5) { [entered.pop, entered.pop] }
      expect(entered_tenants.sort).to eq(%w[acme globex])
      2.times { release << :go }
      threads.each(&:join)

      options_a = env_a['captured.request_options']
      options_b = env_b['captured.request_options']
      expect(options_a['client_id']).to eq('acme-id')
      expect(options_b['client_id']).to eq('globex-id')
      expect(options_a['client_secret']).to eq('acme-secret')
      expect(options_b['client_secret']).to eq('globex-secret')
      # Each request mutated its own copy of the nested client_options;
      # neither saw the other's mutation or tenant.
      expect(options_a['client_options']['authorize_url']).to eq('https://mutated.example/acme-id')
      expect(options_b['client_options']['authorize_url']).to eq('https://mutated.example/globex-id')
      # The shared instance options and class defaults were never touched.
      expect(strategy_a.options['client_options']['authorize_url']).to eq('https://global.idp.example/authorize')
      expect(strategy_b.options['client_options']['authorize_url']).to eq('https://global.idp.example/authorize')
      expect(TenantStrategy.default_options['client_options']['authorize_url']).to eq('https://global.idp.example/authorize')
    end
  end

  context 'logging' do
    around do |example|
      original = OmniAuth.config.logger
      OmniAuth.config.logger = Logger.new(log_output)
      example.run
    ensure
      OmniAuth.config.logger = original
    end

    let(:log_output) { StringIO.new }
    let(:setup_lambda) { lambda { |env| assign_verified(env, 1) } }

    it 'never logs client secrets' do
      session = {}
      strategy.call(request_env(session))
      strategy.call(callback_env(session))

      expect(log_output.string).to include('acme')
      expect(log_output.string).not_to include('acme-secret')
      expect(log_output.string).not_to include('global-secret')
    end
  end
end

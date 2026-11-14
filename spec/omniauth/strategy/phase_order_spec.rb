require 'helper'
require 'fileutils'

# Records what actually happened, in order, for the security ordering tests.
# Each event is a small array (a tag and, sometimes, a fact), and every hook,
# phase, and downstream app call writes one. Trace lines are rendered from
# these events, so the expectations read as a timeline.
class PhaseOrderStrategy
  include OmniAuth::Strategy

  option :name, 'phaseorder'

  attr_reader :trace

  def initialize(app, options = {})
    super
    @trace = options.fetch(:trace, [])
  end

  def record(event, detail = nil)
    @trace << (detail ? [event, detail] : [event])
  end

  def request_phase
    record(:request_phase)
    return options[:request_result] if options.key?(:request_result)

    [200, {}, ['request phase']]
  end

  def callback_phase
    record(:callback_phase)
    return options[:callback_result] if options.key?(:callback_result)

    record(:auth_hash_written)
    env['omniauth.auth'] = {'provider' => 'phaseorder', 'uid' => 'real'}
    call_app!
  end

  def other_phase
    record(:other_phase)
    [404, {}, ['other phase']]
  end
end

# Renders events as a compact, stable phase trace. Security-relevant facts
# (whether the app saw an auth hash, what failure type was recorded) are
# part of the trace, not separate assertions, so the whole ordering is one
# readable value.
def phase_trace(events)
  events.map do |tag, detail|
    detail.nil? ? tag.to_s : "#{tag}(#{detail})"
  end.join(' -> ')
end

describe OmniAuth::Strategy, 'phase hook ordering' do
  let(:app_calls) { [] }
  let(:app) do
    lambda do |env|
      app_calls << env['PATH_INFO']
      trace << [:downstream_app, env.key?('omniauth.auth') ? 'auth' : 'no_auth']
      [200, {'content-type' => 'text/plain'}, ["app:#{env.key?('omniauth.auth') ? 'auth' : 'no_auth'}"]]
    end
  end
  let(:trace) { [] }
  let(:strategy) { PhaseOrderStrategy.new(app, :trace => trace) }
  let(:session) { {} }
  let(:failure_body) { [] }
  let(:on_failure) do
    lambda do |env|
      failure_body << [env['omniauth.error.type'].to_s, env.key?('omniauth.auth')]
      trace << [:on_failure, env['omniauth.error.type']]
      [401, {}, ["failure:#{env['omniauth.error.type']}"]]
    end
  end

  around do |example|
    old_on_failure = OmniAuth.config.on_failure
    old_validation = OmniAuth.config.request_validation_phase
    old_before_request = OmniAuth.config.before_request_phase
    old_after_request = OmniAuth.config.after_request_phase
    old_before_callback = OmniAuth.config.before_callback_phase
    old_before_options = OmniAuth.config.before_options_phase
    old_test_mode = OmniAuth.config.test_mode

    OmniAuth.config.on_failure = on_failure
    OmniAuth.config.request_validation_phase = nil
    OmniAuth.config.before_request_phase = nil
    OmniAuth.config.after_request_phase = nil
    OmniAuth.config.before_callback_phase = nil
    OmniAuth.config.before_options_phase = nil
    OmniAuth.config.test_mode = false

    example.run
  ensure
    OmniAuth.config.on_failure = old_on_failure
    OmniAuth.config.request_validation_phase = old_validation
    OmniAuth.config.before_request_phase = old_before_request
    OmniAuth.config.after_request_phase = old_after_request
    OmniAuth.config.before_callback_phase = old_before_callback
    OmniAuth.config.before_options_phase = old_before_options
    OmniAuth.config.test_mode = old_test_mode
  end

  def env_for(path, props = {})
    {
      'REQUEST_METHOD' => 'POST',
      'PATH_INFO' => path,
      'rack.session' => session,
      'rack.input' => StringIO.new(''),
      'SCRIPT_NAME' => ''
    }.merge(props)
  end

  # Hooks that write an event, so the trace shows the hook itself, not just
  # its effects. Returning a Rack response or raising is the caller's choice.
  def hook(name, &block)
    OmniAuth.config.public_send("#{name}=", lambda do |env|
      trace << [name]
      block&.call(env)
    end)
  end

  def request_trace(props = {})
    response = strategy.call(env_for('/auth/phaseorder', props))
    [response, phase_trace(trace)]
  end

  it 'records the request phase order and shows it as a trace' do
    hook(:request_validation_phase)
    hook(:before_request_phase) { |env| env['before_request.seen'] = true }
    hook(:after_request_phase)

    response, trace = request_trace

    expect(response[0]).to eq(200)
    expect(trace).to eq(
      'request_validation_phase -> before_request_phase -> request_phase -> after_request_phase'
    )
    expect(app_calls).to be_empty
  end

  it 'runs setup before validation and before the request phase' do
    setup_seen = []
    setup = lambda do |_env|
      trace << [:setup_phase]
      setup_seen << session.key?('omniauth.params')
    end
    strategy.options[:setup] = setup
    hook(:request_validation_phase)
    hook(:before_request_phase)

    _, trace = request_trace

    expect(trace).to eq('setup_phase -> request_validation_phase -> before_request_phase -> request_phase')
    expect(setup_seen).to eq([false])
  end

  it 'does not store omniauth.params when validation returns a Rack denial' do
    OmniAuth.config.request_validation_phase = lambda do |_env|
      trace << [:request_validation_phase, 'deny']
      [403, {}, ['denied']]
    end
    env = env_for('/auth/phaseorder', 'QUERY_STRING' => 'evil=1')

    response = strategy.call(env)

    expect(response[0]).to eq(403)
    expect(phase_trace(trace)).to eq('request_validation_phase(deny)')
    expect(session).not_to have_key('omniauth.params')
    expect(calls_to_request_phase).to be_empty
  end

  it 'does not run setup or request hooks when validation raises' do
    OmniAuth.config.request_validation_phase = lambda do |_env|
      trace << [:request_validation_phase]
      raise OmniAuth::AuthenticityError, 'bad token'
    end
    hook(:before_request_phase)
    hook(:after_request_phase)

    response, trace = request_trace

    expect(response[0]).to eq(401)
    expect(trace).to eq('request_validation_phase -> on_failure(authenticity_error)')
    expect(failure_body).to eq([['authenticity_error', false]])
    expect(app_calls).to be_empty
  end

  it 'does not run the callback phase or the app after the callback hook raises' do
    hook(:before_callback_phase) { raise 'hook rejected callback' }

    response = strategy.call(env_for('/auth/phaseorder/callback'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('before_callback_phase -> on_failure(hook rejected callback)')
    expect(failure_body).to eq([['hook rejected callback', false]])
    expect(app_calls).to be_empty
  end

  it 'restores origin and params before the callback hook and phase' do
    session['omniauth.origin'] = '/after-login'
    session['omniauth.params'] = {'plan' => 'pro'}
    seen = []
    hook(:before_callback_phase) do |env|
      seen << [env['omniauth.origin'], env['omniauth.params']]
    end

    strategy.call(env_for('/auth/phaseorder/callback'))

    expect(seen).to eq([['/after-login', {'plan' => 'pro'}]])
    expect(phase_trace(trace)).to eq('before_callback_phase -> callback_phase -> auth_hash_written -> downstream_app(auth)')
    expect(app_calls).to eq(['/auth/phaseorder/callback'])
  end

  it 'runs the OPTIONS hook before the allow response' do
    hook(:before_options_phase)

    response = strategy.call(env_for('/auth/phaseorder', 'REQUEST_METHOD' => 'OPTIONS'))

    expect(response).to eq([200, {'Allow' => 'POST'}, []])
    expect(phase_trace(trace)).to eq('before_options_phase')
  end

  it 'does not run auth phases, setup, or hooks on non-auth paths without other_phase' do
    hook(:request_validation_phase)
    hook(:before_request_phase)
    hook(:before_callback_phase)
    hook(:before_options_phase)
    plain = Class.new(PhaseOrderStrategy) { undef_method :other_phase }.new(app, :trace => trace)

    response = plain.call(env_for('/elsewhere'))

    expect(response[0]).to eq(200)
    expect(phase_trace(trace)).to eq('downstream_app(no_auth)')
    expect(app_calls).to eq(['/elsewhere'])
  end

  it 'runs only other_phase on a non-auth path when the strategy defines it' do
    hook(:request_validation_phase)
    hook(:before_callback_phase)

    response = strategy.call(env_for('/elsewhere'))

    expect(response[0]).to eq(404)
    expect(phase_trace(trace)).to eq('other_phase')
  end

  it 'runs the callback hook before the auth hash is written in test mode' do
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:phaseorder] = {'provider' => 'phaseorder', 'uid' => 'mock'}
    seen = []
    hook(:before_callback_phase) do |env|
      seen << env.key?('omniauth.auth')
      env['omniauth.auth'] = {'provider' => 'hook', 'uid' => 'forged'}
    end

    strategy.call(env_for('/auth/phaseorder/callback'))

    expect(seen).to eq([false])
    expect(phase_trace(trace)).to eq('before_callback_phase -> downstream_app(auth)')
    expect(app_calls).to eq(['/auth/phaseorder/callback'])
  ensure
    OmniAuth.config.mock_auth.delete(:phaseorder)
  end

  it 'keeps a mocked failure from leaving an auth hash when the hook writes one' do
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:phaseorder] = :invalid_credentials
    hook(:before_callback_phase) do |env|
      env['omniauth.auth'] = {'provider' => 'hook', 'uid' => 'forged'}
    end
    env = env_for('/auth/phaseorder/callback')

    response = strategy.call(env)

    expect(response[0]).to eq(401)
    expect(env).not_to have_key('omniauth.auth')
    expect(failure_body).to eq([['invalid_credentials', false]])
    expect(app_calls).to be_empty
  ensure
    OmniAuth.config.mock_auth.delete(:phaseorder)
  end

  it 'stops the request phase when a request hook calls fail! and returns normally' do
    OmniAuth.config.before_request_phase = lambda do |env|
      trace << [:before_request_phase]
      env['omniauth.strategy'].fail!(:blocked_by_hook)
    end
    hook(:after_request_phase)

    response = strategy.call(env_for('/auth/phaseorder', 'QUERY_STRING' => 'evil=1'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('before_request_phase -> on_failure(blocked_by_hook)')
    expect(app_calls).to be_empty
  end

  it 'finishes with a callback failure when the callback hook calls fail!' do
    OmniAuth.config.before_callback_phase = lambda do |env|
      trace << [:before_callback_phase]
      env['omniauth.strategy'].fail!(:tenant_mismatch)
    end

    response = strategy.call(env_for('/auth/phaseorder/callback'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('before_callback_phase -> on_failure(tenant_mismatch)')
    expect(app_calls).to be_empty
    expect(failure_body).to eq([['tenant_mismatch', false]])
  end

  it 'removes an auth hash written by the callback hook before it fails' do
    OmniAuth.config.before_callback_phase = lambda do |env|
      trace << [:before_callback_phase]
      env['omniauth.auth'] = {'uid' => 'forged'}
      env['omniauth.strategy'].fail!(:hook_failed)
    end
    env = env_for('/auth/phaseorder/callback')

    strategy.call(env)

    expect(env).not_to have_key('omniauth.auth')
    expect(failure_body).to eq([['hook_failed', false]])
  end

  it 'finishes with a failure when a request hook raises after writing an auth hash' do
    OmniAuth.config.after_request_phase = lambda do |env|
      trace << [:after_request_phase]
      env['omniauth.auth'] = {'uid' => 'forged'}
      raise 'after request rejected'
    end
    env = env_for('/auth/phaseorder')

    response = strategy.call(env)

    expect(response[0]).to eq(401)
    expect(env).not_to have_key('omniauth.auth')
    expect(failure_body).to eq([['after request rejected', false]])
  end

  it 'does not re-enter on_failure when a handler calls fail! again' do
    calls = []
    deep = Class.new(PhaseOrderStrategy) do
      def callback_phase
        raise 'callback failed'
      end
    end
    OmniAuth.config.on_failure = lambda do |env|
      calls << env['omniauth.error.type']
      env['omniauth.error.strategy'].fail!(:nested_failure)
      [401, {}, ['failure handler returned']]
    end

    response = deep.new(app, :trace => trace).call(env_for('/auth/phaseorder/callback'))

    expect(calls).to eq([:'callback failed'])
    expect(response).to eq([401, {}, ['failure handler returned']])
    expect(app_calls).to be_empty
  end

  it 'reports a failure handler that raises instead of re-entering it' do
    OmniAuth.config.on_failure = lambda { |_env| raise 'handler exploded' }
    OmniAuth.config.before_request_phase = lambda { |_env| raise 'request rejected' }

    expect do
      strategy.call(env_for('/auth/phaseorder'))
    end.to raise_error(RuntimeError, 'handler exploded')

    expect(app_calls).to be_empty
  end

  it 'keeps a valid hook early response when one hook legitimately short-circuits' do
    OmniAuth.config.before_request_phase = lambda do |env|
      trace << [:before_request_phase]
      return nil
    end
    OmniAuth.config.request_validation_phase = lambda do |_env|
      trace << [:request_validation_phase, 'early']
      [302, {'Location' => '/auth/phaseorder/tenant'}, []]
    end

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response).to eq([302, {'Location' => '/auth/phaseorder/tenant'}, []])
    expect(phase_trace(trace)).to eq('request_validation_phase(early)')
    expect(app_calls).to be_empty
    expect(session).not_to have_key('omniauth.params')
  end

  it 'wraps a Rack::Response returned by validation as the request denial' do
    OmniAuth.config.request_validation_phase = lambda do |_env|
      trace << [:request_validation_phase, 'rack_response']
      Rack::Response.new(['denied'], 403, 'content-type' => 'text/plain')
    end

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(403)
    expect(response[2]).to eq(['denied'])
    expect(phase_trace(trace)).to eq('request_validation_phase(rack_response)')
  end

  it 'does not run the request phase when the setup endpoint calls fail!' do
    setup = lambda do |env|
      trace << [:setup_phase]
      env['omniauth.strategy'].fail!(:unknown_tenant)
    end
    strategy.options[:setup] = setup
    hook(:request_validation_phase)

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('setup_phase -> on_failure(unknown_tenant)')
    expect(app_calls).to be_empty
  end

  it 'does not answer OPTIONS with an allow list when the options hook calls fail!' do
    OmniAuth.config.before_options_phase = lambda do |env|
      trace << [:before_options_phase]
      env['omniauth.strategy'].fail!(:options_denied)
    end

    response = strategy.call(env_for('/auth/phaseorder', 'REQUEST_METHOD' => 'OPTIONS'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('before_options_phase -> on_failure(options_denied)')
  end

  it 'does not run the after-request hook when the request phase calls fail!' do
    strategy.options[:request_result] = nil
    deep = Class.new(PhaseOrderStrategy) do
      def request_phase
        fail!(:request_denied)
      end
    end
    hook(:after_request_phase)

    response = deep.new(app, :trace => trace).call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('on_failure(request_denied)')
    expect(app_calls).to be_empty
  end

  it 'does not finish a request after a validation hook calls fail! and returns' do
    OmniAuth.config.request_validation_phase = lambda do |env|
      trace << [:request_validation_phase]
      env['omniauth.strategy'].fail!(:invalid_token)
      nil
    end
    hook(:before_request_phase)

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('request_validation_phase -> on_failure(invalid_token)')
    expect(app_calls).to be_empty
  end

  it 'does not run the callback phase when the setup endpoint calls fail!' do
    setup = lambda do |env|
      trace << [:setup_phase]
      env['omniauth.strategy'].fail!(:unknown_tenant)
    end
    strategy.options[:setup] = setup
    hook(:before_callback_phase)

    response = strategy.call(env_for('/auth/phaseorder/callback'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('setup_phase -> on_failure(unknown_tenant)')
    expect(app_calls).to be_empty
  end

  it 'ends in a terminal response when on_failure returns nothing' do
    OmniAuth.config.on_failure = lambda { |_env| nil }
    hook(:before_request_phase) { |_env| raise 'request rejected' }

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(500)
    expect(app_calls).to be_empty
  end

  it 'reports a handler raise that happens while a phase calls fail!' do
    OmniAuth.config.on_failure = lambda { |_env| raise 'handler exploded' }
    deep = Class.new(PhaseOrderStrategy) do
      def request_phase
        fail!(:request_denied)
      end
    end

    expect do
      deep.new(app, :trace => trace).call(env_for('/auth/phaseorder'))
    end.to raise_error(RuntimeError, 'handler exploded')

    expect(app_calls).to be_empty
  end

  it 'stops after an after-request hook calls fail! and returns' do
    OmniAuth.config.after_request_phase = lambda do |env|
      trace << [:after_request_phase]
      env['omniauth.strategy'].fail!(:after_request_denied)
      nil
    end

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('request_phase -> after_request_phase -> on_failure(after_request_denied)')
    expect(app_calls).to be_empty
  end

  it 'keeps the first failure response when a hook fails and then raises' do
    OmniAuth.config.before_request_phase = lambda do |env|
      trace << [:before_request_phase]
      env['omniauth.strategy'].fail!(:first_failure)
      raise 'after failing'
    end

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(401)
    expect(phase_trace(trace)).to eq('before_request_phase -> on_failure(first_failure)')
    expect(failure_body).to eq([['first_failure', false]])
    expect(app_calls).to be_empty
  end

  context 'in test mode' do
    before do
      OmniAuth.config.test_mode = true
    end

    after do
      OmniAuth.config.mock_auth.delete(:phaseorder)
    end

    it 'does not run the mocked request phase when setup calls fail!' do
      strategy.options[:setup] = lambda do |env|
        trace << [:setup_phase]
        env['omniauth.strategy'].fail!(:unknown_tenant)
      end
      hook(:request_validation_phase)

      response = strategy.call(env_for('/auth/phaseorder'))

      expect(response[0]).to eq(401)
      expect(phase_trace(trace)).to eq('setup_phase -> on_failure(unknown_tenant)')
    end

    it 'does not store params or redirect when validation returns a denial' do
      OmniAuth.config.request_validation_phase = lambda do |_env|
        trace << [:request_validation_phase, 'deny']
        [403, {}, ['denied']]
      end

      response = strategy.call(env_for('/auth/phaseorder', 'QUERY_STRING' => 'evil=1'))

      expect(response[0]).to eq(403)
      expect(phase_trace(trace)).to eq('request_validation_phase(deny)')
      expect(session).not_to have_key('omniauth.params')
    end

    it 'ends the mocked request phase when a request hook calls fail!' do
      OmniAuth.config.before_request_phase = lambda do |env|
        trace << [:before_request_phase]
        env['omniauth.strategy'].fail!(:blocked_by_hook)
      end
      hook(:after_request_phase)

      response = strategy.call(env_for('/auth/phaseorder'))

      expect(response[0]).to eq(401)
      expect(phase_trace(trace)).to eq('before_request_phase -> on_failure(blocked_by_hook)')
    end

    it 'ends the mocked request phase when the after-request hook calls fail!' do
      OmniAuth.config.after_request_phase = lambda do |env|
        trace << [:after_request_phase]
        env['omniauth.strategy'].fail!(:after_request_denied)
      end

      response = strategy.call(env_for('/auth/phaseorder'))

      expect(response[0]).to eq(401)
      expect(phase_trace(trace)).to eq('after_request_phase -> on_failure(after_request_denied)')
    end

    it 'does not run the mocked callback when setup calls fail!' do
      strategy.options[:setup] = lambda do |env|
        trace << [:setup_phase]
        env['omniauth.strategy'].fail!(:unknown_tenant)
      end
      hook(:before_callback_phase)

      response = strategy.call(env_for('/auth/phaseorder/callback'))

      expect(response[0]).to eq(401)
      expect(phase_trace(trace)).to eq('setup_phase -> on_failure(unknown_tenant)')
    end

    it 'does not write the mocked auth hash when the callback hook fails' do
      OmniAuth.config.mock_auth[:phaseorder] = {'provider' => 'phaseorder', 'uid' => 'mock'}
      OmniAuth.config.before_callback_phase = lambda do |env|
        trace << [:before_callback_phase]
        env['omniauth.strategy'].fail!(:hook_denied)
      end
      env = env_for('/auth/phaseorder/callback')

      response = strategy.call(env)

      expect(response[0]).to eq(401)
      expect(env).not_to have_key('omniauth.auth')
      expect(phase_trace(trace)).to eq('before_callback_phase -> on_failure(hook_denied)')
      expect(app_calls).to be_empty
    end
  end

  describe 'the trace table generated by these tests' do
    # Runs one request with hooks that record themselves, and returns the
    # event trace. The same table is written to spec/security/phase_order_trace.md,
    # so the current contract can be inspected without reading the code.
    def capture_trace(path, options = {})
      events = []
      install_trace_hooks(options.fetch(:hooks, {}), events)
      old_on_failure = install_trace_failure_handler(events)
      OmniAuth.config.test_mode = options.fetch(:test_mode, false)
      OmniAuth.config.mock_auth[:phaseorder] = options[:mock] if options[:mock]
      strategy = trace_strategy(path, options, events)
      strategy.call(env_for(path, options.fetch(:props, {})))
      phase_trace(events)
    ensure
      OmniAuth.config.on_failure = old_on_failure if old_on_failure
      OmniAuth.config.mock_auth.delete(:phaseorder)
      reset_phase_config!
    end

    def install_trace_hooks(hooks, events)
      hooks.each do |name, action|
        OmniAuth.config.public_send("#{name}=", lambda do |env|
          events << [name]
          action&.call(env)
        end)
      end
    end

    def install_trace_failure_handler(events)
      old = OmniAuth.config.on_failure
      OmniAuth.config.on_failure = lambda do |env|
        events << [:on_failure, env['omniauth.error.type']]
        [401, {}, ['failure']]
      end
      old
    end

    def trace_strategy(path, options, events)
      app = lambda do |env|
        events << [:downstream_app, env.key?('omniauth.auth') ? 'auth' : 'no_auth']
        [200, {}, ['app']]
      end
      return PhaseOrderStrategy.new(app, :trace => events) if options[:other_phase]

      Class.new(PhaseOrderStrategy) { undef_method :other_phase }.new(app, :trace => events).tap do |strategy|
        add_trace_setup(strategy, options[:setup], events)
      end
    end

    def add_trace_setup(strategy, setup, events)
      return unless setup

      strategy.options[:setup] = lambda do |env|
        events << [:setup_phase]
        setup.call(env)
      end
    end

    def reset_phase_config!
      OmniAuth.config.test_mode = false
      OmniAuth.config.request_validation_phase = nil
      OmniAuth.config.before_request_phase = nil
      OmniAuth.config.after_request_phase = nil
      OmniAuth.config.before_callback_phase = nil
      OmniAuth.config.before_options_phase = nil
    end

    def deny_with_failure(message_key)
      lambda { |env| env['omniauth.strategy'].fail!(message_key) }
    end

    def with_hook(hook_names, name, action)
      hook_names.each_with_object({}) { |hook, hash| hash[hook] = hook == name ? action : nil }
    end

    def request_row(hooks, setup = nil)
      capture_trace('/auth/phaseorder', :hooks => hooks, :setup => setup)
    end

    def scenario_rows
      hook_names = %i[request_validation_phase before_request_phase after_request_phase]
      rows = {}
      rows['request'] = request_row(hook_names)
      rows['request, setup'] = request_row(hook_names, proc { |_env| nil })
      rows['request, validation returns a denial'] =
        request_row(with_hook(hook_names, :request_validation_phase, proc { [403, {}, ['denied']] }))
      rows['request, validation raises'] =
        request_row(with_hook(hook_names, :request_validation_phase, proc { raise OmniAuth::AuthenticityError, 'bad token' }))
      rows['request, before hook calls fail!'] =
        request_row(with_hook(hook_names, :before_request_phase, deny_with_failure(:blocked_by_hook)))
      rows['request, setup calls fail!'] = request_row(hook_names, deny_with_failure(:unknown_tenant))
      rows.merge!(callback_rows)
    end

    def callback_rows
      {
        'callback' => capture_trace('/auth/phaseorder/callback', :hooks => %i[before_callback_phase]),
        'callback, hook raises' => capture_trace(
          '/auth/phaseorder/callback', :hooks => {:before_callback_phase => proc { raise 'hook rejected callback' }}
        ),
        'callback, hook calls fail!' => capture_trace(
          '/auth/phaseorder/callback', :hooks => {:before_callback_phase => deny_with_failure(:tenant_mismatch)}
        )
      }
    end

    def options_rows
      {
        'OPTIONS' => capture_trace('/auth/phaseorder', :props => {'REQUEST_METHOD' => 'OPTIONS'},
                                   :hooks => %i[before_options_phase]),
        'OPTIONS, hook calls fail!' => capture_trace(
          '/auth/phaseorder', :props => {'REQUEST_METHOD' => 'OPTIONS'},
          :hooks => {:before_options_phase => deny_with_failure(:options_denied)}
        )
      }
    end

    def other_path_rows
      {
        'non-auth path' => capture_trace('/elsewhere'),
        'other_phase path' => capture_trace('/elsewhere', :other_phase => true,
                                            :hooks => %i[request_validation_phase before_callback_phase])
      }
    end

    def test_mode_rows
      names = %i[request_validation_phase before_request_phase after_request_phase]
      {
        'test-mode request' => capture_trace('/auth/phaseorder', :test_mode => true, :hooks => names),
        'test-mode callback' => capture_trace(
          '/auth/phaseorder/callback', :test_mode => true,
          :mock => {'provider' => 'phaseorder', 'uid' => 'mock'},
          :hooks => %i[before_callback_phase]
        ),
        'test-mode callback, mocked failure' => capture_trace(
          '/auth/phaseorder/callback', :test_mode => true, :mock => :invalid_credentials,
          :hooks => %i[before_callback_phase]
        )
      }
    end

    it 'matches the expected request, callback, OPTIONS, and non-auth timelines' do
      rows = scenario_rows.merge!(callback_rows).merge!(options_rows)
      rows.merge!(other_path_rows).merge!(test_mode_rows)
      table = rows.keys.map { |name| "| #{name} | #{rows[name]} |" }.join("\n")

      FileUtils.mkdir_p('spec/security')
      File.write('spec/security/phase_order_trace.md', "# Generated phase trace\n\n| Scenario | Events |\n| --- | --- |\n" + table + "\n")
      expect(table).to eq(expected_rows.join("\n"))
    end

    def expected_rows
      [
        '| request | request_validation_phase -> before_request_phase -> request_phase -> after_request_phase |',
        '| request, setup | setup_phase -> request_validation_phase -> before_request_phase -> request_phase -> after_request_phase |',
        '| request, validation returns a denial | request_validation_phase |',
        '| request, validation raises | request_validation_phase -> on_failure(authenticity_error) |',
        '| request, before hook calls fail! | request_validation_phase -> before_request_phase -> on_failure(blocked_by_hook) |',
        '| request, setup calls fail! | setup_phase -> on_failure(unknown_tenant) |',
        '| callback | before_callback_phase -> callback_phase -> auth_hash_written -> downstream_app(auth) |',
        '| callback, hook raises | before_callback_phase -> on_failure(hook rejected callback) |',
        '| callback, hook calls fail! | before_callback_phase -> on_failure(tenant_mismatch) |',
        '| OPTIONS | before_options_phase |',
        '| OPTIONS, hook calls fail! | before_options_phase -> on_failure(options_denied) |',
        '| non-auth path | downstream_app(no_auth) |',
        '| other_phase path | other_phase |',
        '| test-mode request | request_validation_phase -> before_request_phase -> after_request_phase |',
        '| test-mode callback | before_callback_phase -> downstream_app(auth) |',
        '| test-mode callback, mocked failure | before_callback_phase -> on_failure(invalid_credentials) |'
      ]
    end
  end

  it 'ignores a Rack response returned by the before-request hook' do
    OmniAuth.config.before_request_phase = lambda do |_env|
      trace << [:before_request_phase]
      [403, {}, ['ignored']]
    end
    hook(:after_request_phase)

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(200)
    expect(phase_trace(trace)).to eq('before_request_phase -> request_phase -> after_request_phase')
    expect(app_calls).to be_empty
  end

  it 'ignores a Rack response returned by the after-request hook and keeps the phase response' do
    strategy.options[:request_result] = [302, {'Location' => '/provider'}, []]
    OmniAuth.config.after_request_phase = lambda do |_env|
      trace << [:after_request_phase]
      [403, {}, ['ignored']]
    end

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response).to eq([302, {'Location' => '/provider'}, []])
    expect(phase_trace(trace)).to eq('request_phase -> after_request_phase')
  end

  it 'ignores a Rack response returned by the before-callback hook' do
    OmniAuth.config.before_callback_phase = lambda do |_env|
      trace << [:before_callback_phase]
      [403, {}, ['ignored']]
    end

    response = strategy.call(env_for('/auth/phaseorder/callback'))

    expect(response[0]).to eq(200)
    expect(phase_trace(trace)).to eq('before_callback_phase -> callback_phase -> auth_hash_written -> downstream_app(auth)')
  end

  it 'ignores a Rack response returned by setup' do
    strategy.options[:setup] = lambda do |_env|
      trace << [:setup_phase]
      [403, {}, ['ignored']]
    end

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(200)
    expect(phase_trace(trace)).to eq('setup_phase -> request_phase')
  end

  it 'keeps the request phase early response while still running the after hook' do
    strategy.options[:request_result] = [302, {'Location' => 'https://provider.example/'}, []]
    hook(:after_request_phase)

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response).to eq([302, {'Location' => 'https://provider.example/'}, []])
    expect(phase_trace(trace)).to eq('request_phase -> after_request_phase')
  end

  it 'keeps a form endpoint early response while still running the after hook' do
    strategy.options[:form] = lambda { |_env| [200, {'content-type' => 'text/html'}, ['<form>']] }
    hook(:after_request_phase)

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response).to eq([200, {'content-type' => 'text/html'}, ['<form>']])
    expect(phase_trace(trace)).to eq('after_request_phase')
  end

  it 'does not stop a real request when on_failure has never been needed' do
    hook(:after_request_phase)

    response = strategy.call(env_for('/auth/phaseorder'))

    expect(response[0]).to eq(200)
    expect(failure_body).to be_empty
  end

  it 'does not send a partial auth hash to the app or the failure body when the callback phase fails' do
    deep = Class.new(PhaseOrderStrategy) do
      def callback_phase
        env['omniauth.auth'] = {'uid' => 'partial'}
        raise 'callback failed after writing'
      end
    end
    env = env_for('/auth/phaseorder/callback')

    response = deep.new(app, :trace => trace).call(env)

    expect(response[0]).to eq(401)
    expect(env).not_to have_key('omniauth.auth')
    expect(failure_body).to eq([['callback failed after writing', false]])
    expect(app_calls).to be_empty
  end

  def calls_to_request_phase
    trace.select { |event, _| event == :request_phase }
  end
end

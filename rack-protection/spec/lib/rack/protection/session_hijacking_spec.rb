# frozen_string_literal: true

RSpec.describe Rack::Protection::SessionHijacking do
  it_behaves_like 'any rack application'

  it 'accepts a session without changes to tracked parameters' do
    session = { foo: :bar }
    get '/', {}, 'rack.session' => session
    get '/', {}, 'rack.session' => session
    expect(session[:foo]).to eq(:bar)
  end

  it 'denies requests with a changing User-Agent header' do
    session = { foo: :bar }
    get '/', {}, 'rack.session' => session, 'HTTP_USER_AGENT' => 'a'
    get '/', {}, 'rack.session' => session, 'HTTP_USER_AGENT' => 'b'
    expect(session).to be_empty
  end

  it 'accepts requests with a changing Accept-Encoding header' do
    # this is tested because previously it led to clearing the session
    session = { foo: :bar }
    get '/', {}, 'rack.session' => session, 'HTTP_ACCEPT_ENCODING' => 'a'
    get '/', {}, 'rack.session' => session, 'HTTP_ACCEPT_ENCODING' => 'b'
    expect(session).not_to be_empty
  end

  it 'accepts requests with a changing Version header' do
    session = { foo: :bar }
    get '/', {}, 'rack.session' => session, 'SERVER_PROTOCOL' => 'HTTP/1.0'
    get '/', {}, 'rack.session' => session, 'SERVER_PROTOCOL' => 'HTTP/1.1'
    expect(session[:foo]).to eq(:bar)
  end
end

RSpec.describe Rack::Protection::SessionHijacking, 'graded mode' do
  it_behaves_like 'any rack application'

  let(:device_token) { ->(env) { env['HTTP_X_DEVICE_TOKEN'] } }

  # Inner app modelling an application that gates sensitive operations on
  # the restricted state and exposes re-authentication / logout / restore.
  let(:inner_app) do
    lambda do |env|
      Thread.current[:last_env] = env
      case env['PATH_INFO']
      when '/reauth'  then Rack::Protection::SessionHijacking.confirm_reauthentication(env)
      when '/logout'  then Rack::Protection::SessionHijacking.reset_tracking(env)
      when '/restore' then Rack::Protection::SessionHijacking.rebaseline(env)
      end
      body = Rack::Protection::SessionHijacking.restricted?(env) ? 'restricted' : 'ok'
      [200, { 'content-type' => 'text/plain' }, [body]]
    end
  end

  def graded_app(**options)
    inner = inner_app
    mock_app do
      use Rack::Head
      use(Rack::Config) { |e| e['rack.session'] ||= {} }
      use Rack::Protection::SessionHijacking, **options
      run inner
    end
  end

  def graded_env(session, ua: 'mobile-a', device: 'device-1')
    env = { 'rack.session' => session, 'HTTP_USER_AGENT' => ua }
    env['HTTP_X_DEVICE_TOKEN'] = device if device
    env
  end

  context 'with identity and weak signals configured' do
    before { graded_app(identity_signals: [device_token]) }

    it 'establishes a baseline on the first request without restricting' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session)
      expect(body).to eq('ok')
      expect(session[:user_id]).to eq(42)
      expect(session[:tracking]['restricted']).to be(false)
    end

    it 'normal mobile scenario: a changed user agent only restricts the session' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session, ua: 'mobile-a')
      get '/', {}, graded_env(session, ua: 'mobile-b') # network/device trait changed
      expect(body).to eq('restricted')
      expect(session[:user_id]).to eq(42) # session is NOT cleared
      expect(env['rack.protection.session_hijacking.restricted']).to be(true)
    end

    it 'keeps the restricted state until the app confirms re-authentication' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session, ua: 'mobile-a')
      get '/', {}, graded_env(session, ua: 'mobile-b')
      get '/', {}, graded_env(session, ua: 'mobile-b')
      expect(body).to eq('restricted')
      get '/reauth', {}, graded_env(session, ua: 'mobile-b')
      expect(body).to eq('ok')
      get '/', {}, graded_env(session, ua: 'mobile-b')
      expect(body).to eq('ok')
    end

    it 'does not let attack requests teach the weak baseline new traits' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session, ua: 'mobile-a')
      get '/', {}, graded_env(session, ua: 'mobile-b') # legit user roams, restricted
      get '/', {}, graded_env(session, ua: 'attacker-ua') # attacker replays cookie
      expect(body).to eq('restricted')
      expect(session[:tracking]['weak']['HTTP_USER_AGENT']).to eq('mobile-a')
      # the legitimate user re-authenticates from the new device
      get '/reauth', {}, graded_env(session, ua: 'mobile-b')
      expect(body).to eq('ok')
      # only now the baseline moved to mobile-b; the attacker is still detected
      get '/', {}, graded_env(session, ua: 'attacker-ua')
      expect(body).to eq('restricted')
    end

    it 'copied session scenario: an identity signal mismatch drops the session' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session, device: 'device-1')
      get '/', {}, graded_env(session, device: nil) # cookie replayed without device token
      expect(session).to be_empty
    end

    it 'rebuilds the baseline on logout / account switch via reset_tracking' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session, ua: 'mobile-a')
      get '/logout', {}, graded_env(session, ua: 'mobile-a')
      expect(session[:tracking]).to be_nil
      get '/', {}, graded_env(session, ua: 'other-device') # next login elsewhere
      expect(body).to eq('ok')
      expect(session[:tracking]['weak']['HTTP_USER_AGENT']).to eq('other-device')
    end

    it 'captures a fresh baseline immediately on session restore' do
      session = {}
      get '/restore', {}, graded_env(session, ua: 'restored-device')
      expect(body).to eq('ok')
      expect(session[:tracking]['weak']['HTTP_USER_AGENT']).to eq('restored-device')
    end
  end

  context 'with only weak signals configured' do
    before { graded_app(weak_signals: ['HTTP_ACCEPT_LANGUAGE']) }

    it 'restricts on weak signal changes without dropping the session' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session).merge('HTTP_ACCEPT_LANGUAGE' => 'en')
      get '/', {}, graded_env(session).merge('HTTP_ACCEPT_LANGUAGE' => 'de')
      expect(body).to eq('restricted')
      expect(session[:user_id]).to eq(42)
    end
  end

  it 'refuses client-forgeable headers as identity signals' do
    expect do
      graded_app(identity_signals: ['HTTP_USER_AGENT'])
    end.to raise_error(ArgumentError, /weak signal/)
  end

  it 'rejects unknown weak_reaction values' do
    expect do
      graded_app(weak_signals: ['HTTP_ACCEPT_LANGUAGE'], weak_reaction: :explode)
    end.to raise_error(ArgumentError, /weak_reaction/)
  end

  context 'with weak_reaction: :drop_session (legacy-style clearing)' do
    before { graded_app(weak_signals: ['HTTP_ACCEPT_LANGUAGE'], weak_reaction: :drop_session) }

    it 'clears the session on weak signal changes' do
      session = { user_id: 42 }
      get '/', {}, graded_env(session).merge('HTTP_ACCEPT_LANGUAGE' => 'en')
      get '/', {}, graded_env(session).merge('HTTP_ACCEPT_LANGUAGE' => 'de')
      expect(session).to be_empty
    end
  end

  it 'raises a helpful error when helpers are used without the middleware' do
    expect do
      Rack::Protection::SessionHijacking.restricted?({})
    end.to raise_error(RuntimeError, /middleware/)
  end
end

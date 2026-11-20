# encoding: utf-8
# frozen_string_literal: true
require 'rack/session'

RSpec.describe "backend callback authentication" do
  before(:all) do
    load_strategies
    Warden::Strategies.add(:backend_callback) do
      def valid?
        !!env['HTTP_X_BACKEND_TICKET']
      end

      def authenticate!
        success!("backend-user")
      end

      def store?
        false
      end
    end
  end

  around do |example|
    on_request = Warden::Manager._on_request.dup
    after_set_user = Warden::Manager._after_set_user.dup
    example.run
  ensure
    Warden::Manager._on_request.replace(on_request)
    Warden::Manager._after_set_user.replace(after_set_user)
  end

  def without_session(&app)
    Rack::Builder.new do
      use Warden::Manager, failure_app: Warden::Spec::Helpers::FAILURE_APP do |config|
        config.default_strategies :backend_callback
      end
      run app
    end.to_app
  end

  def with_session(&app)
    Rack::Builder.new do
      use Rack::Session::Pool
      use Warden::Manager, failure_app: Warden::Spec::Helpers::FAILURE_APP do |config|
        config.default_strategies :backend_callback
      end
      run app
    end.to_app
  end

  def callback_env(headers = {})
    Rack::MockRequest.env_for("/callback", headers)
  end

  def login_cookie(app)
    _, headers, = app.call(Rack::MockRequest.env_for('/login'))
    headers['set-cookie'] || headers['Set-Cookie']
  end

  describe "legal callback without a Rack session" do
    it "authenticates only for the current request and writes no session" do
      observed = {}
      app = without_session do |env|
        observed[:user] = env['warden'].authenticate(:backend_callback)
        observed[:authenticated] = env['warden'].authenticated?
        observed[:raw_session] = env['warden'].raw_session
        observed[:serializer_session] = env['warden'].session_serializer.session
        observed[:session_key] = env.key?('rack.session')
        [200, {}, ['ok']]
      end

      app.call(callback_env('HTTP_X_BACKEND_TICKET' => 'valid'))

      expect(observed[:user]).to eq('backend-user')
      expect(observed[:authenticated]).to be(true)
      expect(observed[:raw_session]).to be_nil
      expect(observed[:serializer_session]).to eq({})
      expect(observed[:session_key]).to be(false)
    end

    it "does not create a Rack session when authentication fails" do
      observed = {}
      app = without_session do |env|
        env['warden'].authenticate!(:backend_callback)
        observed[:reached_app] = true
        [200, {}, ['ok']]
      end

      status, _, body = app.call(callback_env)

      expect(status).to eq(401)
      expect(body).to eq(['You Fail!'])
      expect(observed).not_to have_key(:reached_app)
    end
  end

  describe "anonymous request without a Rack session" do
    it "stays anonymous and does not run the callback strategy" do
      observed = {}
      app = without_session do |env|
        observed[:authenticated] = env['warden'].authenticated?
        observed[:user] = env['warden'].user
        observed[:strategies] = env['warden.spec.strategies']
        observed[:session_key] = env.key?('rack.session')
        [200, {}, ['ok']]
      end

      app.call(callback_env)

      expect(observed[:authenticated]).to be(false)
      expect(observed[:user]).to be_nil
      expect(observed[:strategies]).to be_nil
      expect(observed[:session_key]).to be(false)
    end

    it "does not run a strategy whose valid? guard rejects the request" do
      observed = {}
      app = without_session do |env|
        observed[:user] = env['warden'].authenticate(:backend_callback)
        observed[:authenticated] = env['warden'].authenticated?
        observed[:strategies] = env['warden.spec.strategies']
        [200, {}, ['ok']]
      end

      app.call(callback_env)

      expect(observed[:user]).to be_nil
      expect(observed[:authenticated]).to be(false)
      expect(observed[:strategies]).to be_nil
    end
  end

  describe "callback on a request that carries a page session" do
    it "reuses the page user for the default scope and skips the callback strategy" do
      observed = {}
      app = with_session do |env|
        case env['PATH_INFO']
        when '/login'
          env['warden'].set_user('page-user')
        when '/callback'
          observed[:result] = env['warden'].authenticate(:backend_callback)
          observed[:strategies] = env['warden.spec.strategies']
        end
        [200, {}, ['ok']]
      end
      cookie = login_cookie(app)

      app.call(callback_env('HTTP_COOKIE' => cookie, 'HTTP_X_BACKEND_TICKET' => 'valid'))

      expect(observed[:result]).to eq('page-user')
      expect(observed[:strategies]).to be_nil
    end

    it "keeps callback identity request-scoped when using an explicit scope and store:false" do
      observed = {}
      app = with_session do |env|
        case env['PATH_INFO']
        when '/login'
          env['warden'].set_user('page-user')
        when '/callback'
          env['warden'].authenticate(:backend_callback, scope: :backend, store: false)
          observed[:backend_user] = env['warden'].user(:backend)
          observed[:page_user] = env['warden'].user
          observed[:backend_key] = env['rack.session']['warden.user.backend.key']
        when '/page'
          observed[:page_after_callback] = env['warden'].user
          observed[:backend_after_callback] = env['warden'].user(:backend)
        end
        [200, {}, ['ok']]
      end
      cookie = login_cookie(app)

      app.call(callback_env('HTTP_COOKIE' => cookie, 'HTTP_X_BACKEND_TICKET' => 'valid'))
      app.call(Rack::MockRequest.env_for('/page', 'HTTP_COOKIE' => cookie))

      expect(observed[:backend_user]).to eq('backend-user')
      expect(observed[:page_user]).to eq('page-user')
      expect(observed[:backend_key]).to be_nil
      expect(observed[:page_after_callback]).to eq('page-user')
      expect(observed[:backend_after_callback]).to be_nil
    end

    it "writes the default-scope key and requests renewal when store is enabled" do
      observed = {}
      app = with_session do |env|
        env['warden'].authenticate(:backend_callback, store: true)
        observed[:key] = env['rack.session']['warden.user.default.key']
        observed[:renew] = env['rack.session.options'][:renew]
        [200, {}, ['ok']]
      end
      env = callback_env('HTTP_X_BACKEND_TICKET' => 'valid')
      env['rack.session'] = { 'marker' => 'page' }

      app.call(env)

      expect(observed[:key]).to eq('backend-user')
      expect(observed[:renew]).to be(true)
      expect(env['rack.session']['marker']).to eq('page')
    end
  end

  describe "trusted identity entry" do
    it "accepts identity placed on the env by upstream code without a Rack session" do
      observed = {}
      app = without_session do |env|
        env['warden'].set_user(env['app.trusted_identity'], scope: :backend, store: false)
        observed[:user] = env['warden'].user(:backend)
        observed[:session_key] = env.key?('rack.session')
        [200, {}, ['ok']]
      end
      env = callback_env
      env['app.trusted_identity'] = 'trusted-user'

      app.call(env)

      expect(observed[:user]).to eq('trusted-user')
      expect(observed[:session_key]).to be(false)
    end

    it "does not distinguish a trusted env key from a client-controlled header" do
      observed = {}
      app = without_session do |env|
        env['warden'].set_user(env['HTTP_X_FORWARDED_USER'], scope: :backend, store: false)
        observed[:user] = env['warden'].user(:backend)
        [200, {}, ['ok']]
      end

      app.call(callback_env('HTTP_X_FORWARDED_USER' => 'forged-user'))

      expect(observed[:user]).to eq('forged-user')
    end
  end

  describe "session writes outside set_user" do
    it "lets an after_set_user hook mutate the persistent session even with store:false" do
      Warden::Manager.after_set_user do |user, auth, _opts|
        auth.raw_session[:last_backend_user] = user if auth.raw_session
      end
      observed = {}
      app = with_session do |env|
        env['warden'].authenticate(:backend_callback, store: false)
        observed[:session] = env['rack.session'].to_hash
        observed[:key] = env['rack.session']['warden.user.default.key']
        [200, {}, ['ok']]
      end

      app.call(callback_env('HTTP_X_BACKEND_TICKET' => 'valid'))

      expect(observed[:key]).to be_nil
      expect(observed[:session]).to eq('last_backend_user' => 'backend-user')
    end
  end
end

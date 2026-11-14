require 'helper'
require 'json'

# A provider and an application sharing one in-memory session, so the
# request and callback round trips run exactly as they would in Rack. The
# fake provider only takes the state the authorize endpoint was given and
# returns the email it was told to; it never decides what the intent means.
class FakeIdentityProvider
  attr_reader :authorize_states

  def initialize
    @authorize_states = []
  end

  def authorize(state)
    @authorize_states << state
  end

  def callback_params(state, email)
    Rack::Utils.build_query('state' => state, 'code' => 'fake-code', 'email' => email)
  end
end

class IntentStrategy
  include OmniAuth::Strategy

  option :name, 'second_provider'

  def request_phase
    remember_sign_in(request.params.fetch('state'))
    redirect "https://provider.example/authorize?state=#{request.params.fetch('state')}"
  end

  def callback_sign_in_key
    request.params['state']
  end

  # The fake provider's identity, which the application must not treat as
  # proof of an intent.
  uid { request.params['email'] }

  info { {'email' => request.params['email']} }
end

describe OmniAuth::Strategy, 'auth intents' do
  # The application's account store and session generation. The library only
  # carries and compares them; it never writes the account or the link.
  class IntentAccountStore
    attr_reader :links, :session_generation

    def initialize
      @links = []
      @session_generation = 0
      @current_user = nil
    end

    def current_user
      @current_user
    end

    def sign_in(user_id)
      @current_user = user_id
      @session_generation += 1
    end

    def sign_out
      @current_user = nil
      @session_generation += 1
    end

    def link(provider, uid, user_id)
      @links << [provider, uid, user_id]
    end
  end

  let(:provider) { FakeIdentityProvider.new }
  let(:accounts) { IntentAccountStore.new }
  let(:session) { {} }
  let(:seen) { [] }
  let(:app) do
    lambda do |env|
      seen << env
      intent = env['omniauth.auth_intent']
      accounts.link(env['omniauth.auth']['provider'], env['omniauth.auth']['uid'], intent['user_id']) if intent && intent['type'] == 'link'
      [200, {'Content-Type' => 'application/json'}, [JSON.generate(intent)]]
    end
  end
  # The context for the current session. An ordinary login has none, which
  # lets one strategy serve both flows; a proc reads the account store on
  # each phase, as an application would read its own session.
  let(:strategy) do
    IntentStrategy.new(app, :auth_intent => lambda do |_env|
      next if accounts.current_user.nil?

      {'type' => 'link', 'user_id' => accounts.current_user, 'session_generation' => accounts.session_generation}
    end)
  end

  around do |example|
    validation_phase = OmniAuth.config.request_validation_phase
    OmniAuth.config.request_validation_phase = nil
    example.run
  ensure
    OmniAuth.config.request_validation_phase = validation_phase
  end

  def start(state = 'state-1', using: strategy)
    response = using.call(Rack::MockRequest.env_for("http://app.example/auth/second_provider?state=#{state}", :method => 'POST', 'rack.session' => session))
    expect(response[0]).to eq(302)
    provider.authorize(state)
    state
  end

  def finish(state, email = 'person@provider.example', using: strategy)
    using.call(Rack::MockRequest.env_for("http://app.example/auth/second_provider/callback?#{provider.callback_params(state, email)}", 'rack.session' => session))
  end

  def context_from(response)
    JSON.parse(response[2].join)
  end

  describe 'a normal link flow' do
    it 'hands the application the trusted link context and binds the external identity' do
      accounts.sign_in('user-7')
      start('state-7')

      response = finish('state-7')

      expect(response[0]).to eq(200)
      expect(context_from(response)).to eq(
        'type' => 'link',
        'user_id' => 'user-7',
        'session_generation' => accounts.session_generation
      )
      expect(seen.last['omniauth.auth']['uid']).to eq('person@provider.example')
      expect(accounts.links).to eq([['second_provider', 'person@provider.example', 'user-7']])
      expect(session['omniauth.sign_ins']).to eq({})
    end

    it 'leaves other in-flight sign-ins and their authentication alone' do
      accounts.sign_in('user-7')
      start('state-a')
      start('state-b')

      expect(context_from(finish('state-a'))['user_id']).to eq('user-7')
      expect(session['omniauth.sign_ins'].keys).to eq(%w[state-b])

      expect(context_from(finish('state-b'))['user_id']).to eq('user-7')
      expect(accounts.links.length).to eq(2)
    end

    it 'treats a cancelled link as only ending its own transaction' do
      accounts.sign_in('user-7')
      start('state-a')
      start('state-b')

      expect(OmniAuth::Strategy::AuthIntents.cancel_sign_in(session, 'state-a')).to be(true)
      expect(session['omniauth.sign_ins'].keys).to eq(%w[state-b])

      # The cancelled transaction's late callback fails and links nothing.
      response = finish('state-a')
      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_missing')
      expect(accounts.links).to be_empty

      # The other transaction still completes normally.
      expect(context_from(finish('state-b'))['user_id']).to eq('user-7')
      expect(accounts.links.length).to eq(1)
    end

    it "rejects a repeated callback without touching another sign-in's result" do
      accounts.sign_in('user-7')
      start('state-a')
      start('state-b')

      expect(context_from(finish('state-a'))['user_id']).to eq('user-7')
      # Replaying the consumed state must not link a second time or restore
      # anything from the first transaction.
      response = finish('state-a')
      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_missing')
      expect(accounts.links.length).to eq(1)

      expect(context_from(finish('state-b'))['user_id']).to eq('user-7')
      expect(accounts.links.length).to eq(2)
    end
  end

  describe 'when the local identity changed while the provider had the user' do
    it 'refuses to link after the user signed out and signed in as someone else' do
      accounts.sign_in('user-7')
      start('state-7')

      accounts.sign_out
      accounts.sign_in('user-9')

      response = finish('state-7')

      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
      expect(accounts.links).to be_empty
      expect(seen).to be_empty
      # The transaction is consumed, so a replay cannot succeed either.
      expect(session['omniauth.sign_ins']).to eq({})
    end

    it 'ends only the failed transaction, leaving others to complete' do
      accounts.sign_in('user-7')
      start('state-old')
      start('state-new')

      accounts.sign_out
      accounts.sign_in('user-9')

      # The old transaction fails and links nothing, but its record is gone.
      expect(finish('state-old')[0]).to eq(302)
      expect(session['omniauth.sign_ins'].keys).to eq(%w[state-new])

      # A fresh link started after the account change still works, and the
      # older transaction cannot be replayed in its place.
      start('state-fresh')
      expect(finish('state-fresh')[0]).to eq(200)
      expect(accounts.links).to eq([['second_provider', 'person@provider.example', 'user-9']])
      expect(finish('state-old')[0]).to eq(302)
      expect(accounts.links.length).to eq(1)
    end

    it 'refuses after the same user starts a fresh auth session' do
      accounts.sign_in('user-7')
      start('state-7')

      accounts.sign_in('user-7')

      response = finish('state-7')

      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
      expect(accounts.links).to be_empty
    end

    it 'refuses after a sign-out with no new user' do
      accounts.sign_in('user-7')
      start('state-7')
      accounts.sign_out

      response = finish('state-7')

      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
      expect(accounts.links).to be_empty
    end

    it 'does not accept the same provider email as an identity confirmation' do
      accounts.sign_in('user-7')
      start('state-7')

      accounts.sign_out
      accounts.sign_in('user-9')

      response = finish('state-7', 'user-7@provider.example')

      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
      expect(accounts.links).to be_empty
    end
  end

  describe 'when the intent itself changed between request and callback' do
    it 'refuses a login that arrives after the user signed in and started a link' do
      # An ordinary login was started while signed out, then the user signed
      # in elsewhere and began a link (which this callback is not).
      start('state-login')
      accounts.sign_in('user-7')

      response = finish('state-login')
      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
      expect(accounts.links).to be_empty
    end

    it 'rejects a callback whose state belongs to another strategy' do
      accounts.sign_in('user-7')
      start('state-7')

      other_app = lambda { |_env| [200, {}, ['unexpected']] }
      other = Class.new(IntentStrategy) do
        option :name, 'other_provider'
      end.new(other_app, :auth_intent => ->(_env) { {'type' => 'link', 'user_id' => 'user-7', 'session_generation' => accounts.session_generation} })

      response = other.call(Rack::MockRequest.env_for("http://app.example/auth/other_provider/callback?#{provider.callback_params('state-7', 'x@provider.example')}", 'rack.session' => session))
      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_missing')
      expect(session['omniauth.sign_ins'].keys).to eq(%w[state-7])

      # The rightful strategy can still finish its own transaction.
      expect(context_from(finish('state-7'))['user_id']).to eq('user-7')
    end
  end

  describe 'a strategy without an auth intent' do
    let(:strategy) { IntentStrategy.new(app) }

    it 'keeps the legacy sign-in and callback behaviour' do
      accounts.sign_in('user-7')
      start('state-7')

      response = finish('state-7')

      expect(response[0]).to eq(200)
      expect(context_from(response)).to be_nil
      expect(seen.last['omniauth.auth']['uid']).to eq('person@provider.example')
    end
  end

  describe 'intent values and cancellation edge cases' do
    it 'records symbol, boolean, integer, and finite float context values' do
      context = {'type' => 'login', 'tenant' => :acme, 'remember' => true, 'count' => 2, 'ratio' => 0.5}
      strategy = IntentStrategy.new(app, :auth_intent => context)
      strategy.call(Rack::MockRequest.env_for('http://app.example/auth/second_provider?state=s', :method => 'POST', 'rack.session' => session))

      expect(session['omniauth.sign_ins']['s']['auth_intent']).to eq(
        'type' => 'login', 'tenant' => 'acme', 'remember' => true, 'count' => 2, 'ratio' => 0.5
      )
    end

    it 'returns the application context on a login callback, without binding' do
      login = IntentStrategy.new(app, :auth_intent => {'type' => 'login', 'tenant' => 'acme'})
      start('state-1', :using => login)

      response = finish('state-1', :using => login)

      expect(context_from(response)).to eq('type' => 'login', 'tenant' => 'acme')
      expect(accounts.links).to be_empty
    end

    it 'refuses a login callback whose recorded user changed' do
      context = {'type' => 'login', 'user_id' => 'user-a', 'session_generation' => 1}
      login = IntentStrategy.new(app, :auth_intent => ->(_env) { context })
      start('state-1', :using => login)
      context.replace('user_id' => 'user-b', 'type' => 'login', 'session_generation' => 1)

      response = finish('state-1', :using => login)
      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
    end

    it 'refuses a type the library does not recognise' do
      login = IntentStrategy.new(app, :auth_intent => {'type' => 'step_up', 'user_id' => 'user-7'})
      start('state-1', :using => login)

      response = finish('state-1', :using => login)
      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
    end

    it 'reports a callback-time context that raises as a mismatch' do
      login = IntentStrategy.new(app, :auth_intent => lambda do |env|
        raise OmniAuth::AuthIntentError, 'missing session user' if env['PATH_INFO'].end_with?('/callback')

        {'type' => 'link', 'user_id' => 'user-7', 'session_generation' => 1}
      end)
      start('state-1', :using => login)

      response = finish('state-1', :using => login)
      expect(response[1]['Location']).to include('message=auth_intent_mismatch')
    end

    it 'reports a request-time context that is not a Hash as an authentication failure' do
      login = IntentStrategy.new(app, :auth_intent => 'not a hash')
      response = login.call(Rack::MockRequest.env_for('http://app.example/auth/second_provider?state=s', :method => 'POST', 'rack.session' => session))

      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_invalid')
      expect(session['omniauth.sign_ins']).to be_nil
    end

    it 'rejects a non-string, non-symbol context key' do
      login = IntentStrategy.new(app, :auth_intent => {'type' => 'login', 1 => 'x'})
      response = login.call(Rack::MockRequest.env_for('http://app.example/auth/second_provider?state=s', :method => 'POST', 'rack.session' => session))

      expect(response[1]['Location']).to include('message=auth_intent_invalid')
    end

    it 'rejects a context string longer than the limit' do
      login = IntentStrategy.new(app, :auth_intent => {'type' => 'login', 'note' => 'x' * (OmniAuth::Strategy::AuthIntents::MAX_AUTH_INTENT_VALUE_LENGTH + 1)})
      response = login.call(Rack::MockRequest.env_for('http://app.example/auth/second_provider?state=s', :method => 'POST', 'rack.session' => session))

      expect(response[1]['Location']).to include('message=auth_intent_invalid')
    end

    it 'rejects a non-finite float' do
      login = IntentStrategy.new(app, :auth_intent => {'type' => 'login', 'ratio' => Float::INFINITY})
      response = login.call(Rack::MockRequest.env_for('http://app.example/auth/second_provider?state=s', :method => 'POST', 'rack.session' => session))

      expect(response[1]['Location']).to include('message=auth_intent_invalid')
    end

    it 'returns false when cancelling a transaction that does not exist' do
      expect(OmniAuth::Strategy::AuthIntents.cancel_sign_in(session, 'missing')).to be(false)
      expect(OmniAuth::Strategy::AuthIntents.cancel_sign_in(nil, 'missing')).to be(false)
      expect(OmniAuth::Strategy::AuthIntents.cancel_sign_in(session, :missing)).to be(false)
      session['omniauth.sign_ins'] = 'junk'
      expect(OmniAuth::Strategy::AuthIntents.cancel_sign_in(session, 'missing')).to be(false)
    end

    it 'is idempotent, returning false the second time' do
      accounts.sign_in('user-7')
      start('state-7')

      expect(OmniAuth::Strategy::AuthIntents.cancel_sign_in(session, 'state-7')).to be(true)
      expect(OmniAuth::Strategy::AuthIntents.cancel_sign_in(session, 'state-7')).to be(false)
    end

    it 'ignores a tampered, non-string sign-in key' do
      accounts.sign_in('user-7')
      start('state-7')
      session['omniauth.sign_ins'] = session['omniauth.sign_ins'].merge(1 => 'junk')

      response = finish('state-7')
      expect(response[0]).to eq(200)
      expect(accounts.links.length).to eq(1)
    end

    it 'ignores a callback key that is not a string' do
      accounts.sign_in('user-7')
      start('state-7')

      response = strategy.call(Rack::MockRequest.env_for('http://app.example/auth/second_provider/callback?state[]=state-7', 'rack.session' => session))
      expect(response[0]).to eq(302)
      expect(response[1]['Location']).to include('message=auth_intent_missing')
    end
  end

  describe 'invalid intent configurations' do
    def failure_for(context)
      strategy = IntentStrategy.new(app, :auth_intent => context)
      accounts.sign_in('user-7')
      strategy.call(Rack::MockRequest.env_for('http://app.example/auth/second_provider?state=s', :method => 'POST', 'rack.session' => session))
    end

    it 'requires a type' do
      expect(failure_for({'user_id' => 'user-7'})[0]).to eq(302)
      expect(session['omniauth.sign_ins']).to be_nil
    end

    it 'requires the local user and generation for a link' do
      expect(failure_for({'type' => 'link', 'user_id' => 'user-7'})[0]).to eq(302)
      expect(session['omniauth.sign_ins']).to be_nil
    end

    it 'rejects a non-scalar value' do
      failure_for({'type' => 'login', 'nested' => {'a' => 'b'}})
      expect(session['omniauth.sign_ins']).to be_nil
    end
  end
end

# A self-contained run of the three account-linking flows: a normal link, a
# callback after the user switched accounts, and a repeated callback. It uses
# a fake provider and one in-memory session, so it needs no network access.
#
#   ruby -Ilib examples/account_linking.rb

require 'omniauth'
require 'json'
require 'securerandom'

OmniAuth.config.logger = Logger.new(File::NULL)
OmniAuth.config.request_validation_phase = nil

class FakeProvider
  def authorize(state)
    "https://provider.example/authorize?state=#{state}"
  end

  def callback(state, email)
    "http://app.example/auth/second_provider/callback?#{Rack::Utils.build_query('state' => state, 'email' => email)}"
  end
end

class SecondProvider
  include OmniAuth::Strategy

  option :name, 'second_provider'

  # The app's own session fields: the local user and an auth-session
  # generation that changes on sign-in, sign-out, and re-login.
  option :auth_intent, lambda { |env|
    session = env['rack.session']
    next unless session['user_id']

    {'type' => 'link', 'user_id' => session['user_id'], 'session_generation' => session['session_generation']}
  }

  def request_phase
    remember_sign_in(request.params.fetch('state'))
    redirect "https://provider.example/authorize?state=#{request.params.fetch('state')}"
  end

  def callback_sign_in_key
    request.params['state']
  end

  uid { request.params['email'] }
  info { {'email' => request.params['email']} }
end

session = {}
provider = FakeProvider.new
app = lambda do |env|
  intent = env['omniauth.auth_intent']
  links = env['omniauth.links'] ||= []
  links << {'provider' => env['omniauth.auth']['provider'], 'uid' => env['omniauth.auth']['uid'], 'user' => intent['user_id']}
  [200, {'Content-Type' => 'application/json'}, [JSON.generate('intent' => intent, 'links' => links)]]
end
strategy = SecondProvider.new(app)
def sign_in(session, user)
  session['user_id'] = user
  session['session_generation'] = (session['session_generation'] || 0) + 1
end
def sign_out(session)
  session.delete('user_id')
  session['session_generation'] = (session['session_generation'] || 0) + 1
end
def start(strategy, session, state)
  strategy.call(Rack::MockRequest.env_for("http://app.example/auth/second_provider?state=#{state}", :method => 'POST', 'rack.session' => session))[1]['Location']
end
def finish(strategy, session, url)
  response = strategy.call(Rack::MockRequest.env_for(url, 'rack.session' => session))
  [response[0], response[2].join]
end

sign_in(session, 'user-7')
state = SecureRandom.hex(8)
puts "1. normal link, signed in as #{session['user_id']}, generation #{session['session_generation']}"
start(strategy, session, state)
puts "   provider: #{provider.authorize(state)}"
puts "   app received: #{finish(strategy, session, provider.callback(state, 'seven@provider.example')).inspect}"
puts "   session left: #{session.inspect}"

state = SecureRandom.hex(8)
start(strategy, session, state)
puts "\n2. link started as #{session['user_id']}, then the user signs out and in as user-9"
sign_out(session)
sign_in(session, 'user-9')
status, body = finish(strategy, session, provider.callback(state, 'seven@provider.example'))
puts "   callback status/body: #{status} #{body}"
puts "   app called? #{status == 200} (it must not be)"
puts "   session left: #{session.inspect}"

sign_in(session, 'user-7')
state = SecureRandom.hex(8)
start(strategy, session, state)
puts "\n3. normal link, then the same callback is replayed"
first = finish(strategy, session, provider.callback(state, 'seven@provider.example'))
second = finish(strategy, session, provider.callback(state, 'seven@provider.example'))
puts "   first: #{first.inspect}"
puts "   replay: #{second.inspect}"

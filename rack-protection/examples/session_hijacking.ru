# frozen_string_literal: true

# Demo: graded session hijacking detection for mobile clients.
#
# Run from the repository root (only rack + rack-protection are needed):
#
#   rackup rack-protection/examples/session_hijacking.ru
#
# --- Scenario 1: normal mobile user --------------------------------------
# The user roams / the browser updates: the User-Agent changes. The session
# is kept but restricted; sensitive routes demand re-authentication.
#
#   curl -c jar -b jar -X POST -d password=s3cret localhost:9292/login
#   curl -c jar -b jar -A 'Mobile/1.0' localhost:9292/
#   curl -c jar -b jar -A 'Mobile/2.0' localhost:9292/transfer
#     # => 403 re-authentication required (session NOT cleared)
#   curl -c jar -b jar -A 'Mobile/2.0' -X POST -d password=s3cret localhost:9292/reauthenticate
#   curl -c jar -b jar -A 'Mobile/2.0' localhost:9292/transfer   # => 200
#
# --- Scenario 2: copied session -------------------------------------------
# An attacker replays only the stolen demo_session cookie, without the
# device_token cookie the app issued at login:
#
#   curl -b 'demo_session=<stolen-id>' localhost:9292/
#     # => identity signal mismatch, session is dropped
#
# --- Legacy mode -----------------------------------------------------------
# Use the middleware without :identity_signals/:weak_signals (or set
# weak_reaction: :drop_session) to keep the old "clear the whole session on
# any tracked header change" behaviour.

require 'rack'
require 'rack/protection'
require 'securerandom'
require 'json'

# Minimal server-side session store so the demo runs without extra gems.
# Use your framework's real session middleware in production.
class DemoSession
  STORE = {}

  def initialize(app)
    @app = app
  end

  def call(env)
    sid = Rack::Request.new(env).cookies['demo_session']
    sid = nil unless sid && STORE.key?(sid)
    sid ||= SecureRandom.hex(16)
    env['rack.session'] = (STORE[sid] ||= {})
    status, headers, body = @app.call(env)
    response = Rack::Response.new(body, status, headers)
    response.set_cookie('demo_session', value: sid, path: '/', httponly: true)
    response.finish
  end
end

class DemoApp
  PASSWORD = 's3cret'

  def call(env)
    req = Rack::Request.new(env)
    case [req.request_method, req.path_info]
    when ['POST', '/login']          then login(req, env)
    when ['POST', '/reauthenticate'] then reauthenticate(req, env)
    when ['POST', '/logout']         then logout(env)
    when ['GET', '/transfer']        then transfer(env)
    else home(env)
    end
  end

  private

  # The session holding a user_id only proves the user authenticated AT SOME
  # POINT. A restricted session must NOT be treated as strongly
  # authenticated: weak signals changed and the app has not confirmed
  # re-authentication yet. Note the asymmetry:
  #   restricted? == true  -> definitely require fresh credentials
  #   restricted? == false -> merely "no anomaly detected", never proof of
  #                           authentication on its own
  def strongly_authenticated?(env)
    env['rack.session'][:user_id] && !Rack::Protection::SessionHijacking.restricted?(env)
  end

  def login(req, env)
    return json(403, error: 'bad password') unless req.params['password'] == PASSWORD

    session = env['rack.session']
    session[:user_id] = 1
    # Login / account switch: forget the old baseline. The next request
    # carries the freshly issued device_token cookie and captures a new one.
    Rack::Protection::SessionHijacking.reset_tracking(env)
    response = Rack::Response.new
    response.set_cookie('device_token', value: SecureRandom.hex(8), path: '/', httponly: true)
    response.write(JSON.generate(logged_in: true))
    response.headers['content-type'] = 'application/json'
    response.finish
  end

  def reauthenticate(req, env)
    session = env['rack.session']
    return json(401, error: 'not logged in') unless session[:user_id]
    # Verify fresh credentials FIRST. confirm_reauthentication re-baselines
    # the weak signals from the current request, so calling it without a
    # real credential check would let an attacker teach the middleware
    # their own traits.
    return json(403, error: 'bad password') unless req.params['password'] == PASSWORD

    Rack::Protection::SessionHijacking.confirm_reauthentication(env)
    json(200, reauthenticated: true, restricted: false)
  end

  def logout(env)
    Rack::Protection::SessionHijacking.reset_tracking(env)
    env['rack.session'].clear
    json(200, logged_out: true)
  end

  def transfer(env)
    return json(401, error: 'not logged in') unless env['rack.session'][:user_id]
    unless strongly_authenticated?(env)
      return json(403, error: 're-authentication required', restricted: true)
    end

    json(200, transferred: true)
  end

  def home(env)
    json(200,
         user_id: env['rack.session'][:user_id],
         restricted: Rack::Protection::SessionHijacking.restricted?(env),
         strongly_authenticated: strongly_authenticated?(env))
  end

  def json(status, payload)
    [status, { 'content-type' => 'application/json' }, [JSON.generate(payload)]]
  end
end

use DemoSession
use Rack::Protection::SessionHijacking,
    identity_signals: [
      # Server-trusted credential: the device token the app issued at login
      # lives in a SEPARATE cookie. Copying only the session cookie (the
      # classic Firesheep scenario) misses it. Note this is a callable, not
      # a header name: client-forgeable headers are refused here.
      ->(env) { Rack::Request.new(env).cookies['device_token'] }
    ],
    # Weak signals: cheap to observe, easy to spoof, change often on mobile.
    # HTTP_USER_AGENT comes in via the legacy :track default.
    weak_signals: %w[HTTP_ACCEPT_LANGUAGE]
run DemoApp.new

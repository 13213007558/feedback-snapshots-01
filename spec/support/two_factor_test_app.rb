require 'active_record'
require 'devise'
require 'devise/orm/active_record'
require 'devise-two-factor'
require 'rack'
require 'rack/session/cookie'
require 'json'
require 'rotp'

# A minimal Rack application wired with Warden/Devise and the gem's
# strategies. It exists so the session-level behaviour can be exercised with
# real requests instead of stubs.
module TwoFactorTestApp
  module_function

  def boot
    return @app if defined?(@app) && @app

    ActiveRecord::Encryption.configure(
      primary_key: 'a' * 32,
      deterministic_key: 'b' * 32,
      key_derivation_salt: 'c' * 32
    )
    ActiveRecord::Base.establish_connection(adapter: 'sqlite3', database: ':memory:')
    ActiveRecord::Schema.define do
      create_table :users do |t|
        t.string :email
        t.string :encrypted_password
        t.string :otp_secret
        t.integer :consumed_timestep
        t.boolean :otp_required_for_login, default: false, null: false
        t.text :otp_backup_codes
      end
    end

    Class.new(ActiveRecord::Base) do
      self.table_name = 'users'
      serialize :otp_backup_codes, coder: YAML, type: Array

      devise :two_factor_authenticatable, :two_factor_backupable

      def self.name
        'User'
      end
    end.tap { |klass| Object.const_set(:User, klass) }

    mapping = Devise::Mapping.new(:user, failure_app: ->(_env) { [401, { 'Content-Type' => 'text/plain' }, ['unauthorized']] })
    Devise.mappings[:user] = mapping
    Devise.default_scope = :user

    Devise.warden_config = Warden::Config.new
    Devise.configure_warden!

    @app = Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'test-secret-' + ('x' * 52)
      use Warden::Manager do |config|
        config.merge! Devise.warden_config
        config.failure_app = lambda { |_env| [401, { 'Content-Type' => 'text/plain' }, ['unauthorized']] }
      end
      run TwoFactorTestApp::Router.new('devise' => mapping)
    end.to_app
  end

  def reset!
    boot
    User.delete_all
  end

  def create_user(email:, password: 'secret', two_factor: true)
    user = User.new(email: email)
    user.password = password
    user.otp_secret = User.generate_otp_secret
    user.otp_required_for_login = two_factor
    user.save!
    user
  end

  def otp_for(user)
    ROTP::TOTP.new(user.otp_secret).at(Time.now)
  end

  # Routes used by the tests:
  #
  # POST /sign_in          - password (+ optional otp_attempt)
  # GET  /status           - the session's real two-factor status
  # GET  /sensitive        - opens a sensitive request
  # POST /sensitive        - attempts to submit the sensitive request
  # POST /confirm          - confirms this session with an OTP or backup code
  # DELETE /sign_out       - signs the scope out
  class Router
    def initialize(devise)
      @devise = devise
    end

    def call(env)
      request = Rack::Request.new(env)
      env['devise.allow_params_authentication'] = true

      case [request.request_method, request.path_info]
      when ['POST', '/sign_in']
        sign_in(env, request)
      when ['GET', '/status']
        status(env)
      when ['GET', '/sensitive']
        open_sensitive(env)
      when ['POST', '/sensitive']
        submit_sensitive(env)
      when ['POST', '/confirm']
        confirm(env, request)
      when ['DELETE', '/sign_out']
        sign_out(env)
      else
        [404, { 'Content-Type' => 'text/plain' }, ['not found']]
      end
    end

    private

    def sign_in(env, request)
      user = env['warden'].authenticate!(scope: :user)
      json(env, 200, signed_in: true, email: user && user.email)
    rescue StandardError => e
      json(env, 200, signed_in: false, error: "#{e.class}: #{e.message}")
    end

    def status(env)
      session = Devise::TwoFactorAuthentication::Session.new(env)
      json(env, 200, session.status.to_h)
    end

    def open_sensitive(env)
      session = Devise::TwoFactorAuthentication::Session.new(env)
      status = session.begin_sensitive_request!
      json(env, 200, opened: true, status: status.to_h)
    end

    def submit_sensitive(env)
      session = Devise::TwoFactorAuthentication::Session.new(env)
      status = session.sensitive_request_status
      submitted = status.eligible_for_sensitive_actions?
      session.complete_sensitive_request! if submitted
      json(env, submitted ? 200 : 403,
           performed: submitted, status: status.to_h)
    end

    def confirm(env, request)
      session = Devise::TwoFactorAuthentication::Session.new(env)
      code = request.params['code']
      accepted = session.confirm_two_factor!(code)
      json(env, accepted ? 200 : 422, accepted: accepted, status: session.status.to_h)
    end

    def sign_out(env)
      env['warden'].logout(:user)
      env['warden'].request.session
      [200, { 'Content-Type' => 'application/json' }, [JSON.generate(signed_out: true)]]
    end

    def json(env, status, payload)
      env['warden'].request.session # force session persistence
      [status, { 'Content-Type' => 'application/json' }, [JSON.generate(payload)]]
    end
  end
end

require 'spec_helper'
require 'rack/test'
require 'support/two_factor_test_app'

RSpec.describe 'session-level two-factor authentication state', type: :request do
  include Rack::Test::Methods

  def app
    TwoFactorTestApp.boot
  end

  before(:each) { TwoFactorTestApp.reset! }

  def new_session
    Rack::Test::Session.new(app)
  end

  def sign_in(session, email:, password: 'secret', otp: nil)
    params = { user: { email: email, password: password } }
    params[:user][:otp_attempt] = otp if otp
    session.post '/sign_in', params
    return { 'signed_in' => false, 'status' => session.last_response.status } if session.last_response.status != 200

    JSON.parse(session.last_response.body)
  end

  def status(session)
    session.get '/status'
    JSON.parse(session.last_response.body)
  end

  def confirm(session, code)
    session.post '/confirm', code: code
    JSON.parse(session.last_response.body)
  end

  def open_sensitive(session)
    session.get '/sensitive'
    JSON.parse(session.last_response.body)
  end

  def submit_sensitive(session)
    session.post '/sensitive'
    [session.last_response.status, JSON.parse(session.last_response.body)]
  end

  describe 'a session that predates the two-factor requirement' do
    it 'starts writable and becomes read-only once two-factor is enabled' do
      user = TwoFactorTestApp.create_user(email: 'legacy@example.com', two_factor: false)
      session = new_session

      sign_in(session, email: user.email)
      expect(status(session)).to include('level' => 'not_required', 'read_only' => false)

      user.update!(otp_required_for_login: true)

      legacy = status(session)
      expect(legacy).to include(
        'level' => 'legacy',
        'read_only' => true,
        'restricted' => true,
        'authenticated' => true,
        'eligible_for_sensitive_actions' => false
      )
      expect(legacy['prompt']).to eq('verify_two_factor')
    end

    it 'does not inherit a confirmation made in another session' do
      user = TwoFactorTestApp.create_user(email: 'shared@example.com', two_factor: false)
      session_a = new_session
      sign_in(session_a, email: user.email)

      user.update!(otp_required_for_login: true)

      session_b = new_session
      sign_in(session_b, email: user.email, otp: TwoFactorTestApp.otp_for(user.reload))

      expect(status(session_b)).to include('level' => 'confirmed', 'read_only' => false)
      expect(status(session_a)).to include('level' => 'legacy', 'read_only' => true, 'stale' => false)
    end
  end

  describe 'confirming a pending session' do
    it 'confirms only the session that supplied the OTP' do
      user = TwoFactorTestApp.create_user(email: 'otp@example.com', two_factor: false)
      session_a = new_session
      session_b = new_session

      sign_in(session_a, email: user.email)
      sign_in(session_b, email: user.email)
      user.update!(otp_required_for_login: true)

      accepted = confirm(session_a, TwoFactorTestApp.otp_for(user.reload))
      expect(accepted['accepted']).to be true
      expect(accepted['status']).to include('level' => 'confirmed', 'read_only' => false)

      expect(status(session_b)).to include('level' => 'legacy', 'read_only' => true)
    end

    it 'accepts a backup code at sign-in and consumes it' do
      user = TwoFactorTestApp.create_user(email: 'backup@example.com')
      codes = user.generate_otp_backup_codes!
      user.save!

      session = new_session
      result = sign_in(session, email: user.email, otp: codes.first)
      expect(result['signed_in']).to be true
      expect(status(session)).to include('level' => 'confirmed', 'read_only' => false)

      other = new_session
      retry_result = sign_in(other, email: user.email, otp: codes.first)
      expect(retry_result['signed_in']).to be false
    end

    it 'accepts a backup code when confirming an already-open session' do
      user = TwoFactorTestApp.create_user(email: 'backup-pending@example.com', two_factor: false)
      codes = user.generate_otp_backup_codes!
      user.save!

      session_a = new_session
      session_b = new_session
      sign_in(session_a, email: user.email)
      sign_in(session_b, email: user.email)
      user.update!(otp_required_for_login: true)

      accepted = confirm(session_a, codes.first)
      expect(accepted['accepted']).to be true
      expect(accepted['status']).to include('level' => 'confirmed')

      expect(status(session_b)).to include('level' => 'legacy', 'read_only' => true)
    end
  end

  describe 'two password sessions across an account configuration change' do
    it 'reports real levels, read-only state, restricted execution and prompts differently per session' do
      user = TwoFactorTestApp.create_user(email: 'pair@example.com', two_factor: false)

      session_a = new_session
      session_b = new_session
      expect(sign_in(session_a, email: user.email)['signed_in']).to be true
      expect(sign_in(session_b, email: user.email)['signed_in']).to be true

      user.update!(otp_required_for_login: true)

      # Both sessions open the feature while still unconfirmed.
      opened_a = open_sensitive(session_a)
      opened_b = open_sensitive(session_b)
      expect(opened_a['status']).to include('level' => 'legacy', 'read_only' => true,
                                            'restricted' => true, 'prompt' => 'verify_two_factor')
      expect(opened_b['status']).to include('level' => 'legacy', 'read_only' => true,
                                            'restricted' => true, 'prompt' => 'verify_two_factor')

      # The restricted business action must not run for either session.
      expect(submit_sensitive(session_a)).to match([403, hash_including('performed' => false)])
      expect(submit_sensitive(session_b)).to match([403, hash_including('performed' => false)])

      # Confirm only session A.
      accepted = confirm(session_a, TwoFactorTestApp.otp_for(user.reload))
      expect(accepted['accepted']).to be true

      expect(status(session_a)).to include('level' => 'confirmed', 'read_only' => false, 'prompt' => nil)
      expect(status(session_b)).to include('level' => 'legacy', 'read_only' => true,
                                           'prompt' => 'verify_two_factor')

      # A may perform restricted business, B may not.
      expect(submit_sensitive(session_a)).to match([200, hash_including('performed' => true)])
      expect(submit_sensitive(session_b)).to match([403, hash_including('performed' => false)])

      # Open a fresh sensitive request, then change the account configuration
      # while it is still open.
      expect(open_sensitive(session_a)['status']).to include('level' => 'confirmed')
      user = User.find(user.id)
      user.update!(otp_secret: User.generate_otp_secret, consumed_timestep: nil)

      expect(status(session_a)).to include('level' => 'pending', 'read_only' => true,
                                           'reason' => 'two_factor_configuration_changed',
                                           'prompt' => 'reverify_two_factor')
      expect(status(session_b)).to include('level' => 'legacy', 'read_only' => true,
                                           'prompt' => 'verify_two_factor')

      # The already-entered request is explicitly reported as ineligible.
      code, body = submit_sensitive(session_a)
      expect(code).to eq(403)
      expect(body['status']).to include('stale' => true, 'verification_required' => true)
    end
  end

  describe 'switching accounts within one browser session' do
    it 'clears the previous session state on sign-out' do
      user_a = TwoFactorTestApp.create_user(email: 'alice@example.com')
      user_b = TwoFactorTestApp.create_user(email: 'bob@example.com')
      session = new_session

      sign_in(session, email: user_a.email, otp: TwoFactorTestApp.otp_for(user_a))
      expect(status(session)).to include('level' => 'confirmed')

      session.delete '/sign_out'
      expect(session.last_response.status).to eq(200)

      sign_in(session, email: user_b.email, otp: TwoFactorTestApp.otp_for(user_b))
      expect(status(session)).to include('level' => 'confirmed', 'authenticated' => true)
      expect(status(session)['fingerprint']).to eq(user_b.two_factor_configuration_fingerprint)
    end

    it 'starts a fresh state for the next account after sign-out' do
      user_a = TwoFactorTestApp.create_user(email: 'carol@example.com', two_factor: false)
      user_b = TwoFactorTestApp.create_user(email: 'dave@example.com')

      session = new_session
      sign_in(session, email: user_a.email)
      expect(status(session)).to include('level' => 'not_required')

      # Warden keeps a user cached for an already-authenticated scope, so the
      # next account signs in after an explicit sign-out (as Devise does).
      session.delete '/sign_out'
      expect(session.last_response.status).to eq(200)

      sign_in(session, email: user_b.email, otp: TwoFactorTestApp.otp_for(user_b))
      expect(status(session)).to include('level' => 'confirmed')
    end
  end

  describe 'sensitive requests entered before another session changes the account' do
    it 'tells the pending session that the configuration changed' do
      user = TwoFactorTestApp.create_user(email: 'sensitive@example.com', two_factor: false)
      session_a = new_session
      sign_in(session_a, email: user.email)

      user.update!(otp_required_for_login: true)
      open_sensitive(session_a)
      expect(submit_sensitive(session_a)).to match([403, hash_including('performed' => false)])

      # Another session confirms and rotates the account configuration.
      session_b = new_session
      sign_in(session_b, email: user.email, otp: TwoFactorTestApp.otp_for(user.reload))
      user.update!(otp_secret: User.generate_otp_secret)

      status_a = submit_sensitive(session_a).last
      expect(status_a['status']).to include(
        'level' => 'pending',
        'reason' => 'two_factor_configuration_changed',
        'stale' => true,
        'prompt' => 'reverify_two_factor'
      )
      expect(status_a['performed']).to be false
    end

    it 'requires a confirmed session to resubmit after the configuration changed even if it was confirmed at entry' do
      user = TwoFactorTestApp.create_user(email: 'rotate@example.com')
      session = new_session
      sign_in(session, email: user.email, otp: TwoFactorTestApp.otp_for(user))
      expect(status(session)).to include('level' => 'confirmed')

      expect(open_sensitive(session)['opened']).to be true
      user = User.find(user.id)
      user.update!(otp_secret: User.generate_otp_secret, consumed_timestep: nil)

      code, body = submit_sensitive(session)
      expect(code).to eq(403)
      expect(body['status']).to include(
        'level' => 'pending',
        'reason' => 'two_factor_configuration_changed',
        'stale' => true
      )

      accepted = confirm(session, TwoFactorTestApp.otp_for(user.reload))
      expect(accepted['accepted']).to be true
      expect(accepted['status']).to include('level' => 'confirmed')

      # The request entered under the old configuration is still explicitly
      # reported as ineligible until it is opened again.
      code, body = submit_sensitive(session)
      expect(code).to eq(403)
      expect(body['status']).to include('stale' => true, 'verification_required' => true)

      expect(open_sensitive(session)['status']).to include('level' => 'confirmed')
      expect(submit_sensitive(session)).to match([200, hash_including('performed' => true)])
    end
  end
end

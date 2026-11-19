require_relative 'spec_helper'
require 'rotp'
require 'json'

begin
  require 'webauthn/fake_client'
rescue LoadError
else
describe 'Rodauth TOTP to WebAuthn migration' do
  SECRET_LENGTH = (ROTP::Base32.respond_to?(:random_base32) ? ROTP::Base32.random_base32 : ROTP::Base32.random).length
  ORIGIN = 'http://www.example.com'

  def setup_migration_app(&block)
    rodauth do
      enable :login, :logout, :change_password, :otp, :recovery_codes, :webauthn
      hmac_secret '123'
      auto_add_recovery_codes? true
      auto_remove_recovery_codes? false
      instance_exec(&block) if block
    end
    roda do |r|
      r.rodauth
      r.get('state') do
        JSON.generate(
          :authenticated_by=>rodauth.authenticated_by,
          :authenticated=>rodauth.authenticated?,
          :webauthn_id=>rodauth.authenticated_webauthn_id,
          :webauthn_setup=>rodauth.webauthn_setup?,
          :methods=>rodauth.possible_authentication_methods,
          :webauthn_keys=>DB[:account_webauthn_keys].count,
          :webauthn_user_ids=>DB[:account_webauthn_user_ids].count,
          :recovery_codes=>DB[:account_recovery_codes].count,
          :otp_keys=>DB[:account_otp_keys].count,
          :partially_authenticated=>rodauth.send(:two_factor_partially_authenticated?),
          :uses_two_factor=>rodauth.uses_two_factor_authentication?
        )
      end
      r.redirect '/login' unless rodauth.logged_in?
      view :content=>'ok'
    end
  end

  def migration_state
    visit '/state'
    JSON.parse(page.body, :symbolize_names=>true)
  end

  def enable_totp
    visit '/otp-setup'
    secret = page.html.match(/Secret: ([a-z2-7]{#{SECRET_LENGTH}})/)[1]
    totp = ROTP::TOTP.new(secret)
    fill_in 'Password', :with=>'0123456789' if page.has_field?('Password')
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Setup TOTP Authentication'
    totp
  end

  def register_webauthn(client)
    visit '/webauthn-setup'
    challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789' if page.has_field?('Password')
    fill_in 'webauthn_setup', :with=>client.create(challenge: challenge).to_json
    click_button 'Setup WebAuthn Authentication'
  end

  def authenticate_webauthn(client)
    visit '/webauthn-auth'
    challenge = JSON.parse(page.find('#webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
  end

  it "should keep pre-existing raw TOTP usable after enabling webauthn" do
    no_hmac = true
    rodauth do
      enable :login, :logout, :otp
      hmac_secret{no_hmac ? nil : '123'}
    end
    roda do |r|
      r.rodauth
      view :content=>'legacy'
    end

    login
    totp = enable_totp
    legacy_key = DB[:account_otp_keys].get(:key)
    legacy_key.must_equal totp.secret

    # 新配置启用 webauthn 后，默认 otp_keys_use_hmac? 为 true，
    # 旧 raw key 不能再通过验证
    no_hmac = false
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :webauthn
      hmac_secret '123'
      auto_add_recovery_codes? true
    end
    roda do |r|
      r.rodauth
      r.redirect '/login' unless rodauth.logged_in?
      view :content=>'new-default'
    end

    login
    visit '/otp-auth'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'
    page.find('#error_flash').text.must_equal 'Error logging in via TOTP authentication'
    DB[:account_otp_keys].get(:key).must_equal legacy_key
    DB[:account_otp_keys].update(:last_use=>Sequel.date_sub(Sequel::CURRENT_TIMESTAMP, :seconds=>600), :num_failures=>0)

    # 显式保留 raw key 语义后，旧 TOTP 可继续使用
    rodauth do
      enable :login, :logout, :otp, :recovery_codes, :webauthn
      hmac_secret '123'
      otp_keys_use_hmac? false
      auto_add_recovery_codes? true
    end
    roda do |r|
      r.rodauth
      r.get('state') do
        JSON.generate(:authenticated_by=>rodauth.authenticated_by)
      end
      r.redirect '/login' unless rodauth.logged_in?
      view :content=>'new-raw'
    end

    login
    visit '/otp-auth'
    fill_in 'Authentication Code', :with=>totp.now
    click_button 'Authenticate Using TOTP'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'
    JSON.parse(page.driver.get('/state').body)['authenticated_by'].must_equal ['password', 'totp']
    DB[:account_otp_keys].get(:key).must_equal legacy_key
  end

  it "should treat webauthn registration as complete only after successful authentication" do
    setup_migration_app
    first_request = nil
    roda do |r|
      first_request ||= r
      r.rodauth
      r.get('state') do
        JSON.generate(
          :authenticated_by=>rodauth.authenticated_by,
          :authenticated=>rodauth.authenticated?,
          :webauthn_id=>rodauth.authenticated_webauthn_id,
          :webauthn_keys=>DB[:account_webauthn_keys].count,
          :webauthn_user_ids=>DB[:account_webauthn_user_ids].count
        )
      end
      r.redirect '/login' unless rodauth.logged_in?
      view :content=>'ok'
    end

    login
    client = WebAuthn::FakeClient.new(first_request.base_url)
    enable_totp
    migration_state[:authenticated_by].must_equal ['password', 'totp']

    register_webauthn(client)
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'

    DB[:account_webauthn_keys].count.must_equal 1
    DB[:account_webauthn_user_ids].count.must_equal 1
    key = DB[:account_webauthn_keys].first
    key[:sign_count].must_be_kind_of Integer
    key[:last_use].wont_be_nil

    migration_state[:authenticated_by].must_equal ['password', 'totp']
    migration_state[:webauthn_id].must_be_nil

    logout
    login
    authenticate_webauthn(client)
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    migration_state[:authenticated_by].must_equal ['password', 'webauthn']
    migration_state[:webauthn_id].must_equal key[:webauthn_id]
  end

  it "should reject an abandoned registration challenge and accept a fresh one" do
    setup_migration_app
    login
    client = WebAuthn::FakeClient.new(ORIGIN)
    enable_totp

    visit '/webauthn-setup'
    abandoned_challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
    abandoned_hmac = page.find('input[name=webauthn_setup_challenge_hmac]', visible: false).value

    visit '/webauthn-setup'
    fresh_challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
    fresh_hmac = page.find('input[name=webauthn_setup_challenge_hmac]', visible: false).value

    fresh_challenge.wont_equal abandoned_challenge
    fresh_hmac.wont_equal abandoned_hmac
    DB[:account_webauthn_keys].count.must_equal 0
    DB[:account_webauthn_user_ids].count.must_equal 1
    DB[:account_webauthn_keys].empty?.must_equal true

    page.find('input[name=webauthn_setup_challenge]', visible: false).set(abandoned_challenge)
    page.find('input[name=webauthn_setup_challenge_hmac]', visible: false).set(abandoned_hmac)
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>client.create(challenge: abandoned_challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#error_flash').text.must_equal 'Error setting up WebAuthn authentication'
    DB[:account_webauthn_keys].count.must_equal 0

    fresh_challenge = JSON.parse(page.find('#webauthn-setup-form')['data-credential-options'])['challenge']
    fill_in 'Password', :with=>'0123456789'
    fill_in 'webauthn_setup', :with=>client.create(challenge: fresh_challenge).to_json
    click_button 'Setup WebAuthn Authentication'
    page.find('#notice_flash').text.must_equal 'WebAuthn authentication is now setup'
    DB[:account_webauthn_keys].count.must_equal 1
    DB[:account_webauthn_user_ids].count.must_equal 1
  end

  it "should support multiple authenticators and reject a removed one" do
    setup_migration_app
    login
    old_client = WebAuthn::FakeClient.new(ORIGIN)
    new_client = WebAuthn::FakeClient.new(ORIGIN)

    enable_totp
    register_webauthn(old_client)
    old_id = DB[:account_webauthn_keys].get(:webauthn_id)
    register_webauthn(new_client)
    ids = DB[:account_webauthn_keys].select_order_map(:webauthn_id)
    ids.length.must_equal 2
    ids.wont_include nil

    logout
    login
    authenticate_webauthn(new_client)
    migration_state[:authenticated_by].must_equal ['password', 'webauthn']
    migration_state[:webauthn_id].wont_equal old_id

    visit '/webauthn-remove'
    choose "webauthn-remove-#{old_id}"
    fill_in 'Password', :with=>'0123456789' if page.has_field?('Password')
    click_button 'Remove WebAuthn Authenticator'
    page.find('#notice_flash').text.must_equal 'WebAuthn authenticator has been removed'

    DB[:account_webauthn_keys].count.must_equal 1
    DB[:account_webauthn_user_ids].count.must_equal 1

    logout
    login
    visit '/webauthn-auth'
    challenge = JSON.parse(page.find('#webauthn-auth-form')['data-credential-options'])['challenge']
    fill_in 'webauthn_auth', :with=>old_client.get(challenge: challenge).to_json
    click_button 'Authenticate Using WebAuthn'
    page.find('#error_flash').text.must_equal 'Error authenticating using WebAuthn'
  end

  it "should consume recovery codes exactly once" do
    setup_migration_app
    login
    enable_totp
    codes = DB[:account_recovery_codes].select_map(:code)
    codes.length.must_equal 16

    logout
    login
    visit '/recovery-auth'
    fill_in 'Recovery Code', :with=>codes.first
    click_button 'Authenticate via Recovery Code'
    page.find('#notice_flash').text.must_equal 'You have been multifactor authenticated'

    migration_state[:authenticated_by].must_equal ['password', 'recovery_code']
    migration_state[:authenticated].must_equal true
    migration_state[:webauthn_id].must_be_nil
    DB[:account_recovery_codes].count.must_equal 15

    logout
    login
    visit '/recovery-auth'
    fill_in 'Recovery Code', :with=>codes.first
    click_button 'Authenticate via Recovery Code'
    page.find('#error_flash').text.must_equal 'Error authenticating via recovery code'
    DB[:account_recovery_codes].count.must_equal 15
  end

  it "should require a second factor for sensitive actions" do
    setup_migration_app
    login
    client = WebAuthn::FakeClient.new(ORIGIN)
    enable_totp
    register_webauthn(client)

    logout
    login
    visit '/change-password'
    page.current_path.must_equal '/multifactor-auth'

    authenticate_webauthn(client)
    migration_state[:authenticated_by].must_equal ['password', 'webauthn']

    visit '/change-password'
    page.current_path.must_equal '/change-password'
  end

  it "should not silently remove recovery codes when the last device factor is removed" do
    setup_migration_app
    login
    client = WebAuthn::FakeClient.new(ORIGIN)
    enable_totp
    register_webauthn(client)

    logout
    login
    authenticate_webauthn(client)

    visit '/otp-disable'
    fill_in 'Password', :with=>'0123456789' if page.has_field?('Password')
    click_button 'Disable TOTP Authentication'
    migration_state[:otp_keys].must_equal 0
    migration_state[:recovery_codes].must_equal 16

    visit '/webauthn-remove'
    id = DB[:account_webauthn_keys].get(:webauthn_id)
    choose "webauthn-remove-#{id}"
    fill_in 'Password', :with=>'0123456789' if page.has_field?('Password')
    click_button 'Remove WebAuthn Authenticator'

    migration_state[:webauthn_keys].must_equal 0
    migration_state[:recovery_codes].must_equal 16
    migration_state[:methods].must_equal ['password', 'recovery_code']

    logout
    login
    visit '/change-password'
    page.current_path.must_equal '/recovery-auth'
  end
end
end

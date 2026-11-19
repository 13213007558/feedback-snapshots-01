require_relative 'spec_helper'

describe 'Rodauth close_account feature' do
  it "should support closing accounts when passwords are not required" do
    rodauth do
      enable :login, :close_account
      close_account_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view(:content=>"")}
    end

    login
    page.current_path.must_equal '/'

    visit '/close-account'
    click_button 'Close Account'
    page.current_path.must_equal '/'

    DB[:accounts].select_map(:status_id).must_equal [3]
  end

  it "should update account information when closing accounts" do
    statuses = nil
    rodauth do
      enable :login, :close_account
      close_account_requires_password? false
      after_close_account{statuses = [account[:status_id], account_ds.get(:status_id)]}
    end
    roda do |r|
      r.rodauth
      r.root{view(:content=>"")}
    end

    login
    visit '/close-account'
    click_button 'Close Account'
    statuses[0].must_equal 3
    statuses[1].must_equal 3
  end

  it "should delete accounts when skip_status_checks? is true" do
    rodauth do
      enable :login, :close_account
      close_account_requires_password? false
      skip_status_checks? true
    end
    roda do |r|
      r.rodauth
      r.root{view(:content=>"")}
    end

    login
    page.current_path.must_equal '/'

    visit '/close-account'
    click_button 'Close Account'
    page.current_path.must_equal '/'

    DB[:accounts].count.must_equal 0
  end

  it "should support closing accounts when passwords are required" do
    rodauth do
      enable :login, :close_account
    end
    roda do |r|
      r.rodauth
      r.root{view(:content=>"")}
    end

    login
    page.current_path.must_equal '/'

    visit '/close-account'
    fill_in 'Password', :with=>'012345678'
    click_button 'Close Account'
    page.find('#error_flash').text.must_equal "There was an error closing your account"
    page.html.must_include("invalid password")
    DB[:accounts].select_map(:status_id).must_equal [2]

    fill_in 'Password', :with=>'0123456789'
    click_button 'Close Account'
    page.find('#notice_flash').text.must_equal "Your account has been closed"
    page.current_path.must_equal '/'

    DB[:accounts].select_map(:status_id).must_equal [3]
  end

  it "should support closing accounts with overrides" do
    rodauth do
      enable :login, :close_account
      close_account do
        account_ds.update(:email => 'foo@bar.com', :status_id=>3)
      end
      close_account_route 'close'
      close_account_redirect '/login'
    end
    roda do |r|
      r.rodauth
      r.root{""}
    end

    login
    page.current_path.must_equal '/'

    visit '/close'
    page.title.must_equal 'Close Account'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Close Account'
    page.find('#notice_flash').text.must_equal "Your account has been closed"
    page.current_path.must_equal '/login'

    DB[:accounts].select_map(:status_id).must_equal [3]
    DB[:accounts].select_map(:email).must_equal ['foo@bar.com']
  end

  it "should close accounts when account_password_hash_column is set" do
    rodauth do
      enable :create_account, :close_account
      close_account_requires_password? false
      account_password_hash_column :ph
    end
    roda do |r|
      r.rodauth
      r.root{view(:content=>"")}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'foo2@example.com'
    fill_in 'Confirm Login', :with=>'foo2@example.com'
    fill_in 'Password', :with=>'apple2'
    fill_in 'Confirm Password', :with=>'apple2'
    click_button 'Create Account'

    visit '/close-account'
    click_button 'Close Account'
    page.current_path.must_equal '/'

    DB[:accounts].where(:email=>'foo2@example.com').get(:status_id).must_equal 3
  end

  [:jwt, :json].each do |json|
    it "should support closing accounts via #{json}" do
      rodauth do
        enable :login, :close_account
      end
      roda(json) do |r|
        r.rodauth
      end

      json_login

      res = json_request('/close-account', :password=>'0123456')
      res.must_equal [401, {'reason'=>"invalid_password",'error'=>"There was an error closing your account", "field-error"=>["password", "invalid password"]}]
      DB[:accounts].select_map(:status_id).must_equal [2]

      res = json_request('/close-account', :password=>'0123456789')
      res.must_equal [200, {'success'=>"Your account has been closed"}]
      DB[:accounts].select_map(:status_id).must_equal [3]
    end
  end

  it "should revoke all browser sessions and remember logins when closing account" do
    rodauth do
      enable :login, :close_account, :remember, :active_sessions
      hmac_secret '123'
      close_account_redirect '/login'
    end
    roda do |r|
      r.rodauth
      rodauth.load_memory
      r.get('protected'){rodauth.require_account; "Logged In"}
      r.root{rodauth.logged_in? ? "Logged In" : "Not Logged In"}
    end

    # First browser session
    login
    page.body.must_include "Logged In"
    session1 = get_cookie('rack.session')

    # Second browser session
    remove_cookie('rack.session')
    login
    page.body.must_include "Logged In"
    session2 = get_cookie('rack.session')

    # Third browser with a saved remember login
    remove_cookie('rack.session')
    login
    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    remember_cookie = get_cookie('_remember')
    remove_cookie('rack.session')
    visit '/'
    page.body.must_include "Logged In"

    DB[:accounts].select_map(:status_id).must_equal [2]
    DB[:account_remember_keys].count.must_equal 1
    DB[:account_active_session_keys].count.must_be(:>=, 3)

    # Close the account from the remember-authenticated browser
    visit '/close-account'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Close Account'
    page.current_path.must_equal '/login'

    DB[:accounts].select_map(:status_id).must_equal [3]
    DB[:account_remember_keys].count.must_equal 0
    DB[:account_active_session_keys].count.must_equal 0

    # The first browser session is blocked
    set_cookie('rack.session', session1)
    visit '/protected'
    page.current_path.must_equal '/login'
    visit '/'
    page.body.must_include "Not Logged In"

    # The second browser session is blocked
    set_cookie('rack.session', session2)
    visit '/protected'
    page.current_path.must_equal '/login'
    visit '/'
    page.body.must_include "Not Logged In"

    # The saved remember login no longer authenticates
    remove_cookie('rack.session')
    set_cookie('_remember', remember_cookie)
    visit '/'
    page.body.must_include "Not Logged In"
    visit '/protected'
    page.current_path.must_equal '/login'
  end

  it "should not close account or clear sessions and remember logins if the close transaction fails" do
    session_value_at_failure = nil
    rodauth do
      enable :login, :close_account, :remember, :active_sessions
      hmac_secret '123'
    end
    roda do |r|
      rodauth.define_singleton_method(:clear_tokens) do |reason|
        super(reason)
        if reason == :close_account
          session_value_at_failure = session_value()
          raise StandardError, "simulated close transaction failure"
        end
      end
      r.rodauth
      rodauth.load_memory
      r.get('protected'){rodauth.require_account; "Logged In"}
      r.root{rodauth.logged_in? ? "Logged In" : "Not Logged In"}
    end

    # First browser session
    login
    page.body.must_include "Logged In"
    session1 = get_cookie('rack.session')

    # Second browser with a saved remember login
    remove_cookie('rack.session')
    login
    visit '/remember'
    choose 'Remember Me'
    click_button 'Change Remember Setting'
    remember_cookie = get_cookie('_remember')
    remove_cookie('rack.session')
    visit '/'
    page.body.must_include "Logged In"

    DB[:accounts].select_map(:status_id).must_equal [2]
    DB[:account_remember_keys].count.must_equal 1
    active_sessions = DB[:account_active_session_keys].count
    active_sessions.must_be(:>=, 2)

    # The close transaction fails, so nothing must be left half closed
    set_cookie('rack.session', session1)
    visit '/close-account'
    fill_in 'Password', :with=>'0123456789'
    proc{click_button 'Close Account'}.must_raise StandardError

    # The session must not have been cleared before the transaction failed
    session_value_at_failure.must_equal DB[:accounts].get(:id)

    DB[:accounts].select_map(:status_id).must_equal [2]
    DB[:account_remember_keys].count.must_equal 1
    DB[:account_active_session_keys].count.must_equal active_sessions

    # The session used to attempt the close is still accepted
    visit '/protected'
    page.body.must_include "Logged In"

    # The saved remember login still authenticates
    remove_cookie('rack.session')
    set_cookie('_remember', remember_cookie)
    visit '/protected'
    page.body.must_include "Logged In"
  end

  it "should support closing accounts using an internal request" do
    rodauth do
      enable :login, :logout, :close_account, :internal_request
    end
    roda do |r|
      r.rodauth
      r.root{rodauth.logged_in?.nil?.to_s}
    end

    visit '/'
    page.body.must_equal 'true'

    login
    page.body.must_equal 'false'

    logout

    app.rodauth.close_account(:account_login=>'foo@example.com').must_be_nil

    login
    page.current_path.must_equal '/login'

    DB[:accounts].select_map(:status_id).must_equal [3]
  end
end

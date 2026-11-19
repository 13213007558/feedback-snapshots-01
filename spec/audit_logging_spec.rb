require_relative 'spec_helper'

describe 'Rodauth audit_logging feature' do
  ds = DB[:account_authentication_audit_logs].order(Sequel.desc(:at), Sequel.desc(:id))

  it "should handle audit logging of all actions" do
    rodauth do
      enable :login, :logout, :audit_logging
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    account_id, at, message, metadata = ds.get([:account_id, :at, :message, :metadata])
    account_id.must_equal DB[:accounts].get(:id)
    at = Time.parse(at) unless at.is_a?(Time)
    at.must_be(:>, Time.now - 86400)
    message.must_equal 'login'
    metadata.must_be_nil

    logout
    ds.where(message: 'logout').count.must_equal 1

    login(:pass=>'012345678')
    ds.where(message: 'login_failure').count.must_equal 1
  end

  it "should not duplicate logout audit log when account is already loaded" do
    rodauth do
      enable :login, :logout, :audit_logging
      before_logout{account_from_session}
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    ds.where(message: 'login').count.must_equal 1

    logout
    ds.where(message: 'logout').count.must_equal 1
  end

  it "should allow customizing of audit log messages and metadata" do
    rodauth do
      enable :login, :logout, :audit_logging
      audit_log_message_for :login, "Login Ahoy!"
      audit_log_message_for :login_failure do
        "Login failure for #{param(login_param)}"
      end
      audit_log_metadata_for :logout, {'details'=>'A wild logout appears!'}
      audit_log_metadata_for :login_failure do
        {'never_do_this'=>param(password_param)}
      end
      audit_log_message_default do |action|
        action.to_s.upcase
      end
      audit_log_metadata_default('nothing'=>'specific')
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    account_id, at, message, metadata = ds.get([:account_id, :at, :message, :metadata])
    account_id.must_equal DB[:accounts].get(:id)
    at = Time.parse(at) unless at.is_a?(Time)
    at.must_be(:>, Time.now - 86400)
    message.must_equal 'Login Ahoy!'
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata.must_equal('nothing'=>'specific')

    logout
    message, metadata = ds.where(message: 'LOGOUT').get([:message, :metadata])
    message.wont_equal nil
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata.must_equal('details'=>'A wild logout appears!')

    login(:pass=>'012345678')
    message, metadata = ds.where(message: 'Login failure for foo@example.com').get([:message, :metadata])
    message.wont_equal nil
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata.must_equal('never_do_this'=>'012345678')
  end

  it "should skip audit logging if there is no message" do
    rodauth do
      enable :login, :audit_logging
      audit_log_message_for :login, nil
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    ds.must_be_empty
  end

  it "should distinguish committed changes, rolled back attempts, and failures" do
    rollback = false
    rodauth do
      enable :login, :logout, :change_password, :audit_logging
      require_password_confirmation? false
      after_change_password do
        raise Sequel::Rollback if rollback
      end
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>"Logged In"}
    end

    login
    visit '/change-password'
    fill_in 'Password', :with=>'0123456789'
    fill_in 'New Password', :with=>'0123456'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    changed = ds.where(:message=>'change_password').all
    changed.length.must_equal 1
    changed.first[:status].must_equal 'committed'
    changed.first[:metadata].must_be_nil

    rollback = true
    visit '/change-password'
    fill_in 'Password', :with=>'0123456'
    fill_in 'New Password', :with=>'012345678'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    attempted = ds.where(:message=>'change_password', :status=>'attempted').all
    attempted.length.must_equal 1
    attempted.first[:metadata].must_be_nil
    ds.where(:message=>'change_password', :status=>'committed').count.must_equal 1

    logout
    login(:pass=>'0123456789')
    ds.where(:message=>'login_failure', :status=>'failed').count.must_equal 1
  end

  it "should not include sensitive values in audit log metadata or messages" do
    rodauth do
      enable :login, :logout, :audit_logging
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    session_id = get_cookie('rack.session')
    logout
    login(:pass=>'012345678')
    login(:login=>'bar@example.com')

    entries = ds.all
    entries.wont_be_empty
    entries.each do |entry|
      "#{entry[:message]} #{entry[:metadata]}".tap do |text|
        text.wont_include '0123456789'
        text.wont_include '012345678'
        text.wont_include session_id if session_id
      end
    end
  end

  it "should not change request result if audit logging fails" do
    rodauth do
      enable :login, :audit_logging
      add_audit_log do |account_id, action|
        raise 'audit failure'
      end
    end
    roda do |r|
      r.rodauth
      view :content=>"Logged In"
    end

    login
    page.current_path.must_equal '/'
    page.find('#notice_flash').text.must_equal "You have been logged in"
    ds.must_be_empty
  end
end

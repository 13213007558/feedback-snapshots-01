require_relative 'spec_helper'

describe 'Rodauth internal_request_permissions feature' do
  it "should allow a read-only principal to perform registered reads" do
    rodauth do
      enable :login, :internal_request_permissions
      internal_request_permission :account_reader, :account_exists?, :account_id_for_login
      internal_request_permission :account_notifier, :verify_account
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>''}
    end

    app.rodauth.account_exists?(:principal=>:account_reader, :login=>'foo@example.com').must_equal true
    app.rodauth.account_exists?(:principal=>:account_reader, :login=>'foo2@example.com').must_equal false
    app.rodauth.account_id_for_login(:principal=>:account_reader, :login=>'foo@example.com').must_equal DB[:accounts].get(:id)

    error = proc do
      app.rodauth.account_exists?(:principal=>:account_notifier, :login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestNotAuthorized
    error.principal.must_equal :account_notifier
    error.operation.must_equal :account_exists?
    error.feature.must_equal :base
    error.denial_reason.must_equal :operation_not_allowed
  end

  it "should deny an internal request without a registered principal before the operation" do
    hooks = []
    rodauth do
      enable :login, :verify_account, :internal_request_permissions
      verify_account_email_last_sent_column nil
      internal_request_permission :account_notifier, :verify_account_resend
      before_verify_account_resend_route{hooks << :route}
      before_verify_account_email_resend{hooks << :operation}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>''}
    end

    error = proc do
      app.rodauth.verify_account_resend(:account_login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestNotAuthorized
    error.principal.must_be_nil
    error.operation.must_equal :verify_account_resend
    error.feature.must_equal :verify_account
    error.denial_reason.must_equal :no_internal_request_principal
    hooks.must_be_empty
    Mail::TestMailer.deliveries.must_be_empty
  end

  it "should allow an approved notification and attribute the audit event to the principal" do
    hooks = []
    rodauth do
      enable :login, :verify_account, :audit_logging, :internal_request_permissions
      verify_account_email_last_sent_column nil
      internal_request_permission :account_reader, :account_exists?
      internal_request_permission :account_notifier, :verify_account
      before_verify_account_resend_route{hooks << :route}
      before_verify_account_email_resend{hooks << :operation}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>''}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'bar@example.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    email_sent('bar@example.com')
    hooks.clear

    app.rodauth.verify_account_resend(:principal=>:account_notifier, :account_login=>'bar@example.com').must_be_nil
    hooks.must_equal [:route, :operation]
    email_sent('bar@example.com')

    metadata = DB[:account_authentication_audit_logs].
      where(:message=>'verify_account_email_resend').
      get(:metadata)
    metadata = JSON.parse(metadata) if metadata.is_a?(String)
    metadata['internal_request_principal'].must_equal 'account_notifier'
    metadata['internal_request_operation'].must_equal 'verify_account_resend'
  end

  it "should deny an unapproved notification before the feature operation" do
    hooks = []
    rodauth do
      enable :login, :verify_account, :internal_request_permissions
      verify_account_email_last_sent_column nil
      internal_request_permission :account_reader, :account_exists?
      internal_request_permission :account_notifier, :verify_account_resend
      before_verify_account_resend_route{hooks << :route}
      before_verify_account_email_resend{hooks << :operation}
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>''}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'baz@example.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    email_sent('baz@example.com')
    hooks.clear

    error = proc do
      app.rodauth.verify_account_resend(:principal=>:account_reader, :account_login=>'baz@example.com')
    end.must_raise Rodauth::InternalRequestNotAuthorized
    error.principal.must_equal :account_reader
    error.operation.must_equal :verify_account_resend
    error.feature.must_equal :verify_account
    error.denial_reason.must_equal :operation_not_allowed
    hooks.must_be_empty
    Mail::TestMailer.deliveries.must_be_empty

    app.rodauth.verify_account_resend(:principal=>:account_notifier, :account_login=>'baz@example.com').must_be_nil
    hooks.must_equal [:route, :operation]
    email_sent('baz@example.com')
  end

  it "should support feature-level permissions, inheritance, and unregistered principals" do
    require 'rodauth'

    base = Class.new(Rodauth::Auth) do
      configure do
        enable :login, :verify_account, :internal_request_permissions
        verify_account_email_last_sent_column nil
        internal_request_permission :base_reader, :account_exists?
      end
    end

    child = Class.new(base) do
      configure do
        internal_request_permission :child_reader, :account_id_for_login
        internal_request_permission :notifier, :verify_account
      end
    end

    base_app = Class.new(Roda)
    base_app.plugin :rodauth, :auth_class=>base
    base_app.rodauth.account_exists?(:principal=>:base_reader, :login=>'foo@example.com').must_equal true
    base.internal_request_permission_for(:child_reader).must_be_nil

    child_app = Class.new(Roda)
    child_app.plugin :rodauth, :auth_class=>child
    child_app.rodauth.account_exists?(:principal=>:base_reader, :login=>'foo@example.com').must_equal true
    child_app.rodauth.account_id_for_login(:principal=>:child_reader, :login=>'foo@example.com').must_equal DB[:accounts].get(:id)
    child.internal_request_permission_for(:notifier).must_equal [:verify_account]

    error = proc do
      child_app.rodauth.account_exists?(:principal=>:unregistered, :login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestNotAuthorized
    error.denial_reason.must_equal :operation_not_allowed

    error = proc do
      base_app.rodauth.account_id_for_login(:principal=>:base_reader, :login=>'foo@example.com')
    end.must_raise Rodauth::InternalRequestNotAuthorized
    error.operation.must_equal :account_id_for_login
  end

  it "should require explicit permission for internal_request_eval" do
    values = []
    rodauth do
      enable :login, :internal_request_permissions
      internal_request_permission :account_reader, :account_exists?
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>''}
    end

    error = proc do
      app.rodauth.internal_request_eval(:principal=>:account_reader){ values << :ran }
    end.must_raise Rodauth::InternalRequestNotAuthorized
    error.operation.must_equal :internal_request_eval
    error.feature.must_equal :base
    values.must_be_empty

    app.rodauth.internal_request_permission(:account_evaluator, :internal_request_eval)
    app.rodauth.internal_request_eval(:principal=>:account_evaluator){ values << :ran; values.last }.must_equal :ran
    values.must_equal [:ran]
  end

  it "should keep the existing Rack verify-account-resend flow working" do
    rodauth do
      enable :login, :verify_account, :internal_request_permissions
      verify_account_email_last_sent_column nil
      internal_request_permission :account_reader, :account_exists?
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>''}
    end

    visit '/create-account'
    fill_in 'Login', :with=>'quux@example.com'
    click_button 'Create Account'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    email_sent('quux@example.com')

    visit '/verify-account-resend'
    fill_in 'Login', :with=>'quux@example.com'
    click_button 'Send Verification Email Again'
    page.find('#notice_flash').text.must_equal "An email has been sent to you with a link to verify your account"
    email_sent('quux@example.com')
  end
end

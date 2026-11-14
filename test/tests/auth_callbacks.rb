require_relative '../test'

class AuthCallbacksTests < Minitest::Test
  include BrakemanTester::FindWarning

  def report
    @@report ||= BrakemanTester.run_scan "auth_callbacks", "AuthCallbacks",
      :rails3 => true,
      :run_all_checks => true,
      :authentication_callbacks => [:authenticate_user!],
      :protected_controllers => ["Admin::"],
      :public_actions => ["Admin::DashboardController#overview"]
  end

  def unconfigured_report
    @@unconfigured_report ||= BrakemanTester.run_scan "auth_callbacks", "AuthCallbacksUnconfigured",
      :rails3 => true,
      :run_all_checks => true
  end

  def test_silent_without_policy_configuration
    warnings = unconfigured_report[:controller_warnings].select do |w|
      w.check.to_s.include? "UnprotectedActions"
    end

    assert_equal 0, warnings.length, "Expected no warnings without authentication policy configuration"
  end

  def test_skip_removes_inherited_authentication
    assert_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::UsersController",
      :method => :destroy,
      :line => 2,
      :confidence => 0,
      :message => /removed authentication for this action/,
      :relative_path => "app/controllers/admin/users_controller.rb"
  end

  def test_skip_then_reregister_is_protected
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::UsersController",
      :method => :index
  end

  def test_inherited_concern_registration_is_protected
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::UsersController",
      :method => :show
  end

  def test_public_helper_not_routable
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::UsersController",
      :method => :audit_trail
  end

  def test_private_helper_not_routable
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::UsersController",
      :method => :stats_helper
  end

  def test_skip_then_prepend_reregister_is_protected
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::ReportsController",
      :method => :download
  end

  def test_inheritance_override_skip
    assert_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::DashboardController",
      :method => :stats,
      :line => 2,
      :confidence => 0,
      :message => /removed authentication for this action/,
      :relative_path => "app/controllers/admin/dashboard_controller.rb"
  end

  def test_fixed_public_action_exemption
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::DashboardController",
      :method => :overview
  end

  def test_dynamic_condition_cannot_prove
    assert_warning :type => :controller,
      :warning_code => 131,
      :controller => :"Admin::SettingsController",
      :method => :update,
      :line => 3,
      :confidence => 2,
      :message => /cannot prove the action is protected/,
      :relative_path => "app/controllers/admin/settings_controller.rb"
  end

  def test_except_exclusion_after_skip
    assert_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::SystemController",
      :method => :health,
      :line => 2,
      :confidence => 0,
      :relative_path => "app/controllers/admin/system_controller.rb"
  end

  def test_except_reregistered_action_is_protected
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::SystemController",
      :method => :status
  end

  def test_only_option_excludes_action
    assert_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::AuditController",
      :method => :download,
      :line => 2,
      :confidence => 0,
      :message => /does not cover this action/,
      :relative_path => "app/controllers/admin/audit_controller.rb"
  end

  def test_only_option_covers_action
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :"Admin::AuditController",
      :method => :index
  end

  def test_controller_outside_protected_scope
    assert_no_warning :type => :controller,
      :warning_code => 130,
      :controller => :SessionsController,
      :method => :new
  end
end

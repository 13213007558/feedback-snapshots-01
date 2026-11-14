require_relative '../test'

# Tests for tracking permitted parameters into sensitive attribute
# assignment, configured per model with full attribute paths.
class PermitTrackingTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  SENSITIVE_ATTRIBUTES = {
    "User" => ["role", "account.plan", "roles"]
  }

  def report
    @@report ||= BrakemanTester.run_scan "permit_tracking", "Permit Tracking",
      :run_checks => ["CheckPermitAttributes"],
      :sensitive_attributes => SENSITIVE_ATTRIBUTES
  end

  def expected
    @@expected ||= {
      :controller => 0,
      :model => 0,
      :template => 0,
      :generic => 15
    }
  end

  def test_inline_role_permitted
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Mass Assignment",
      :line => 4,
      :message => /Permitted\ parameters\ from\ `params\.require\(:user\)`\ are\ assigned\ to\ sensitive\ User\.role/,
      :confidence => 0,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_reordered_keys_same_result
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 9,
      :message => /sensitive\ User\.role/,
      :confidence => 0,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_address_update_is_allowed
    assert_no_warning :warning_code => 130,
      :line => 14,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_nested_sensitive_path
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 19,
      :message => /sensitive\ User\.account\.plan/,
      :confidence => 0,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_sensitive_array_declaration
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 24,
      :message => /sensitive\ User\.roles/,
      :confidence => 0,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_permitted_hash_via_variable
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 30,
      :message => /sensitive\ User\.role/,
      :confidence => 0,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_reassigned_params_are_safe
    assert_no_warning :warning_code => 130,
      :line => 37,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_permitted_hash_via_method
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 42,
      :message => /sensitive\ User\.role/,
      :confidence => 0,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_safe_strong_params_method
    assert_no_warning :warning_code => 130,
      :line => 47,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_permit_bang_permits_sensitive_attributes
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 52,
      :message => /`permit!`\ permits\ all\ parameters,\ including\ sensitive/,
      :confidence => 0,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_merge_with_trusted_values_is_safe
    assert_no_warning :warning_code => 130,
      :line => 57,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_merge_with_unpermitted_params
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 62,
      :message => /Unpermitted\ parameters\ from\ `params`\ may\ overwrite\ sensitive/,
      :confidence => 1,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_dynamic_keys_keep_uncertainty
    assert_warning :type => :warning,
      :warning_code => 130,
      :line => 67,
      :message => /Cannot\ determine\ permitted\ keys/,
      :confidence => 2,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_create_with_display_fields_is_safe
    assert_no_warning :warning_code => 130,
      :line => 71,
      :relative_path => "app/controllers/users_controller.rb"
  end

  def test_display_role_on_other_model_is_safe
    assert_no_warning :warning_code => 130,
      :relative_path => "app/controllers/profiles_controller.rb"
  end
end

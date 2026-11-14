require_relative '../test'
require_relative '../apps/credential_timing/support/short_circuit_demo'

class CredentialComparisonTimingTests < Minitest::Test
  include BrakemanTester::FindWarning

  FIXTURE = "credential_timing"

  def report
    @@report ||= BrakemanTester.run_scan(
      FIXTURE,
      "Credential timing",
      :enable_checks => ["CheckCredentialComparisonTiming"]
    )
  end

  # The harmless demo records how many comparisons actually ran, so the
  # short-circuit difference is asserted deterministically without network
  # access or statistical timing.
  def test_short_circuit_skips_second_comparison
    result = ShortCircuitDemo.short_circuit_count

    assert_equal 1, result[:user_comparisons]
    assert_equal 0, result[:password_comparisons]
    assert_equal 1, result[:total]
  end

  def test_non_short_circuit_runs_both_comparisons
    result = ShortCircuitDemo.non_short_circuit_count

    assert_equal 1, result[:user_comparisons]
    assert_equal 1, result[:password_comparisons]
    assert_equal 2, result[:total]
  end

  def test_only_short_circuit_skips_work
    skipped = ShortCircuitDemo.short_circuit_count[:total]
    always = ShortCircuitDemo.non_short_circuit_count[:total]

    assert_equal 1, skipped
    assert_equal 2, always
    assert_operator always, :>, skipped
  end

  def test_flags_plain_equals_joined_by_and
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Timing Attack",
      :line => 6,
      :confidence => 0,
      :relative_path => "app/controllers/vulnerable_auth_controller.rb",
      :message => /Short-circuiting credential check/
  end

  def test_flags_secure_compare_joined_by_and
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Timing Attack",
      :line => 14,
      :confidence => 0,
      :relative_path => "app/controllers/vulnerable_auth_controller.rb",
      :message => /secure_compare.*&&\/\|\|/
  end

  def test_flags_digest_comparison_joined_by_and
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Timing Attack",
      :line => 23,
      :confidence => 0,
      :relative_path => "app/controllers/vulnerable_auth_controller.rb",
      :message => /Short-circuiting credential check/
  end

  def test_flags_locally_wrapped_credentials_joined_by_and
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Timing Attack",
      :line => 33,
      :confidence => 0,
      :relative_path => "app/controllers/vulnerable_auth_controller.rb",
      :message => /Short-circuiting credential check/
  end

  def test_flags_unknown_compare_helper_by_name
    assert_warning :type => :warning,
      :warning_code => 131,
      :warning_type => "Timing Attack",
      :line => 41,
      :confidence => 1,
      :relative_path => "app/controllers/vulnerable_auth_controller.rb",
      :message => /Unrecognized comparison helper super_secure_compare/
  end

  def test_flags_short_circuit_even_with_unknown_helper
    assert_warning :type => :warning,
      :warning_code => 130,
      :warning_type => "Timing Attack",
      :line => 41,
      :confidence => 0,
      :relative_path => "app/controllers/vulnerable_auth_controller.rb",
      :message => /super_secure_compare.*&&\/\|\|/
  end

  def test_flags_single_plain_equality
    assert_warning :type => :warning,
      :warning_code => 132,
      :warning_type => "Timing Attack",
      :line => 50,
      :confidence => 1,
      :relative_path => "app/controllers/vulnerable_auth_controller.rb",
      :message => /Credential compared with == or !=/
  end

  def test_safe_controller_has_no_warnings
    assert_no_warning :type => :warning,
      :relative_path => "app/controllers/safe_auth_controller.rb"
  end

  def test_expected_warning_count
    assert_equal 7, report[:generic_warnings].length
  end

  def test_warnings_do_not_embed_code_or_user_input
    report[:generic_warnings].each do |warning|
      assert_nil warning.code
      assert_nil warning.user_input
    end
  end

  # The fixture's fake secrets must never be copied into any rendered report
  # or into a warning's code/user_input/context fields. Internal parsed-source
  # AST sections are not part of any rendered output and are excluded.
  def test_no_fixture_secret_in_any_report
    tracker = BrakemanTester.run_scan_tracker(FIXTURE, :enable_checks => ["CheckCredentialComparisonTiming"])
    json = tracker.report.to_json
    html = tracker.report.to_html
    rendered_hash = tracker.report.to_hash
    warning_section = (
      rendered_hash[:generic_warnings] +
      rendered_hash[:controller_warnings] +
      rendered_hash[:model_warnings] +
      rendered_hash[:template_warnings]
    ).inspect

    ["fixture-admin", "fixture-user", "fixture-pass"].each do |needle|
      refute_includes json, needle
      refute_includes html, needle
      refute_includes warning_section, needle
    end
  end
end

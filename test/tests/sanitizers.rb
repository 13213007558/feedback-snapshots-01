require_relative '../test'
require 'brakeman/sanitizers'

class SanitizersTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def report
    @@report ||= BrakemanTester.run_scan "sanitizers", "Sanitizers"
  end

  def expected
    @@expected ||= {
      :controller => 0,
      :model => 0,
      :template => 4,
      :generic => 5
    }
  end

  # The same method (`clean_text`) flows to HTML, SQL, and file path
  # sinks. Only the HTML path is cleaned, because the description is
  # bound to the :html context.

  def test_html_sanitizer_removes_xss_warning
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 1,
      :relative_path => "app/views/clean/show.html.erb"
  end

  def test_html_sanitizer_does_not_apply_to_sql
    assert_warning :type => :warning,
      :warning_type => "SQL Injection",
      :line => 4,
      :message => /^Possible\ SQL\ injection/,
      :confidence => 0,
      :relative_path => "app/controllers/clean_controller.rb"
  end

  def test_html_sanitizer_does_not_apply_to_file_paths
    assert_warning :type => :warning,
      :warning_type => "File Access",
      :line => 7,
      :message => /^Parameter\ value\ used\ in\ file\ name/,
      :confidence => 2,
      :relative_path => "app/controllers/clean_controller.rb"
  end

  # A SQL proof cannot be borrowed by HTML output or file paths.

  def test_sql_sanitizer_removes_sql_warning
    assert_no_warning :type => :warning,
      :warning_type => "SQL Injection",
      :line => 10,
      :relative_path => "app/controllers/clean_controller.rb"
  end

  def test_sql_sanitizer_does_not_apply_to_html
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 4,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/clean/show.html.erb"
  end

  def test_sql_sanitizer_does_not_apply_to_file_paths
    assert_warning :type => :warning,
      :warning_type => "File Access",
      :line => 16,
      :message => /^Parameter\ value\ used\ in\ file\ name/,
      :confidence => 2,
      :relative_path => "app/controllers/clean_controller.rb"
  end

  # A file path proof cannot be borrowed by HTML output.

  def test_path_sanitizer_removes_file_access_warning
    assert_no_warning :type => :warning,
      :warning_type => "File Access",
      :line => 13,
      :relative_path => "app/controllers/clean_controller.rb"
  end

  def test_path_sanitizer_does_not_apply_to_html
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 5,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/clean/show.html.erb"
  end

  # Cleaning only the first argument must not clean the other arguments.

  def test_sanitizer_only_cleans_configured_argument_in_html
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 2,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/clean/show.html.erb"
  end

  def test_sanitizer_only_cleans_configured_argument_in_sql
    assert_warning :type => :warning,
      :warning_type => "SQL Injection",
      :line => 23,
      :message => /^Possible\ SQL\ injection/,
      :confidence => 0,
      :relative_path => "app/controllers/clean_controller.rb"
  end

  # A sanitized return value mixed back into unprocessed input
  # restores the risk.

  def test_sanitized_value_reinterpolated_with_user_input_in_html
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 3,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/clean/show.html.erb"
  end

  def test_sanitized_value_reinterpolated_with_user_input_in_sql
    assert_warning :type => :warning,
      :warning_type => "SQL Injection",
      :line => 20,
      :message => /^Possible\ SQL\ injection/,
      :confidence => 0,
      :relative_path => "app/controllers/clean_controller.rb"
  end

  # Without any configured custom sanitizers, the previous results
  # are preserved: every sink warns again.

  def test_without_sanitizer_config_all_warnings_remain
    baseline = BrakemanTester.run_scan "sanitizers", "SanitizersBaseline", :sanitizers => []

    template_lines = baseline[:template_warnings].map(&:line)
    generic_lines = baseline[:generic_warnings].map(&:line)

    assert_equal [1, 2, 3, 4, 5], template_lines.sort
    assert_equal 7, generic_lines.length
    assert_includes generic_lines, 10
    assert_includes generic_lines, 13
  end

  def test_sanitizers_loaded_from_scan_config
    tracker = Brakeman.run(:app_path => "#{TEST_PATH}/apps/sanitizers", :parallel_checks => false)

    assert tracker.sanitizers.find(:clean_text, :html)
    assert_empty tracker.sanitizers.problems
  end

  # Configuration problems are reported with reasons.

  def test_conflicting_descriptions_are_reported_with_reason
    sanitizers = Brakeman::Sanitizers.new([
      { :method => :clean_text, :argument => 0, :returns => true, :for => [:html] },
      { :method => :clean_text, :argument => 1, :returns => true, :for => [:html] }
    ])

    assert_equal 1, sanitizers.problems.length
    assert_match(/conflicting/i, sanitizers.problems.first)

    # First description wins
    assert_equal 0, sanitizers.find(:clean_text, :html).argument
  end

  def test_missing_return_propagation_is_reported_with_reason
    sanitizers = Brakeman::Sanitizers.new([
      { :method => :clean_text, :for => [:html] }
    ])

    assert_equal 1, sanitizers.problems.length
    assert_match(/return\ value/, sanitizers.problems.first)
    assert_nil sanitizers.find(:clean_text, :html)
  end

  def test_unknown_context_is_reported_with_reason
    sanitizers = Brakeman::Sanitizers.new([
      { :method => :clean_text, :returns => true, :for => [:javascript] }
    ])

    assert_equal 1, sanitizers.problems.length
    assert_match(/context/, sanitizers.problems.first)
    assert sanitizers.empty?
  end

  def test_no_custom_sanitizers_configured
    sanitizers = Brakeman::Sanitizers.new(nil)

    assert sanitizers.empty?
    assert_empty sanitizers.problems
    assert_nil sanitizers.find(:clean_text, :html)
  end

  def test_contexts_do_not_borrow_from_each_other
    sanitizers = Brakeman::Sanitizers.new([
      { :method => :clean_text, :returns => true, :for => [:html] }
    ])

    assert sanitizers.find(:clean_text, :html)
    assert_nil sanitizers.find(:clean_text, :sql)
    assert_nil sanitizers.find(:clean_text, :path)
  end
end

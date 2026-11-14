require_relative '../test'

class SafeBufferTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def report
    @@report ||= BrakemanTester.run_scan "safe_buffer", "SafeBuffer", :interprocedural => true
  end

  def expected
    @expected ||= {
      :controller => 0,
      :model => 0,
      :template => 6,
      :warning => 0
    }
  end

  # safe_concat does not escape its argument. Once the buffer is returned
  # from a helper and output in the view, the append and output locations
  # should both be represented.
  def test_helper_safe_concat
    assert_warning :type => :template,
      :warning_code => 2,
      :warning_type => "Cross-Site Scripting",
      :line => 1,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/buffers/helper_safe_concat.html.erb",
      :code => s(:call, s(:call, s(:str, ""), :html_safe), :safe_concat, s(:call, s(:params), :[], s(:lit, :unsafe)))
  end

  # A second name for the same mutable buffer observes the append.
  def test_helper_shared_buffer_alias
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 1,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/buffers/helper_alias.html.erb",
      :code => s(:call, s(:call, s(:str, ""), :html_safe), :safe_concat, s(:call, s(:params), :[], s(:lit, :aliased)))
  end

  # SafeBuffer#<< escapes non-SafeBuffer arguments, so this is safe.
  def test_helper_plain_concat_is_escaped
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :relative_path => "app/views/buffers/helper_plain_concat.html.erb"
  end

  # Fixed markup contains no user data. This exercises the harmless angle
  # brackets used in the fixture.
  def test_helper_static_markup_is_safe
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :relative_path => "app/views/buffers/helper_static_markup.html.erb"
  end

  # Replacing the buffer contents drops the previously unsafe data.
  def test_helper_replace_static_is_safe
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :relative_path => "app/views/buffers/helper_replace_static.html.erb"
  end

  # Direct in-template safe_concat is not escaped by <%= %> because the
  # buffer is a SafeBuffer.
  def test_direct_safe_concat
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 3,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/buffers/direct_safe_concat.html.erb",
      :code => s(:call, s(:call, s(:str, ""), :html_safe), :safe_concat, s(:call, s(:params), :[], s(:lit, :direct)))
  end

  # Direct in-template << escapes. Do not report every concatenation.
  def test_direct_plain_concat_is_escaped
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :relative_path => "app/views/buffers/direct_plain_concat.html.erb"
  end

  def test_direct_static_markup_is_safe
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :relative_path => "app/views/buffers/direct_static_markup.html.erb"
  end

  # The unsafe append is on one variable but output goes through its alias.
  def test_direct_shared_buffer_alias
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 4,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 2,
      :relative_path => "app/views/buffers/direct_alias.html.erb",
      :code => s(:call, s(:call, s(:str, ""), :html_safe), :safe_concat, s(:call, s(:params), :[], s(:lit, :aliased)))
  end

  # Reassigning the variable drops the SafeBuffer; <%= %> escapes it.
  def test_direct_reassign_is_escaped
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :relative_path => "app/views/buffers/direct_reassign.html.erb"
  end

  # With <%== the reassigned value is output directly.
  def test_direct_reassign_raw
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 3,
      :message => /^Unescaped\ parameter\ value/,
      :confidence => 0,
      :relative_path => "app/views/buffers/direct_reassign_raw.html.erb",
      :code => s(:call, s(:params), :[], s(:lit, :reassigned))
  end

  # Auto-escaping is preserved for ordinary output.
  def test_plain_parameter_is_escaped
    assert_no_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :relative_path => "app/views/buffers/plain_escaped.html.erb"
  end

  # A buffer carrying unsafe content is not escaped when passed to concat.
  def test_direct_buffer_argument
    assert_warning :type => :template,
      :warning_type => "Cross-Site Scripting",
      :line => 5,
      :message => /^Unescaped\ parameter\ value/,
      :relative_path => "app/views/buffers/direct_buffer_argument.html.erb",
      :confidence => 0,
      :code => s(:call, s(:call, s(:str, ""), :html_safe), :concat,
                   s(:call, s(:call, s(:str, ""), :html_safe), :safe_concat,
                     s(:call, s(:params), :[], s(:lit, :nested))))
  end
end

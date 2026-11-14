require_relative '../test'

# Parameter-combination tests for CheckRenderInline.
#
# Each anchor documents the final render options (after Ruby keyword/hash
# semantics) and how the dangerous input is interpreted in the response.
# A non-HTML Content-Type is only a safe exception for `render text:`
# (plain body); it can never suppress `render inline:` template execution.
class RenderInlineTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def report
    @@report ||= BrakemanTester.run_scan "render_inline", "RenderInline"
  end

  def expected
    @@expected ||= {
      :controller => 0,
      :model => 0,
      :template => 0,
      :generic => 9
    }
  end

  def assert_inline_xss method_name, line
    assert_warning :type => :warning,
      :warning_code => 84,
      :warning_type => "Cross-Site Scripting",
      :line => line,
      :message => /^Unescaped\ parameter\ value\ rendered\ inline/,
      :confidence => 0,
      :relative_path => "app/controllers/render_inline_controller.rb",
      :method => method_name
  end

  def assert_no_inline_xss method_name
    assert_no_warning :type => :warning,
      :warning_code => 84,
      :relative_path => "app/controllers/render_inline_controller.rb",
      :method => method_name
  end

  # text + "text/plain": plain-text body, safe exception
  def test_plain_text_no_warning
    assert_no_inline_xss :plain_text
  end

  # text + "text/html": body served as HTML
  def test_html_text_warns
    assert_inline_xss :html_text, 11
  end

  # text + "Text/Plain": case-insensitive MIME, still plain text
  def test_plain_text_case_no_warning
    assert_no_inline_xss :plain_text_case
  end

  # text + "Text/HTML": case-insensitive MIME, served as HTML
  def test_html_text_case_warns
    assert_inline_xss :html_text_case, 25
  end

  # text + "text/html; charset=utf-8": parameters keep media type HTML
  def test_html_text_with_params_warns
    assert_inline_xss :html_text_with_params, 32
  end

  # text + duplicate content_type, "text/html" last: last key wins, HTML
  def test_duplicate_content_type_html_last_warns
    assert_inline_xss :duplicate_content_type_html_last, 39
  end

  # text + duplicate content_type, "text/plain" last: last key wins, plain
  def test_duplicate_content_type_plain_last_no_warning
    assert_no_inline_xss :duplicate_content_type_plain_last
  end

  # text + interpolated MIME: response type not statically provable
  def test_dynamic_content_type_warns
    assert_inline_xss :dynamic_content_type, 53
  end

  # text + merged options hash: content_type not statically visible
  def test_merged_options_warns
    assert_inline_xss :merged_options, 61
  end

  # text without content_type: default response type is HTML
  def test_default_content_type_warns
    assert_inline_xss :default_content_type, 67
  end

  # inline + "text/plain": input is executed as a template; changing the
  # MIME cannot remove template execution
  def test_inline_with_plain_content_type_warns
    assert_inline_xss :inline_with_plain_content_type, 74
  end

  # inline + "text/html": template executed and served as HTML
  def test_inline_with_html_content_type_warns
    assert_inline_xss :inline_with_html_content_type, 81
  end
end

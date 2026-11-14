require_relative '../test'

#Tests that locals are propagated per render call when a partial is
#rendered from multiple places, instead of reusing the result of
#whichever render happened to be processed first.
#
#AlphaController and ZetaController render the same partials.
#AlphaController (processed first, controllers are sorted by name)
#passes trusted constants, ZetaController passes user input.
#Every dangerous value must still be reported when it reaches an
#unescaped output.
class RenderLocalsTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def expected
    @expected ||= {
      :controller => 3,
      :model => 0,
      :template => 6,
      :warning => 0 }
  end

  def report
    @@report ||= BrakemanTester.run_scan "render_locals", "RenderLocals", :interprocedural => true
  end

  #Full render path including the final rendered template,
  #which is tracked in the last entry of the render path
  def assert_render_path warning, *expected
    actual = warning.called_from.to_a

    if rendered = warning.called_from.path.last[:rendered]
      actual += ["Template:#{rendered[:name]}"]
    end

    assert_equal expected, actual,
      "Expected render path #{expected.inspect}, got #{actual.inspect}"
  end

  #Basic case: same partial, safe local from AlphaController,
  #params from ZetaController
  def test_xss_shared_partial_locals
    assert_warning :type => :template,
      :warning_code => 2,
      :fingerprint => "98ca66360c941cd3379e2fca3cab1783d27d22f85ff846538c929c1595ae4a8b",
      :check_name => "CrossSiteScripting",
      :message => /^Unescaped\ parameter\ value\ near\ line\ 2:\ params/,
      :line => 2,
      :relative_path => "app/views/shared/_widget.html.erb"

    warning = find(:type => :template,
      :fingerprint => "98ca66360c941cd3379e2fca3cab1783d27d22f85ff846538c929c1595ae4a8b").first

    assert_render_path warning, "ZetaController#show", "Template:shared/_widget"
  end

  #The same partial rendered with an escaped output must not warn
  def test_no_xss_for_escaped_output
    assert_no_warning :type => :template,
      :relative_path => "app/views/shared/_widget.html.erb",
      :line => 1
  end

  #No warning may come from AlphaController's renders,
  #since it only passes trusted constants
  def test_no_xss_from_safe_locals
    report[:template_warnings].each do |warning|
      refute warning.called_from.to_a.any? { |loc| loc.start_with? "AlphaController" },
        "Unexpected warning from AlphaController render: #{warning.message}"
    end
  end

  #Locals propagated through a nested partial
  def test_xss_nested_partial_locals
    assert_warning :type => :template,
      :warning_code => 2,
      :fingerprint => "d9a7316896af433b8d99d9850063233824479562e1f0fb53e681cbea73225552",
      :check_name => "CrossSiteScripting",
      :message => /^Unescaped\ parameter\ value\ near\ line\ 1:\ params/,
      :line => 1,
      :relative_path => "app/views/shared/_inner.html.erb"

    warning = find(:type => :template,
      :fingerprint => "d9a7316896af433b8d99d9850063233824479562e1f0fb53e681cbea73225552").first

    assert_render_path warning, "ZetaController#nested", "Template:shared/_outer", "Template:shared/_inner"
  end

  #Collection with :as sets the local used by the partial
  def test_xss_collection_with_as
    assert_warning :type => :template,
      :warning_code => 2,
      :fingerprint => "38da43094f9b906eb0bcceb93e554493fd92cb48c3fb22ad57654eda5d7eed6a",
      :check_name => "CrossSiteScripting",
      :message => /^Unescaped\ model\ attribute\ near\ line\ 1:\ \(Unres/,
      :line => 1,
      :relative_path => "app/views/shared/_thing.html.erb"

    warning = find(:type => :template,
      :fingerprint => "38da43094f9b906eb0bcceb93e554493fd92cb48c3fb22ad57654eda5d7eed6a").first

    assert_render_path warning, "ZetaController#items", "Template:shared/_thing"
  end

  #Helper return value passed as a local
  def test_xss_helper_return_value_in_locals
    assert_warning :type => :template,
      :warning_code => 2,
      :fingerprint => "74723c9248d8e26110957b23bb3317cec0349b531a02c8d7cb598f7d59f679d4",
      :check_name => "CrossSiteScripting",
      :message => /^Unescaped\ parameter\ value\ near\ line\ 1:\ params/,
      :line => 1,
      :relative_path => "app/views/shared/_from_helper.html.erb"

    warning = find(:type => :template,
      :fingerprint => "74723c9248d8e26110957b23bb3317cec0349b531a02c8d7cb598f7d59f679d4").first

    assert_render_path warning, "ZetaController#helper_value", "Template:shared/_from_helper"
  end

  #A local passed to a partial shadows the same-named variable
  #in the rendering template
  def test_xss_shadowed_local
    assert_warning :type => :template,
      :warning_code => 2,
      :fingerprint => "fc0d2a5fe087b84a5fe41b9bc8ca93f31f46cf1ed86781135f13f57f77f969d7",
      :check_name => "CrossSiteScripting",
      :message => /^Unescaped\ parameter\ value\ near\ line\ 1:\ params/,
      :line => 1,
      :relative_path => "app/views/shared/_shadow.html.erb"

    warning = find(:type => :template,
      :fingerprint => "fc0d2a5fe087b84a5fe41b9bc8ca93f31f46cf1ed86781135f13f57f77f969d7").first

    assert_render_path warning, "ZetaController#shadowed", "Template:zeta/shadowed", "Template:shared/_shadow"
  end

  #The safe local passed from alpha/shadowed must not warn,
  #even though the template itself assigns a tainted same-named variable
  def test_no_xss_when_safe_local_shadows
    report[:template_warnings].each do |warning|
      refute warning.called_from.to_a.any? { |loc| loc == "Template:alpha/shadowed" },
        "Unexpected warning from alpha/shadowed render: #{warning.message}"
    end
  end

  #A partial rendering itself must terminate and still keep
  #the warning from the entry render
  def test_xss_recursive_partial_keeps_entry_render
    assert_warning :type => :template,
      :warning_code => 2,
      :fingerprint => "e8772083989987ee901396dc41a209e4a9683e7da1df0e8d975d57d33978e2e9",
      :check_name => "CrossSiteScripting",
      :message => /^Unescaped\ parameter\ value\ near\ line\ 1:\ params/,
      :line => 1,
      :relative_path => "app/views/shared/_recursive.html.erb"

    warning = find(:type => :template,
      :fingerprint => "e8772083989987ee901396dc41a209e4a9683e7da1df0e8d975d57d33978e2e9").first

    assert_render_path warning, "ZetaController#recursive", "Template:shared/_recursive"
  end
end

#Same shared partial as RenderLocalsTests, but the tainted render
#is processed first (AlphaController) and the safe render second
#(ZetaController). Results must be identical to RenderLocalsTests
#except for which controller carries the dangerous value:
#swapping the scan order must not change the outcome.
class RenderLocalsReversedTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def expected
    @expected ||= {
      :controller => 3,
      :model => 0,
      :template => 1,
      :warning => 0 }
  end

  def report
    @@report ||= BrakemanTester.run_scan "render_locals_reversed", "RenderLocalsReversed", :interprocedural => true
  end

  def assert_render_path warning, *expected
    actual = warning.called_from.to_a

    if rendered = warning.called_from.path.last[:rendered]
      actual += ["Template:#{rendered[:name]}"]
    end

    assert_equal expected, actual
  end

  def test_xss_shared_partial_locals_tainted_first
    assert_warning :type => :template,
      :warning_code => 2,
      :fingerprint => "c4311ddcd08b82c71e5e75e7eb13ba3ef1ffc5969f35c10c3d30d9c10d9601a7",
      :check_name => "CrossSiteScripting",
      :message => /^Unescaped\ parameter\ value\ near\ line\ 2:\ params/,
      :line => 2,
      :relative_path => "app/views/shared/_widget.html.erb"

    warning = find(:type => :template,
      :fingerprint => "c4311ddcd08b82c71e5e75e7eb13ba3ef1ffc5969f35c10c3d30d9c10d9601a7").first

    assert_render_path warning, "AlphaController#show", "Template:shared/_widget"
  end

  def test_no_xss_for_escaped_output
    assert_no_warning :type => :template,
      :relative_path => "app/views/shared/_widget.html.erb",
      :line => 1
  end
end

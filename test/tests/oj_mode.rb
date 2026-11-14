require_relative '../test'
require 'fileutils'

# Exercises Oj.load mode inference in CheckDeserialize.
#
# Each fixture app shares app/controllers/users_controller.rb with these calls:
#   line 3: Oj.load(params[:json])                       # inherits global default
#   line 4: Oj.load(params[:json], mode: :strict)        # explicit safe mode
#   line 5: Oj.load(params[:json], mode: :object)        # explicit object mode
#   line 6: Oj.load(params[:json], mode: ENV["OJ_MODE"]) # unknown call-level mode
#   line 7: Oj.object_load(params[:json])                # always unsafe
class OjModeInferenceTests < Minitest::Test
  PLAIN_LOAD_LINE   = 3
  EXPLICIT_SAFE_LINE = 4
  OBJECT_MODE_LINE  = 5
  UNKNOWN_MODE_LINE = 6
  OBJECT_LOAD_LINE  = 7

  DESERIALIZE_WARNING_CODE = 25 # Brakeman::WarningCodes::Codes[:unsafe_deserialize]

  # Calls that warn regardless of any global configuration: an explicit object
  # mode, an unresolvable call-level mode, and Oj.object_load itself.
  ALWAYS_UNSAFE_LINES = [OBJECT_MODE_LINE, UNKNOWN_MODE_LINE, OBJECT_LOAD_LINE].freeze

  def deserialize_warning_lines(app, extra_options = {})
    report = BrakemanTester.run_scan(app, nil, extra_options)
    report[:generic_warnings]
      .select { |warning| warning.warning_code == DESERIALIZE_WARNING_CODE }
      .map(&:line)
      .sort
  end

  # Fixture: every Oj default change is in one file and the last assignment is
  # a known safe mode, so the effective global default is provably safe.
  def test_safe_mode_fixture
    assert_equal ALWAYS_UNSAFE_LINES, deserialize_warning_lines("oj_safe_mode")
  end

  # An explicit safe call must never produce a warning, even when the global
  # default is unsafe. This is the no-false-positive control for every app.
  def test_explicit_safe_call_never_warns
    %w[oj_safe_mode oj_object_mode oj_unknown_order].each do |app|
      lines = deserialize_warning_lines(app)
      refute_includes lines, EXPLICIT_SAFE_LINE,
        "#{app}: explicit :strict call produced a false positive"
    end
  end

  # Fixture: a later same-file default_options= switches back to :object mode,
  # overriding earlier mimic_JSON/:strict settings. The plain load inherits an
  # unsafe default, so it warns in addition to the always-unsafe calls.
  def test_object_mode_fixture
    expected = ([PLAIN_LOAD_LINE] + ALWAYS_UNSAFE_LINES).sort
    assert_equal expected, deserialize_warning_lines("oj_object_mode")
  end

  # Fixture: configuration is spread across files and one file derives the mode
  # from a condition and an environment variable. The effective default cannot
  # be proven safe, so the plain load warns.
  def test_unknown_order_fixture
    expected = ([PLAIN_LOAD_LINE] + ALWAYS_UNSAFE_LINES).sort
    assert_equal expected, deserialize_warning_lines("oj_unknown_order")
  end

  # Swapping the order in which the two initializer files appear must not change
  # the conclusion: an unsafe or environment-derived mode in any file means an
  # unsafe default is reachable, regardless of file enumeration order.
  def test_unknown_order_is_stable_when_files_are_swapped
    Dir.mktmpdir do |dir|
      FileUtils.cp_r(File.join(TEST_PATH, "apps", "oj_unknown_order", "."), dir)
      initializers = File.join(dir, "config", "initializers")

      original = Dir.glob(File.join(initializers, "*.rb")).sort
      baseline = scan_relative(dir)

      # Rename so the previously-later (runtime) file sorts first, then restore
      # and assert the warning set is identical.
      FileUtils.mv(original.first, File.join(initializers, "zzz_runtime_first.rb"))
      swapped = scan_relative(dir)

      assert_equal baseline, swapped
    end
  end

  # Within one file the last *unconditional* assignment is what counts.
  # :object followed by :strict is provably safe, while the reversed order is
  # provably unsafe; line order (not file enumeration) decides.
  def test_same_file_order_uses_last_unconditional_assignment
    with_app("Oj.default_options = { mode: :object }\nOj.default_options = { mode: :strict }\n") do |lines|
      assert_equal ALWAYS_UNSAFE_LINES, lines
    end

    with_app("Oj.default_options = { mode: :strict }\nOj.default_options = { mode: :object }\n") do |lines|
      assert_equal ([PLAIN_LOAD_LINE] + ALWAYS_UNSAFE_LINES).sort, lines
    end
  end

  # A safe assignment nested in a conditional only runs on some paths. The
  # earlier unconditional :object default stays reachable, so the plain load
  # must warn even though the guarded assignment appears last.
  def test_guarded_safe_assignment_does_not_override_unsafe_default
    source = <<~RUBY
      Oj.default_options = { mode: :object }
      if some_condition?
        Oj.default_options = { mode: :strict }
      end
    RUBY

    with_app(source) do |lines|
      assert_equal ([PLAIN_LOAD_LINE] + ALWAYS_UNSAFE_LINES).sort, lines
    end
  end

  # A mode read from an environment variable is not a source-level constant, so
  # it yields multiple possible modes and cannot be treated as safe.
  def test_environment_derived_mode_is_unknown
    with_app("Oj.default_options = { mode: ENV['OJ_MODE'] }\n") do |lines|
      assert_equal ([PLAIN_LOAD_LINE] + ALWAYS_UNSAFE_LINES).sort, lines
    end
  end

  # Guard detection also applies to case/when branches: a safe assignment in a
  # when clause leaves the earlier unconditional :object default reachable.
  def test_case_when_guarded_assignment_is_not_safe
    source = <<~RUBY
      Oj.default_options = { mode: :object }
      case framework
      when :rails
        Oj.default_options = { mode: :strict }
      end
    RUBY

    with_app(source) do |lines|
      assert_equal ([PLAIN_LOAD_LINE] + ALWAYS_UNSAFE_LINES).sort, lines
    end
  end

  private

  # Builds a minimal app around a single initializer and returns the warning
  # lines produced for the shared controller fixture.
  def with_app(initializer_source)
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, "app", "controllers"))
      FileUtils.mkdir_p(File.join(dir, "config", "initializers"))

      File.write(
        File.join(dir, "app", "controllers", "users_controller.rb"),
        File.read(File.join(TEST_PATH, "apps", "oj_safe_mode", "app", "controllers", "users_controller.rb"))
      )
      File.write(File.join(dir, "config", "initializers", "oj.rb"), initializer_source)

      yield scan_relative(dir)
    end
  end

  def scan_relative(dir)
    report = Brakeman.run(
      app_path: dir,
      url_safe_methods: [:ensure_valid_proto!],
      parallel_checks: false
    ).report.to_hash

    report[:generic_warnings]
      .select { |warning| warning.warning_code == DESERIALIZE_WARNING_CODE }
      .map(&:line)
      .sort
  end
end

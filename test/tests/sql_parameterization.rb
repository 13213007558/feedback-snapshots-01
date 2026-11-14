require_relative '../test'
require_relative '../support/sql_param_generator'

# Probes the trust boundary of Brakeman::CheckSQL around where/order/joins and
# Arel.sql. The same tainted source (params[:q]) is reused everywhere, so a
# verdict difference is purely a function of the position the source occupies:
# value placeholder, identifier or raw SQL fragment.
#
# Rails 6.1 changes the entry-point semantics for order/reorder/pluck (they are
# no longer checked), so those anchors are asserted separately by version.
class SqlParameterizationTests < Minitest::Test
  GEN = BrakemanTester::SqlParamGenerator

  RAILS_VERSIONS = %w[6.0.0 6.1.0 7.0.0].freeze

  # Confidence integers used by Brakeman warnings: 0 high, 1 medium, 2 weak.
  HIGH = 0
  MEDIUM = 1

  def setup
    @temp_dirs = []
    @apps = {}
    RAILS_VERSIONS.each do |version|
      anchors = GEN.anchors_for(version)
      dir = Dir.mktmpdir("sql-param-#{version}-")
      @temp_dirs << dir
      root = File.join(dir, "app")
      FileUtils.mkdir_p(root)
      GEN.write_app(root, version, anchors)

      tracker = Brakeman.run(app_path: root, parallel_checks: false, quiet: true)
      sql_warnings = tracker.report.to_hash[:generic_warnings].select do |warning|
        warning.warning_type == "SQL Injection"
      end

      @apps[version] = {
        anchors: anchors,
        line_map: GEN.line_map(anchors),
        warnings: sql_warnings.group_by(&:line)
      }
    end
  end

  def teardown
    @temp_dirs&.each { |dir| FileUtils.remove_entry(dir, true) }
  end

  def test_deterministic_anchor_ordering
    ids = GEN::ANCHORS.map { |anchor| anchor[:id] }
    assert_equal ids.size, ids.uniq.size, "anchor ids are unique"
    assert_equal GEN.shuffled_ids(GEN::ANCHORS), GEN.shuffled_ids(GEN::ANCHORS),
      "the fixed seed must produce the same presentation permutation every run"
    refute_equal ids, GEN.shuffled_ids(GEN::ANCHORS),
      "the shuffled presentation order must actually differ from definition order"
  end

  def test_same_source_is_used_by_every_anchor
    assert GEN::ANCHORS.size >= 20
    GEN::ANCHORS.each do |anchor|
      if anchor[:cat] == :safe_bind
        # A safe anchor either places the shared source in a value position or
        # contains no source at all; it must never inject it into a fragment.
        next
      end

      assert_equal(true, anchor[:code].include?(GEN::SOURCE) || anchor.key?(:helper),
        "#{anchor[:id]} must keep the shared source or explicitly declare a helper")
    end
  end

  def test_value_position_anchors_never_warn
    each_anchor(:safe_bind) do |version, anchor, entry|
      assert_nil warning_for(entry, anchor),
        "#{anchor[:id]} on Rails #{version}: source in value position must not warn"
    end
  end

  def test_dangerous_fragment_anchors_warn_high
    each_anchor(:danger) do |version, anchor, entry|
      warning = warning_for(entry, anchor)
      refute_nil warning,
        "#{anchor[:id]} on Rails #{version}: #{anchor[:note]}"
      assert_includes warning.map(&:confidence), HIGH,
        "#{anchor[:id]} on Rails #{version}: must be high confidence"
    end
  end

  # Regression anchor for the bind-array/hash-key fix: a dynamic identifier key
  # hidden inside an array must not be treated as parameterized bind data.
  def test_dynamic_key_inside_array_is_caught
    anchor = anchor_by_id("W08")
    each_version do |version, entry|
      warning = warning_for(entry, anchor)
      refute_nil warning, "W08 on Rails #{version}: array-wrapped identifier key must warn"
    end
  end

  # The same dangerous source moved into a legitimate bind position must stay
  # quiet. This is the "why it no longer warns" counterpart to W08: the source
  # is identical, only its position changes.
  def test_same_source_in_named_bind_position_stays_silent
    dangerous = anchor_by_id("W04")
    bound = anchor_by_id("W02")
    each_version do |version, entry|
      refute_nil warning_for(entry, dangerous),
        "W04 on Rails #{version}: interpolation must warn"
      assert_nil warning_for(entry, bound),
        "W02 on Rails #{version}: named bind value must not warn"
    end
  end

  def test_order_and_pluck_are_version_gated
    order_anchor = anchor_by_id("O01")
    pluck_anchor = anchor_by_id("O05")

    refute_nil warning_for(@apps["6.0.0"], order_anchor),
      "order interpolation is checked before Rails 6.1"
    refute_nil warning_for(@apps["6.0.0"], pluck_anchor),
      "pluck interpolation is checked before Rails 6.1"

    %w[6.1.0 7.0.0].each do |version|
      entry = @apps[version]
      assert_nil entry[:line_map][order_anchor[:id]],
        "order anchors are not emitted on Rails >= 6.1 (#{version})"
      assert_nil entry[:line_map][pluck_anchor[:id]],
        "pluck anchors are not emitted on Rails >= 6.1 (#{version})"
    end
  end

  # Documented minimal false negative: String#% builds SQL without a recognized
  # string-building method, so the checker misses it. Pin the current behavior so
  # a future improvement is an intentional, visible change.
  def test_known_false_negative_string_percent
    anchor = anchor_by_id("W11")
    each_version do |version, entry|
      assert_nil warning_for(entry, anchor),
        "W11 on Rails #{version}: String#% is currently a known false negative"
    end
  end

  # Documented minimal false positive: a whitelist helper result cannot be
  # resolved, so safe code is flagged at medium confidence.
  def test_known_false_positive_whitelist_helper
    anchor = anchor_by_id("F01")
    each_version do |version, entry|
      warning = warning_for(entry, anchor)
      refute_nil warning,
        "F01 on Rails #{version}: unresolved whitelist helper is conservatively flagged"
      assert_includes warning.map(&:confidence), MEDIUM
    end
  end

  private

  def each_anchor(category)
    each_version do |version, entry|
      entry[:anchors].select { |anchor| anchor[:cat] == category }.each do |anchor|
        yield version, anchor, entry
      end
    end
  end

  def each_version
    RAILS_VERSIONS.each { |version| yield version, @apps[version] }
  end

  def warning_for(entry, anchor)
    line = entry[:line_map][anchor[:id]]
    return nil if line.nil?

    entry[:warnings][line]
  end

  def anchor_by_id(id)
    GEN::ANCHORS.find { |anchor| anchor[:id] == id }
  end
end

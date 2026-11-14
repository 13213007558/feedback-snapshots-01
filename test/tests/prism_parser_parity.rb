require_relative '../test'

# Verifies that migrating Brakeman's Ruby parsing entry point from
# ruby_parser to Prism (via Prism::Translation::RubyParser) does not make
# existing vulnerability warnings disappear.
#
# Fixtures live in test/fixtures/prism_parity:
#   both_parsers/ - syntax supported by both parsers; AST + source/sink/location
#                   must match exactly under use_prism false and true
#   coverage/     - syntax only one parser accepts; recorded as a coverage gap,
#                   never interpreted as "no vulnerability"
#   mutants/      - variants with the dangerous source node deliberately removed;
#                   prove the harness itself catches a false negative
#   invalid/      - intentionally unparseable; failures must be fail-closed
class PrismParserParityTest < Minitest::Test
  FIXTURE_ROOT = File.join(TEST_PATH, 'fixtures', 'prism_parity')
  BOTH_DIR     = File.join(FIXTURE_ROOT, 'both_parsers')
  COVERAGE_DIR = File.join(FIXTURE_ROOT, 'coverage')
  MUTANT_DIR   = File.join(FIXTURE_ROOT, 'mutants')
  INVALID_DIR  = File.join(FIXTURE_ROOT, 'invalid')

  DANGEROUS_SINKS = [:eval, :constantize, :query, :where, :find,
                     :public_send, :relay, :render].freeze

  def self.fixture_test_name(fixture, suffix)
    base = fixture.gsub(/[^a-z0-9]+/i, '_')
    suffix.empty? ? base : "#{suffix}_for_#{base}"
  end

  def setup
    @tracker = BrakemanTester.new_tracker
    @ruby_parser_file_parser = new_file_parser(false)
    @prism_file_parser       = new_file_parser(true)
  end

  # ------------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------------

  def new_file_parser(use_prism)
    Brakeman::FileParser.new(@tracker.app_tree, 10, false, use_prism)
  end

  def read_fixture(dir, name)
    File.read(File.join(dir, name))
  end

  def parse_each_way(dir, name)
    source = read_fixture(dir, name)
    relative = "fixtures/prism_parity/#{File.basename(dir)}/#{name}"

    ruby_parser_ast = @ruby_parser_file_parser.parse_ruby(source, relative)
    prism_ast       = @prism_file_parser.parse_ruby(source, relative)

    [ruby_parser_ast, prism_ast]
  end

  # Alias resolution is what Brakeman uses to connect a local variable sink
  # argument back to the params assignment that tainted it.
  def alias_process(ast)
    Brakeman::AliasProcessor.new(@tracker).process_safely(ast)
  end

  # Flatten a Sexp into [node_type, line, file] triples so metadata drift
  # (a warning pointing at the wrong line) is caught, not just structure.
  def node_skeleton(sexp)
    entries = []
    walk = lambda do |node|
      return unless node.is_a? Sexp
      entries << [node.sexp_type, node.line, node.file]
      node.each { |child| walk.call(child) }
    end
    walk.call(sexp)
    entries
  end

  def each_call(sexp, &block)
    return unless sexp.is_a? Sexp

    if sexp.node_type == :call || sexp.node_type == :safe_call
      block.call(sexp)
    end

    sexp.each { |child| each_call(child, &block) }
  end

  def method_name(call_node)
    call_node.method
  end

  def contains_node?(sexp, &predicate)
    return false unless sexp.is_a? Sexp
    return true if predicate.call(sexp)

    sexp.any? { |child| contains_node?(child, &predicate) }
  end

  # A params source: s(:call, s(:call, nil, :params), :[], s(:lit, key))
  def params_source?(sexp)
    sexp.is_a?(Sexp) &&
      sexp.node_type == :call &&
      sexp.length >= 2 &&
      sexp[1].is_a?(Sexp) &&
      sexp[1].node_type == :call &&
      sexp[1][1].nil? &&
      sexp[1][2] == :params
  end

  def sink_nodes(ast)
    nodes = []
    each_call(ast) do |call_node|
      nodes << call_node if DANGEROUS_SINKS.include?(method_name(call_node))
    end
    nodes
  end

  def sink_names(source)
    source.each_line.map { |line| line[/#\s*SINK:\s*(\w+)/, 1] }.compact.map(&:to_sym)
  end

  # Sinks whose argument subtree directly contains a params source after
  # Brakeman alias resolution (line numbers match the fixture files).
  # Cross-method/forwarding sinks are covered separately via
  # #forwarding_expectations and the call-site source assertions below.
  def direct_sink_expectations(fixture)
    {
      'safe_navigation.rb'     => [[:eval, 4], [:constantize, 6], [:public_send, 8], [:query, 10]],
      'keyword_forwarding.rb'  => [[:relay, 7], [:eval, 15]],
      'interpolation.rb'       => [[:eval, 4], [:query, 6], [:render, 9]],
      'nested_calls.rb'        => [[:find, 3], [:constantize, 6], [:where, 9]],
    }.fetch(fixture)
  end

  # Node types that encode the source-to-sink forwarding relationship and
  # must survive both AST conversions even when the params source is not
  # syntactically inside the sink subtree.
  def forwarding_expectations(fixture)
    {
      'keyword_forwarding.rb' => [:forward_args],
    }.fetch(fixture, [])
  end

  # Sinks reached only through a method/block scope (forwarding or block
  # arguments). They are asserted structurally (node survival + call-site
  # source) rather than by a params node inside their own subtree.
  def scoped_sink_expectations(fixture)
    {
      'keyword_forwarding.rb' => [[:query, 3], [:eval, 10]],
    }.fetch(fixture, [])
  end

  # Guard against the hard-coded line manifests drifting from the fixtures.
  def test_direct_sink_manifest_matches_actual_ast
    Dir[File.join(BOTH_DIR, '*.rb')].each do |path|
      fixture = File.basename(path)
      ast = @ruby_parser_file_parser.parse_ruby(read_fixture(BOTH_DIR, fixture), fixture)
      actual = sink_nodes(ast).map { |node| [method_name(node), node.line] }
      expected = direct_sink_expectations(fixture) + scoped_sink_expectations(fixture)

      assert_equal actual.sort, expected.sort,
                   "sink manifest is stale for #{fixture}"
    end
  end

  def test_every_annotated_sink_is_covered
    Dir[File.join(BOTH_DIR, '*.rb')].each do |path|
      fixture = File.basename(path)
      annotated = sink_names(read_fixture(BOTH_DIR, fixture)).uniq
      manifest  = (direct_sink_expectations(fixture) +
                   scoped_sink_expectations(fixture)).map(&:first).uniq

      annotated.each do |sink|
        assert_includes manifest, sink,
                        "annotated sink :#{sink} in #{fixture} has no parity expectation"
      end
    end
  end

  # ------------------------------------------------------------------
  # 1. AST parity for syntax both parsers support
  # ------------------------------------------------------------------

  Dir[File.join(BOTH_DIR, '*.rb')].each do |path|
    fixture = File.basename(path)

    define_method("test_ast_skeleton_#{fixture_test_name(fixture, 'matches')}") do
      ruby_parser_ast, prism_ast = parse_each_way(BOTH_DIR, fixture)

      assert_equal node_skeleton(ruby_parser_ast),
                   node_skeleton(prism_ast),
                   "AST node types/line/file metadata differ for #{fixture}"
    end

    define_method("test_full_sexp_#{fixture_test_name(fixture, 'matches')}") do
      ruby_parser_ast, prism_ast = parse_each_way(BOTH_DIR, fixture)

      assert_equal ruby_parser_ast, prism_ast,
                   "Full Sexp differs for #{fixture}"
    end

    define_method("test_alias_processed_sexp_#{fixture_test_name(fixture, 'matches')}") do
      ruby_parser_ast, prism_ast = parse_each_way(BOTH_DIR, fixture)

      assert_equal alias_process(ruby_parser_ast),
                   alias_process(prism_ast),
                   "Alias-resolved Sexp (source-to-sink view) differs for #{fixture}"
    end
  end

  # ------------------------------------------------------------------
  # 2. Dangerous call, input source and location survive both conversions
  # ------------------------------------------------------------------

  Dir[File.join(BOTH_DIR, '*.rb')].each do |path|
    fixture = File.basename(path)

    define_method("test_dangerous_sinks_preserved_#{fixture_test_name(fixture, '')}".chomp('_')) do
      source = read_fixture(BOTH_DIR, fixture)
      annotated_sinks = sink_names(source)

      [[false, @ruby_parser_file_parser], [true, @prism_file_parser]].each do |use_prism, parser|
        ast = parser.parse_ruby(source, fixture)
        found = sink_nodes(ast).map { |call_node| method_name(call_node) }

        annotated_sinks.uniq.each do |sink|
          assert_includes found, sink,
            "use_prism=#{use_prism} lost dangerous sink :#{sink} in #{fixture}"
        end
      end
    end

    define_method("test_params_source_reaches_direct_sinks_#{fixture_test_name(fixture, '')}".chomp('_')) do
      source = read_fixture(BOTH_DIR, fixture)

      [[false, @ruby_parser_file_parser], [true, @prism_file_parser]].each do |use_prism, parser|
        ast = alias_process(parser.parse_ruby(source, fixture))

        direct_sink_expectations(fixture).each do |sink_name, line|
          sink = sink_nodes(ast).find { |node| method_name(node) == sink_name && node.line == line }
          refute_nil sink,
            "use_prism=#{use_prism}: expected sink :#{sink_name} at line #{line} in #{fixture}"
          assert contains_node?(sink) { |node| params_source?(node) },
            "use_prism=#{use_prism}: sink :#{sink_name} at line #{line} in #{fixture} " \
            'is no longer linked to a params source after alias resolution'
        end
      end
    end

    define_method("test_forwarding_nodes_preserved_#{fixture_test_name(fixture, '')}".chomp('_')) do
      ruby_parser_ast, prism_ast = parse_each_way(BOTH_DIR, fixture)

      forwarding_expectations(fixture).each do |node_type|
        [ruby_parser_ast, prism_ast].each_with_index do |ast, index|
          assert contains_node?(ast) { |node| node.is_a?(Sexp) && node.node_type == node_type },
            "parser index #{index}: forwarding node :#{node_type} missing in #{fixture}"
        end
      end
    end

    define_method("test_sink_locations_match_#{fixture_test_name(fixture, '')}".chomp('_')) do
      ruby_parser_ast, prism_ast = parse_each_way(BOTH_DIR, fixture)

      ruby_parser_locations = sink_nodes(ruby_parser_ast).map { |node| [method_name(node), node.line, node.file] }
      prism_locations       = sink_nodes(prism_ast).map { |node| [method_name(node), node.line, node.file] }

      assert_equal ruby_parser_locations, prism_locations,
                   "Sink locations differ for #{fixture}"
    end
  end

  # ------------------------------------------------------------------
  # 3. One-sided syntax support is a coverage gap, not a clean result
  # ------------------------------------------------------------------

  # Parse directly with each translation layer, bypassing FileParser's
  # rescue/fallback so a genuine one-sided support gap is visible.
  def direct_parse(layer, source, name)
    case layer
    when :ruby_parser
      RubyParser.new.parse(source, name)
    when :prism
      Prism::Translation::RubyParser.parse(source, name)
    end
  end

  def test_coverage_fixtures_are_exactly_one_sided
    Dir[File.join(COVERAGE_DIR, '*.rb')].each do |coverage_path|
      fixture = File.basename(coverage_path)
      source  = read_fixture(COVERAGE_DIR, fixture)
      results = {}

      [[:ruby_parser], [:prism]].each do |(layer)|
        results[layer] = begin
          direct_parse(layer, source, fixture)
          :parsed
        rescue StandardError, Racc::ParseError
          :failed
        end
      end

      supported = results.select { |_, outcome| outcome == :parsed }.keys
      assert_equal [:ruby_parser], supported,
                   "#{fixture} must be a ruby_parser-only coverage gap " \
                   "(got #{results.inspect}) so the Prism migration scope stays explicit"
    end
  end

  def test_coverage_fixtures_keep_sink_and_source_on_supported_path
    Dir[File.join(COVERAGE_DIR, '*.rb')].each do |coverage_path|
      fixture = File.basename(coverage_path)
      ast = alias_process(direct_parse(
        :ruby_parser, read_fixture(COVERAGE_DIR, fixture), fixture
      ))

      sink = sink_nodes(ast).find { |node| method_name(node) == :eval }
      refute_nil sink, "#{fixture} still contains its eval sink on the supported path"
      assert contains_node?(sink) { |node| params_source?(node) },
             "#{fixture} preserves the params source on its supported parser path"
    end
  end

  def test_prism_translation_rejects_coverage_fixture_before_fallback
    # parse_ruby rescues the Prism failure and falls back to ruby_parser,
    # which still returns an AST. Assert both halves of that contract so a
    # change that swallows the Prism error is caught here.
    Dir[File.join(COVERAGE_DIR, '*.rb')].each do |coverage_path|
      fixture = File.basename(coverage_path)
      source  = read_fixture(COVERAGE_DIR, fixture)

      assert_raises(RubyParser::SyntaxError) do
        direct_parse(:prism, source, fixture)
      end

      assert_kind_of Sexp,
                     @prism_file_parser.parse_ruby(source, fixture),
                     "#{fixture} falls back to ruby_parser instead of being dropped"
    end
  end

  # ------------------------------------------------------------------
  # 4. Parse failure / fallback is fail-closed
  # ------------------------------------------------------------------

  def test_invalid_fixture_fails_under_both_parsers
    source = read_fixture(INVALID_DIR, 'syntax_error.rb')

    [@ruby_parser_file_parser, @prism_file_parser].each do |parser|
      assert_raises(StandardError) do
        parser.parse_ruby(source, 'syntax_error.rb')
      end
    end
  end

  def test_prism_path_falls_back_then_reports_error
    source = read_fixture(INVALID_DIR, 'syntax_error.rb')
    errors = []

    begin
      @prism_file_parser.parse_ruby(source, 'syntax_error.rb')
    rescue StandardError => e
      errors << e
    end

    assert_equal 1, errors.length,
                 'a Prism failure that ruby_parser cannot rescue must be recorded, not swallowed'
    assert_match(/syntax_error\.rb/, errors.first.message)
  end

  def test_failed_parse_never_returns_a_clean_empty_result
    source = read_fixture(INVALID_DIR, 'syntax_error.rb')

    [false, true].each do |use_prism|
      parser = new_file_parser(use_prism)
      refute_nil parser.parse_ruby("User.find(params[:id])\n", 'ok.rb')

      assert_raises(StandardError) { parser.parse_ruby(source, 'syntax_error.rb') }
    end
  end

  # ------------------------------------------------------------------
  # 5. Mutation: removing the source node must be detected
  # ------------------------------------------------------------------

  def test_mutant_missing_params_source_is_detected
    original = read_fixture(BOTH_DIR, 'safe_navigation.rb')
    mutant   = read_fixture(MUTANT_DIR, 'safe_navigation_source_removed.rb')

    [[false, @ruby_parser_file_parser], [true, @prism_file_parser]].each do |use_prism, parser|
      original_ast = alias_process(parser.parse_ruby(original, 'safe_navigation.rb'))
      mutant_ast   = alias_process(parser.parse_ruby(mutant,   'safe_navigation_source_removed.rb'))

      original_sinks = sink_nodes(original_ast)
      mutant_sinks   = sink_nodes(mutant_ast)

      refute_empty original_sinks
      assert_equal original_sinks.map { |node| method_name(node) },
                   mutant_sinks.map { |node| method_name(node) },
                   'sinks remain after mutation; only the source was removed'

      original_sinks.each do |sink|
        assert contains_node?(sink) { |node| params_source?(node) },
               "use_prism=#{use_prism}: original fixture should link sink to params"
      end

      mutant_sinks.each do |sink|
        refute contains_node?(sink) { |node| params_source?(node) },
               "use_prism=#{use_prism}: mutant lost its params source; the harness " \
               'must flag this instead of silently accepting the variant'
      end
    end
  end

  def test_mutation_predicate_distinguishes_source_presence
    # Negative control: prove the source-tracking predicate itself separates
    # the original from the mutant, so a future flattening of source tracking
    # breaks here rather than weakening the mutation test silently.
    original = alias_process(@ruby_parser_file_parser.parse_ruby(
      read_fixture(BOTH_DIR, 'safe_navigation.rb'), 'safe_navigation.rb'
    ))
    mutant = alias_process(@ruby_parser_file_parser.parse_ruby(
      read_fixture(MUTANT_DIR, 'safe_navigation_source_removed.rb'), 'mutant.rb'
    ))

    original_linked = sink_nodes(original).all? { |sink| contains_node?(sink) { |node| params_source?(node) } }
    mutant_linked   = sink_nodes(mutant).all?   { |sink| contains_node?(sink) { |node| params_source?(node) } }

    assert original_linked
    refute mutant_linked
  end

  # ------------------------------------------------------------------
  # 6. End-to-end warning parity on real Rails apps
  # ------------------------------------------------------------------

  # Fingerprints already incorporate warning type, code and source location,
  # so identical fingerprint sets mean no warning appeared, disappeared or
  # moved between parser modes.
  WARNING_TABLES = [:generic_warnings, :template_warnings,
                    :controller_warnings, :model_warnings].freeze

  def warning_signatures(report)
    WARNING_TABLES.flat_map do |table|
      report[table].map do |warning|
        [
          table,
          warning.warning_type,
          warning.line,
          warning.file.relative,
          warning.code&.inspect,
          warning.user_input&.inspect,
          warning.confidence,
          warning.fingerprint
        ].map(&:to_s)
      end
    end.sort
  end

  def scan(app_name, use_prism)
    app_path = File.join(TEST_PATH, 'apps', app_name)
    Brakeman.run(
      app_path: app_path,
      use_prism: use_prism,
      parallel_checks: false,
      run_all_checks: true
    ).report.to_hash
  end

  %w[rails8 rails7 rails6 rails5.2 rails4 rails3.2].each do |app_name|
    define_method("test_end_to_end_warning_parity_#{app_name.gsub('.', '_')}") do
      ruby_parser_report = scan(app_name, false)
      prism_report       = scan(app_name, true)

      assert_equal 0, ruby_parser_report[:errors].length,
                   'ruby_parser baseline scan reported errors'
      assert_equal 0, prism_report[:errors].length,
                   'prism scan reported errors; a fallback failure must not look like a clean scan'

      ruby_parser_signatures = warning_signatures(ruby_parser_report)
      prism_signatures       = warning_signatures(prism_report)

      assert_equal ruby_parser_signatures.length, prism_signatures.length,
                   "warning count changed under Prism for #{app_name}"
      assert_equal ruby_parser_signatures, prism_signatures,
                   "warning type/code/source/location fingerprints differ for #{app_name}"
    end
  end

  # ------------------------------------------------------------------
  # 7. Inline ERB honors the migration switch
  # ------------------------------------------------------------------

  def test_inline_erb_parses_identically_under_both_modes
    template = 'hello <%= params[:name] %> world <%= eval(params[:code]) %>'

    ruby_parser_tracker = BrakemanTester.new_tracker(use_prism: false)
    prism_tracker       = BrakemanTester.new_tracker(use_prism: true)

    ruby_parser_type, ruby_parser_ast =
      Brakeman::TemplateParser.parse_inline_erb(ruby_parser_tracker, template)
    prism_type, prism_ast =
      Brakeman::TemplateParser.parse_inline_erb(prism_tracker, template)

    assert_equal ruby_parser_type, prism_type
    assert_equal ruby_parser_ast, prism_ast
    assert contains_node?(prism_ast) { |node| params_source?(node) },
         'inline ERB must retain the params source through the Prism path'
  end

  def test_inline_erb_default_tracker_keeps_ruby_parser_compat_path
    # A tracker without use_prism must keep the legacy ruby_parser path.
    tracker = BrakemanTester.new_tracker
    _, ast = Brakeman::TemplateParser.parse_inline_erb(
      tracker, '<%= params[:legacy] %>'
    )

    assert_kind_of Sexp, ast
    assert contains_node?(ast) { |node| params_source?(node) }
  end
end

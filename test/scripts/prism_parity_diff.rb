#!/usr/bin/env ruby
# Rerunnable parser-parity diff for the Prism migration.
#
# For every security fixture under test/fixtures/prism_parity it prints:
#   * full-Sexp and node-skeleton (type/line/file) diffs for syntax both
#     parsers support
#   * which parser accepts each one-sided coverage fixture
#   * whether each dangerous sink still links back to a params source
#   * fail-closed behavior for the intentionally invalid fixture
#
# Usage:
#   bundle exec ruby test/scripts/prism_parity_diff.rb
#   TEST_PRISM_FIXTURES=path bundle exec ruby test/scripts/prism_parity_diff.rb
#
# Exit status is non-zero if any supported fixture diverges, so this can gate
# the migration in CI. Parse failures are reported as ERRORS, never as
# "no vulnerability".
$LOAD_PATH.unshift File.expand_path('../../lib', __dir__)

require 'brakeman'
require 'brakeman/scanner'
require 'prism'

Brakeman.set_default_logger({})

FIXTURE_ROOT = ENV['TEST_PRISM_FIXTURES'] ||
  File.expand_path('../fixtures/prism_parity', __dir__)
BOTH_DIR     = File.join(FIXTURE_ROOT, 'both_parsers')
COVERAGE_DIR = File.join(FIXTURE_ROOT, 'coverage')
INVALID_DIR  = File.join(FIXTURE_ROOT, 'invalid')
MUTANT_DIR   = File.join(FIXTURE_ROOT, 'mutants')

DANGEROUS_SINKS = [:eval, :constantize, :query, :where, :find,
                   :public_send, :relay, :render].freeze

def skeleton(sexp)
  entries = []
  walk = lambda do |node|
    return unless node.is_a?(Sexp)
    entries << [node.sexp_type, node.line, node.file]
    node.each { |child| walk.call(child) }
  end
  walk.call(sexp)
  entries
end

def each_call(sexp, &block)
  return unless sexp.is_a?(Sexp)
  block.call(sexp) if %i[call safe_call].include?(sexp.sexp_type)
  sexp.each { |child| each_call(child, &block) }
end

def params_source?(sexp)
  sexp.is_a?(Sexp) &&
    sexp.sexp_type == :call &&
    sexp[1].is_a?(Sexp) &&
    sexp[1].sexp_type == :call &&
    sexp[1][1].nil? &&
    sexp[1][2] == :params
end

def contains?(sexp, &predicate)
  return false unless sexp.is_a?(Sexp)
  return true if predicate.call(sexp)
  sexp.any? { |child| contains?(child, &predicate) }
end

def parse(layer, source, name)
  case layer
  when :ruby_parser then RubyParser.new.parse(source, name)
  when :prism       then Prism::Translation::RubyParser.parse(source, name)
  end
rescue StandardError => e
  { error: "#{e.class}: #{e.message.lines.first.strip}" }
end

def parse_error?(outcome)
  outcome.is_a?(Hash) && outcome.key?(:error)
end

def sink_report(ast)
  alias_ast = Brakeman::AliasProcessor.new.process_safely(ast)
  sinks = []
  each_call(alias_ast) do |call_node|
    next unless DANGEROUS_SINKS.include?(call_node.method)
    sinks << {
      method: call_node.method,
      line: call_node.line,
      file: call_node.file,
      params_linked: contains?(call_node) { |node| params_source?(node) }
    }
  end
  sinks
end

failures = []
puts "Brakeman parser parity diff (#{RUBY_VERSION}, prism #{Prism::VERSION})"
puts "fixtures: #{FIXTURE_ROOT}\n\n"

puts '== Syntax supported by both parsers =='
Dir[File.join(BOTH_DIR, '*.rb')].sort.each do |path|
  name = File.basename(path)
  source = File.read(path)
  ruby_parser_ast = parse(:ruby_parser, source, name)
  prism_ast       = parse(:prism, source, name)

  if parse_error?(ruby_parser_ast) || parse_error?(prism_ast)
    failures << "#{name}: parse error #{ruby_parser_ast.inspect} / #{prism_ast.inspect}"
    puts "  #{name}: ERROR ruby_parser=#{ruby_parser_ast.inspect} prism=#{prism_ast.inspect}"
    next
  end

  sexp_match = ruby_parser_ast == prism_ast
  skeleton_match = skeleton(ruby_parser_ast) == skeleton(prism_ast)
  sink_match = sink_report(ruby_parser_ast) == sink_report(prism_ast)

  failures << "#{name}: sexp diff" unless sexp_match
  failures << "#{name}: skeleton (type/line/file) diff" unless skeleton_match
  failures << "#{name}: sink/source/location diff" unless sink_match

  puts "  #{name}"
  puts "    full_sexp_match=#{sexp_match} skeleton_match=#{skeleton_match} sink_report_match=#{sink_match}"
  sink_report(ruby_parser_ast).each do |sink|
    puts "    sink :#{sink[:method].to_s.ljust(11)} line=#{sink[:line].to_s.ljust(3)} params_linked=#{sink[:params_linked]}"
  end
end

puts "\n== One-sided coverage (gap, not a clean result) =="
Dir[File.join(COVERAGE_DIR, '*.rb')].sort.each do |path|
  name = File.basename(path)
  source = File.read(path)
  results = %i[ruby_parser prism].map do |layer|
    outcome = parse(layer, source, name)
    [layer, parse_error?(outcome) ? :failed : :parsed]
  end.to_h
  one_sided = results.values.uniq.length == 2
  failures << "#{name}: expected exactly one parser to succeed, got #{results.inspect}" unless one_sided
  puts "  #{name.ljust(28)} ruby_parser=#{results[:ruby_parser]} prism=#{results[:prism]}"
end

puts "\n== Fail-closed invalid syntax =="
Dir[File.join(INVALID_DIR, '*.rb')].sort.each do |path|
  name = File.basename(path)
  source = File.read(path)
  %i[ruby_parser prism].each do |layer|
    outcome = parse(layer, source, name)
    ok = parse_error?(outcome)
    failures << "#{name}: #{layer} did not fail on invalid syntax" unless ok
    puts "  #{name.ljust(28)} #{layer}=#{ok ? 'ERROR (fail-closed)' : 'PARSED (unexpected)'}"
  end
end

puts "\n== Mutation (source node removed) =="
Dir[File.join(MUTANT_DIR, '*.rb')].sort.each do |path|
  name = File.basename(path)
  source = File.read(path)
  %i[ruby_parser prism].each do |layer|
    ast = parse(layer, source, name)
    linked = !parse_error?(ast) &&
      sink_report(ast).any? { |sink| sink[:params_linked] }
    failures << "#{name}: #{layer} mutant still links a sink to params (harness blind spot)" if linked
    puts "  #{name.ljust(36)} #{layer}=params_linked_any=#{linked} (expected false)"
  end
end

puts "\n#{failures.empty? ? 'OK: no parser parity differences' : "FAIL: #{failures.length} difference(s)"}"
failures.each { |failure| puts "  - #{failure}" }
exit(failures.empty? ? 0 : 1)

# frozen_string_literal: true

# Compliance evidence generator for CanCanCan rule compression / explicit-deny review.
#
# Ticket-safe by construction: this script never prints business condition VALUES and
# never prints object CONTENT. It only emits:
#   * the action and subject class,
#   * the ability module that sourced each rule and its declaration order,
#   * the structural SHAPE of each rule's conditions (catch-all vs. hash; key names only),
#   * allow/deny BOOLEANS for positional subject tokens (A/B/C),
#   * aggregate counts and a redacted SQL shape (literals replaced by '?').
#
# Run:  ruby compliance/ability_audit.rb
require 'active_record'
require 'sqlite3'

LIB = File.expand_path('../lib', __dir__)
$LOAD_PATH.unshift(LIB) unless $LOAD_PATH.include?(LIB)
require 'cancancan'

ACTION  = :read
SUBJECT = :Article

# ---------------------------------------------------------------------------
# 1. Deterministic in-memory schema (structure only; no business rows shown).
# ---------------------------------------------------------------------------
ActiveRecord::Base.establish_connection(adapter: 'sqlite3', database: ':memory:')
ActiveRecord::Migration.verbose = false
ActiveRecord::Schema.define do
  create_table(:articles) do |t|
    t.boolean :published
    t.boolean :secret
    t.boolean :flagged
    t.integer :category_id
  end
end

class Article < ActiveRecord::Base
end

# ---------------------------------------------------------------------------
# 2. Several ability modules contribute rules to the SAME action (:read).
#    Each declaration is mirrored in a source manifest so the audit can show
#    where every effective rule came from and in what declaration order.
# ---------------------------------------------------------------------------
class CompositeAbility
  include CanCan::Ability

  # Manifest entry: { token:, source:, verb:, action:, subject:, shape:, keys: }
  attr_reader :manifest

  def initialize
    @manifest = []
    @seq = 0
    build_workflow
    build_ownership
    build_restriction
    build_baseline
    build_hold
  end

  private

  def record(source, verb, condition_hash)
    @seq += 1
    token = format('R%d', @seq)
    @manifest << {
      token: token,
      source: source,
      verb: verb,
      action: ACTION,
      subject: SUBJECT,
      shape: condition_hash.empty? ? 'catch_all (no conditions)' : 'hash conditions',
      keys: condition_hash.keys.map(&:to_sym)
    }
    token
  end

  def build_workflow
    h = { published: true }
    record('WorkflowAbility', :can, h)
    can ACTION, Article, h
  end

  def build_ownership
    h = { category_id: 7 }
    record('OwnershipAbility', :can, h)
    can ACTION, Article, h
  end

  def build_restriction
    h = { secret: true }
    record('RestrictionAbility', :cannot, h)
    cannot ACTION, Article, h
  end

  def build_baseline
    h = {}
    record('BaselineAbility', :can, h)
    can ACTION, Article
  end

  def build_hold
    h = { flagged: true }
    record('HoldAbility', :cannot, h)
    cannot ACTION, Article, h
  end
end

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def rule_signature(rule)
  [
    rule.base_behavior ? :can : :cannot,
    rule.actions.map(&:to_sym),
    rule.subjects.map { |s| s.is_a?(Class) ? s.name.to_sym : s.to_sym },
    rule.conditions.is_a?(Hash) ? rule.conditions.keys.map(&:to_sym) : :non_hash
  ]
end

def manifest_signature(entry)
  [entry[:verb], [entry[:action]], [entry[:subject]], entry[:keys].empty? ? [] : entry[:keys]]
end

def token_for(rule, manifest)
  sig = rule_signature(rule)
  hit = manifest.find { |m| manifest_signature(m) == sig }
  hit ? hit[:token] : '?'
end

# Replace any literal that could carry business data, keeping only SQL structure.
def redact(sql)
  sql
    .gsub(/'[^']*'/, '?')
    .gsub(/\b\d+\b/, '?')
    .gsub(/\s+/, ' ')
    .strip
end

def divider(title)
  puts
  puts "==== #{title} ===="
end

# ---------------------------------------------------------------------------
# 2b. Explicit-deny worked example. The same rows are decided twice: once with
#     the full rule set (R5 explicit cannot present) and once on a control
#     ability where R5 is absent. Only booleans are emitted, never row content.
# ---------------------------------------------------------------------------
def explicit_deny_worked_example
  divider('EXPLICIT-DENY WORKED EXAMPLE (R5 present vs. control without R5)')
  Article.delete_all
  rows = {
    'A' => Article.create!(published: true,  secret: false, flagged: false, category_id: 7),
    'B' => Article.create!(published: false, secret: true,  flagged: false, category_id: 1),
    'C' => Article.create!(published: false, secret: false, flagged: true,  category_id: 1)
  }

  full    = CompositeAbility.new
  control = Class.new do
    include CanCan::Ability
    def initialize
      can :read, Article, published: true
      can :read, Article, category_id: 7
      cannot :read, Article, secret: true
      can :read, Article
      # R5 (cannot :read, Article, flagged: true) intentionally omitted
    end
  end.new

  rows.each do |token, record|
    with_deny    = full.can?(ACTION, record)
    without_deny = control.can?(ACTION, record)
    flipped = (!with_deny && without_deny)
    puts "subject_#{token} verdict_with_R5=#{with_deny} verdict_without_R5=#{without_deny} changed_by_explicit_deny=#{flipped}"
  end
  puts 'note=R3 (cannot before the catch-all R4) never decides, because the later R4 catch-all overrides it'
end

# ---------------------------------------------------------------------------
# 3. Audit one compressor setting; the outer block compares ON vs OFF.
# ---------------------------------------------------------------------------
def run_audit(compression_enabled)
  CanCan.with_rules_compressor_enabled(compression_enabled) do
    ability = CompositeAbility.new

    divider("COMPRESSOR #{compression_enabled ? 'ENABLED (default)' : 'DISABLED'}")

    # 3a. Declared rules and their sources, in declaration order.
    divider('Declared rule registry (source + order; values omitted)')
    ability.manifest.each do |m|
      keys = m[:keys].empty? ? '-' : m[:keys].join(',')
      puts format('%s | source=%-18s | %-6s | action=%-5s | subject=%-7s | %-25s | keys=[%s]',
                  m[:token], m[:source], m[:verb].to_s, m[:action].to_s,
                  m[:subject].to_s, m[:shape], keys)
    end
    puts "declared_rule_count=#{ability.manifest.size}"

    # 3b. Actual pure-Ruby evaluation order used by CanCan#can? detection.
    eval_order = ability.send(:relevant_rules, ACTION, Article)
    divider('Pure-Ruby evaluation order (relevant_rules, first-match wins)')
    puts eval_order.map { |r| "#{token_for(r, ability.manifest)}:#{r.base_behavior ? 'can' : 'cannot'}" }.join(' -> ')

    # 3c. Library-native compression evidence, read from the adapter that actually
    #     builds the scope (single source of truth; RulesCompressor is invoked there).
    adapter = ability.model_adapter(Article, ACTION)
    divider('RulesCompressor library counters')
    puts "compressor_enabled=#{CanCan.rules_compressor_enabled}"
    puts "rules_seen_by_adapter=#{eval_order.size}"
    puts "rules_handed_to_scope_query=#{adapter.compressed_rules.size}"
    puts "adapter_rule_tokens=#{adapter.compressed_rules.map { |r| token_for(r, ability.manifest) }.join(' -> ')}"

    # 3d. Persist exactly three positional rows, then decide each in pure Ruby.
    # Only booleans are printed; the row contents themselves never appear.
    Article.delete_all
    subjects = {
      'A' => Article.create!(published: true,  secret: false, flagged: false, category_id: 7),
      'B' => Article.create!(published: false, secret: true,  flagged: false, category_id: 1),
      'C' => Article.create!(published: false, secret: false, flagged: true,  category_id: 1)
    }
    divider('Pure-Ruby can? verdicts (boolean only; row content omitted)')
    ruby_verdicts = {}
    subjects.each do |token, record|
      verdict = ability.can?(ACTION, record)
      ruby_verdicts[token] = verdict
      puts "subject_#{token} can?(:#{ACTION})=#{verdict}"
    end

    # 3e. Real scope query and redacted SQL shape.
    scope = Article.accessible_by(ability, ACTION)
    divider('Real accessible_by scope query')
    puts "redacted_sql=#{redact(scope.to_sql)}"

    # 3f. Cross-check invariant: the SQL scope set must equal the pure-Ruby allow set.
    scoped_records = scope.to_a
    scoped_tokens = subjects.select { |_, r| scoped_records.include?(r) }.keys.sort
    ruby_allowed_tokens = ruby_verdicts.select { |_, v| v }.keys.sort
    ruby_denied_tokens  = ruby_verdicts.reject { |_, v| v }.keys.sort
    sets_match = (scoped_tokens == ruby_allowed_tokens)
    divider('Equivalence invariant (pure Ruby vs. SQL scope)')
    puts "ruby_allowed_tokens=[#{ruby_allowed_tokens.join(',')}]"
    puts "ruby_explicit_denied_tokens=[#{ruby_denied_tokens.join(',')}]"
    puts "scope_row_count=#{scoped_records.size}"
    puts "scope_allowed_tokens=[#{scoped_tokens.join(',')}]"
    puts "scope_set_equals_ruby_allow_set=#{sets_match}"

    {
      compression: compression_enabled,
      declared: ability.manifest.size,
      compressed: adapter.compressed_rules.size,
      ruby_verdicts: ruby_verdicts,
      scope_count: scoped_records.size,
      sets_match: sets_match
    }
  end
end

explicit_deny_worked_example

on_result  = run_audit(true)
off_result = run_audit(false)

divider('ON vs OFF SUMMARY (compression changes rule count, never the decision)')
puts "declared_rules=#{on_result[:declared]} (identical both runs)"
puts "adapter_rules_compressor_ON=#{on_result[:compressed]}"
puts "adapter_rules_compressor_OFF=#{off_result[:compressed]}"
puts "ruby_verdicts_identical=#{on_result[:ruby_verdicts] == off_result[:ruby_verdicts]}"
puts "scope_count_identical=#{on_result[:scope_count] == off_result[:scope_count]}"
puts "scope_invariant_holds_ON=#{on_result[:sets_match]}"
puts "scope_invariant_holds_OFF=#{off_result[:sets_match]}"

# Hard fail (non-zero exit) if any compliance invariant breaks.
failures = []
failures << 'ruby verdicts differ between compressor settings' unless on_result[:ruby_verdicts] == off_result[:ruby_verdicts]
failures << 'scope counts differ between compressor settings'     unless on_result[:scope_count] == off_result[:scope_count]
failures << 'scope/ruby invariant broken (ON)'  unless on_result[:sets_match]
failures << 'scope/ruby invariant broken (OFF)' unless off_result[:sets_match]
unless failures.empty?
  warn "AUDIT FAILED: #{failures.join('; ')}"
  exit 1
end
puts 'result=PASS (effective authorization identical; only the stored rule count changed)'

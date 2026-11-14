# frozen_string_literal: true

# Audit pipeline demo: emit a redacted YAML copy of a configuration without
# losing graph semantics (aliases, merge keys, cycles).  Run with:
#
#   ruby -Ilib examples/audit_redaction_demo.rb

require 'psych'
require_relative '../lib/psych/redactor'

CONFIG = <<~YAML
  db: &db
    host: db.internal.example.com
    port: 5432
    password: hunter2-super-secret
    api_token: shared-api-token
  services:
    primary: *db
  staging:
    <<: *db
    password: staging-explicit-pw
  pool: &pool
    - member-secret-a
    - member-secret-b
  pool_alias: *pool
  topology: &topo
    name: root-node
    secret_node: topology-secret
    self_ref: *topo
    parent: *topo
  ring: &ring
    label: ring-secret-label
    loopback: *ring
  gateway:
    headers:
      X-Api-Key: header-value-not-secret
    timeout: 30
YAML

SECRETS = [
  ["db", "password"],
  ["db", "api_token"],
  ["staging", "password"],
  ["pool"],
  ["topology", "secret_node"],
  ["ring"],
  ["gateway", "headers", "X-Api-Key", Psych::Redactor::KEY]
].freeze

def reachable_values(object, seen = {}.compare_by_identity, output = [])
  return output if seen.key?(object)
  seen[object] = true

  case object
  when Hash
    object.each do |key, value|
      output << key unless key.is_a?(Hash) || key.is_a?(Array)
      reachable_values(value, seen, output)
    end
  when Array
    object.each { |item| reachable_values(item, seen, output) }
  else
    output << object
  end
  output
end

def section(title)
  puts "\n=== #{title} ==="
end

original_tree = Psych.parse(CONFIG)
result = Psych::Redactor.redact(original_tree, paths: SECRETS)

section "Redacted YAML emitted for the audit log"
puts result.yaml

section "Additional paths hidden because of sharing (not named by the caller)"
result.additional_paths.each do |entry|
  puts "- #{Psych::Redactor.format_path(entry.path)} (#{entry.reason}/#{entry.role})"
end

section "All recorded hidden paths (requested first, then sharing-derived)"
result.hidden_paths.each { |entry| puts "- #{entry}" }

reparsed = Psych.unsafe_load(result.yaml)
all_values = reachable_values(reparsed).grep(String)

forbidden_secrets = %w[
  hunter2-super-secret
  shared-api-token
  staging-explicit-pw
  member-secret-a
  member-secret-b
  topology-secret
  ring-secret-label
  X-Api-Key
]

section "Proof 1: re-parse output and walk every reachable value for leaks"
forbidden_secrets.each do |secret|
  leaked = all_values.include?(secret) || result.yaml.include?(secret)
  puts "secret #{secret.inspect} present? #{leaked} (expected false)"
  raise "LEAK: #{secret} survived redaction" if leaked
end
puts "no sensitive value or sensitive key is reachable or present in raw text"

section "Proof 2: unaffected configuration content is preserved"
preserved = {
  "db.host"                 => reparsed["db"]["host"],
  "db.port"                 => reparsed["db"]["port"],
  "services.host(alias)"    => reparsed["services"]["primary"]["host"],
  "staging.host(merge)"     => reparsed["staging"]["host"],
  "staging.port(merge)"     => reparsed["staging"]["port"],
  "topology.name"           => reparsed["topology"]["name"],
  "redacted key's value"    => reparsed["gateway"]["headers"].values.first,
  "gateway.timeout"         => reparsed["gateway"]["timeout"]
}
preserved.each { |label, value| puts "- #{label}: #{value.inspect}" }
raise "merge content lost" unless reparsed["staging"]["port"] == 5432
raise "alias content lost" unless reparsed["services"]["primary"]["host"] == "db.internal.example.com"
raise "paired value lost" unless reparsed["gateway"]["headers"].values.first == "header-value-not-secret"
raise "cycle broken" unless reparsed["topology"]["parent"].equal?(reparsed["topology"])
raise "cycle node content leaked" unless reparsed["topology"]["secret_node"] == "[REDACTED]"
raise "non-secret cycle field lost" unless reparsed["topology"]["name"] == "root-node"

section "Proof 3: explicit merge override hides the value; merged-only field is hidden via merge"
raise "explicit override not redacted" unless reparsed["staging"]["password"] == "[REDACTED]"
raise "merged-only secret not redacted" unless reparsed["staging"]["api_token"] == "[REDACTED]"
merge_entry = result.hidden_paths.find { |entry| entry.reason == :merge }
puts "merge-derived hidden entry: #{merge_entry}"
cycle_entry = result.hidden_paths.find { |entry| entry.reason == :cycle }
puts "cycle back-edge hidden entry: #{cycle_entry}"
raise "missing merge report" unless merge_entry
raise "missing cycle report" unless cycle_entry

section "Proof 4: the live object used by the business is untouched"
roundtrip = original_tree.to_ruby
raise "original mutated" if roundtrip["db"]["password"] != "hunter2-super-secret"
raise "original mutated" if roundtrip["staging"]["password"] != "staging-explicit-pw"
raise "original aliasing changed" unless roundtrip["services"]["primary"].equal?(roundtrip["db"])
raise "original pool mutated" unless roundtrip["pool"] == %w[member-secret-a member-secret-b]
raise "original topology mutated" unless roundtrip["topology"]["secret_node"] == "topology-secret"
raise "original ring mutated" unless roundtrip["ring"]["label"] == "ring-secret-label"
puts "original parsed tree still resolves every secret and keeps its aliases"
puts "\nOK"

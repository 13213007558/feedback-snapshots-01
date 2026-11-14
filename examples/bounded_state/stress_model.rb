#!/usr/bin/env ruby
# frozen_string_literal: true

# Dependency-free model comparing bounded-state throttling strategies under
# account rotation. It replays one identical workload through each policy and
# reports live state, evictions, legitimate false blocks, and attack admissions.
#
# Run:
#   ruby examples/bounded_state/stress_model.rb
#   ruby examples/bounded_state/stress_model.rb --attack 20000 --capacity 4096
#   ruby examples/bounded_state/stress_model.rb --help
#
# The model does not call an account-existence service. The "known-account
# shortcut" row models the forbidden free-lookup design only as a reference for
# its state growth and is not a recommended strategy.

require 'digest'
require 'optparse'

Options = Struct.new(
  :legit, :accounts, :attack, :attack_ips, :capacity,
  :buckets, :depth, :tenant_budget, :ip_slot_budget, :ip_slots,
  :account_limit, :attack_repeats, :seed
)

options = Options.new(
  legit: 600, accounts: 120, attack: 12_000, attack_ips: 250, capacity: 50_000,
  buckets: 4096, depth: 3, tenant_budget: 3000, ip_slot_budget: 30, ip_slots: 512,
  account_limit: 5, attack_repeats: 1, seed: 7
)

OptionParser.new do |opts|
  opts.banner = 'Usage: ruby examples/bounded_state/stress_model.rb [options]'
  opts.on('--legit N', Integer) { |v| options.legit = v }
  opts.on('--accounts N', Integer) { |v| options.accounts = v }
  opts.on('--attack N', Integer) { |v| options.attack = v }
  opts.on('--attack-ips N', Integer) { |v| options.attack_ips = v }
  opts.on('--capacity N', Integer) { |v| options.capacity = v }
  opts.on('--buckets N', Integer) { |v| options.buckets = v }
  opts.on('--depth N', Integer) { |v| options.depth = v }
  opts.on('--tenant-budget N', Integer) { |v| options.tenant_budget = v }
  opts.on('--ip-slot-budget N', Integer) { |v| options.ip_slot_budget = v }
  opts.on('--ip-slots N', Integer) { |v| options.ip_slots = v }
  opts.on('--account-limit N', Integer) { |v| options.account_limit = v }
  opts.on('--attack-repeats N', Integer) { |v| options.attack_repeats = v }
  opts.on('--seed N', Integer) { |v| options.seed = v }
end.parse!

Request = Struct.new(:account, :ip, :tenant, :legit)

def hash_to_slot(value, salt, slots)
  Digest::SHA256.hexdigest("#{salt}\0#{value}").to_i(16) % slots
end

# Capacity-limited key/value store with LRU eviction. This models a real
# memcached/Redis cache under maxmemory. Counters are independent because every
# key carries its own TTL in rack-attack.
class LruStore
  attr_reader :peak_keys, :evictions

  def initialize(capacity)
    @capacity = capacity
    @data = {}
    @peak_keys = 0
    @evictions = 0
  end

  def keys
    @data.size
  end

  def increment(key, amount = 1)
    value = @data.delete(key)
    if value.nil?
      evict_one while @data.size >= @capacity
      value = 0
    end
    @data[key] = value + amount
    @peak_keys = [@peak_keys, @data.size].max
    @data[key]
  end

  def read(key)
    value = @data.delete(key)
    @data[key] = value if value
    value
  end

  def reset!
    @data.clear
  end

  private

  def evict_one
    return if @data.empty?

    @data.delete(@data.keys.first)
    @evictions += 1
  end
end

def build_workload(options)
  legit = options.legit.times.map do |i|
    Request.new(
      account: "user-#{i % options.accounts}@example.com",
      ip: "10.0.#{i % 200}.#{(i / 200) % 200}",
      tenant: 'tenant-a',
      legit: true
    )
  end

  attack = options.attack.times.map do |i|
    Request.new(
      account: "evil-#{i / options.attack_repeats}@example.com",
      ip: "203.0.#{(i % options.attack_ips) / 250}.#{i % 250}",
      tenant: 'tenant-a',
      legit: false
    )
  end

  (legit + attack).shuffle(random: Random.new(options.seed + 1))
end

class Policy
  attr_reader :store

  def initialize(options)
    @options = options
    @store = LruStore.new(options.capacity)
  end

  def keys
    @store.keys
  end

  def peak_keys
    @store.peak_keys
  end

  def evictions
    @store.evictions
  end

  def reset!
    @store.reset!
  end

  private

  def account_key(request)
    "account:#{request.account}"
  end

  def increment_account(request)
    @store.increment(account_key(request)) > @options.account_limit
  end
end

# Exact per-account counting. Correct for repeated attempts on a known account,
# but every unseen account creates a key.
class ExactPerAccount < Policy
  NAME = 'exact per-account'

  def allow?(request)
    !increment_account(request)
  end
end

# Models the forbidden "account lookup is free" design. Known accounts skip the
# counter; unknown accounts still create one key each. Included only as a
# reference row.
class ExactKnownAccountShortcut < Policy
  NAME = 'exact + known-account skip'

  def allow?(request)
    return true if request.account.start_with?('user-')

    !increment_account(request)
  end
end

# Exact per-account plus one shared tenant request budget. The budget bounds
# admitted account keys but lets a large attack consume the tenant's budget.
class ExactPlusTenantBudget < Policy
  NAME = 'exact + tenant budget'

  def allow?(request)
    tenant_count = @store.increment('budget:tenant')
    return false if tenant_count > @options.tenant_budget

    !increment_account(request)
  end
end

# Layered budgets on trusted dimensions, then exact per-account counting only
# for admitted requests. IP is hashed into a fixed number of slots so IP
# rotation cannot grow state. Slot collisions share a budget and can false-block.
class LayeredGate < Policy
  NAME = 'layered gate (IP+tenant, exact)'

  def allow?(request)
    ip_slot = hash_to_slot(request.ip, 'ip-slot', @options.ip_slots)
    ip_count = @store.increment("budget:ip:#{ip_slot}")
    return false if ip_count > @options.ip_slot_budget

    tenant_count = @store.increment('budget:tenant')
    return false if tenant_count > @options.tenant_budget

    !increment_account(request)
  end
end

# Fixed count-min sketch for the per-account limit. The account is never a key.
class CountMinSketch < Policy
  NAME = 'count-min sketch'

  def allow?(request)
    estimate = nil
    @options.depth.times do |row|
      bucket = hash_to_slot("#{row}\0#{request.account}", 'sketch', @options.buckets)
      count = @store.increment("sketch:#{row}:#{bucket}")
      estimate = estimate.nil? ? count : [estimate, count].min
    end
    estimate <= @options.account_limit
  end
end

# Tenant admission budget followed by a count-min sketch. Budget-first means
# traffic already over budget does not pollute the sketch.
class SketchPlusTenantBudget < Policy
  NAME = 'sketch + tenant budget'

  def allow?(request)
    tenant_count = @store.increment('budget:tenant')
    return false if tenant_count > @options.tenant_budget

    estimate = nil
    @options.depth.times do |row|
      bucket = hash_to_slot("#{row}\0#{request.account}", 'sketch', @options.buckets)
      count = @store.increment("sketch:#{row}:#{bucket}")
      estimate = estimate.nil? ? count : [estimate, count].min
    end
    estimate <= @options.account_limit
  end
end

def observe(policy, requests)
  legit_blocked = 0
  attack_allowed = 0
  legit_total = 0
  attack_total = 0

  requests.each do |request|
    allowed = policy.allow?(request)
    if request.legit
      legit_total += 1
      legit_blocked += 1 unless allowed
    else
      attack_total += 1
      attack_allowed += 1 if allowed
    end
  end

  {
    name: policy.class::NAME,
    keys: policy.keys,
    peak_keys: policy.peak_keys,
    evictions: policy.evictions,
    legit_blocked: legit_blocked,
    legit_total: legit_total,
    attack_allowed: attack_allowed,
    attack_total: attack_total
  }
end

workload = build_workload(options)
policy_classes = [
  ExactPerAccount,
  ExactKnownAccountShortcut,
  ExactPlusTenantBudget,
  LayeredGate,
  CountMinSketch,
  SketchPlusTenantBudget
]

results = policy_classes.map { |klass| observe(klass.new(options), workload) }

# Recovery: at the next period boundary counters expire. Replay the same
# legitimate traffic after a reset and check whether normal users recover.
recovery = policy_classes.map do |klass|
  policy = klass.new(options)
  next if %w[exact + known-account skip].include?(klass::NAME)

  policy.reset!
  blocked = 0
  options.legit.times do |i|
    request = Request.new(
      "user-#{i % options.accounts}@example.com",
      "10.0.#{i % 200}.#{(i / 200) % 200}",
      'tenant-a',
      true
    )
    blocked += 1 unless policy.allow?(request)
  end
  [klass::NAME, blocked]
end.to_h

distinct_attack_accounts = (options.attack + options.attack_repeats - 1) / options.attack_repeats
puts "Workload: #{options.legit} legitimate (#{options.accounts} accounts) and " \
     "#{options.attack} attack requests over #{distinct_attack_accounts} accounts " \
     "(#{options.attack_repeats} request(s) per account), #{options.attack_ips} IPs."
puts "Limits: account #{options.account_limit}, tenant budget #{options.tenant_budget}, " \
     "IP slot budget #{options.ip_slot_budget} over #{options.ip_slots} slots, " \
     "sketch #{options.buckets}x#{options.depth}, cache capacity #{options.capacity} keys."
puts

header = format(
  '%-30s %8s %8s %10s %15s %15s',
  'strategy', 'keys', 'peak', 'evictions', 'legit blocked', 'attack allowed'
)
puts header
puts '-' * header.length
results.each do |row|
  puts format(
    '%-30s %8d %8d %10d %6d / %-6d %6d / %-6d',
    row[:name], row[:keys], row[:peak_keys], row[:evictions],
    row[:legit_blocked], row[:legit_total], row[:attack_allowed], row[:attack_total]
  )
end

puts
puts 'Recovery after reset (legitimate requests blocked in a clean window):'
recovery.each { |name, blocked| puts format('  %-30s %d', name, blocked) }
puts
puts 'Reading the rows:'
puts '- exact per-account: perfect for repeated attempts, but state grows one key per unseen account.'
puts '- exact + tenant budget: state bounded by admitted accounts; attack burns the shared budget.'
puts '- layered gate: bounds IP-rotating state and keeps exact per-account checks for admitted traffic.'
puts '- count-min sketch: state fixed by buckets*depth, but one-shot rotated accounts are not blocked;'
puts '  collisions become false blocks as load approaches the bucket count.'
puts '- sketch + tenant budget: the budget stops rotation; the sketch only applies to admitted traffic.'

# Optional invariant check for CI: every policy must be deterministic and the
# bounded policies must never exceed their configured capacity.
if ENV['BOUNDED_STATE_SELFTEST']
  exact = ExactPerAccount.new(options)
  exact_capacity_ok = results.select { |row| row[:name] == ExactPerAccount::NAME }
                             .all? { |row| row[:keys] <= options.capacity }
  gate_keys = results.select { |row| row[:name] == LayeredGate::NAME }
                     .map { |row| row[:keys] }
  sketch_keys = results.select { |row| row[:name] == CountMinSketch::NAME }
                       .map { |row| row[:keys] }
  ok = exact_capacity_ok && gate_keys.all? { |keys| keys <= options.capacity } &&
       sketch_keys.all? { |keys| keys <= options.capacity } &&
       ExactPerAccount.new(options).respond_to?(:keys)
  abort 'bounded-state selftest failed' unless ok

  puts
  puts 'selftest: ok'
end

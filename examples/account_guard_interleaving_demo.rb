# frozen_string_literal: true
$stdout.sync = true

# Deterministic demonstration of response-based credential-stuffing protection.
#
# Run with:
#   ruby -Ilib examples/account_guard_interleaving_demo.rb
#
# It shows, without random timing or sleeps:
#   1. when a ban starts (the request that reaches maxretry failures),
#   2. which failures a later successful login is allowed to offset,
#   3. that a success finishing after a newer failure cannot erase it,
#   4. that a banned request never reaches the login handler,
#   5. that entry-time IP throttling still blocks before the application.
#
# Each request runs on its own thread and blocks inside the login handler on a
# gate until the script releases it, so response ordering is fully controlled.

require 'rack'
require 'active_support'
require 'active_support/cache'
require 'rack/attack'

ACCOUNT = 'victim@example.com'
MAXRETRY = 3
FINDTIME = 60
BANTIME = 300

# Coordinates in-flight requests deterministically (no sleeps, no timing luck).
class Coordinator
  def initialize
    @mutex = Mutex.new
    @cond = ConditionVariable.new
    @inside = []
    @gates = Hash.new { |hash, key| hash[key] = Queue.new }
  end

  def gate_for(id)
    @gates[id]
  end

  def entered(id)
    @mutex.synchronize do
      @inside << id
      @cond.broadcast
    end
  end

  def wait_until_inside(id, timeout = 2)
    deadline = Time.now + timeout
    @mutex.synchronize do
      @cond.wait(@mutex, timeout) until @inside.include?(id) || Time.now >= deadline
    end
  end

  def inside?(id)
    @mutex.synchronize { @inside.include?(id) }
  end
end

class LoginHandler
  attr_reader :calls

  def initialize(coordinator)
    @coordinator = coordinator
    @calls = []
  end

  def call(env)
    request = Rack::Attack::Request.new(env)
    id = request.env['login.id']
    @calls << id
    @coordinator.entered(id)
    @coordinator.gate_for(id).pop # block until the script releases this request

    status = request.env['login.outcome'] == :failure ? 401 : 200
    [status, { 'content-type' => 'text/plain' }, [status == 401 ? 'Unauthorized' : 'Welcome']]
  end
end

Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new

# Basic IP throttling remains an entry-time check (before the app is called).
Rack::Attack.throttle('logins/ip', limit: 100, period: 60) { |req| req.post? && req.path == '/login' && req.ip }

# Account protection settles from the downstream response. Its classifier only
# sees method/path/ip/agent + status/headers: never the password or body.
Rack::Attack.account_guard(
  'logins/account',
  maxretry: MAXRETRY,
  findtime: FINDTIME,
  bantime: BANTIME,
  classifier: ->(result) { result.status == 401 ? :failure : :success }
) do |request|
  request.post? && request.path == '/login' ? request.params['email'].to_s.downcase : nil
end

coordinator = Coordinator.new
handler = LoginHandler.new(coordinator)
stack = Rack::Attack.new(handler)
registry = Rack::Attack.account_guards['logins/account'].registry

def request_env(id, outcome, ip = '10.0.0.7')
  Rack::MockRequest.env_for(
    '/login',
    method: 'POST',
    input: "email=#{ACCOUNT}&password=#{id}-plaintext-secret",
    'REMOTE_ADDR' => ip,
    'login.id' => id,
    'login.outcome' => outcome
  )
end

def finish(response)
  status, _headers, body = response
  body.close if body.respond_to?(:close)
  status
end

# Starts a request and blocks the main script until the request is parked
# inside the login handler. Returns [thread, entered?]; a banned request is
# rejected up front and never enters, so `entered?` comes back false.
def start_request(stack, coordinator, id, outcome, ip = '10.0.0.7')
  thread = Thread.new { stack.call(request_env(id, outcome, ip)) }
  coordinator.wait_until_inside(id)
  [thread, coordinator.inside?(id)]
end

def release(coordinator, thread, id)
  coordinator.gate_for(id) << true
  finish(thread.value)
end

def section(title)
  puts
  puts "== #{title} =="
end

def line(text)
  puts "  #{text}"
end

section 'Scenario A: the ban starts on the maxretry failure; later requests skip the handler'
[:f1, :f2, :f3].each do |id|
  thread, entered = start_request(stack, coordinator, id, :failure)
  raise "request #{id} should have entered the handler" unless entered

  line "#{id} is inside the handler; releasing it as a failure"
  status = release(coordinator, thread, id)
  line "#{id} -> client #{status}, failures=#{registry.failure_count(ACCOUNT)}, banned? #{registry.banned?(ACCOUNT)}"
end

# Banned request: it must be rejected without ever entering the handler.
blocked_thread = Thread.new { stack.call(request_env(:blocked, :success)) }
blocked_status = finish(blocked_thread.value)
line "banned request :blocked -> client #{blocked_status} (expected 429)"
line "reached handler? #{handler.calls.include?(:blocked)} (expected false)"
line "handler call log: #{handler.calls.inspect}"

section 'Scenario B: interleaving - an older success cannot erase a newer failure'
registry.reset!
f1, = start_request(stack, coordinator, :f1, :failure)
release(coordinator, f1, :f1)
line "f1 finishes first: failures=#{registry.failure_count(ACCOUNT)}"

s2, = start_request(stack, coordinator, :s2, :success)
line "s2 (success) is parked inside the handler"
f3, = start_request(stack, coordinator, :f3, :failure)
line "f3 (failure) enters the handler while s2 is still running"

line "releasing f3 first..."
f3_status = release(coordinator, f3, :f3)
line "f3 -> client #{f3_status}, failures=#{registry.failure_count(ACCOUNT)}, banned? #{registry.banned?(ACCOUNT)}"

line "releasing s2 afterwards..."
s2_status = release(coordinator, s2, :s2)
line "s2 -> client #{s2_status}, failures=#{registry.failure_count(ACCOUNT)} (f3 must survive)"
line "banned? #{registry.banned?(ACCOUNT)}"

section 'Scenario C: a clean success offsets only failures that predated it'
registry.reset!
f_one, = start_request(stack, coordinator, :f_one, :failure)
release(coordinator, f_one, :f_one)
line "one failure recorded: failures=#{registry.failure_count(ACCOUNT)}"
ok, = start_request(stack, coordinator, :ok, :success)
release(coordinator, ok, :ok)
line "success clears it: failures=#{registry.failure_count(ACCOUNT)}, banned? #{registry.banned?(ACCOUNT)}"

section 'Checks'
registry.reset!
3.times do |i|
  thread, entered = start_request(stack, coordinator, "b#{i}".to_sym, :failure)
  raise "request b#{i} should have entered the handler" unless entered

  release(coordinator, thread, "b#{i}".to_sym)
end
banned_now = registry.banned?(ACCOUNT)
_after_thread, after_entered = start_request(stack, coordinator, :after_ban, :success)
banned_status = finish(_after_thread.value)
reached_handler = after_entered || handler.calls.include?(:after_ban)
checks = {
  'account banned once maxretry failures recorded' => banned_now == true,
  'banned request returns 429' => banned_status == 429,
  'banned request never reached the login handler' => reached_handler == false
}
# Concrete re-check of the interleaving rule on a fresh registry.
registry.reset!
f, = start_request(stack, coordinator, :chk_f, :failure)
release(coordinator, f, :chk_f)
s, = start_request(stack, coordinator, :chk_s, :success)
g, = start_request(stack, coordinator, :chk_g, :failure)
release(coordinator, g, :chk_g)
release(coordinator, s, :chk_s)
checks['interleaving preserved the newer failure'] = registry.failure_count(ACCOUNT) == 1
checks.each { |name, ok| puts "  [#{ok ? 'PASS' : 'FAIL'}] #{name}" }
raise 'demo assertions failed' unless checks.values.all?

section 'Scenario D: entry-time IP throttle rejects before the handler runs'
Rack::Attack.throttle('demo/ip', limit: 1, period: 60) do |req|
  req.post? && req.path == '/login' && req.ip == '10.0.0.9' && req.ip
end
direct_hits = []
direct_app = lambda do |env|
  request = Rack::Attack::Request.new(env)
  direct_hits << request.env['login.id']
  [200, { 'content-type' => 'text/plain' }, ['ok']]
end
direct_stack = Rack::Attack.new(direct_app)
ip_status = finish(direct_stack.call(request_env(:ip_one, :success, '10.0.0.9')))
line "first request from 10.0.0.9: status #{ip_status}, handler reached? #{direct_hits.include?(:ip_one)}"
second_status = finish(direct_stack.call(request_env(:ip_two, :success, '10.0.0.9')))
line "second request from same IP: status #{second_status} (expected 429)"
line "handler reached? #{direct_hits.include?(:ip_two)} (expected false)"

puts
puts 'All demo assertions passed.'

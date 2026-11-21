# frozen_string_literal: true

# Runnable without Rails, a database, Redis, or any network access:
#
#   ruby -Ilib examples/delegated_approval.rb
#
# A manager delegates approval rights to a colleague until `expires_at`.
# The delegate must lose access at that instant, including for policies that
# were already instantiated during the same request.

require "pundit"
require "active_support"
require "active_support/core_ext/numeric/time"

T0 = Time.utc(2026, 11, 21, 12, 0, 0)

# A tiny request clock. Production code should inject Time.current (or similar)
# so authorization decisions have one explicit time source.
class Clock
  attr_accessor :now

  def initialize(now)
    @now = now
  end
end

class User
  attr_reader :name

  def initialize(name)
    @name = name
  end
end

class Approval
  attr_reader :id, :owner
  attr_accessor :status

  def initialize(id:, owner:, status: :pending)
    @id = id
    @owner = owner
    @status = status
  end

  def self.all
    ApprovalRelation.new(@all ||= [])
  end

  def self.reset!(rows)
    @all = rows
  end
end

# Approval rows are queried in memory, but deliberately return the same
# relation-shaped object an ActiveRecord scope would.
class ApprovalRelation
  include Enumerable

  def initialize(rows)
    @rows = rows
  end

  # ActiveRecord relations expose the model name; stand in for that here so
  # Pundit resolves ApprovalPolicy::Scope instead of ApprovalRelationPolicy.
  def policy_class
    ApprovalPolicy
  end

  def where(**conditions)
    ApprovalRelation.new(@rows.select do |row|
      conditions.all? { |name, expected| row.public_send(name) == expected }
    end)
  end

  def each(&block)
    @rows.each(&block)
  end

  def to_a
    @rows.dup
  end

  def inspect
    "ApprovalRelation(#{@rows.map(&:id).inspect})"
  end
end

class Delegations
  Entry = Struct.new(:manager, :delegate, :expires_at, keyword_init: true)

  def initialize
    @entries = []
  end

  def add(manager:, delegate:, expires_at:)
    @entries << Entry.new(manager:, delegate:, expires_at:)
  end

  # This is the security boundary. It is evaluated on every policy call rather
  # than copied into a policy at construction time.
  def active?(manager:, delegate:, now:)
    @entries.any? do |entry|
      entry.manager.equal?(manager) &&
        entry.delegate.equal?(delegate) &&
        now < entry.expires_at
    end
  end
end

class ApprovalPolicy
  attr_reader :user, :record

  def initialize(user, record)
    @user = user
    @record = record
  end

  def approve?
    user.actor.equal?(record.owner) ||
      user.delegations.active?(manager: record.owner, delegate: user.actor, now: user.clock.now)
  end

  # Scope membership is intentionally independent of the delegation clock.
  # `approve?` is the per-record gate; the scope answers "which rows may this
  # user see at all?" and must not bake in an expiring decision.
  class Scope
    def initialize(_user, scope)
      @scope = scope
    end

    def resolve
      @scope
    end
  end
end

# A request-scoped object passed through `pundit_user`. Pundit policies receive
# only (user, record), so this is how the delegation repository and clock reach
# the policy without global state.
class ActorContext
  attr_reader :actor, :delegations, :clock

  def initialize(actor:, delegations:, clock:)
    @actor = actor
    @delegations = delegations
    @clock = clock
  end
end

class ApprovalController
  include Pundit::Authorization

  attr_reader :action_name

  def initialize(actor_context, action_name: "show")
    @actor_context = actor_context
    @action_name = action_name
  end

  # The documented Pundit user entry point. `pundit` memoizes a Context around
  # this object for the duration of the request.
  def pundit_user
    @actor_context
  end

  public(*Pundit::Authorization.protected_instance_methods)
end

# Deliberately wrong for contrast: it caches the *answer* (`true`) rather than
# evaluating the delegation on each call.
class NaiveDecisionCache
  def initialize
    @answer = nil
  end

  def allow?(approval:, user:, delegations:, now:)
    @answer ||= user.equal?(approval.owner) ||
      delegations.active?(manager: approval.owner, delegate: user, now: now)
  end
end

# --- Demo -------------------------------------------------------------------

def attempt_approval(controller, approval)
  controller.authorize(approval, :approve?)
  "allowed"
rescue Pundit::NotAuthorizedError
  "denied"
end

manager = User.new("manager")
colleague = User.new("colleague")
approvals = [
  Approval.new(id: 101, owner: manager),
  Approval.new(id: 102, owner: manager)
]
Approval.reset!(approvals)

delegations = Delegations.new
delegations.add(manager: manager, delegate: colleague, expires_at: T0 + 30.minutes)

clock = Clock.new(T0)
actor = ActorContext.new(actor: colleague, delegations: delegations, clock: clock)
controller = ApprovalController.new(actor)

before = approvals.map { |approval| attempt_approval(controller, approval) }
puts "T0: delegation active"
puts "  approve 101: #{before[0]}"
puts "  approve 102: #{before[1]}"

# Keep the very same controller/request/context and expire the delegation.
# This models a long request, streaming response, or job that crosses the
# boundary; it also proves the cached policy instance is not the source of
# truth.
clock.now = T0 + 31.minutes
after = approvals.map { |approval| attempt_approval(controller, approval) }
puts "T0 + 31m: delegation expired in the same request"
puts "  approve 101: #{after[0]}"
puts "  approve 102: #{after[1]}"
puts "  distinct cached policy instance per record: " \
  "#{!controller.policy(approvals[0]).equal?(controller.policy(approvals[1]))}"
puts "  cached policy instance reuse for 101: " \
  "#{controller.policy(approvals[0]).equal?(controller.policy(approvals[0]))}"

# A scope is a visibility result, not an allow decision. The controller helper
# memoizes it with `policy_scopes[scope] ||= ...`; using it as the approval
# gate would freeze the pre-expiry answer for the rest of the request.
scope_input = Approval.all
scope_before = controller.policy_scope(scope_input)
policy_scope_before = controller.policy_scopes[scope_input]
clock.now = T0 + 60.minutes
scope_after = controller.policy_scope(scope_input)
puts "scope memoized across the expiry boundary: " \
  "#{scope_before.equal?(scope_after)} (cache key: #{policy_scope_before.inspect})"
puts "scope contents: #{scope_after.inspect}"

# Why caching "allowed = true" is not enough: the first approval poisons the
# second read after expiry, even though they are different objects.
naive = NaiveDecisionCache.new
clock.now = T0
naive_before = naive.allow?(approval: approvals[0], user: colleague, delegations: delegations, now: clock.now)
clock.now = T0 + 31.minutes
naive_after = naive.allow?(approval: approvals[1], user: colleague, delegations: delegations, now: clock.now)
puts "naive cached decision at T0 (101): #{naive_before}"
puts "naive cached decision at T0+31m (102): #{naive_after}"

raise "expected both approvals at T0" unless before == %w[allowed allowed]
raise "expected both approvals denied after expiry" unless after == %w[denied denied]
raise "expected scope memoization" unless scope_before.equal?(scope_after)
raise "naive cache should demonstrate the bug" unless naive_before && naive_after

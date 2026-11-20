# encoding: utf-8
# frozen_string_literal: true

# Fixture strategies for spec/warden/strategy_chain_spec.rb.
# Every strategy records each entry into authenticate! in
# env['warden.spec.chain'] so the specs can assert how many times the
# business method was entered and in which order.
module WardenChainSpec
  USER = "Chain User".freeze unless const_defined?(:USER)

  def self.record(env, name)
    (env['warden.spec.chain'] ||= []) << name
  end
end

# Skips authentication: performs but never sets a result, so the chain
# always cascades to the next strategy.
Warden::Strategies.add(:chain_skip) do
  def authenticate!
    WardenChainSpec.record(env, :chain_skip)
    pass
  end
end

# Explicitly denies the request with a continuable failure: fail does not
# halt, so the chain cascades to the next strategy.
Warden::Strategies.add(:chain_soft_deny) do
  def authenticate!
    WardenChainSpec.record(env, :chain_soft_deny)
    fail("soft deny")
  end
end

# Explicitly denies the request with a halting failure: fail! halts the
# chain, so no later strategy is attempted.
Warden::Strategies.add(:chain_hard_deny) do
  def authenticate!
    WardenChainSpec.record(env, :chain_hard_deny)
    fail!("hard deny")
  end
end

# Recognizes a valid user: success! halts the chain and sets the user.
Warden::Strategies.add(:chain_valid_user) do
  def authenticate!
    WardenChainSpec.record(env, :chain_valid_user)
    success!(WardenChainSpec::USER)
  end
end

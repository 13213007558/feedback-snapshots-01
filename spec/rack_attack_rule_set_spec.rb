# frozen_string_literal: true

require_relative "spec_helper"

describe Rack::Attack::RuleSet do
  before do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  describe "build and validation" do
    it "builds a valid rule set with a derived counter namespace" do
      rule_set = Rack::Attack.build_rule_set(version: "v2") do |config|
        config.safelist("office") { |req| req.ip == "10.0.0.1" }
        config.throttle("req/ip", limit: 5, period: 60) { |req| req.ip }
      end

      _(rule_set.version).must_equal "v2"
      _(rule_set.namespace).must_equal "v2"
      _(rule_set.configuration.safelists.keys).must_equal ["office"]
    end

    it "allows an explicit counter namespace" do
      rule_set = Rack::Attack.build_rule_set(version: "v2", namespace: "shared") { |_config| }

      _(rule_set.namespace).must_equal "shared"
    end

    it "rejects a missing version" do
      error = _(proc { Rack::Attack.build_rule_set(version: nil) { |_config| } })
        .must_raise(Rack::Attack::InvalidRuleSetError)

      _(error.errors).must_include "version must be present"
    end

    it "collects all validation errors" do
      error = _(proc do
        Rack::Attack.build_rule_set(version: "v2") do |config|
          config.throttled_responder = 42
          config.throttle("req/ip", limit: 0, period: 60) { |req| req.ip }
        end
      end).must_raise(Rack::Attack::InvalidRuleSetError)

      _(error.errors).must_include "throttled_responder must respond to #call"
      _(error.errors).must_include 'throttle "req/ip" limit must be callable or a positive number'
    end
  end

  describe "publish" do
    it "freezes the published rule set" do
      rule_set = Rack::Attack.build_rule_set(version: "v1") { |_config| }
      Rack::Attack.publish(rule_set)

      _(proc { rule_set.configuration.safelist("late") { true } }).must_raise(FrozenError)
      _(proc { rule_set.configuration.throttle("late", limit: 1, period: 1) { "x" } }).must_raise(FrozenError)
    end

    it "keeps the legacy global configuration mutable" do
      Rack::Attack.safelist("still works") { true }

      _(Rack::Attack.safelists.keys).must_equal ["still works"]
      _(Rack::Attack.current_rule_set.legacy?).must_equal true
      _(Rack::Attack.current_rule_set.version).must_be_nil
    end

    it "does not change the current rule set when validation fails" do
      invalid = Rack::Attack::RuleSet.new(
        version: "v1",
        configuration: Rack::Attack::Configuration.new.tap { |config| config.blocklisted_responder = 42 }
      )

      _(proc { Rack::Attack.publish(invalid) }).must_raise(Rack::Attack::InvalidRuleSetError)
      _(Rack::Attack.current_rule_set.legacy?).must_equal true
      _(Rack::Attack.rule_set_history).must_be_empty
    end
  end

  describe "rollback" do
    it "raises without a previous rule set" do
      _(proc { Rack::Attack.rollback }).must_raise(Rack::Attack::Error)
    end

    it "restores the previous rule set and can roll back to legacy" do
      v1 = Rack::Attack.build_rule_set(version: "v1") { |_config| }
      Rack::Attack.publish(v1)

      report = Rack::Attack.rollback

      _(report.from_version).must_equal "v1"
      _(report.to_version).must_be_nil
      _(report.summary).must_include "legacy"
      _(Rack::Attack.current_rule_set.legacy?).must_equal true
    end
  end

  describe "active_bans" do
    it "falls back to the in-process ban journal when the store cannot enumerate keys" do
      Rack::Attack::Allow2Ban.filter("1.2.3.4", maxretry: 1, findtime: 60, bantime: 300) { true }
      Rack::Attack::Allow2Ban.filter("1.2.3.4", maxretry: 1, findtime: 60, bantime: 300) { true }

      bans = Rack::Attack.active_bans

      _(bans).must_equal [{ filter: "allow2ban", discriminator: "1.2.3.4" }]
    end

    it "drops bans that are reset" do
      2.times { Rack::Attack::Allow2Ban.filter("1.2.3.4", maxretry: 1, findtime: 60, bantime: 300) { true } }
      Rack::Attack::Allow2Ban.reset("1.2.3.4", findtime: 60)

      _(Rack::Attack.active_bans).must_equal []
    end
  end

  describe "request pinning" do
    it "stamps version and namespace on the env for published rule sets only" do
      legacy_env = {}
      Rack::Attack::RuleSet.legacy(Rack::Attack.configuration).apply(legacy_env)
      _(legacy_env.keys).must_equal ["rack.attack.rule_set"]

      versioned_env = {}
      Rack::Attack.build_rule_set(version: "v9") { |_config| }.apply(versioned_env)
      _(versioned_env["rack.attack.rule_set_version"]).must_equal "v9"
      _(versioned_env["rack.attack.rule_set_namespace"]).must_equal "v9"
    end
  end
end

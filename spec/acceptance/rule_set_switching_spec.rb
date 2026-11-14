# frozen_string_literal: true

require_relative "../spec_helper"

# Reproducible experiment: two requests cross a rule set switch point.
# Request B enters the middleware under v1, v2 is published while B is in
# flight, and B must still be evaluated, counted, responded to and
# instrumented entirely under v1. Request C, arriving after the switch,
# uses only v2. Run with:
#
#   bundle exec ruby -Ilib:spec spec/acceptance/rule_set_switching_spec.rb
#
class EnumerableStore
  attr_reader :data

  def initialize
    @data = {}
  end

  def read(key)
    @data[key]
  end

  def write(key, value, **_options)
    @data[key] = value
  end

  def delete(key)
    @data.delete(key)
  end

  def increment(key, amount = 1, **_options)
    @data[key] = (@data[key] || 0) + amount
  end

  def keys
    @data.keys
  end
end

describe "rule set switching" do
  before do
    @store = EnumerableStore.new
    Rack::Attack.cache.store = @store

    @events = []
    @subscriber = ActiveSupport::Notifications.subscribe(/rack_attack/) do |*args|
      @events << { name: args.first, payload: args.last }
    end
  end

  after do
    ActiveSupport::Notifications.unsubscribe(@subscriber)
  end

  def throttle_events
    @events.select { |event| event[:name] == "throttle.rack_attack" }.map { |event| event[:payload] }
  end

  def counter_values(namespace, discriminator)
    @store.data.select { |key, _| key.end_with?(":#{namespace}:req/ip:#{discriminator}") }.values
  end

  def versioned_responder
    ->(request) { [429, { "content-type" => "text/plain" }, ["throttled-by-#{request.env['rack.attack.rule_set_version']}\n"]] }
  end

  def allow2ban_rule(config)
    config.blocklist("allow2ban scanners") do |request|
      Rack::Attack::Allow2Ban.filter(request.ip, maxretry: 1, findtime: 60, bantime: 300) do
        request.path == "/admin"
      end
    end
  end

  it "pins each request to one version across the switch point" do
    # `switch` lets the test publish v2 from inside v1's throttle callback,
    # deterministically simulating a publish that lands mid-request.
    switch = -> {}

    v1 = Rack::Attack.build_rule_set(version: "v1") do |config|
      allow2ban_rule(config)
      config.throttle("req/ip", limit: 1, period: 60) do |request|
        switch.call
        request.ip
      end
      config.throttled_responder = versioned_responder
    end

    Rack::Attack.publish(v1)

    # Request A: entirely under v1, first hit is allowed and counted once.
    get "/", {}, "REMOTE_ADDR" => "10.0.0.1"
    _(last_response.status).must_equal 200
    _(counter_values("v1", "10.0.0.1")).must_equal [1]

    v2 = Rack::Attack.build_rule_set(version: "v2") do |config|
      config.safelist("office") { |request| request.ip == "10.0.0.1" }
      allow2ban_rule(config)
      config.throttle("req/ip", limit: 5, period: 60) { |request| request.ip }
      config.throttled_responder = versioned_responder
    end

    # Request B enters under v1; v2 goes live while B is being evaluated.
    published = false
    switch = lambda do
      Rack::Attack.publish(v2) unless published
      published = true
    end

    get "/", {}, "REMOTE_ADDR" => "10.0.0.1"

    # B is NOT safelisted (the v2 safelist must not leak into B), is counted
    # against the v1 namespace, and is answered by the v1 responder.
    _(last_response.status).must_equal 429
    _(last_response.body).must_equal "throttled-by-v1\n"
    _(counter_values("v1", "10.0.0.1")).must_equal [2]
    _(counter_values("v2", "10.0.0.1")).must_equal []

    # The hit event B emitted carries the version, the count and the
    # discriminator, matching the response and the counter above.
    _(throttle_events.size).must_equal 1
    event = throttle_events.first
    _(event[:rule_set_version]).must_equal "v1"
    _(event[:request].env["rack.attack.match_data"][:count]).must_equal 2
    _(event[:request].env["rack.attack.match_discriminator"]).must_equal "10.0.0.1"

    # Request C arrives after the switch: v2's safelist applies, nothing is
    # counted for it in either namespace.
    get "/", {}, "REMOTE_ADDR" => "10.0.0.1"
    _(last_response.status).must_equal 200
    _(counter_values("v1", "10.0.0.1")).must_equal [2]
    _(counter_values("v2", "10.0.0.1")).must_equal []

    # Request D (not safelisted under v2) starts a fresh v2 counter,
    # isolated from v1's counts.
    get "/", {}, "REMOTE_ADDR" => "9.9.9.9"
    _(last_response.status).must_equal 200
    _(counter_values("v2", "9.9.9.9")).must_equal [1]
  end

  it "reports bans that stay in effect when rolling back" do
    v1 = Rack::Attack.build_rule_set(version: "v1") do |config|
      allow2ban_rule(config)
    end
    v2 = Rack::Attack.build_rule_set(version: "v2") do |config|
      allow2ban_rule(config)
    end

    Rack::Attack.publish(v1)
    Rack::Attack.publish(v2)

    # Trip an allow2ban ban under v2: first bad request arms the ban,
    # the second one is blocked.
    get "/admin", {}, "REMOTE_ADDR" => "5.6.7.8"
    _(last_response.status).must_equal 200
    get "/admin", {}, "REMOTE_ADDR" => "5.6.7.8"
    _(last_response.status).must_equal 403

    report = Rack::Attack.rollback

    _(report.from_version).must_equal "v2"
    _(report.to_version).must_equal "v1"
    _(report.bans_enumerable?).must_equal true
    _(report.active_bans).must_equal [{ filter: "allow2ban", discriminator: "5.6.7.8" }]
    _(report.summary).must_include "allow2ban:5.6.7.8"
    _(Rack::Attack.current_rule_set.version).must_equal "v1"

    # The ban was written to the shared (unversioned) cache, so it keeps
    # blocking after the rollback: v1 consults the same ban filter.
    get "/", {}, "REMOTE_ADDR" => "5.6.7.8"
    _(last_response.status).must_equal 403
  end

  it "keeps the current version when publishing an invalid rule set" do
    v1 = Rack::Attack.build_rule_set(version: "v1") { |config| allow2ban_rule(config) }
    Rack::Attack.publish(v1)

    invalid = Rack::Attack::RuleSet.new(
      version: "v2",
      configuration: Rack::Attack::Configuration.new.tap do |config|
        config.throttled_responder = "not callable"
      end
    )

    error = _(proc { Rack::Attack.publish(invalid) }).must_raise(Rack::Attack::InvalidRuleSetError)
    _(error.errors).must_equal ["throttled_responder must respond to #call"]
    _(Rack::Attack.current_rule_set.version).must_equal "v1"

    get "/", {}, "REMOTE_ADDR" => "10.0.0.1"
    _(last_response.status).must_equal 200
  end
end

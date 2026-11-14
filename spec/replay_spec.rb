# frozen_string_literal: true

require_relative 'spec_helper'
require 'json'

describe Rack::Attack::Replay do
  def ruleset(&block)
    Rack::Attack::Replay.ruleset(&block)
  end

  def event(overrides = {})
    {
      "at" => "2026-11-14T10:00:00Z",
      "method" => "GET",
      "path" => "/",
      "ip" => "1.2.3.4"
    }.merge(overrides)
  end

  def report_json(report)
    JSON.pretty_generate(report)
  end

  it 'detects tightened, loosened and undecidable diffs' do
    old_rules = ruleset do |config|
      config.throttle("search/ip", limit: 2, period: 60) { |req| req.ip if req.path == "/search" }
      config.blocklist("admin/external") { |req| req.path == "/admin" }
    end
    new_rules = ruleset do |config|
      config.throttle("search/ip", limit: 1, period: 60) { |req| req.ip if req.path == "/search" }
      config.throttle("api/agent", limit: 5, period: 60) { |req| req.user_agent if req.path == "/api" }
    end

    events = [
      event("path" => "/search"),
      event("path" => "/search"),
      event("path" => "/admin"),
      event("path" => "/api")
    ]

    report = Rack::Attack::Replay.run(old: old_rules, new: new_rules, events: events)
    kinds = report["diffs"].map { |diff| [diff["event"], diff["kind"]] }.to_h

    _(kinds[1]).must_equal "tightened"
    _(kinds[2]).must_equal "loosened"
    _(kinds[3]).must_equal "undecidable"

    undecidable = report["runs"]["new"][3]
    _(undecidable["verdict"]).must_equal "undecidable"
    _(undecidable["missing"]).must_equal ["user_agent"]
    _(undecidable["would_be"]).must_equal "allow"
  end

  it 'never defaults to allow when a rule reads a missing field' do
    rules = ruleset do |config|
      config.blocklist("bad-actors") { |req| req.ip == "6.6.6.6" }
    end

    report = Rack::Attack::Replay.run(old: rules, new: rules, events: [event.tap { |e| e.delete("ip") }])

    decision = report["runs"]["old"][0]
    _(decision["verdict"]).must_equal "undecidable"
    _(decision["missing"]).must_equal ["ip"]
  end

  it 'produces byte-identical reports for identical input' do
    rules = ruleset do |config|
      config.throttle("req/ip", limit: 2, period: 60) { |req| req.ip }
    end
    events = [event, event, event]

    first = Rack::Attack::Replay.run(old: rules, new: rules, events: events)
    second = Rack::Attack::Replay.run(old: rules, new: rules, events: events)

    _(report_json(first)).must_equal report_json(second)
  end

  it 'keeps input order for events with identical timestamps' do
    rules = ruleset do |config|
      config.throttle("req/ip", limit: 1, period: 60) { |req| req.ip }
    end
    events = [
      event("path" => "/first"),
      event("path" => "/second")
    ]

    report = Rack::Attack::Replay.run(old: rules, new: rules, events: events)

    _(report["runs"]["old"][0]["verdict"]).must_equal "allow"
    _(report["runs"]["old"][1]["verdict"]).must_equal "throttle"
    _(report["events"].map { |entry| entry["path"] }).must_equal ["/first", "/second"]
  end

  it 'changes the outcome when two causally related events are swapped' do
    rules = ruleset do |config|
      config.blocklist("allow2ban/logins") do |req|
        Rack::Attack::Allow2Ban.filter("logins:#{req.ip}", maxretry: 3, findtime: 60, bantime: 300) do
          req.path == "/login" && req.params["result"] == "fail"
        end
      end
    end

    fail_event = lambda do |seconds|
      event(
        "at" => "2026-11-14T10:00:#{format('%02d', seconds)}Z",
        "method" => "POST",
        "path" => "/login",
        "params" => { "result" => "fail" }
      )
    end
    # Same timestamp as the third failure: input order decides whether the
    # reset happens before or after the ban trips.
    success_event = event(
      "at" => "2026-11-14T10:00:20Z",
      "method" => "POST",
      "path" => "/login",
      "params" => { "result" => "success" },
      "effects" => [{ "allow2ban_reset" => { "discriminator" => "logins:1.2.3.4", "findtime" => 60 } }]
    )

    events = [fail_event.(0), fail_event.(10), success_event, fail_event.(20), fail_event.(30)]
    swapped = [fail_event.(0), fail_event.(10), fail_event.(20), success_event, fail_event.(30)]

    report = Rack::Attack::Replay.run(old: rules, new: rules, events: events)
    swapped_report = Rack::Attack::Replay.run(old: rules, new: rules, events: swapped)

    # Reset first: the failure counter is cleared, the ban never trips.
    _(report["runs"]["old"].map { |decision| decision["verdict"] }).must_equal %w[allow allow allow allow allow]
    # Failure first: the ban trips, the success is blocked and its reset
    # effect never happens.
    _(swapped_report["runs"]["old"].map { |decision| decision["verdict"] }).must_equal %w[allow allow allow block block]
    _(report_json(report)).wont_equal report_json(swapped_report)
  end

  it 'expires bans according to the virtual clock' do
    rules = ruleset do |config|
      config.blocklist("allow2ban/logins") do |req|
        Rack::Attack::Allow2Ban.filter("logins:#{req.ip}", maxretry: 1, findtime: 60, bantime: 300) do
          req.path == "/login"
        end
      end
    end

    events = [
      event("path" => "/login"),
      event("at" => "2026-11-14T10:00:10Z", "path" => "/login"),
      event("at" => "2026-11-14T10:06:01Z", "path" => "/login")
    ]

    report = Rack::Attack::Replay.run(old: rules, new: rules, events: events)
    verdicts = report["runs"]["old"].map { |decision| decision["verdict"] }

    _(verdicts).must_equal %w[allow block allow]
  end

  it 'does not touch the global cache, notifier, or responders' do
    notifications = []
    spy = Object.new
    spy.define_singleton_method(:instrument) { |*args| notifications << args }
    Rack::Attack.notifier = spy

    exploding_store = Object.new
    def exploding_store.read(*); raise "touched production cache"; end
    def exploding_store.write(*); raise "touched production cache"; end
    def exploding_store.increment(*); raise "touched production cache"; end
    def exploding_store.delete(*); raise "touched production cache"; end
    global_cache = Rack::Attack.cache
    global_cache.store = exploding_store

    rules = ruleset do |config|
      config.throttle("req/ip", limit: 1, period: 60) { |req| req.ip }
      config.throttled_responder = ->(_req) { raise "responder must not run" }
      config.blocklisted_responder = ->(_req) { raise "responder must not run" }
    end

    report = Rack::Attack::Replay.run(old: rules, new: rules, events: [event, event])

    _(report["runs"]["old"][1]["verdict"]).must_equal "throttle"
    _(notifications).must_be_empty
    _(Rack::Attack.notifier).must_equal spy
    _(Rack::Attack.cache).must_equal global_cache
  end

  it 'never exposes account plaintext in the report' do
    rules = ruleset do |config|
      config.throttle("logins/account", limit: 5, period: 60) { |req| req.params["account"] }
    end
    events = [
      event("method" => "POST", "path" => "/login", "account" => "alice@example.com")
    ]

    report = Rack::Attack::Replay.run(old: rules, new: rules, events: events)
    json = report_json(report)

    _(json).wont_include "alice@example.com"
    _(report["events"][0]["account_sha256"]).must_match(/\Asha256:[0-9a-f]{16}\z/)
  end

  it 'rejects events missing required keys' do
    rules = ruleset { |_config| }

    _ { Rack::Attack::Replay.run(old: rules, new: rules, events: [{ "method" => "GET" }]) }
      .must_raise(Rack::Attack::Replay::InvalidEventError)
  end

  describe 'sample fixture' do
    def load_ruleset(name)
      path = File.expand_path("../examples/replay/#{name}", __dir__)
      eval(File.read(path), TOPLEVEL_BINDING, path) # rubocop:disable Security/Eval
    end

    it 'shows one tightened, one loosened and one undecidable diff' do
      events_path = File.expand_path("../examples/replay/events.jsonl", __dir__)
      events = File.readlines(events_path).map { |line| JSON.parse(line) }

      report = Rack::Attack::Replay.run(
        old: load_ruleset("rules_old.rb"),
        new: load_ruleset("rules_new.rb"),
        events: events
      )

      kinds = report["diffs"].map { |diff| diff["kind"] }
      _(kinds.count("tightened")).must_equal 1
      _(kinds.count("loosened")).must_equal 1
      _(kinds.count("undecidable")).must_equal 1

      # allow2ban: ban trips on the third failure after the reset, the next
      # attempt is blocked, and the ban has expired 400 seconds later.
      old_verdicts = report["runs"]["old"].map { |decision| decision["verdict"] }
      _(old_verdicts[5]).must_equal "allow"
      _(old_verdicts[6]).must_equal "block"
      _(old_verdicts[7]).must_equal "allow"
    end
  end
end

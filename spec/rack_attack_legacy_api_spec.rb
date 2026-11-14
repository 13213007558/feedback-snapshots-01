# frozen_string_literal: true

require_relative "spec_helper"

# Migration tests: the legacy calling conventions (direct rule predicates,
# Check/Throttle#matched_by?, deprecated responders and clear!) keep working
# while the middleware uses the new metering/decision contracts.
describe "legacy calling conventions" do
  before do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  def build_request(path = "/", env = {})
    Rack::Attack::Request.new(Rack::MockRequest.env_for(path, env))
  end

  describe "configuration predicates" do
    it "safelisted?/blocklisted? still evaluate rules directly" do
      Rack::Attack.safelist("good") { |request| request.path == "/ok" }
      Rack::Attack.blocklist("bad") { |request| request.ip == "1.2.3.4" }

      configuration = Rack::Attack.configuration

      assert configuration.safelisted?(build_request("/ok"))
      refute configuration.safelisted?(build_request("/"))
      assert configuration.blocklisted?(build_request("/", "REMOTE_ADDR" => "1.2.3.4"))
      refute configuration.blocklisted?(build_request("/", "REMOTE_ADDR" => "5.6.7.8"))
    end

    it "throttled? keeps its legacy short-circuit semantics" do
      Rack::Attack.throttle("first", limit: 0, period: 60) { |request| request.ip }
      Rack::Attack.throttle("second", limit: 60, period: 60) { |request| request.ip }

      request = build_request("/", "REMOTE_ADDR" => "1.2.3.4")

      assert Rack::Attack.configuration.throttled?(request)
      # Legacy any? short-circuits: the second throttle is never metered.
      assert_equal ["first"], request.env["rack.attack.throttle_data"].keys
    end

    it "tracked? still instruments matching tracks" do
      Rack::Attack.track("agents") { |request| request.user_agent == "bot" }

      notifications = []
      ActiveSupport::Notifications.subscribe("track.rack_attack") do |_name, _start, _finish, _id, payload|
        notifications.push(payload)
      end

      request = build_request("/", "HTTP_USER_AGENT" => "bot")
      Rack::Attack.configuration.tracked?(request)

      assert_equal 1, notifications.size
      assert_equal "agents", request.env["rack.attack.matched"]
      assert_equal :track, request.env["rack.attack.match_type"]
    end
  end

  describe "Check#matched_by?" do
    it "annotates the request and instruments the match" do
      check = Rack::Attack::Blocklist.new("bad ip") { |request| request.ip == "1.2.3.4" }

      notifications = []
      ActiveSupport::Notifications.subscribe("blocklist.rack_attack") do |_name, _start, _finish, _id, payload|
        notifications.push(payload)
      end

      request = build_request("/", "REMOTE_ADDR" => "1.2.3.4")

      assert check.matched_by?(request)
      assert_equal "bad ip", request.env["rack.attack.matched"]
      assert_equal :blocklist, request.env["rack.attack.match_type"]
      assert_equal 1, notifications.size
    end
  end

  describe "Throttle#matched_by?" do
    it "meters, annotates and instruments when the limit is exceeded" do
      throttle = Rack::Attack::Throttle.new("ip/sec", limit: 1, period: 60) { |request| request.ip }

      notifications = []
      ActiveSupport::Notifications.subscribe("throttle.rack_attack") do |_name, _start, _finish, _id, payload|
        notifications.push(payload)
      end

      refute throttle.matched_by?(build_request("/", "REMOTE_ADDR" => "1.2.3.4"))

      request = build_request("/", "REMOTE_ADDR" => "1.2.3.4")
      assert throttle.matched_by?(request)
      assert_equal "ip/sec", request.env["rack.attack.matched"]
      assert_equal :throttle, request.env["rack.attack.match_type"]
      assert_equal 2, request.env["rack.attack.match_data"][:count]
      assert_equal "1.2.3.4", request.env["rack.attack.match_discriminator"]
      assert_equal 1, notifications.size
    end

    it "returns false without touching the cache when the rule does not apply" do
      throttle = Rack::Attack::Throttle.new("conditional", limit: 1, period: 60) { |_request| nil }

      request = build_request("/")

      refute throttle.matched_by?(request)
      assert_nil request.env["rack.attack.throttle_data"]
    end
  end

  describe "deprecated responders" do
    it "throttled_response= still handles throttled requests" do
      _, err = capture_io do
        Rack::Attack.throttled_response = lambda { |_env| [429, { "content-type" => "text/plain" }, ["legacy throttled"]] }
      end
      assert_match(/DEPRECATION/, err)

      Rack::Attack.throttle("ip/sec", limit: 1, period: 60) { |request| request.ip }

      2.times { get "/", {}, "REMOTE_ADDR" => "1.2.3.4" }

      assert_equal 429, last_response.status
      assert_equal "legacy throttled", last_response.body
    end

    it "blocklisted_response= still handles blocklisted requests" do
      _, err = capture_io do
        Rack::Attack.blocklisted_response = lambda { |_env| [403, { "content-type" => "text/plain" }, ["legacy blocked"]] }
      end
      assert_match(/DEPRECATION/, err)

      Rack::Attack.blocklist("banned") { |request| request.ip == "1.2.3.4" }

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      assert_equal 403, last_response.status
      assert_equal "legacy blocked", last_response.body
    end
  end

  describe "Rack::Attack.clear!" do
    it "still clears the configuration with a deprecation warning" do
      Rack::Attack.throttle("ip/sec", limit: 1, period: 60) { |request| request.ip }

      _, err = capture_io { Rack::Attack.clear! }

      assert_match(/DEPRECATION/, err)
      assert_empty Rack::Attack.throttles
    end
  end
end

# frozen_string_literal: true

require_relative "../spec_helper"

# Acceptance coverage for the metering/decision split: every applicable rule
# meters each attempt, while a single stable decision drives the response.
describe "rule evaluation" do
  before do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  describe "crossing account and ip throttles" do
    before do
      Rack::Attack.throttle("logins per account", limit: 1, period: 60) do |request|
        request.params["account"]
      end

      Rack::Attack.throttle("logins per ip", limit: 3, period: 60) do |request|
        request.ip
      end
    end

    it "counts every applicable throttle even when another one already throttled" do
      get "/", { account: "a" }, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 200, last_response.status

      get "/", { account: "a" }, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 429, last_response.status
      assert_equal "logins per account", last_request.env["rack.attack.matched"]
      assert_equal :throttle, last_request.env["rack.attack.match_type"]
      # The throttled attempt is still counted against the ip throttle.
      assert_equal 2, last_request.env["rack.attack.throttle_data"]["logins per account"][:count]
      assert_equal 2, last_request.env["rack.attack.throttle_data"]["logins per ip"][:count]

      get "/", { account: "b" }, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 200, last_response.status
      assert_equal 3, last_request.env["rack.attack.throttle_data"]["logins per ip"][:count]

      # With the old short-circuit behavior the ip counter would be at 3 here
      # and this request would pass; full metering puts it at 4, over the limit.
      get "/", { account: "c" }, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 429, last_response.status
      assert_equal "logins per ip", last_request.env["rack.attack.matched"]
      assert_equal 4, last_request.env["rack.attack.throttle_data"]["logins per ip"][:count]
    end

    it "lets the first triggered rule decide while recording every match" do
      get "/", { account: "a" }, "REMOTE_ADDR" => "1.2.3.4"
      get "/", { account: "a" }, "REMOTE_ADDR" => "1.2.3.4"
      get "/", { account: "b" }, "REMOTE_ADDR" => "1.2.3.4"
      get "/", { account: "c" }, "REMOTE_ADDR" => "1.2.3.4"

      # Both throttles are exceeded by now; the first defined one decides.
      get "/", { account: "b" }, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 429, last_response.status
      assert_equal "logins per account", last_request.env["rack.attack.matched"]
      assert_equal "b", last_request.env["rack.attack.match_discriminator"]
      assert_equal(
        [
          { name: "logins per account", type: :throttle },
          { name: "logins per ip", type: :throttle }
        ],
        last_request.env["rack.attack.matches"]
      )
    end
  end

  describe "multiple matching blocklists" do
    before do
      Rack::Attack.blocklist("first ban") { |request| request.ip == "1.2.3.4" }
      Rack::Attack.blocklist("second ban") { |request| request.path == "/" }
    end

    it "keeps response priority stable and notifies only once" do
      notifications = []
      ActiveSupport::Notifications.subscribe("blocklist.rack_attack") do |_name, _start, _finish, _id, payload|
        notifications.push(payload)
      end

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      assert_equal 403, last_response.status
      assert_equal "first ban", last_request.env["rack.attack.matched"]
      assert_equal :blocklist, last_request.env["rack.attack.match_type"]
      assert_equal(
        [
          { name: "first ban", type: :blocklist },
          { name: "second ban", type: :blocklist }
        ],
        last_request.env["rack.attack.matches"]
      )

      assert_equal 1, notifications.size
      notification = notifications.pop
      assert_equal "first ban", notification[:request].env["rack.attack.matched"]
      assert_equal 2, notification[:request].env["rack.attack.matches"].size
    end
  end

  describe "blocklisted request crossing a throttle" do
    before do
      Rack::Attack.blocklist("banned ip") { |request| request.ip == "1.2.3.4" }
      Rack::Attack.throttle("requests per ip", limit: 1, period: 60) { |request| request.ip }
    end

    it "still meters the throttle and notifies a single penalty per request" do
      notifications = []
      ["blocklist.rack_attack", "throttle.rack_attack"].each do |event|
        ActiveSupport::Notifications.subscribe(event) do |_name, _start, _finish, _id, payload|
          notifications.push(payload)
        end
      end

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 403, last_response.status
      assert_equal 1, last_request.env["rack.attack.throttle_data"]["requests per ip"][:count]

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 403, last_response.status
      assert_equal "banned ip", last_request.env["rack.attack.matched"]
      assert_equal :blocklist, last_request.env["rack.attack.match_type"]
      assert_equal 2, last_request.env["rack.attack.throttle_data"]["requests per ip"][:count]
      assert_equal(
        [
          { name: "banned ip", type: :blocklist },
          { name: "requests per ip", type: :throttle }
        ],
        last_request.env["rack.attack.matches"]
      )

      # One penalty notification per request, never one per matched rule.
      assert_equal 2, notifications.size
      assert notifications.all? { |n| n[:request].env["rack.attack.match_type"] == :blocklist }
    end
  end

  describe "safelisted requests" do
    before do
      Rack::Attack.safelist("trusted ip") { |request| request.ip == "9.9.9.9" }
      Rack::Attack.throttle("requests per ip", limit: 2, period: 60) { |request| request.ip }
    end

    it "are metered by default" do
      2.times { get "/", {}, "REMOTE_ADDR" => "9.9.9.9" }

      assert_equal 200, last_response.status
      assert_equal 2, last_request.env["rack.attack.throttle_data"]["requests per ip"][:count]
    end

    it "skip metering when explicitly configured" do
      Rack::Attack.meter_safelisted_requests = false

      get "/", {}, "REMOTE_ADDR" => "9.9.9.9"

      assert_equal 200, last_response.status
      assert_nil last_request.env["rack.attack.throttle_data"]
    end
  end

  describe "rule callbacks" do
    it "runs a throttle's discriminator callback only once per request" do
      calls = 0
      Rack::Attack.blocklist("banned ip") { |request| request.ip == "1.2.3.4" }
      Rack::Attack.throttle("requests per ip", limit: 5, period: 60) do |request|
        calls += 1
        request.ip
      end

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      assert_equal 403, last_response.status
      assert_equal 1, calls
    end

    it "runs a check's block only once per request" do
      calls = 0
      Rack::Attack.blocklist("counted") { |_request| (calls += 1) && false }

      get "/"

      assert_equal 200, last_response.status
      assert_equal 1, calls
    end
  end

  describe "inapplicable rules" do
    class RecordingStore
      attr_reader :incremented_keys

      def initialize
        @incremented_keys = []
      end

      def read(_key); end

      def write(_key, _value, _options = {}); end

      def delete(_key); end

      def increment(key, amount, _options = {})
        @incremented_keys << key
        amount
      end
    end

    it "do not write to the cache" do
      store = RecordingStore.new
      Rack::Attack.cache.store = store

      Rack::Attack.throttle("conditional", limit: 1, period: 60) do |request|
        request.params["account"]
      end

      get "/"

      assert_equal 200, last_response.status
      assert_empty store.incremented_keys
      assert_nil last_request.env["rack.attack.throttle_data"]
    end
  end
end

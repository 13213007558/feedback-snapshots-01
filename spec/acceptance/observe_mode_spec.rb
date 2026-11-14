# frozen_string_literal: true

require_relative "../spec_helper"

describe "observe mode (candidate rules)" do
  let(:observed_events) { [] }
  let(:enforced_events) { [] }

  def app
    Rack::Builder.new do
      use Rack::Lint
      use Rack::Attack

      run lambda { |env|
        input = env["rack.input"]
        body = input ? input.read : ""
        [200, { "content-type" => "text/plain" }, ["app saw: #{body}"]]
      }
    end.to_app
  end

  before do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.observed_cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  def subscribe
    observed_sub = ActiveSupport::Notifications.subscribe(/observed_.*\.rack_attack/) do |_name, _start, _finish, _id, payload|
      observed_events << payload
    end
    enforced_sub = ActiveSupport::Notifications.subscribe(/^(blocklist|throttle|track)\.rack_attack/) do |_name, _start, _finish, _id, payload|
      enforced_events << payload
    end
    yield
  ensure
    ActiveSupport::Notifications.unsubscribe(observed_sub)
    ActiveSupport::Notifications.unsubscribe(enforced_sub)
  end

  it "compares official and candidate outcomes over a shared request sequence" do
    # Official rule: throttle login attempts per IP
    Rack::Attack.throttle("logins/ip", limit: 2, period: 60) do |req|
      req.ip if req.path == "/login" && req.post?
    end

    # Candidate rule (observed): stricter credential-stuffing heuristic,
    # throttling per username read from the same request body.
    Rack::Attack.throttle("logins/username", limit: 1, period: 60, observe: true) do |req|
      req.body.read[/username=([^&]*)/, 1] if req.path == "/login" && req.post?
    end

    subscribe do
      # 1. Allowed by both. The candidate read the body, but the app still
      #    receives the same input stream intact.
      post "/login", "username=alice", "REMOTE_ADDR" => "1.1.1.1"
      assert_equal 200, last_response.status
      assert_equal "app saw: username=alice", last_response.body

      # 2. Candidate-only rejection (2nd attempt for "alice"): hypothetical,
      #    the response is unaffected.
      post "/login", "username=alice", "REMOTE_ADDR" => "1.1.1.1"
      assert_equal 200, last_response.status
      assert_equal "app saw: username=alice", last_response.body

      # 3. Official-only rejection (3rd attempt from the IP, fresh username).
      post "/login", "username=bob", "REMOTE_ADDR" => "1.1.1.1"
      assert_equal 429, last_response.status

      # 4. Both reject. The candidate still receives its attempt event even
      #    though the official rule already rejected the request.
      post "/login", "username=alice", "REMOTE_ADDR" => "1.1.1.1"
      assert_equal 429, last_response.status
    end

    # Candidate events are explicitly marked as hypothetical.
    assert_equal 2, observed_events.size
    observed_events.each do |payload|
      env = payload[:request].env
      assert_equal true, payload[:observed]
      assert_equal true, env["rack.attack.observed"]
      assert_equal "logins/username", env["rack.attack.observed.matched"]
      assert_equal :throttle, env["rack.attack.observed.match_type"]
      assert_equal "alice", env["rack.attack.observed.match_discriminator"]
    end
    assert_equal [2, 3], observed_events.map { |payload| payload[:request].env["rack.attack.observed.match_data"][:count] }

    # Penalty subscriptions only see actual (official) interceptions:
    # requests 3 and 4 above.
    assert_equal 2, enforced_events.size
    enforced_events.each do |payload|
      env = payload[:request].env
      assert_nil payload[:observed]
      assert_equal "logins/ip", env["rack.attack.matched"]
      assert_equal :throttle, env["rack.attack.match_type"]
    end
  end

  it "does not consume the official rule's quota" do
    Rack::Attack.throttle("official ip", limit: 2, period: 60) { |req| req.ip }
    Rack::Attack.throttle("candidate ip", limit: 100, period: 60, observe: true) { |req| req.ip }

    2.times { get "/", {}, "REMOTE_ADDR" => "9.9.9.9" }
    assert_equal 200, last_response.status

    get "/", {}, "REMOTE_ADDR" => "9.9.9.9"
    assert_equal 429, last_response.status

    # The official counter reached 3, not 5: candidate counting happened in
    # its own namespace.
    assert_equal 3, last_request.env["rack.attack.match_data"][:count]
    assert_equal 3, last_request.env["rack.attack.observed.throttle_data"]["candidate ip"][:count]
  end

  it "never runs the enforced responders for candidate matches" do
    responder_calls = 0
    Rack::Attack.throttled_responder = lambda do |_req|
      responder_calls += 1
      [429, {}, ["throttled"]]
    end
    Rack::Attack.throttle("candidate only", limit: 1, period: 60, observe: true) { |req| req.ip }

    2.times { get "/", {}, "REMOTE_ADDR" => "3.3.3.3" }

    assert_equal 200, last_response.status
    assert_equal 0, responder_calls
  end

  it "keeps candidate bans virtual and never writes official ban flags" do
    Rack::Attack.blocklist("candidate allow2ban", observe: true) do |req|
      Rack::Attack::Allow2Ban.filter(req.ip, maxretry: 2, findtime: 60, bantime: 60, observe: true) do
        req.path == "/login"
      end
    end

    subscribe do
      get "/login", {}, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 200, last_response.status

      get "/login", {}, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 200, last_response.status

      # The virtual ban is now active: the candidate reports a hypothetical
      # block, but the request is still allowed.
      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      assert_equal 200, last_response.status
    end

    assert Rack::Attack::Allow2Ban.banned?("1.2.3.4", observe: true)
    refute Rack::Attack::Allow2Ban.banned?("1.2.3.4")

    assert_equal 1, observed_events.size
    assert_equal :blocklist, observed_events.first[:request].env["rack.attack.observed.match_type"]
    assert enforced_events.empty?
  end

  it "does not carry virtual bans into enforced mode unless explicitly promoted" do
    configure_candidate = lambda do |observe|
      Rack::Attack.blocklist("candidate allow2ban", observe: observe) do |req|
        Rack::Attack::Allow2Ban.filter(req.ip, maxretry: 1, findtime: 60, bantime: 60, observe: observe) do
          req.path == "/login"
        end
      end
    end

    configure_candidate.call(true)
    get "/login", {}, "REMOTE_ADDR" => "5.5.5.5"
    assert_equal 200, last_response.status
    assert Rack::Attack::Allow2Ban.banned?("5.5.5.5", observe: true)

    # Switching the rule to enforced mode: users observed during the
    # observation period are not suddenly punished.
    configure_candidate.call(false)
    get "/", {}, "REMOTE_ADDR" => "5.5.5.5"
    assert_equal 200, last_response.status

    # Explicit carry-over of the virtual ban.
    Rack::Attack::Allow2Ban.promote_observed!("5.5.5.5", 60)
    get "/", {}, "REMOTE_ADDR" => "5.5.5.5"
    assert_equal 403, last_response.status
  end

  it "keeps the official response when a candidate rule raises" do
    Rack::Attack.throttle("official", limit: 1, period: 60) { |req| req.ip }
    Rack::Attack.blocklist("broken candidate", observe: true) { |_req| raise "boom" }

    get "/", {}, "REMOTE_ADDR" => "4.4.4.4"
    assert_equal 200, last_response.status
    assert_kind_of RuntimeError, last_request.env["rack.attack.observed.error"]

    get "/", {}, "REMOTE_ADDR" => "4.4.4.4"
    assert_equal 429, last_response.status
    assert_kind_of RuntimeError, last_request.env["rack.attack.observed.error"]
  end
end

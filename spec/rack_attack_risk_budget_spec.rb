# frozen_string_literal: true

require_relative "spec_helper"

# A test scorer that can be paused/resumed to simulate a stuck downstream
# service, and that tracks how many concurrent executions it has seen.
class PausableScorer
  attr_reader :max_active, :calls

  def initialize(work_time: 0.02)
    @work_time = work_time
    @mutex = Mutex.new
    @condition = ConditionVariable.new
    @paused = false
    @active = 0
    @max_active = 0
    @calls = 0
  end

  def pause!
    @mutex.synchronize { @paused = true }
  end

  def resume!
    @mutex.synchronize do
      @paused = false
      @condition.broadcast
    end
  end

  def call(query)
    @mutex.synchronize do
      @condition.wait(@mutex) while @paused
      @active += 1
      @calls += 1
      @max_active = [@max_active, @active].max
    end
    begin
      sleep @work_time
      query.to_s.include?("bad") ? 0.9 : 0.1
    ensure
      @mutex.synchronize { @active -= 1 }
    end
  end
end

describe "Rack::Attack risk scoring budget" do
  before do
    @pool = Rack::Attack::Risk::Pool.new(size: 2, queue_capacity: 4)
    @pausable = PausableScorer.new
    @scorer = Rack::Attack::Risk::Scorer.new(@pausable, pool: @pool)
    @old_budget = Rack::Attack.risk_budget
    Rack::Attack.risk_budget = 0.15
  end

  after do
    Rack::Attack.risk_budget = @old_budget
    @pool.shutdown
  end

  def raw_app
    Rack::Attack.new(lambda { |_env| [200, { "content-type" => "text/plain" }, ["ok"]] })
  end

  def call_raw(remote_addr)
    raw_app.call(Rack::MockRequest.env_for("/", "REMOTE_ADDR" => remote_addr))
  end

  describe "when the scorer stalls" do
    before { @pausable.pause! }

    it "denies the request when on_timeout is :deny" do
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :deny, query: ->(req) { req.ip })

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      _(last_response.status).must_equal 403
      _(last_response.headers["x-rack-attack-risk-policy"]).must_equal "deny_on_unknown"
    end

    it "passes the request through when on_timeout is :ignore" do
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :ignore, query: ->(req) { req.ip })

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      _(last_response.status).must_equal 200
    end

    it "falls back to the local rule when on_timeout is :local" do
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :local, query: ->(req) { req.ip }) do |req|
        req.path == "/admin"
      end

      get "/admin", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(last_response.status).must_equal 403
      _(last_response.headers["x-rack-attack-risk-policy"]).must_equal "local_on_unknown"

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(last_response.status).must_equal 200
    end

    it "recovers and scores again once the scorer resumes" do
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :deny, query: ->(req) { req.ip })

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(last_response.status).must_equal 403

      @pausable.resume!

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(last_response.status).must_equal 200
    end
  end

  describe "when the scorer answers" do
    it "blocks high-risk queries and records the scored policy" do
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :ignore, query: ->(req) { req.ip })

      get "/", {}, "REMOTE_ADDR" => "bad-actor"

      _(last_response.status).must_equal 403
      _(last_response.headers["x-rack-attack-risk-policy"]).must_equal "scored_deny"
    end

    it "allows low-risk queries" do
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :deny, query: ->(req) { req.ip })

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      _(last_response.status).must_equal 200
    end
  end

  describe "request env and notifications" do
    it "records the adopted policy and a query digest, never the raw query" do
      captured_env = nil
      Rack::Attack.blocklisted_responder = lambda do |req|
        captured_env = req.env
        [403, { "content-type" => "text/plain" }, ["Forbidden\n"]]
      end
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :deny, query: ->(_req) { "bad-secret-token-xyz" })

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      decisions = captured_env["rack.attack.risk.decisions"]
      _(decisions.size).must_equal 1
      decision = decisions.first
      _(decision[:rule]).must_equal "risky"
      _(decision[:outcome]).must_equal :deny
      _(decision[:policy]).must_equal :scored_deny
      _(decision[:query_digest]).must_equal Digest::SHA256.hexdigest("bad-secret-token-xyz")
      _(decisions.inspect).wont_include "bad-secret-token-xyz"
      _(captured_env["rack.attack.risk"].inspect).wont_include "bad-secret-token-xyz"
    end

    it "instruments the risk policy on the notification payload" do
      seen = []
      subscriber = ActiveSupport::Notifications.subscribe("risk_blocklist.rack_attack") do |*args|
        seen << args.last[:request].env["rack.attack.risk"][:policy]
      end
      Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :deny, query: ->(req) { req.ip })

      get "/", {}, "REMOTE_ADDR" => "bad-actor"

      _(seen).must_equal [:scored_deny]
    ensure
      ActiveSupport::Notifications.unsubscribe(subscriber)
    end
  end

  describe "shared per-request budget" do
    it "shares one scorer call across rules with the same query" do
      options = { scorer: @scorer, on_timeout: :ignore, query: ->(req) { req.ip } }
      Rack::Attack.risk_blocklist("risk-a", **options)
      Rack::Attack.risk_blocklist("risk-b", **options)

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

      _(last_response.status).must_equal 200
      _(@pausable.calls).must_equal 1
    end

    it "never lets a later timeout overturn a confirmed verdict" do
      budget = Rack::Attack::Risk::Budget.new(0.05)
      calls = 0
      score = ->(_remaining) { calls += 1; Rack::Attack::Risk::Result.deny }

      first = budget.fetch("query") { |remaining| score.call(remaining) }
      sleep 0.06 # spend the budget
      second = budget.fetch("query") { |remaining| score.call(remaining) }

      _(first.state).must_equal :deny
      _(second.state).must_equal :deny
      _(calls).must_equal 1
    end

    it "returns unknown without touching the pool once the budget is spent" do
      budget = Rack::Attack::Risk::Budget.new(0)
      result = budget.fetch("query") { |remaining| @scorer.evaluate("query", timeout: remaining) }

      _(result.state).must_equal :unknown
      _(result.reason).must_equal :budget_exhausted
      _(@pausable.calls).must_equal 0
    end
  end

  describe "under concurrent backlog" do
    it "bounds active scorer work to the pool size" do
      big_pool = Rack::Attack::Risk::Pool.new(size: 2, queue_capacity: 16)
      big_scorer = Rack::Attack::Risk::Scorer.new(@pausable, pool: big_pool)
      Rack::Attack.risk_budget = 5
      Rack::Attack.risk_blocklist("risky", scorer: big_scorer, on_timeout: :deny, query: ->(req) { req.ip })

      threads = Array.new(8) { |i| Thread.new { call_raw("10.0.0.#{i}") } }
      statuses = threads.map(&:value).map(&:first)

      _(statuses.uniq).must_equal [200]
      _(@pausable.calls).must_equal 8
      _(@pausable.max_active).must_be :<=, 2
    ensure
      big_pool.shutdown
    end

    it "sheds load with unknown results when the queue is full, without extra threads" do
      small_pool = Rack::Attack::Risk::Pool.new(size: 1, queue_capacity: 1)
      small_scorer = Rack::Attack::Risk::Scorer.new(@pausable, pool: small_pool)
      Rack::Attack.risk_blocklist("risky", scorer: small_scorer, on_timeout: :ignore, query: ->(req) { req.ip })
      @pausable.pause!
      baseline_threads = Thread.list.size

      begin
        threads = Array.new(6) { |i| Thread.new { call_raw("10.0.0.#{i}") } }
        responses = threads.map(&:value)

        _(responses.map(&:first).uniq).must_equal [200]
        reasons = responses.flat_map { |_s, _h, b| b }.size # consume bodies
        _(@pausable.max_active).must_be :<=, 1
        _(Thread.list.size - baseline_threads).must_be :<=, 0
      ensure
        @pausable.resume!
        small_pool.shutdown
      end
    end

    it "records queue_full and timeout as unknown outcomes, never as low risk" do
      small_pool = Rack::Attack::Risk::Pool.new(size: 1, queue_capacity: 1)
      small_scorer = Rack::Attack::Risk::Scorer.new(@pausable, pool: small_pool)
      captured = []
      app = Rack::Attack.new(lambda do |env|
        captured.concat(env["rack.attack.risk.decisions"] || [])
        [200, { "content-type" => "text/plain" }, ["ok"]]
      end)
      Rack::Attack.risk_blocklist("risky", scorer: small_scorer, on_timeout: :ignore, query: ->(req) { req.ip })
      @pausable.pause!

      begin
        threads = Array.new(6) do |i|
          Thread.new { app.call(Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "10.0.0.#{i}")) }
        end
        threads.each(&:join)

        _(captured.size).must_equal 6
        _(captured.map { |d| d[:outcome] }.uniq).must_equal [:unknown]
        _(captured.map { |d| d[:policy] }.uniq).must_equal [:ignore_on_unknown]
        _(captured.map { |d| d[:reason] } - %i[queue_full timeout budget_exhausted]).must_equal []
      ensure
        @pausable.resume!
        small_pool.shutdown
      end
    end
  end

  describe "configuration validation" do
    it "rejects unknown on_timeout policies" do
      error = _(lambda do
        Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :banana, query: ->(req) { req.ip })
      end).must_raise ArgumentError
      _(error.message).must_match(/on_timeout/)
    end

    it "requires a local block for on_timeout: :local" do
      _(lambda do
        Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :local, query: ->(req) { req.ip })
      end).must_raise ArgumentError
    end

    it "requires a query" do
      _(lambda do
        Rack::Attack.risk_blocklist("risky", scorer: @scorer, on_timeout: :deny)
      end).must_raise ArgumentError
    end
  end
end

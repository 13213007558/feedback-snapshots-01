# frozen_string_literal: true

require "sidekiq"
require "sidekiq/api"
require "sidekiq/web"
require "minitest/autorun"
require "rack/mock"
require "uri"
require "logger"
require_relative "web_memory_redis"

# Drives Sidekiq::Web through Rack directly with a small in-memory Redis
# substitute.  The tests cover the Retry/Scheduled/Dead management actions:
# per-action operator permission, confirmation bound to the exact listing
# entry, scheduler movement between page read and confirmation, and replay of
# an already completed action.
describe "Sidekiq::Web job management confirmation" do
  def redis
    @redis ||= WebMemoryRedis.new
  end

  before do
    @original_config = Sidekiq.instance_variable_get(:@config)
    @original_web_config = Sidekiq::Web.configure
    @original_web_pool = Sidekiq::Web.instance_variable_get(:@pool)

    memory = @redis = WebMemoryRedis.new
    @sidekiq_config = Sidekiq::Config.new
    @sidekiq_config.logger = Logger.new(IO::NULL)
    pool = Object.new
    pool.define_singleton_method(:with) { |&blk| blk.call(memory) }
    pool.define_singleton_method(:shutdown) { |&blk| }
    @sidekiq_config.instance_variable_set(:@redis, pool)
    Sidekiq.instance_variable_set(:@config, @sidekiq_config)

    Sidekiq::Web::Confirmation.reset_secret!
    Thread.current[:sidekiq_web_action_secret] = nil
    @session = {}
    @policy = ->(_env, _action, _target) { true }
    Thread.current[:web_test_policy] = @policy

    cfg = Sidekiq::Web::Config.new
    cfg.authorize_action { |env, action, target| Thread.current[:web_test_policy].call(env, action, target) }
    Sidekiq::Web.send(:class_variable_set, :@@config, cfg)
    Sidekiq::Web.redis_pool = pool
    @web = Sidekiq::Web.new
  end

  after do
    Thread.current[:web_test_policy] = nil
    Thread.current[:sidekiq_web_action_secret] = nil
    Sidekiq::Web.send(:class_variable_set, :@@config, @original_web_config)
    Sidekiq::Web.redis_pool = @original_web_pool
    Sidekiq.instance_variable_set(:@config, @original_config)
  end

  def policy(&block)
    @policy = block
    Thread.current[:web_test_policy] = block
  end

  def without_policy
    cfg = Sidekiq::Web::Config.new
    Sidekiq::Web.send(:class_variable_set, :@@config, cfg)
    @web = Sidekiq::Web.new
  end

  def request(method, path, params = {}, env = {})
    headers = {"HTTP_SEC_FETCH_SITE" => "same-origin"}
    headers.merge!(env)
    query = nil
    if method == :get && params.any?
      query = URI.encode_www_form(params)
    end
    body = nil
    if method == :post
      body = URI.encode_www_form(params)
      headers["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
    end
    env_hash = Rack::MockRequest.env_for(path, method: method.to_s.upcase, params: query, input: body)
    headers.each { |key, value| env_hash[key] = value }
    env_hash["rack.session"] = @session
    status, headers_out, response_body = @web.call(env_hash)
    @last_response = Rack::MockResponse.new(status, headers_out, response_body)
  end

  def last_response
    @last_response
  end

  def add_job(set_key, jid:, klass: "HardJob", args: [1], queue: "default", score: 1_700_000_000.0)
    payload = {"class" => klass, "args" => args, "queue" => queue, "jid" => jid,
               "retry_count" => 0, "failed_at" => Time.now.to_f}
    raw = Sidekiq.dump_json(payload)
    redis.call("zadd", set_key, score.to_s, raw)
    [raw, score]
  end

  def page_entries(set_path)
    request(:get, set_path)
    assert_equal 200, last_response.status
    last_response.body.scan(/name="key\[\]" value="([^"]+)"/).flatten
  end

  it "gates each action by operator permission and never mutates without it" do
    add_job("retry", jid: "jidretry", args: ["only-read"])
    policy { |_env, _action, _target| false }

    request(:get, "/retries")
    assert_equal 200, last_response.status
    refute_match(/name="retry"/, last_response.body)
    refute_match(/name="delete"/, last_response.body)

    tokens = last_response.body.scan(/name="key\[\]" value="([^"]+)"/).flatten
    assert_equal 1, tokens.size

    request(:post, "/retries", "key" => tokens, "delete" => "Delete")
    assert_equal 403, last_response.status
    assert_equal "forbidden", last_response.headers["x-sidekiq-action-state"]
    assert_equal 1, redis.members("retry").size, "permission denial must keep the job"
    assert_equal 0, redis.published_jobs.size
  end

  it "permits cancellation and re-retry separately" do
    add_job("retry", jid: "jidcancel", args: ["cancel"])
    add_job("retry", jid: "jidretry2", args: ["retry"], score: 1_700_000_001.0)
    policy { |_env, action, _target| action == :cancel || action == :retry }

    tokens = page_entries("/retries")
    assert_equal 2, tokens.size

    # tokens are signed, so locate them by decoding
    tokens.each do |token|
      payload = Sidekiq::Web::Confirmation.decode(token)
      @cancel_token = token if payload["j"] == "jidcancel"
      @retry_token = token if payload["j"] == "jidretry2"
    end
    assert @cancel_token
    assert @retry_token

    request(:post, "/retries", "key" => [@cancel_token], "delete" => "Delete")
    assert_equal 302, last_response.status
    assert_equal 1, redis.members("retry").size
    assert_equal 0, redis.published_jobs.size

    request(:post, "/retries", "key" => [@retry_token], "retry" => "Retry")
    assert_equal 302, last_response.status
    assert_equal 0, redis.members("retry").size
    assert_equal ["jidretry2"], redis.published_jobs.map { |job| job["jid"] }
  end

  it "refuses a stale confirmation when the scheduler moved the job and it reappeared under the same jid" do
    raw, score = add_job("retry", jid: "jidmoved", args: ["original"])
    token = page_entries("/retries").first
    payload = Sidekiq::Web::Confirmation.decode(token)
    assert_equal "jidmoved", payload["j"]

    # Simulate the scheduler moving the retry into the dead set, then a new
    # entry reappearing in the retry set under the original jid.
    redis.call("zrem", "retry", raw)
    add_job("dead", jid: "jidmoved", args: ["moved"], score: 1_700_000_100.0)
    add_job("retry", jid: "jidmoved", args: ["replacement"], score: 1_700_000_100.0)

    request(:post, "/retries", "key" => [token], "delete" => "Delete")
    assert_equal 409, last_response.status
    assert_equal "needs_confirmation", last_response.headers["x-sidekiq-action-state"]
    assert_match(/newer|changed|Reload|reconfirm/i, last_response.body)

    # The current job is preserved in both sets.
    assert_equal 1, redis.members("retry").size
    assert_equal 1, redis.members("dead").size
    retry_job = Sidekiq.load_json(redis.members("retry").first)
    assert_equal ["replacement"], retry_job["args"]
    assert_equal 0, redis.published_jobs.size
  end

  it "reports an already completed action instead of pushing a second copy" do
    raw, score = add_job("retry", jid: "jidreplay", args: ["replay"])
    token = page_entries("/retries").first

    request(:post, "/retries", "key" => [token], "retry" => "Retry")
    assert_equal 302, last_response.status
    assert_equal ["jidreplay"], redis.published_jobs.map { |job| job["jid"] }

    # Resubmit the exact same form, as a double click or a browser retry would.
    request(:post, "/retries", "key" => [token], "retry" => "Retry")
    assert_equal 200, last_response.status
    assert_equal "completed", last_response.headers["x-sidekiq-action-state"]
    assert_match(/already completed/i, last_response.body)
    assert_equal ["jidreplay"], redis.published_jobs.map { |job| job["jid"] },
      "the replayed action must not publish a second job"
    assert_equal 0, redis.members("retry").size
  end

  it "reports re-confirmation when a previous attempt was interrupted" do
    raw, score = add_job("retry", jid: "jidinterrupted")
    token = page_entries("/retries").first
    payload = Sidekiq::Web::Confirmation.decode(token)

    # Another web process claimed the action but never finished it.
    redis.call("hset", Sidekiq::Web::Confirmation.ledger_key(payload["n"], :retry), "state", "running")

    request(:post, "/retries", "key" => [token], "retry" => "Retry")
    assert_equal 409, last_response.status
    assert_equal "needs_confirmation", last_response.headers["x-sidekiq-action-state"]
    assert_equal 1, redis.members("retry").size
    assert_equal 0, redis.published_jobs.size
  end

  it "rejects a tampered confirmation instead of falling back to the legacy key" do
    add_job("retry", jid: "jidtamper")
    token = page_entries("/retries").first
    encoded, signature = token.split(".", 2)
    tampered = "#{encoded}.#{"0" * signature.length}"

    request(:post, "/retries", "key" => [tampered], "delete" => "Delete")
    assert_equal 409, last_response.status
    assert_equal "needs_confirmation", last_response.headers["x-sidekiq-action-state"]
    assert_equal 1, redis.members("retry").size
    assert_equal 0, redis.published_jobs.size
  end

  it "does not accept a confirmation issued for a different list" do
    add_job("retry", jid: "jidcross")
    token = page_entries("/retries").first

    redis.call("zrem", "retry", redis.members("retry").first)
    add_job("dead", jid: "jidcross", score: 1_700_000_000.0)

    request(:post, "/morgue", "key" => [token], "retry" => "Retry")
    assert_equal 409, last_response.status
    assert_equal 1, redis.members("dead").size
    assert_equal 0, redis.published_jobs.size
  end

  it "checks permission separately for bulk retry and bulk delete" do
    add_job("retry", jid: "jidbulk1")
    add_job("retry", jid: "jidbulk2", score: 1_700_000_001.0)
    policy { |_env, action, target| target[:bulk] && action == :retry }

    request(:post, "/retries/all/delete")
    assert_equal 403, last_response.status
    assert_equal 2, redis.members("retry").size
    assert_equal 0, redis.published_jobs.size

    request(:post, "/retries/all/retry")
    assert_equal 302, last_response.status
    assert_equal 0, redis.members("retry").size
    assert_equal %w[jidbulk1 jidbulk2], redis.published_jobs.map { |job| job["jid"] }.sort
  end

  it "keeps read-only access to listings and detail pages" do
    add_job("retry", jid: "jidreadonly")
    policy { |_env, _action, _target| false }

    request(:get, "/retries")
    assert_equal 200, last_response.status
    assert_match(/HardJob/, last_response.body)
    refute_match(/name="delete"/, last_response.body)

    request(:get, "/retries/1700000000.0-jidreadonly")
    assert_equal 200, last_response.status
    assert_match(/HardJob/, last_response.body)
  end

  it "still honours legacy score-jid keys when no per-action policy is set" do
    without_policy
    raw, score = add_job("retry", jid: "jidlegacy")
    key = "#{score}-jidlegacy"
    request(:post, "/retries", "key" => [key], "delete" => "Delete")
    assert_equal 302, last_response.status
    assert_equal 0, redis.members("retry").size
  end

  it "requires a fresh confirmation for legacy keys once a per-action policy is set" do
    raw, score = add_job("retry", jid: "jidlegacy2")
    policy { |_env, _action, _target| true }

    request(:post, "/retries", "key" => ["#{score}-jidlegacy2"], "delete" => "Delete")
    assert_equal 409, last_response.status
    assert_equal 1, redis.members("retry").size
  end

  it "renders a scheduled confirmation and moves it to the queue exactly once" do
    raw, score = add_job("schedule", jid: "jidsched", args: ["sched"])
    tokens = page_entries("/scheduled")
    token = tokens.first

    request(:post, "/scheduled", "key" => [token], "add_to_queue" => "AddToQueue")
    assert_equal 302, last_response.status
    assert_equal 0, redis.members("schedule").size
    assert_equal ["jidsched"], redis.published_jobs.map { |job| job["jid"] }

    request(:post, "/scheduled", "key" => [token], "add_to_queue" => "AddToQueue")
    assert_equal 200, last_response.status
    assert_equal "completed", last_response.headers["x-sidekiq-action-state"]
    assert_equal ["jidsched"], redis.published_jobs.map { |job| job["jid"] }
  end
end

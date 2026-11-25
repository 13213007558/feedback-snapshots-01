# frozen_string_literal: true

require "sidekiq"
require "sidekiq/api"
require "sidekiq/web"
require "minitest/autorun"
require_relative "web_memory_redis"


describe Sidekiq::Web::Confirmation do
  before do
    @original_config = Sidekiq.instance_variable_get(:@config)
    @original_web_pool = Sidekiq::Web.instance_variable_get(:@pool)

    redis = @redis = WebMemoryRedis.new
    pool = Object.new
    pool.define_singleton_method(:with) { |&blk| blk.call(redis) }
    cfg = Sidekiq::Config.new
    cfg.logger = Logger.new(IO::NULL)
    cfg.instance_variable_set(:@redis, pool)
    Sidekiq.instance_variable_set(:@config, cfg)
    Sidekiq::Web.redis_pool = pool
    Thread.current[:sidekiq_web_action_secret] = nil
  end

  after do
    Thread.current[:sidekiq_web_action_secret] = nil
    Sidekiq::Web.redis_pool = @original_web_pool
    Sidekiq.instance_variable_set(:@config, @original_config)
  end

  def token(**overrides)
    defaults = {set: "retry", key: "1700000000.0-jid1", value: "payload",
                actions: %i[retry cancel], jid: "jid1"}
    Sidekiq::Web::Confirmation.issue(**defaults.merge(overrides))
  end

  it "round trips the signed payload" do
    payload = Sidekiq::Web::Confirmation.decode(token)
    assert_equal "retry", payload["s"]
    assert_equal "1700000000.0-jid1", payload["k"]
    assert_equal "jid1", payload["j"]
    assert_equal %w[retry cancel], payload["a"]
    assert_equal Sidekiq::Web::Confirmation.digest("payload"), payload["d"]
  end

  it "rejects tampered payloads" do
    encoded, signature = token.split(".", 2)
    refute Sidekiq::Web::Confirmation.decode("#{encoded}x.#{signature}")
    refute Sidekiq::Web::Confirmation.decode("#{encoded}.#{"0" * signature.length}")
    refute Sidekiq::Web::Confirmation.decode("garbage")
    refute Sidekiq::Web::Confirmation.decode(nil)
  end

  it "does not validate a token issued for a different payload digest" do
    payload = Sidekiq::Web::Confirmation.decode(token(value: "original"))
    refute_equal Sidekiq::Web::Confirmation.digest("moved"), payload["d"]
  end

  it "records completion once even if claimed concurrently" do
    nonce = Sidekiq::Web::Confirmation.decode(token)["n"]
    assert_equal :free, Sidekiq::Web::Confirmation.state(nonce, :retry)
    assert_equal :claimed, Sidekiq::Web::Confirmation.claim(nonce, :retry)
    assert_equal :uncertain, Sidekiq::Web::Confirmation.claim(nonce, :retry)
    assert_equal :claimed, Sidekiq::Web::Confirmation.state(nonce, :retry)

    Sidekiq::Web::Confirmation.finish(nonce, :retry)
    assert_equal :completed, Sidekiq::Web::Confirmation.claim(nonce, :retry)
    assert_equal :completed, Sidekiq::Web::Confirmation.state(nonce, :retry)
  end

  it "is independent per action for the same token" do
    nonce = Sidekiq::Web::Confirmation.decode(token)["n"]
    assert_equal :claimed, Sidekiq::Web::Confirmation.claim(nonce, :retry)
    assert_equal :claimed, Sidekiq::Web::Confirmation.claim(nonce, :cancel)
  end

  it "rejects tokens older than the maximum age" do
    stale = Sidekiq::Web::Confirmation.issue(
      set: "retry", key: "1700000000.0-jid1", value: "payload",
      actions: %i[retry], jid: "jid1", i: Time.now.to_i - Sidekiq::Web::Confirmation::MAX_AGE - 1
    )
    assert_nil Sidekiq::Web::Confirmation.decode(stale)
  end

  it "carries a stable secret across threads and processes via Redis" do
    first = Sidekiq::Web::Confirmation.secret
    Thread.current[:sidekiq_web_action_secret] = nil
    second = Sidekiq::Web::Confirmation.secret
    assert_equal first, second
  end
end

# frozen_string_literal: true

require "minitest/autorun"
require "rack/mock"
require "sidekiq/web"
require "sidekiq/profiler"

# A tiny in-memory stand-in for the Redis commands Sidekiq uses to store
# profiles. Sorted-set scores model the internal retention deadline so expiry
# behavior can be exercised without a real Redis server.
class InMemoryRedis
  def initialize
    @hashes = {}
    @zsets = {}
    @server_url = "redis://memory:6379/0"
  end

  def config
    Struct.new(:server_url).new(@server_url)
  end

  def with
    yield self
  end

  def multi
    yield self
  end

  def pipelined
    collector = Pipeline.new(self)
    yield collector
    collector.results
  end

  def hset(key, *args)
    h = (@hashes[key] ||= {})
    if args.size == 1 && args.first.is_a?(Hash)
      args.first.each { |f, v| h[f.to_s] = v&.to_s }
    else
      h[args[0].to_s] = args[1]&.to_s
    end
    1
  end

  def hget(key, field)
    @hashes.dig(key, field.to_s)
  end

  def hmget(key, *fields)
    fields.map { |f| @hashes.dig(key, f.to_s) }
  end

  def hgetall(key)
    (@hashes[key] || {}).dup
  end

  def hdel(key, *fields)
    h = @hashes[key]
    return 0 unless h
    fields.count { |f| h.delete(f.to_s) }
  end

  def zadd(key, score, member)
    (@zsets[key] ||= {})[member.to_s] = Float(score)
    1
  end

  def zremrangebyscore(key, min, max)
    z = @zsets[key]
    return 0 unless z
    lo = min.to_s == "-inf" ? -Float::INFINITY : Float(min)
    hi = max.to_s == "+inf" ? Float::INFINITY : Float(max)
    removed = z.select { |_, s| s >= lo && s <= hi }.keys
    removed.each { |m| z.delete(m) }
    removed.size
  end

  def zrange(key, _start, _stop, *opts)
    members = (@zsets[key] || {}).sort_by { |_, s| s }.map(&:first)
    members.reverse! if opts.map(&:downcase).include?("rev")
    members
  end

  def expire(_key, seconds)
    seconds
  end

  def scard(_key) = 0
  def sscan(_key) = []
  def zcard(key) = (@zsets[key] || {}).size
  def get(_key) = nil
  def mget(keys) = keys.map { nil }
  def lindex(_key, _index) = nil
  def llen(_key) = 0

  class Pipeline
    def initialize(redis)
      @redis = redis
      @commands = []
    end

    def method_missing(name, *args)
      @commands << [name, args]
      self
    end

    def respond_to_missing?(*)
      true
    end

    def results
      @commands.map { |name, args| @redis.public_send(name, *args) }
    end
  end
end

# Writes a small placeholder payload to the requested output file and runs the
# block, mimicking Vernier's file-based contract without loading it.
class FakeProfiler
  def profile(out:, **)
    File.binwrite(out, "\x1f\x8bFAKE_PROFILE".b)
    yield
    :profile_result
  end
end

class FakeStore
  attr_reader :uploads

  def initialize
    @uploads = []
  end

  def upload(data)
    @uploads << data
    "sid-#{@uploads.size}"
  end
end

class FakeConfig
  def initialize(redis)
    @redis = redis
  end

  def redis(&block)
    @redis.with(&block)
  end

  def logger
    @logger ||= Logger.new(IO::NULL)
  end
end

class ProfileSharingTest < Minitest::Test
  KEY_RO = "readonly-111"
  KEY_TX = "transfer-222"

  def setup
    @redis = InMemoryRedis.new
    @store = FakeStore.new

    # Route Sidekiq.redis through the in-memory stand-in for this test process.
    @cfg = Sidekiq.default_configuration
    @old_pool = @cfg.instance_variable_get(:@redis)
    @cfg.instance_variable_set(:@redis, @redis)

    # Use a private Web config so this file neither depends on nor mutates the
    # process-wide Sidekiq::Web configuration (which other tests may freeze).
    @web_config = Sidekiq::Web::Config.new
    @web_config[:profile_view_url] = "https://view.local/public/%s"
    @web_config[:profile_store_url] = "https://store.local/upload"
    @web_config[:profile_store_client] = @store

    seed(KEY_RO, "readonly", "111", retained_for: 86_400)
    seed(KEY_TX, "transfer", "222", retained_for: 86_400)
  end

  def teardown
    @cfg.instance_variable_set(:@redis, @old_pool)
  end

  def seed(key, token, jid, retained_for:, retained_until: Time.now + retained_for)
    @redis.zadd("profiles", retained_until.to_f, key)
    @redis.hset(key,
      "started_at" => Time.now.to_i.to_s,
      "token" => token, "jid" => jid, "type" => "ProfileJob",
      "size" => "10", "elapsed" => "0.5",
      "retained_until" => retained_until.to_i.to_s,
      "data" => "GZIPDATA")
    @redis.expire(key, retained_for)
  end

  def request(method, path, params = {})
    env = Rack::MockRequest.env_for(path, method: method, params: params)
    env["HTTP_SEC_FETCH_SITE"] = "same-origin"
    env["rack.session"] = {}
    env[:web_config] = @web_config
    env[:csp_nonce] = "nonce"
    env[:redis_pool] = @redis
    Sidekiq::Web::Application.new(nil).call(env)
  end

  def approve(key, mode:, expires_in:)
    Sidekiq::ProfileRecord.fetch(key)
      .approve_share!(mode: mode, expires_at: Time.now + expires_in)
  end

  def test_read_only_record_reuses_cached_token_without_uploading
    approve(KEY_RO, mode: "read_only", expires_in: 3600)
    # Simulate a viewer token cached by an earlier transferable approval.
    @redis.hset(KEY_RO, "sid" => "cached-sid")

    status, headers, = request(:get, "/profiles/#{KEY_RO}")
    assert_equal 302, status
    assert_equal "https://view.local/public/cached-sid", headers["location"]
    assert_empty @store.uploads, "read-only approval must never upload"
  end

  def test_no_store_configured_blocks_view_without_uploading
    approve(KEY_TX, mode: "transfer", expires_in: 3600)
    @web_config[:profile_store_client] = nil
    @web_config[:profile_store_url] = nil

    status, headers, = request(:get, "/profiles/#{KEY_TX}")
    assert_equal 302, status
    assert_equal "/profiles", headers["location"]
    assert_empty @store.uploads

    # Download remains an internal operation and is unaffected.
    status, _, = request(:get, "/profiles/#{KEY_TX}/data")
    assert_equal 200, status
  end

  def test_listing_shows_per_record_state_and_controls
    approve(KEY_TX, mode: "transfer", expires_in: 3600)

    status, _, body = request(:get, "/profiles")
    assert_equal 200, status
    html = body.join

    assert_includes html, KEY_RO
    assert_includes html, KEY_TX
    assert_includes html, "Approve sharing"
    assert_includes html, "Revoke sharing"
    # Only the approved record gets a View link.
    assert_match(/href="[^"]*profiles\/transfer-222"/, html)
    refute_match(/href="[^"]*profiles\/readonly-111"/, html)
  end

  def test_share_and_revoke_routes_are_per_record
    status, headers, = request(:post, "/profiles/#{KEY_RO}/share",
      "mode" => "read_only", "hours" => "2")
    assert_equal 302, status
    assert_equal "http://example.org/profiles", headers["location"]

    ro = Sidekiq::ProfileRecord.fetch(KEY_RO)
    assert_equal "read_only", ro.share_mode
    assert ro.shareable?
    refute Sidekiq::ProfileRecord.fetch(KEY_TX).shareable?

    request(:post, "/profiles/#{KEY_RO}/share", "revoke" => "1")
    refute Sidekiq::ProfileRecord.fetch(KEY_RO).shareable?
  end

  def test_revoke_drops_cached_token_so_stale_links_stop_working
    approve(KEY_TX, mode: "transfer", expires_in: 3600)
    request(:get, "/profiles/#{KEY_TX}")
    assert_equal "sid-1", Sidekiq::ProfileRecord.fetch(KEY_TX).sid

    request(:post, "/profiles/#{KEY_TX}/share", "revoke" => "1")
    assert_nil Sidekiq::ProfileRecord.fetch(KEY_TX).sid

    status, headers, = request(:get, "/profiles/#{KEY_TX}")
    assert_equal 302, status
    assert_equal "/profiles", headers["location"]
    assert_equal 1, @store.uploads.size
  end

  def test_approves_sharing_per_record_only
    approve(KEY_RO, mode: "read_only", expires_in: 3600)

    ro = Sidekiq::ProfileRecord.fetch(KEY_RO)
    tx = Sidekiq::ProfileRecord.fetch(KEY_TX)

    assert ro.shareable?
    assert_equal "read_only", ro.share_mode
    refute tx.shareable?, "unapproved record must not inherit sharing"
  end

  def test_read_only_record_never_uploads
    approve(KEY_RO, mode: "read_only", expires_in: 3600)

    status, headers, = request(:get, "/profiles/#{KEY_RO}")
    assert_equal 302, status
    assert_equal "/profiles", headers["location"]
    assert_empty @store.uploads, "read-only approval must not contact the store"
  end

  def test_transferable_record_uploads_once_then_uses_cached_token
    approve(KEY_TX, mode: "transfer", expires_in: 3600)

    status, headers, = request(:get, "/profiles/#{KEY_TX}")
    assert_equal 302, status
    assert_equal "https://view.local/public/sid-1", headers["location"]
    assert_equal 1, @store.uploads.size

    # The cached token means the next view is served without another request.
    status, headers, = request(:get, "/profiles/#{KEY_TX}")
    assert_equal 302, status
    assert_equal "https://view.local/public/sid-1", headers["location"]
    assert_equal 1, @store.uploads.size, "cached token should avoid a second upload"
  end

  def test_revoking_before_send_blocks_the_external_request
    approve(KEY_TX, mode: "transfer", expires_in: 3600)
    Sidekiq::ProfileRecord.fetch(KEY_TX).revoke_share!

    status, headers, = request(:get, "/profiles/#{KEY_TX}")
    assert_equal 302, status
    assert_equal "/profiles", headers["location"]
    assert_empty @store.uploads, "revoked record must not be sent"
  end

  def test_revoking_keeps_internal_download_until_original_retention
    approve(KEY_TX, mode: "transfer", expires_in: 3600)
    Sidekiq::ProfileRecord.fetch(KEY_TX).revoke_share!

    status, headers, body = request(:get, "/profiles/#{KEY_TX}/data")
    assert_equal 200, status
    assert_equal "gzip", headers["content-encoding"]
    assert_equal "GZIPDATA", body.join
  end

  def test_share_expiry_stops_viewing_but_not_downloading
    # Approved, but the share window has already closed.
    Sidekiq::ProfileRecord.fetch(KEY_TX)
      .approve_share!(mode: "transfer", expires_at: Time.now + 60)
    @redis.hset(KEY_TX, "share_until" => (Time.now.to_i - 1).to_s)

    status, headers, = request(:get, "/profiles/#{KEY_TX}")
    assert_equal 302, status
    assert_equal "/profiles", headers["location"]
    assert_empty @store.uploads

    status, _, body = request(:get, "/profiles/#{KEY_TX}/data")
    assert_equal 200, status
    assert_equal "GZIPDATA", body.join
  end

  def test_expired_share_blocks_view_even_with_cached_token
    approve(KEY_TX, mode: "transfer", expires_in: 3600)
    request(:get, "/profiles/#{KEY_TX}")
    assert_equal "sid-1", Sidekiq::ProfileRecord.fetch(KEY_TX).sid

    # Move the share deadline into the past; the cached token alone is not enough.
    @redis.hset(KEY_TX, "share_until" => (Time.now.to_i - 1).to_s)

    status, headers, = request(:get, "/profiles/#{KEY_TX}")
    assert_equal 302, status
    assert_equal "/profiles", headers["location"]
    assert_equal 1, @store.uploads.size, "expiry must not trigger a new upload"
  end

  def test_retention_expiry_removes_the_record_and_denies_download
    seed("old-333", "old", "333", retained_for: 60, retained_until: Time.now - 1)

    refute_includes Sidekiq::ProfileSet.new.to_a.map(&:key), "old-333"
    assert_nil Sidekiq::ProfileRecord.fetch("old-333")

    status, _, = request(:get, "/profiles/old-333/data")
    assert_equal 404, status
  end

  def test_retained_record_still_listed
    keys = Sidekiq::ProfileSet.new.to_a.map(&:key)
    assert_includes keys, KEY_RO
    assert_includes keys, KEY_TX
  end

  def test_legacy_record_without_retention_field_stays_listed
    # Records written before per-record retention existed have no
    # retained_until; they fall back to the sorted-set deadline.
    @redis.hset("legacy-444", "started_at" => Time.now.to_i.to_s,
      "token" => "legacy", "jid" => "444", "type" => "ProfileJob",
      "size" => "1", "elapsed" => "0.1", "data" => "GZIPDATA")
    @redis.zadd("profiles", Time.now.to_f + 60, "legacy-444")

    record = Sidekiq::ProfileRecord.fetch("legacy-444")
    refute_nil record
    assert record.retained?
    assert_nil record.retained_until
    refute record.shareable?
  end

  def test_profiler_uses_temp_file_and_cleans_it_up
    dir = Dir.mktmpdir
    ENV["VERNIER_OUTPUT_DIR"] = dir
    profiler = Sidekiq::Profiler.new(FakeConfig.new(@redis), profiler: FakeProfiler.new)

    result = profiler.call({"profile" => "tok", "class" => "SomeJob", "jid" => "999"}) { 1 }
    assert_equal :profile_result, result

    record = Sidekiq::ProfileRecord.fetch("tok-999")
    refute_nil record
    assert_in_delta Time.now.to_i + Sidekiq::Profiler::EXPIRY, record.retained_until.to_i, 5
    refute record.shareable?, "fresh profiles are never shared without approval"

    assert_empty Dir.glob(File.join(dir, "*.json.gz")),
      "temporary profile file must be removed"
  ensure
    ENV.delete("VERNIER_OUTPUT_DIR")
    FileUtils.remove_entry(dir) if dir
  end
end

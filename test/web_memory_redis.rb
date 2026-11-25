# frozen_string_literal: true

require "set"

# A tiny in-memory Redis substitute for the Web UI action tests.
#
# It implements only the commands used by the Web UI's Retry/Scheduled/Dead
# listings and the confirmation ledger.  It records every membership change
# and every job publication, which lets tests compare what was actually
# changed in storage with what the page reported.
class WebMemoryRedis
  CommandError = Class.new(StandardError)

  attr_reader :published, :calls

  def initialize
    @data = Hash.new { |hash, key| hash[key] = {} }
    @published = []
    @calls = []
  end

  # ---- inspection helpers -------------------------------------------------

  def members(key)
    bucket = @data[key] or return []
    case bucket[:type]
    when :zset
      bucket[:members].sort_by { |member, score| [score, member] }.map(&:first)
    when :list
      bucket[:members]
    when :set
      bucket[:members]
    else
      []
    end
  end

  def score(key, member)
    bucket = @data[key]
    bucket && bucket[:type] == :zset ? bucket[:members][member] : nil
  end

  def type(key)
    bucket = @data[key]
    bucket ? bucket[:type].to_s : "none"
  end

  def exists?(key)
    @data.key?(key) && !@data[key].empty?
  end

  def published_jobs
    @published.map { |entry| Sidekiq.load_json(entry) }
  end

  def snapshot
    @data.transform_values { |bucket| bucket[:members].dup }
  end

  # ---- commands used by the Web UI ---------------------------------------

  def call(command, *args, **kwargs)
    name = command.to_s.downcase.tr(" ", "_")
    @calls << [name, args, kwargs]
    public_send(name, *args, **kwargs)
  end

  def del(*keys)
    keys.flatten.each { |key| @data.delete(key) }
    keys.flatten.size
  end

  def exists(key)
    exists?(key) ? 1 : 0
  end

  def flushdb
    @data.clear
    @published.clear
    @calls.clear
    "OK"
  end

  def close; end
  def ping = "PONG"
  def config = Struct.new(:server_url).new("redis://memory")

  # strings / hashes -------------------------------------------------------

  def get(key)
    bucket = @data[key]
    bucket &.[](:value)
  end

  def set(key, value, *args)
    options = args.flatten
    nx = options.include?("NX")
    existing = @data[key]
    return nil if nx && existing && !existing.empty?
    @data[key] = {type: :string, value: value.to_s}
    "OK"
  end

  def hset(key, *pairs)
    bucket = hash_bucket(key)
    fields = normalize_pairs(pairs)
    created = fields.keys.count { |field| !bucket[:members].key?(field) }
    bucket[:members].merge!(fields)
    created
  end

  def hsetnx(key, field, value)
    bucket = hash_bucket(key)
    return 0 if bucket[:members].key?(field.to_s)
    bucket[:members][field.to_s] = value.to_s
    1
  end

  def hget(key, field)
    bucket = @data[key]
    bucket && bucket[:type] == :hash ? bucket[:members][field.to_s] : nil
  end

  def hgetall(key)
    bucket = @data[key]
    bucket && bucket[:type] == :hash ? bucket[:members].dup : {}
  end

  def hmget(key, *fields)
    fields.flatten.map { |field| hget(key, field) }
  end

  def hdel(key, *fields)
    bucket = @data[key]
    return 0 unless bucket && bucket[:type] == :hash
    fields.flatten.count { |field| !bucket[:members].delete(field.to_s).nil? }
  end

  def expire(key, _seconds)
    exists?(key) ? 1 : 0
  end

  def incr(key)
    bucket = @data[key] ||= {type: :string, value: "0"}
    bucket[:value] = (bucket[:value].to_i + 1).to_s
    bucket[:value].to_i
  end

  def mget(*keys)
    keys.flatten.map { |key| get(key) }
  end

  def mset(*pairs)
    normalize_pairs(pairs).each { |key, value| set(key, value) }
    "OK"
  end

  # sets -------------------------------------------------------------------

  def sadd(key, *members)
    bucket = set_bucket(key)
    fresh = members.flatten.compact.count { |member| bucket[:members].add?(member.to_s) }
    fresh
  end

  def srem(key, *members)
    bucket = @data[key]
    return 0 unless bucket && bucket[:type] == :set
    members.flatten.count { |member| bucket[:members].delete(member.to_s) }
  end

  def sismember(key, member)
    bucket = @data[key]
    bucket && bucket[:type] == :set && bucket[:members].include?(member.to_s) ? 1 : 0
  end

  def scard(key)
    bucket = @data[key]
    bucket && bucket[:type] == :set ? bucket[:members].size : 0
  end

  def smembers(key)
    bucket = @data[key]
    bucket && bucket[:type] == :set ? bucket[:members].to_a : []
  end

  def sscan(key, **_opts)
    smembers(key)
  end

  # lists ------------------------------------------------------------------

  def lpush(key, *values)
    bucket = list_bucket(key)
    values.flatten.reverse_each do |value|
      bucket[:members].unshift(value)
      @published << value if key.start_with?("queue:")
    end
    bucket[:members].size
  end

  def rpush(key, *values)
    bucket = list_bucket(key)
    values.flatten.each { |value| bucket[:members].push(value) }
    bucket[:members].size
  end

  def lrange(key, start, finish)
    bucket = @data[key]
    return [] unless bucket && bucket[:type] == :list
    slice(bucket[:members], start, finish)
  end

  def llen(key)
    bucket = @data[key]
    bucket && bucket[:type] == :list ? bucket[:members].size : 0
  end

  def lindex(key, index)
    bucket = @data[key]
    return nil unless bucket && bucket[:type] == :list
    bucket[:members][index]
  end

  def lrem(key, count, value)
    bucket = @data[key]
    return 0 unless bucket && bucket[:type] == :list
    before = bucket[:members].size
    bucket[:members].delete(value)
    before - bucket[:members].size
  end

  def lpop(key)
    bucket = @data[key]
    return nil unless bucket && bucket[:type] == :list
    bucket[:members].shift
  end

  # sorted sets ------------------------------------------------------------

  def zadd(key, *args)
    bucket = zset_bucket(key)
    pairs = args.flatten.each_slice(2).to_a
    pairs.empty? ? 0 : nil
    pairs.count do |score, member|
      unless bucket[:members].key?(member)
        bucket[:members][member] = score.to_f
        true
      end
    end
  end

  def zcard(key)
    bucket = @data[key]
    bucket && bucket[:type] == :zset ? bucket[:members].size : 0
  end

  def zrem(key, *members)
    bucket = @data[key]
    return 0 unless bucket && bucket[:type] == :zset
    members.flatten.count { |member| !bucket[:members].delete(member).nil? }
  end

  def zrange(key, start, finish, *modes)
    flags = modes.flatten.map(&:to_s).map(&:downcase)
    byscore = flags.include?("byscore")
    withscores = flags.include?("withscores")
    reverse = flags.include?("rev")
    bucket = @data[key]
    return [] unless bucket && bucket[:type] == :zset

    sorted = bucket[:members].sort_by { |member, score| [score, member] }
    entries = if byscore
      low, high = [start, finish].map { |value| bound(value) }
      sorted.select { |_member, score| score >= low && score <= high }
    else
      slice(sorted, start.to_i, finish.to_i)
    end
    entries = entries.reverse if reverse
    withscores ? entries.map { |member, score| [member, score] } : entries.map(&:first)
  end

  def bound(value)
    case value.to_s
    when "-inf" then -Float::INFINITY
    when "+inf", "inf" then Float::INFINITY
    else value.to_f
    end
  end

  def zpopmin(key, count = 1)
    bucket = @data[key]
    return nil unless bucket && bucket[:type] == :zset && !bucket[:members].empty?
    sorted = bucket[:members].sort_by { |member, score| [score, member] }.first(count.to_i)
    sorted.each { |member, _score| bucket[:members].delete(member) }
    sorted.map { |member, score| [member, score.to_s] }
  end

  def zremrangebyscore(key, min, max)
    bucket = @data[key]
    return 0 unless bucket && bucket[:type] == :zset
    low = min.to_s == "-inf" ? -Float::INFINITY : min.to_f
    high = max.to_s == "+inf" ? Float::INFINITY : max.to_f
    removed = bucket[:members].select { |_member, score| score >= low && score <= high }.keys
    removed.each { |member| bucket[:members].delete(member) }
    removed.size
  end

  def zremrangebyrank(key, start, finish)
    bucket = @data[key]
    return 0 unless bucket && bucket[:type] == :zset
    sorted = bucket[:members].sort_by { |member, score| [score, member] }
    doomed = slice(sorted, start.to_i, finish.to_i).map(&:first)
    doomed.each { |member| bucket[:members].delete(member) }
    doomed.size
  end

  def zscan(key, match: "*", count: 100)
    return to_enum(:zscan, key, match: match, count: count) unless block_given?
    bucket = @data[key]
    return unless bucket && bucket[:type] == :zset
    pattern = Regexp.new("\\A#{Regexp.escape(match).gsub("\\*", ".*")}\\z")
    bucket[:members].sort_by { |member, score| [score, member] }.each do |member, score|
      yield [member, score] if pattern.match?(member)
    end
  end

  def unlink(*keys)
    del(*keys)
  end

  # transactions / pipelines ----------------------------------------------

  def multi
    results = []
    transaction = Transaction.new(self, results)
    yield transaction
    results
  end

  def pipelined
    results = []
    pipeline = Transaction.new(self, results)
    yield pipeline
    results
  end

  class Transaction
    def initialize(redis, results)
      @redis = redis
      @results = results
    end

    def method_missing(name, *args, **kwargs, &block)
      result = @redis.public_send(name, *args, **kwargs)
      if block
        nested = []
        block.call(Transaction.new(@redis, nested))
      end
      @results << result
      result
    end
  end

  private

  def hash_bucket(key)
    bucket = @data[key]
    return bucket if bucket && bucket[:type] == :hash
    @data[key] = {type: :hash, members: {}}
  end

  def set_bucket(key)
    bucket = @data[key]
    return bucket if bucket && bucket[:type] == :set
    @data[key] = {type: :set, members: Set.new}
  end

  def list_bucket(key)
    bucket = @data[key]
    return bucket if bucket && bucket[:type] == :list
    @data[key] = {type: :list, members: []}
  end

  def zset_bucket(key)
    bucket = @data[key]
    return bucket if bucket && bucket[:type] == :zset
    @data[key] = {type: :zset, members: {}}
  end

  def normalize_pairs(pairs)
    pairs = pairs.flatten
    pairs.each_slice(2).to_h.transform_keys(&:to_s).transform_values(&:to_s)
  end

  def slice(list, start, finish)
    start = start.to_i
    finish = finish.to_i
    start += list.size if start < 0
    finish += list.size if finish < 0
    # Redis clamps out-of-range bounds instead of returning nil/[].
    start = 0 if start < 0
    return [] if start > finish || start >= list.size
    list[start..finish] || []
  end

  # publish is used by Sidekiq::Client? It writes lists/sets directly, but keep
  # this for completeness and explicit publication recording.
  def publish(channel, message)
    @published << message
    0
  end
end

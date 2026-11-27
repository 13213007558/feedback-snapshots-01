require "fileutils"
require "sidekiq/component"

module Sidekiq
  # Allows the user to profile jobs running in production.
  # See details in the Profiling wiki page.
  class Profiler
    EXPIRY = 86400 # 1 day of internal retention
    DEFAULT_OPTIONS = {
      mode: :wall
    }

    include Sidekiq::Component

    def initialize(config, clock: Time, profiler: nil)
      @config = config
      @clock = clock
      @profiler = profiler
      @vernier_output_dir = ENV.fetch("VERNIER_OUTPUT_DIR") { Dir.tmpdir }
    end

    def call(job, &block)
      return yield unless job["profile"]

      token = job["profile"]
      type = job["wrapped"] || job["class"]
      jid = job["jid"]
      started_at = @clock.now
      retained_until = started_at.to_i + EXPIRY

      rundata = {
        started_at: started_at.to_i,
        token: token,
        type: type,
        jid: jid,
        # Sharing is never granted implicitly: a profile must be approved
        # record-by-record before it can leave this instance.
        retained_until: retained_until,
        # .gz extension tells Vernier to compress the data
        filename: File.join(
          @vernier_output_dir,
          "#{token}-#{type}-#{jid}-#{started_at.strftime("%Y%m%d-%H%M%S")}.json.gz"
        )
      }
      profiler_options = profiler_options(job, rundata)

      profiler = @profiler || begin
        require "vernier"
        Vernier
      end
      begin
        a = @clock.now
        rc = profiler.profile(**profiler_options, &block)
        b = @clock.now

        # Failed jobs will raise an exception on previous line and skip this
        # block. Only successful jobs will persist profile data to Redis.
        key = "#{token}-#{jid}"
        data = File.read(rundata[:filename])
        redis do |conn|
          conn.multi do |m|
            # The sorted set score is the internal retention deadline.
            m.zadd("profiles", retained_until, key)
            # Clear any sharing state left over from an older record with
            # the same token/jid so a new profile never inherits approval.
            m.hdel(key, "share_until", "share_mode", "share_approved_at", "sid")
            m.hset(key, rundata.merge(elapsed: (b - a), data: data, size: data.bytesize))
            m.expire(key, EXPIRY)
          end
        end
        rc
      ensure
        # The temporary profiling artifact lives only as long as this job.
        FileUtils.rm_f(rundata[:filename])
      end
    end

    private

    def profiler_options(job, rundata)
      profiler_options = (job["profiler_options"] || {}).transform_keys(&:to_sym)
      profiler_options[:mode] = profiler_options[:mode].to_sym if profiler_options[:mode]

      DEFAULT_OPTIONS.merge(profiler_options, {out: rundata[:filename]})
    end
  end
end

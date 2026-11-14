# frozen_string_literal: true

require "rack"

module SidechannelLab
  # Option A (recommended): path-based gate. It runs *before* Rack::Deflater
  # and never needs to inspect (or rewind) the body, so streaming responses
  # keep streaming. Sensitive paths bypass compression entirely and are marked
  # Cache-Control: no-transform so every conforming proxy also leaves them
  # alone; public paths still flow through normal gzip compression.
  class SelectiveDeflation
    NO_TRANSFORM = "no-transform"

    # @param app inner Rack app
    # @param sensitive matcher against PATH_INFO (Regexp, Array, #===)
    def initialize(app, sensitive: %r{\A/(reflection|separate|stream|token-only)(\z|/)}, &public_app)
      @app = app
      @sensitive = sensitive
      @public_app = public_app
    end

    def call(env)
      status, headers, body = @app.call(env)
      path = env[Rack::PATH_INFO]

      if sensitive?(path)
        mark_no_transform(headers)
        [status, headers, body]
      elsif @public_app
        @public_app.call(env)
      else
        [status, headers, body]
      end
    end

    private

    def sensitive?(path)
      @sensitive === path
    end

    def mark_no_transform(headers)
      cache_control = headers[Rack::CACHE_CONTROL].to_s
        .split(",").map(&:strip).reject(&:empty?)
      cache_control << NO_TRANSFORM unless cache_control.include?(NO_TRANSFORM)
      cache_control << "private" unless cache_control.include?("private")
      headers[Rack::CACHE_CONTROL] = cache_control.join(", ")
    end
  end

  # Option B: the inner app/ middleware marks a request in the Rack
  # environment. Rack::Deflater's :if condition runs *after* the downstream
  # app returns, so the marker is visible there. Routing knowledge stays in
  # the app instead of a path list.
  module SensitiveMarker
    SENSITIVE_ENV_KEY = "sidechannel.sensitive"

    def self.new(app)
      lambda do |env|
        status, headers, body = app.call(env)
        env[SENSITIVE_ENV_KEY] = true if headers["x-sensitive"] == "1"
        [status, headers, body]
      end
    end
  end

  # Rack::Deflater :if condition for Option B.
  DEFLATE_UNLESS_MARKED = lambda { |env, _status, _headers, _body|
    !env[SensitiveMarker::SENSITIVE_ENV_KEY]
  }

  # Reference stack: gate wraps a Deflater that only sees public responses.
  # The gate yields the *env* of a public request to the pipeline, which runs
  # the inner app itself; sensitive requests never enter the Deflater.
  def self.build_stack
    app = SidechannelLab::App.new
    deflater = Rack::Deflater.new(app)
    SelectiveDeflation.new(app) do |env|
      deflater.call(env)
    end
  end

  # Alternative stack using the env marker + Deflater :if condition.
  def self.build_marker_stack(sync: true)
    app = SidechannelLab::App.new
    marked = SensitiveMarker.new(app)
    Rack::Deflater.new(marked, sync: sync, if: DEFLATE_UNLESS_MARKED)
  end
end

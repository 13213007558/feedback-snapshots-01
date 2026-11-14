# frozen_string_literal: true

require 'uri'
require 'stringio'

require_relative 'constants'

module Rack
  # Rack::ForwardRequest gets caught by Rack::Recursive and redirects
  # the current request to the app at +url+.
  #
  #   raise ForwardRequest.new("/not-found")
  #
  # A ForwardRequest only carries the target URL and whatever the raising
  # application explicitly placed in its env. The receiving
  # Rack::Recursive re-applies its Rack::InternalPolicy, so raising a
  # ForwardRequest cannot widen the reachable targets or smuggle the
  # outer request's credentials into the subrequest.

  class ForwardRequest < Exception
    attr_reader :url, :env

    def initialize(url, env = {})
      @url = URI(url)
      @env = env.dup

      @env[PATH_INFO]       = @url.path
      @env[QUERY_STRING]    = @url.query.to_s
      @env[HTTP_HOST]       = @url.host   if @url.host
      @env[HTTP_PORT]       = @url.port   if @url.port
      @env[RACK_URL_SCHEME] = @url.scheme if @url.scheme

      super "forwarding to #{url}"
    end
  end

  # Explicit policy for internal subrequests performed through
  # Rack::Recursive, covering both +rack.recursive.include+ calls and
  # raised Rack::ForwardRequest objects.
  #
  # A policy answers two questions:
  #
  # 1. Which targets may a subrequest reach? +allowed_paths+ lists path
  #    prefixes that are considered internal. Anything outside those
  #    prefixes is rejected before the target application is called. A
  #    nil value means "any path on this same application", which keeps
  #    the historical Rack::Recursive behavior; mounting under a
  #    SCRIPT_NAME further restricts includes to that mount point.
  # 2. Which already-verified identity facts may travel with the
  #    subrequest? +identity_facts+ is an allowlist of env keys holding
  #    facts established by an upstream authenticator. Credential
  #    headers and every other request fact are stripped instead of
  #    being inherited, and the allowlist is re-applied on every nested
  #    hop.
  #
  # The policy only forwards facts it can name; it never copies the
  # whole outer environment on trust.

  class InternalPolicy
    # Env-key prefix for identity facts established inside the trust
    # boundary (for example by an authenticator mounted before
    # Rack::Recursive). Keys using this prefix are removed from
    # subrequests unless they are explicitly listed in +identity_facts+,
    # so a client cannot forge an internal fact by sending the matching
    # header on the outer request.
    IDENTITY_PREFIX = 'rack.internal.identity.'

    # Credential-bearing headers that never cross an internal boundary
    # unless an operator explicitly names the corresponding env key in
    # +identity_facts+.
    CREDENTIAL_HEADERS = %w[
      HTTP_AUTHORIZATION
      HTTP_PROXY_AUTHORIZATION
      HTTP_COOKIE
      HTTP_X_CSRF_TOKEN
      HTTP_X_ACCESS_TOKEN
      HTTP_X_AUTH_TOKEN
      HTTP_X_API_KEY
    ].freeze

    # Rack::Request memoization keys. A subrequest parses its own query
    # string and body from its own env, so inherited caches are always
    # discarded to prevent stale GET/POST/cookie data from leaking.
    REQUEST_CACHE_KEYS = %w[
      rack.request.query_hash
      rack.request.query_string
      rack.request.form_hash
      rack.request.form_pairs
      rack.request.form_vars
      rack.request.form_input
      rack.request.form_error
      rack.request.cookie_hash
      rack.request.cookie_string
      rack.request.config
    ].freeze

    attr_reader :allowed_paths, :identity_facts

    def initialize(allowed_paths: nil, identity_facts: [])
      @allowed_paths = allowed_paths && Array(allowed_paths).map(&:dup)
      @identity_facts = Array(identity_facts).map { |key| key.to_s.dup }.freeze

      @allowed_paths&.each do |path|
        unless path.start_with?('/')
          raise ArgumentError, "allowed paths must start with /, got #{path.inspect}"
        end
      end

      @identity_facts.each do |key|
        unless valid_identity_key?(key)
          raise ArgumentError,
            "identity fact #{key.inspect} is not a valid env key " \
            "(use an HTTP_ header or a namespaced rack. key)"
        end
      end
    end

    # True when +path+ equals an allowed prefix or is nested directly
    # below one. A prefix never matches a sibling sharing the same
    # leading string (e.g. +/internal+ does not allow +/internal-secret+).
    def allows_path?(path)
      return false if path.nil? || !path.start_with?('/')
      return true if @allowed_paths.nil?

      @allowed_paths.any? do |prefix|
        path == prefix || path.start_with?("#{prefix}/")
      end
    end

    def allows_identity?(key)
      @identity_facts.include?(key)
    end

    # Copy only the explicitly allowed identity facts from +env+ into a
    # fresh hash. Values not present on the outer request are not
    # synthesized, and unlisted identity-prefixed keys never survive.
    def propagate_identity(env)
      @identity_facts.each_with_object({}) do |key, propagated|
        propagated[key] = env[key] if env.key?(key)
      end
    end

    private

    def valid_identity_key?(key)
      key.include?('.') || key.start_with?('HTTP_') ||
        key == CONTENT_TYPE || key == CONTENT_LENGTH
    end
  end

  # Raised when a subrequest targets a path outside the configured
  # Rack::InternalPolicy. It is a StandardError so applications can
  # handle a denied internal hop without rescuing the control-flow
  # Rack::ForwardRequest exception.
  class ForwardingDenied < StandardError
  end

  # Rack::Recursive allows applications called down the chain to
  # include data from other applications (by using
  # <tt>rack['rack.recursive.include'][...]</tt> or raise a
  # ForwardRequest to redirect internally.
  #
  # Every subrequest runs behind an explicit Rack::InternalPolicy that
  # bounds the reachable targets and the verified identity facts that
  # may be propagated. Subrequests receive a copy of the outer env with
  # credentials and parsed GET/POST/cookie caches removed, so changing
  # the path, query string or body cannot borrow the outer request's
  # parameters, and mutations made by a target application cannot leak
  # back into the request that continues after the subrequest returns.

  class Recursive
    def initialize(app, policy = nil, **options)
      @app = app
      @policy = policy || InternalPolicy.new(**options)
    end

    def call(env)
      dup._call(env)
    end

    def _call(env)
      @script_name = env[SCRIPT_NAME]
      dispatch(env)
    end

    # Perform an internal GET against +path+ (interpreted relative to
    # the current SCRIPT_NAME) and return its Rack response triple. A
    # query string embedded in +path+ is honored by the subrequest
    # instead of the outer request's query string.
    def include(env, path)
      path, query = path.split('?', 2)
      ensure_below_mount!(path)

      target = full_path(path)
      ensure_allowed!(target)

      subrequest = build_subrequest(env)
      apply_identity!(subrequest, env)
      subrequest[RACK_RECURSIVE_INCLUDE] = method(:include)
      subrequest[PATH_INFO] = target
      subrequest[SCRIPT_NAME] = @script_name
      subrequest[REQUEST_METHOD] = GET
      subrequest[QUERY_STRING] = query.to_s
      subrequest[CONTENT_LENGTH] = '0'
      subrequest[CONTENT_TYPE] = ''
      subrequest[RACK_INPUT] = StringIO.new(String.new)

      dispatch(subrequest)
    end

    private

    # Every dispatch, including nested subrequests, routes a raised
    # ForwardRequest back through the policy so a nested hop cannot
    # escape the configured target scope.
    def dispatch(env)
      @app.call(env.merge(RACK_RECURSIVE_INCLUDE => method(:include)))
    rescue ForwardRequest => request
      forward(request, env)
    end

    def forward(request, outer_env)
      target = request.url.path
      ensure_allowed!(target)

      # The raising application may pass extra env entries, but the
      # outer request supplies the base env; explicit entries on the
      # ForwardRequest win, matching the historical env.merge behavior.
      source_env = outer_env.merge(request.env)
      subrequest = build_subrequest(source_env)
      # Identity facts are re-projected from the outer request only, so
      # an application cannot forge or escalate a fact by placing it in
      # the ForwardRequest env.
      apply_identity!(subrequest, outer_env)
      subrequest[RACK_RECURSIVE_INCLUDE] = method(:include)
      subrequest[SCRIPT_NAME] = outer_env[SCRIPT_NAME]
      subrequest[PATH_INFO] = target
      subrequest[QUERY_STRING] = request.url.query.to_s
      subrequest[HTTP_HOST] = request.url.host if request.url.host
      subrequest[HTTP_PORT] = request.url.port if request.url.port
      subrequest[RACK_URL_SCHEME] = request.url.scheme if request.url.scheme

      dispatch(subrequest)
    end

    # Preserve the historical guarantee that includes stay below the
    # SCRIPT_NAME at which this middleware was reached.
    def ensure_below_mount!(path)
      at_mount = path.index(@script_name) == 0 &&
                 (path[@script_name.size] == '/' ||
                  path[@script_name.size].nil?)
      return if at_mount

      raise ArgumentError, "can only include below #{@script_name}, not #{path}"
    end

    def ensure_allowed!(path)
      return if @policy.allows_path?(path)

      raise ForwardingDenied,
        "internal forwarding to #{path.inspect} is not permitted by the policy"
    end

    def full_path(path)
      "#{@script_name}#{path}"
    end

    # Build the isolated env used for a subrequest. The outer env is
    # never mutated: callers keep executing with their original env once
    # the subrequest completes or raises. Credentials, identity facts and
    # parsed-request caches are stripped; the caller is responsible for
    # re-projecting the explicitly allowed identity facts from a trusted
    # source via apply_identity!.
    def build_subrequest(env)
      subrequest = {}

      env.each do |key, value|
        subrequest[key] = value unless denied_subrequest_key?(key)
      end

      if (input = subrequest[RACK_INPUT]).respond_to?(:rewind)
        # Let the subrequest read the body from the beginning without
        # depending on the read position left by the outer application.
        input.rewind
      end

      subrequest
    end

    # Copy only the policy-allowed identity facts from +trusted_env+
    # (the request that entered this middleware hop) into +subrequest+.
    # Values present on a ForwardRequest's custom env but absent from
    # the trusted chain are ignored.
    def apply_identity!(subrequest, trusted_env)
      subrequest.merge!(@policy.propagate_identity(trusted_env))
    end

    def denied_subrequest_key?(key)
      return true if InternalPolicy::REQUEST_CACHE_KEYS.include?(key)
      return true if InternalPolicy::CREDENTIAL_HEADERS.include?(key)
      return true if key.start_with?(InternalPolicy::IDENTITY_PREFIX)
      return true if key.start_with?('rack.request.')

      false
    end
  end
end

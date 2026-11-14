# frozen_string_literal: true

require_relative 'constants'

module Rack
  # Rack::Cascade tries a request on several apps, and returns the
  # first response that is not 404 or 405 (or in a list of configured
  # status codes).  If all applications tried return one of the configured
  # status codes, return the last response.
  #
  # == Environment isolation
  #
  # Every candidate application receives the very same +env+ object, so by
  # default any changes an application makes are visible to the applications
  # tried afterwards.  An application that ultimately rejects the request (by
  # returning a cascading status) can therefore establish state that a later
  # application then trusts, for example by setting <tt>REMOTE_USER</tt> or by
  # populating a parsed parameter cache such as
  # <tt>rack.request.query_hash</tt> / <tt>rack.request.form_hash</tt>.
  #
  # Pass <tt>isolate: true</tt> to opt in to per-application environment
  # isolation.  While isolation is enabled, each application is invoked against
  # a private copy of the mutable parts of the environment:
  #
  # * Hash and Array values are deep duplicated, so a cached parameter or
  #   session hash can never be shared between applications.  A plain
  #   +env.dup+ (a shallow copy) is deliberately not used, because it would
  #   still share every nested mutable hash.
  # * Values that are not plain containers (IO streams, Tempfiles, query
  #   parser objects, application specific value objects, ...) are kept by
  #   reference; they are not duplicated.
  #
  # When an application accepts the request (returns a non-cascading status),
  # its environment changes are committed back onto the original +env+ and the
  # response is returned.  When an application rejects the request, its private
  # environment is discarded and the original +env+ is restored, so the next
  # application starts from exactly the state handed to Rack::Cascade:
  #
  # * Scalar values (+REMOTE_USER+, +SCRIPT_NAME+, +PATH_INFO+, ...) are
  #   restored to what they were before the rejected application ran, and keys
  #   the application introduced are removed.
  # * The request body stream <tt>rack.input</tt> is never replaced or closed;
  #   after a rejection it is rewound so the next application can read the
  #   whole body again.
  # * Any entries added to <tt>rack.tempfiles</tt> while processing a rejected
  #   application are closed and unlinked before the next application runs.
  # * The rejected application's response body is closed, exactly as for a
  #   non-isolated cascade.
  class Cascade
    # The environment keys whose values are stream/IO objects rather than
    # plain data.  They are never duplicated or replaced; +rack.input+ is only
    # rewound after a rejected attempt and +rack.errors+ is left untouched.
    STREAM_KEYS = [RACK_INPUT, RACK_ERRORS].freeze

    # Environment keys that, when present, hold an Array of Tempfile objects
    # created while parsing the request.  Tempfiles added by a rejected
    # application must be reaped so they do not leak onto the next attempt.
    TEMPFILES_KEY = RACK_TEMPFILES

    # An array of applications to try in order.
    attr_reader :apps

    # Set the apps to send requests to, and what statuses result in
    # cascading.  Arguments:
    #
    # apps: An enumerable of rack applications.
    # cascade_for: The statuses to use cascading for.  If a response is received
    #              from an app, the next app is tried.
    # isolate: When true, give each application a private deep copy of the
    #          mutable environment and restore the original environment after
    #          any application that returns a cascading status.  This prevents
    #          an application that rejects a request from leaving
    #          authentication facts or cached parameters for a later
    #          application to inherit.  Defaults to false to preserve the
    #          historical shared-environment behavior.
    def initialize(apps, cascade_for = [404, 405], isolate: false)
      @apps = []
      apps.each { |app| add app }

      @cascade_for = {}
      [*cascade_for].each { |status| @cascade_for[status] = true }

      @isolate = isolate
    end

    # Call each app in order.  If the responses uses a status that requires
    # cascading, try the next app.  If all responses require cascading,
    # return the response from the last app.
    #
    # When isolation is enabled, a rejecting app's environment mutations are
    # rolled back before the next app is tried, while an accepting app's
    # mutations are committed to the shared environment.
    def call(env)
      return [404, { CONTENT_TYPE => "text/plain" }, []] if @apps.empty?
      result = nil
      last_body = nil

      @apps.each do |app|
        # The SPEC says that the body must be closed after it has been iterated
        # by the server, or if it is replaced by a middleware action. Cascade
        # replaces the body each time a cascade happens. It is assumed that nil
        # does not respond to close, otherwise the previous application body
        # will be closed. The final application body will not be closed, as it
        # will be passed to the server as a result.
        last_body.close if last_body.respond_to? :close

        if @isolate
          snapshot = snapshot_env(env)
          attempt_env = build_attempt_env(env, snapshot)
          result = app.call(attempt_env)

          if @cascade_for.include?(result[0].to_i)
            last_body = result[2]
            rollback_env(env, snapshot, attempt_env)
            next
          end

          commit_env(env, snapshot, attempt_env)
          return result
        end

        result = app.call(env)
        return result unless @cascade_for.include?(result[0].to_i)
        last_body = result[2]
      end

      result
    end

    # Append an app to the list of apps to cascade.  This app will
    # be tried last.
    def add(app)
      @apps << app
    end

    # Whether the given app is one of the apps to cascade to.
    def include?(app)
      @apps.include?(app)
    end

    alias_method :<<, :add

    private

    # Capture the values a restoring attempt must be able to put back.
    # Stream IO objects are remembered as references (never copied), while
    # every plain Hash/Array value is deep duplicated so the snapshot cannot
    # be mutated through the working environment.
    def snapshot_env(env)
      snapshot = {}
      env.each do |key, value|
        snapshot[key] =
          if STREAM_KEYS.include?(key)
            value
          else
            deep_dup(value)
          end
      end
      snapshot
    end

    # Build the environment handed to a single application.  Stream keys keep
    # referencing the shared IO objects; everything else starts from a fresh
    # deep copy, so nested hashes (parameter caches, sessions, ...) are not
    # shared with the caller's environment.
    def build_attempt_env(env, snapshot)
      attempt = {}
      env.each_key do |key|
        attempt[key] =
          if STREAM_KEYS.include?(key)
            env[key]
          else
            deep_dup(snapshot[key])
          end
      end
      attempt
    end

    # Discard a rejecting application's environment.  Scalar keys and nested
    # hashes are restored from the snapshot, keys introduced by the attempt
    # are removed, the input stream is rewound, and tempfiles it created are
    # reaped.
    def rollback_env(env, snapshot, attempt_env)
      restore_env(env, snapshot)
      rewind_input(env)
      reap_tempfiles(snapshot, attempt_env)
    end

    # Publish an accepting application's environment back onto the shared
    # environment so downstream middleware and the server observe it.  The
    # input stream is deliberately not rewound: an accepting application is
    # allowed to have consumed the body.
    def commit_env(env, _snapshot, attempt_env)
      env.replace(attempt_env)
    end

    # Restore +env+ to exactly the keys/values captured in +snapshot+.
    def restore_env(env, snapshot)
      env.delete_if { |key,| !snapshot.key?(key) }
      snapshot.each do |key, value|
        env[key] =
          if STREAM_KEYS.include?(key)
            value
          else
            deep_dup(value)
          end
      end
    end

    # Rewind the request body so a later application can consume it from the
    # beginning.  The stream is shared server-owned state and is never closed
    # or replaced here.
    #
    # rack.input is only optionally rewindable per the Rack SPEC, so this is a
    # no-op when the stream does not expose #rewind.  Deployments that need a
    # later application to re-read a body consumed by a rejecting one should
    # place Rack::RewindableInput in front of the cascade.
    def rewind_input(env)
      input = env[RACK_INPUT]
      input.rewind if input.respond_to?(:rewind)
    end

    # Close and unlink Tempfiles that the rejected attempt registered but
    # that were not part of the pre-attempt environment.
    def reap_tempfiles(snapshot, attempt_env)
      original = snapshot[TEMPFILES_KEY] || []
      created = attempt_env[TEMPFILES_KEY]
      return unless created

      (created - original).each do |tempfile|
        tempfile.close! if tempfile.respond_to?(:close!)
      end
    end

    # Deep duplicate plain containers while leaving every other object
    # (IO, Tempfile, parser, value object, ...) by reference.  This is what
    # makes the isolation real: a shallow dup would still share nested hashes.
    #
    # #dup is used rather than building a new Hash/Array so that subclasses
    # (for example a session hash) and a Hash default block keep their class
    # and behavior.  A frozen container still yields a writable copy because
    # #dup does not preserve the frozen state.
    def deep_dup(value)
      case value
      when Hash
        copy = value.dup
        copy.each_key { |key| copy[key] = deep_dup(copy[key]) }
        copy
      when Array
        value.dup.map! { |element| deep_dup(element) }
      else
        value
      end
    end
  end
end

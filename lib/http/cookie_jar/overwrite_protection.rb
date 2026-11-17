# :markup: markdown

class HTTP::CookieJar
  # An optional policy that prevents cookies received over an insecure
  # transport from overwriting, shadowing, or deleting an existing
  # Secure cookie.
  #
  # The policy is intentionally narrower than "drop every cookie from
  # an HTTP origin".  It only rejects an incoming cookie when an
  # existing, unexpired Secure cookie has the same name and shares a
  # send scope with it.  Cookies with different names, unrelated
  # domains, or disjoint paths are still stored normally.
  #
  # Two cookies are considered to share a send scope when the domain
  # scopes intersect (taking the host-only flag and parent domains into
  # account) and the paths overlap as defined by RFC 6265 5.1.4.
  #
  # A deletion cookie (an expired cookie, typically sent as `Max-Age=0`
  # or with a past `Expires` value) is treated separately: it may only
  # delete a Secure cookie stored under the same name, domain and path.
  # The `host-only` flag does not change that identity in HashStore, so a
  # host-only and a parent-domain cookie with the same domain and path
  # are conservatively considered to collide.  A deletion for another
  # domain or path is stored normally and leaves the Secure cookie alone.
  #
  # Example:
  #
  #     audit = lambda { |event| logger.warn(event.inspect) }
  #     jar = HTTP::CookieJar.new(
  #       :overwrite_protection => { :audit => audit })
  #
  #     # Accepted: a new secure value from an HTTPS origin may replace it.
  #     # Rejected: the same-name value from an HTTP origin is not stored.
  #     jar.parse("sid=login; Secure; Path=/login", "https://example.com/login")
  #     jar.parse("sid=shadow; Path=/login", "http://example.com/login")
  #
  # Audit events contain only scope information and a reason.  Cookie
  # values are never included.
  class OverwriteProtection
    # Reasons reported in audit events.
    REASON_OVERWRITE = :insecure_overwrite_of_secure_cookie
    REASON_SHADOW    = :insecure_shadowing_of_secure_cookie
    REASON_DELETION  = :insecure_deletion_of_secure_cookie

    class << self
      # Builds a policy from an option value.
      #
      # `nil` and `false` disable the policy.  `true` enables it with
      # the default settings.  A Hash is passed to the constructor, and
      # an existing OverwriteProtection is returned as is.
      def build(value, defaults = nil)
        case value
        when nil, false
          nil
        when true
          new(defaults)
        when Hash
          new(defaults ? defaults.merge(value) : value)
        when self
          value
        else
          raise TypeError, 'invalid overwrite protection: %s' % value.class
        end
      end
    end

    # :call-seq:
    #   new(**options)
    #
    # Available options are:
    #
    # :protect_secure
    # : Whether to protect Secure cookies.  (default: `true`)
    #
    # :audit
    # : A callable object that receives a frozen Hash for each rejected
    #   cookie.  The Hash contains `:event`, `:reason`, `:deletion`,
    #   `:incoming` and `:protected`.  Only scope information (name,
    #   domain, host-only flag, path, secure flag and origin scheme/host)
    #   is included; no cookie value is ever exposed.
    #
    # :logger
    # : A Logger-like object that receives a warning for each rejected
    #   cookie.  The message contains the same scope information as the
    #   audit event and no cookie value.
    def initialize(options = nil)
      case options
      when nil
        options = {}
      when Hash
        options = options.dup
      else
        raise TypeError, 'invalid options: %s' % options.class
      end
      @protect_secure = options.fetch(:protect_secure, true)
      @audit = options[:audit]
      @logger = options[:logger]
      @rejected_count = 0
    end

    # Whether Secure cookies are protected.
    attr_reader :protect_secure

    # The audit callback.
    attr_reader :audit

    # The logger used for audit warnings.
    attr_reader :logger

    # The number of cookies rejected by this policy so far.
    attr_reader :rejected_count

    # Checks `incoming` against the cookies currently in the store.
    # `stored_cookies` can be any enumerable of cookies, including a
    # store.  It is only enumerated when the policy may apply.
    #
    # Returns a frozen audit event Hash if the cookie must be rejected,
    # or nil if it may be stored.
    def check(incoming, stored_cookies)
      return nil unless @protect_secure
      return nil if trusted_source?(incoming)

      deletion = incoming.expired?
      protected = []
      exact_collision = false

      stored_cookies.each { |existing|
        next unless existing.name == incoming.name
        next unless existing.secure?
        next if existing.expired?

        if deletion
          next unless same_storage_identity?(incoming, existing)
        else
          next unless send_scopes_overlap?(incoming, existing)
        end

        protected << existing
        exact_collision ||= same_storage_identity?(incoming, existing)
      }

      return nil if protected.empty?

      reason = if deletion
                 REASON_DELETION
               elsif exact_collision
                 REASON_OVERWRITE
               else
                 REASON_SHADOW
               end

      {
        :event => :cookie_overwrite_rejected,
        :reason => reason,
        :deletion => deletion,
        :incoming => scope_of(incoming),
        :protected => protected.map { |cookie| scope_of(cookie) }.freeze,
      }.freeze
    end

    # Records an audit event, increments the rejected counter and
    # returns the event.
    def record(event)
      @rejected_count += 1
      @audit.call(event) if @audit
      if @logger
        @logger.warn('cookie overwrite rejected: %s incoming=%s protected=%s' % [
            event[:reason],
            scope_label(event[:incoming]),
            event[:protected].map { |scope| scope_label(scope) }.join(','),
          ])
      end
      event
    end

    private

    # A cookie is only trusted to replace a Secure cookie when it was
    # actually received over HTTPS.  A cookie without an origin is
    # trusted only if it is explicitly marked Secure; otherwise the
    # provenance is unknown and the policy fails closed.
    def trusted_source?(cookie)
      origin = cookie.origin
      return cookie.secure? if origin.nil?
      URI::HTTPS === origin
    end

    # The storage identity used by HashStore: name, domain and path.
    # The host-only flag is deliberately not part of it.
    def same_storage_identity?(a, b)
      a.name == b.name && a.domain == b.domain && a.path == b.path
    end

    def send_scopes_overlap?(a, b)
      domain_scopes_overlap?(a, b) && path_scopes_overlap?(a.path, b.path)
    end

    def domain_scopes_overlap?(a, b)
      da = a.domain_name
      db = b.domain_name
      return false unless da && db
      return da == db if da.ipaddr? || db.ipaddr?

      case
      when a.for_domain? && b.for_domain?
        subdomain_or_equal?(da, db) || subdomain_or_equal?(db, da)
      when a.for_domain?
        subdomain_or_equal?(db, da)
      when b.for_domain?
        subdomain_or_equal?(da, db)
      else
        da == db
      end
    end

    def subdomain_or_equal?(host, parent)
      host == parent || host.cookie_domain?(parent)
    end

    def path_scopes_overlap?(a, b)
      HTTP::Cookie.path_match?(a, b) || HTTP::Cookie.path_match?(b, a)
    end

    def scope_of(cookie)
      {
        :name => cookie.name,
        :domain => cookie.domain,
        :for_domain => cookie.for_domain?,
        :path => cookie.path,
        :secure => cookie.secure?,
        :origin => origin_scope(cookie.origin),
      }.freeze
    end

    def origin_scope(origin)
      return nil unless origin
      {
        :scheme => origin.scheme,
        :host => origin.host,
        :port => origin.port,
      }.freeze
    end

    def scope_label(scope)
      domain = scope[:for_domain] ? '.%s' % scope[:domain] : scope[:domain]
      origin = scope[:origin]
      source = origin ? '%s://%s' % [origin[:scheme], origin[:host]] : 'unknown'
      '%s@%s%s (%s)' % [scope[:name], domain, scope[:path], source]
    end
  end
end

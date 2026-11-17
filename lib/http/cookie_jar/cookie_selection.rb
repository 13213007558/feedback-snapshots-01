# :markup: markdown

class HTTP::CookieJar
  # Raised when an authentication value is requested for a cookie name
  # that matches more than one cookie eligible for the URL, so that no
  # single identity can be chosen unambiguously.
  class AmbiguousCookieError < StandardError
  end

  # Raised when an authentication value is requested for a cookie name
  # that no cookie eligible for the URL carries.
  class CookieNotFoundError < StandardError
  end

  # Represents the set of cookies that should be sent to a particular
  # URL, preserving every cookie even when several of them share the
  # same name.
  #
  # A selection keeps two concerns separate:
  #
  # 1. *What is sent on the wire* – #cookies and #cookie_header follow
  #    RFC 6265 section 5.4 and retain every matching cookie, including
  #    same-name cookies coming from different domains or paths, in the
  #    standard sending order (longer path first, earlier creation
  #    first).
  #
  # 2. *What a backend may treat as a unique identity* – picking a
  #    single value for an explicitly named authentication cookie is
  #    only possible when exactly one eligible cookie carries that
  #    name.  Otherwise #authentication_value! raises
  #    AmbiguousCookieError instead of silently letting one of several
  #    identities win.
  #
  # Use HTTP::CookieJar#cookies_for to obtain an instance; do not
  # construct one directly.
  class CookieSelection
    include Enumerable

    # The URL/URI the selected cookies are going to be sent to.
    attr_reader :url

    # :call-seq:
    #   new(cookies, url)
    #
    # Wraps an array of cookies already filtered for `url`.  The
    # array is sorted into the RFC 6265 sending order and stored by
    # reference; callers are not expected to mutate it afterwards.
    def initialize(cookies, url)
      @cookies = cookies.sort
      @url = url
      @by_name = nil
    end

    # Returns the selected cookies in the RFC 6265 sending order.
    #
    # Same-name cookies are never collapsed; every cookie eligible for
    # the URL is returned.
    attr_reader :cookies

    # Iterates over the selected cookies in the sending order.
    def each(&block)
      return to_enum(__method__) unless block_given?
      @cookies.each(&block)
      self
    end

    # Returns the number of selected cookies.
    def size
      @cookies.size
    end
    alias length size

    # Tests if no cookie is eligible for the URL.
    def empty?
      @cookies.empty?
    end

    # Returns all selected cookies carrying `name`, in the sending
    # order.  An empty array is returned when none matches.
    #
    # The returned cookies retain their domain, path, origin and
    # creation information, which is what disambiguates same-name
    # cookies.
    def cookies_named(name)
      by_name.fetch(name, [])
    end

    # Returns the groups of same-name selected cookies whose name maps
    # to more than one cookie.  Each value is an array of cookies in
    # the sending order.
    def ambiguous_names
      by_name.select { |_name, group| group.size > 1 }
    end

    # Tests if more than one selected cookie carries `name`.
    def ambiguous?(name)
      cookies_named(name).size > 1
    end

    # Builds the value for the Cookie request header following RFC
    # 6265 section 5.4, e.g. `name1=value1; name2=value2`.
    #
    # Every eligible cookie is emitted in the standard sending order,
    # so same-name cookies are all present rather than being hashed
    # away.  Returns nil when there is no cookie for the URL.
    def cookie_header
      return nil if @cookies.empty?
      HTTP::Cookie.cookie_value(@cookies)
    end
    alias to_s cookie_header

    # Returns the unique value of the authentication cookie named
    # `name`, or nil when no eligible cookie carries that name or when
    # the name is ambiguous.
    #
    # This never picks one of several same-name cookies implicitly;
    # check #ambiguous? (or use #authentication_value!) when the
    # difference matters.
    def authentication_value(name)
      group = cookies_named(name)
      group.size == 1 ? group.first.value : nil
    end

    # Returns the unique value of the authentication cookie named
    # `name`.
    #
    # CookieNotFoundError is raised when no eligible cookie carries
    # the name, and AmbiguousCookieError is raised when more than one
    # eligible cookie carries it.  The caller must name the cookie it
    # authenticates with; there is no default "last one wins".
    def authentication_value!(name)
      group = cookies_named(name)
      if group.empty?
        raise CookieNotFoundError,
              "no cookie named %s is eligible for %s" % [name.inspect, url.inspect]
      end
      if group.size > 1
        raise AmbiguousCookieError,
              "cookie name %s is ambiguous for %s: %d candidates (%s)" % [
                name.inspect,
                url.inspect,
                group.size,
                group.map { |cookie|
                  "value=%s domain=%s path=%s created_at=%s" % [
                    cookie.value.inspect,
                    cookie.domain.inspect,
                    cookie.path.inspect,
                    cookie.created_at.iso8601,
                  ]
                }.join('; '),
              ]
      end
      group.first.value
    end

    # Returns a description of the selection useful for debugging and
    # audit logging.  The domain, path and creation time of each
    # cookie are included so same-name cookies stay distinguishable.
    def inspect
      '#<%s url=%s cookies=[%s]>' % [
        self.class,
        url.inspect,
        @cookies.map { |cookie|
          '%s=%s domain=%s path=%s created_at=%s' % [
            cookie.name,
            cookie.value.inspect,
            cookie.domain.inspect,
            cookie.path.inspect,
            cookie.created_at.iso8601,
          ]
        }.join(', '),
      ]
    end

    private

    # Groups the selected cookies by name without losing any of them.
    def by_name
      @by_name ||= @cookies.each_with_object(Hash.new { |hash, key| hash[key] = [] }) { |cookie, hash|
        hash[cookie.name] << cookie
      }
    end
  end
end

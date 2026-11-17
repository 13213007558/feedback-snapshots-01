# :markup: markdown
require 'domain_name'
require 'time'

class HTTP::CookieJar
  # A store class that uses a hash-based cookie store.
  #
  # In this store, cookies that share the same name, domain and path
  # will overwrite each other regardless of the `for_domain` flag
  # value.  This store is built after the storage model described in
  # RFC 6265 5.3 where there is no mention of how the host-only-flag
  # affects in storing cookies.  On the other hand, in MozillaStore
  # two cookies with the same name, domain and path coexist as long as
  # they differ in the `for_domain` flag value, which means they need
  # to be expired individually.
  #
  # == Capacity policy
  #
  # An untrusted subdomain can keep setting cookies.  Without a policy
  # that knows which site a cookie belongs to, that flood would evict
  # cookies belonging to unrelated, active sessions.  This store
  # therefore enforces two independent quotas:
  #
  # * a per-site quota (`:max_cookies_per_site`, default
  #   `HTTP::Cookie::MAX_COOKIES_PER_DOMAIN`), and
  # * a total quota (`:max_cookies_total`, default
  #   `HTTP::Cookie::MAX_COOKIES_TOTAL`).
  #
  # A *site* is the bucket a cookie is counted in.  It is computed
  # from the cookie's domain attribute according to `:site_mode`:
  #
  # [:host] (default)
  #   The cookie's exact domain attribute.  A host-only cookie for
  #   `www.example.com` and a domain cookie declared as
  #   `Domain=www.example.com` share a bucket, while a domain cookie
  #   declared as `Domain=example.com` has its own bucket.  This is
  #   the historical grouping: the per-site limit is the traditional
  #   per-domain limit.
  # [:cookie_scope]
  #   A host-only cookie uses its exact host; a domain cookie uses
  #   the registrable domain (eTLD+1) of its `Domain` attribute as
  #   determined by the Public Suffix List.  This keeps a host's
  #   host-only cookies in their own bucket while grouping domain
  #   cookies that are intentionally shared across a site.  Rotating
  #   subdomains cannot multiply a per-site quota, so this is the
  #   stricter choice for deployments that accept host-only cookies.
  # [:site]
  #   The registrable domain of the cookie's domain; every host under
  #   `example.com`, and every cookie declared as `Domain=example.com`,
  #   shares one bucket.
  # [callable]
  #   Any object responding to `#call` is invoked with a cookie and
  #   must return the site name as a String.  It should be
  #   deterministic: the same cookie must always map to the same site.
  #
  # IP addresses, public suffixes and internal names without a
  # registrable domain use the domain itself as their site.
  #
  # === Fixed eviction order
  #
  # The same order is used for both quotas, and it never depends on the
  # host-only flag:
  #
  # 1. Expired cookies are always removed first, before any quota is
  #    applied, and never count towards a quota.  A received cookie
  #    that is already expired is treated as a deletion instruction.
  #    With `cleanup(true)`, session cookies are removed next, for the
  #    same reason.
  # 2. Access time comes before creation time.  A cookie that this jar
  #    has actually sent via #each(uri) ranks above a cookie that has
  #    never been sent, and among sent cookies the least recently sent
  #    goes first.  Among never-sent cookies, the oldest `created_at`
  #    goes first.  `created_at` then breaks remaining ties, followed
  #    by domain, path and name so the result is deterministic.
  #
  #    This ordering keeps a flood of fresh cookies from looking
  #    "recently used" merely because it was just created: unsent
  #    flood cookies leave before a session cookie that the jar has
  #    actually been sending.
  #
  # === Which site pays
  #
  # The per-site quota evicts from the site that is over quota.  The
  # total quota is charged to the site that wrote the newest cookie,
  # i.e. the last writer.  Ties are broken by the number of cookies
  # that site accepted since the previous cleanup, then by site name.
  # Each charge states the site and the timestamp it was charged on.
  # If that site cannot pay the whole overage, the next site in that
  # order pays the rest.  A site that merely reads or replaces its
  # existing cookies therefore does not pay for another site's growth.
  #
  # === Overflow handling
  #
  # `:overflow` selects what happens when a new cookie does not fit:
  #
  # [:evict] (default)
  #   The cookie is stored, and the policy above evicts cookies until
  #   both quotas hold.
  # [:reject]
  #   The new cookie is refused and nothing else is evicted.  The
  #   refusal is recorded as a decision with reason `:rejected`.
  #
  # #add runs the policy once every `:gc_threshold` stored cookies, so
  # with the default threshold a store may briefly exceed a quota by at
  # most `gc_threshold - 1` cookies.  Call #cleanup, or lower
  # `:gc_threshold`, to bound the overshoot more tightly.  With
  # `:overflow => :reject`, a refused cookie is retried after expired
  # cookies are reclaimed at the start of a GC window; only expired
  # cookies are reclaimed in that path, so refusal never evicts a live
  # cookie.
  #
  # === Host-only cookies and parent-domain cookies
  #
  # A host-only cookie belongs to one host.  A parent-domain cookie
  # (`Domain=example.com`) is deliberately shared with every host
  # under that domain, including an untrusted subdomain.  The two
  # compete only through the total quota, and that quota is charged to
  # the last writer as described above:
  #
  # * Under the default `:host` grouping, a flood of host-only
  #   cookies from `evil.example.com` is counted in the
  #   `evil.example.com` bucket and can never evict the host-only
  #   cookie of `www.example.com`.  Under `:cookie_scope`, the same is
  #   true, and a parent-domain cookie is additionally grouped with
  #   the registrable domain it is shared with.
  # * A flood of `Domain=example.com` cookies from the same subdomain
  #   is counted in the `example.com` bucket.  Those cookies compete
  #   with other `Domain=example.com` cookies, because they are all
  #   readable and writable by that subdomain by design.  They still
  #   cannot evict a host-only cookie of another host.
  # * A host-only cookie never receives eviction priority over a
  #   domain cookie, or vice versa.  The ordering rules above apply
  #   uniformly.
  #
  # Capacity enforcement only deletes whole cookies (or, with
  # `:overflow => :reject`, declines to store a new one).  It never
  # rewrites the domain, path, secure or httponly flags of a surviving
  # cookie, so neither eviction nor rejection can widen or narrow the
  # set of URIs to which the remaining cookies are sent.
  #
  # Replacing a cookie with the same name, domain and path is an RFC
  # 6265 5.3 operation that happens before capacity enforcement and is
  # not affected by this policy; see the note above about
  # `for_domain`.
  class HashStore < AbstractStore
    # A capacity decision.  `cookie` is the cookie object concerned,
    # `reason` is one of `:expired`, `:session`, `:site_limit`,
    # `:total_limit` or `:rejected`, `site` is the computed site and
    # `detail` is a human-readable explanation.
    Decision = Struct.new(:cookie, :reason, :site, :detail) do
      def to_s
        '%s: %s (%s)' % [cookie.name, reason, detail]
      end
    end

    # The result of the most recent #cleanup.  `evictions` is an array
    # of Decision objects, and `sites` is a hash of the remaining
    # cookie count per site.
    CleanupReport = Struct.new(:time, :max_cookies_per_site,
                               :max_cookies_total, :evictions, :sites)

    # A snapshot of the current capacity usage.
    CapacityReport = Struct.new(:site_mode, :max_cookies_per_site,
                                :max_cookies_total, :total, :sites)

    # The report generated by the most recent #cleanup, or nil if it
    # has not run yet.
    attr_reader :last_cleanup_report

    # Cookies most recently refused because of `:overflow => :reject`.
    # At most REJECTION_LOG_SIZE entries are kept; #rejection_count
    # reports the total since the last #clear.  Each entry is a
    # Decision with reason `:rejected`.
    attr_reader :rejections

    # The total number of cookies refused since the last #clear.
    attr_reader :rejection_count

    # The most recent already-expired cookies received, at most
    # REJECTION_LOG_SIZE of them.  Each entry is a Decision with reason
    # `:expired`; these are deletion instructions and never occupy
    # quota.
    attr_reader :expired

    # How many rejection details to retain.
    REJECTION_LOG_SIZE = 32

    def default_options
      {
        :gc_threshold => nil,
        :max_cookies_per_site => HTTP::Cookie::MAX_COOKIES_PER_DOMAIN,
        :max_cookies_total => HTTP::Cookie::MAX_COOKIES_TOTAL,
        :site_mode => :host,
        :overflow => :evict,
      }
    end

    # :call-seq:
    #   new(**options)
    #
    # Generates a hash based cookie store.
    #
    # Available option keywords are as below:
    #
    # :gc_threshold
    # : GC threshold; A GC happens when this many times cookies have
    # been stored (default: `max_cookies_total / 20`, at least 1)
    #
    # :max_cookies_per_site
    # : Maximum number of cookies per site (default:
    #   `HTTP::Cookie::MAX_COOKIES_PER_DOMAIN`)
    #
    # :max_cookies_total
    # : Maximum number of cookies in the store (default:
    #   `HTTP::Cookie::MAX_COOKIES_TOTAL`)
    #
    # :site_mode
    # : How cookies are grouped into sites.  One of `:host` (default),
    #   `:cookie_scope`, `:site`, or a callable that takes a cookie
    #   and returns a site name.  See the class documentation for
    #   details.
    #
    # :overflow
    # : What to do when adding a cookie would exceed a quota.  `:evict`
    #   (default) stores the cookie and evicts others; `:reject`
    #   refuses the new cookie and evicts nothing.
    #
    # All limits must be positive integers.  There is no option to
    # disable them; use the default limits instead.
    def initialize(options = nil)
      super

      @gc_threshold ||= [@max_cookies_total / 20, 1].max
      validate_limit(:gc_threshold, @gc_threshold)
      validate_limit(:max_cookies_per_site, @max_cookies_per_site)
      validate_limit(:max_cookies_total, @max_cookies_total)
      validate_site_mode(@site_mode)
      validate_overflow(@overflow)

      @jar = {
      # hostname => {
      #   path => {
      #     name => cookie,
      #     ...
      #   },
      #   ...
      # },
      # ...
      }

      @gc_index = 0
      @added = Hash.new(0)
      @accessed = {}
      @site_cache = {}
      @site_counts = Hash.new(0)
      @total_count = 0
      @last_cleanup_report = nil
      @rejections = []
      @rejection_count = 0
      @expired = []
    end

    # The copy constructor.  This store class supports cloning.
    def initialize_copy(other)
      super
      @jar = Marshal.load(Marshal.dump(other.instance_variable_get(:@jar)))
      @gc_index = 0
      @added = Hash.new(0)
      @accessed = other.instance_variable_get(:@accessed).dup
      @site_cache = {}
      @site_counts = other.instance_variable_get(:@site_counts).dup
      @total_count = other.instance_variable_get(:@total_count)
      @last_cleanup_report = nil
      @rejections = []
      @rejection_count = 0
      @expired = []
    end

    def add(cookie)
      site = site_for(cookie)
      paths = @jar[cookie.domain]
      path_cookies = paths && paths[cookie.path]
      stored = path_cookies && path_cookies[cookie.name]

      if cookie.expired?
        # An already-expired cookie is a deletion instruction (RFC 6265
        # 5.3).  Remove any stored value and do not count it anywhere.
        if stored
          path_cookies.delete(cookie.name)
          untrack(stored)
          @accessed.delete(lookup_key(stored))
          if path_cookies.empty?
            paths.delete(cookie.path)
            @jar.delete(cookie.domain) if paths.empty?
          end
        end
        if @expired.size >= REJECTION_LOG_SIZE
          @expired.shift
        end
        @expired << Decision.new(
          cookie, :expired, site,
          'cookie already expired at %s; treated as a deletion instruction' %
            format_time(cookie.expires))
        return self
      end

      if stored.nil? && @overflow == :reject && would_overflow?(site)
        # Expired cookies must not block a new cookie.  At the start of
        # each GC window, reclaim only expired cookies and retry the
        # decision.  This never evicts a live cookie, and later
        # rejections in the same window only record the refusal so a
        # flood cannot force a full scan per request.
        reclaim_expired if @gc_index == 0
        if would_overflow?(site)
          record_rejection(Decision.new(
            cookie, :rejected, site,
            'site %p holds %d cookies and the store holds %d, at the ' \
            'per-site limit of %d / total limit of %d; new cookie ' \
            'refused without evicting existing cookies' % [
              site, @site_counts[site], @total_count,
              @max_cookies_per_site, @max_cookies_total,
            ]))
          @gc_index += 1
          cleanup if @gc_index >= @gc_threshold
          return self
        end
      end

      if stored.nil?
        @added[site] += 1
      else
        untrack(stored)
        @accessed.delete(lookup_key(stored))
      end

      path_cookies ||= ((@jar[cookie.domain] ||= {})[cookie.path] ||= {})
      path_cookies[cookie.name] = cookie
      track(site)
      cleanup if (@gc_index += 1) >= @gc_threshold
      self
    end

    def delete(cookie)
      paths = @jar[cookie.domain]
      if paths && (path_cookies = paths[cookie.path]) &&
          (stored = path_cookies.delete(cookie.name))
        untrack(stored)
        @accessed.delete(lookup_key(stored))
      end
      self
    end

    def each(uri = nil) # :yield: cookie
      now = Time.now
      if uri
        tpath = uri.path
        @jar.each { |domain, paths|
          paths.each { |path, hash|
            next unless HTTP::Cookie.path_match?(path, tpath)
            hash.delete_if { |name, cookie|
              if cookie.expired?(now)
                untrack(cookie)
                @accessed.delete(lookup_key(cookie))
                true
              else
                if cookie.valid_for_uri?(uri)
                  cookie.accessed_at = now
                  @accessed[lookup_key(cookie)] = now
                  yield cookie
                end
                false
              end
            }
          }
        }
      else
        synchronize {
          @jar.each { |domain, paths|
            paths.each { |path, hash|
              hash.delete_if { |name, cookie|
                if cookie.expired?(now)
                  untrack(cookie)
                  @accessed.delete(lookup_key(cookie))
                  true
                else
                  yield cookie
                  false
                end
              }
            }
          }
        }
      end
      self
    end

    def clear
      @jar.clear
      @added.clear
      @accessed.clear
      @site_cache.clear
      @site_counts.clear
      @total_count = 0
      @rejections = []
      @rejection_count = 0
      @expired = []
      @last_cleanup_report = nil
      @gc_index = 0
      self
    end

    # Returns a snapshot of the current capacity usage, with the
    # number of live cookies per site.  This does not modify the
    # store.
    def capacity_report
      synchronize {
        now = Time.now
        sites = Hash.new(0)
        @jar.each_value { |paths|
          paths.each_value { |hash|
            hash.each_value { |cookie|
              next if cookie.expired?(now)
              sites[site_for(cookie)] += 1
            }
          }
        }
        CapacityReport.new(@site_mode, @max_cookies_per_site,
                           @max_cookies_total, sites.values.sum,
                           sites.freeze)
      }
    end

    # Returns the capacity decisions recorded by the most recent
    # #cleanup.
    def evictions
      report = @last_cleanup_report
      report ? report.evictions : []
    end

    def cleanup(session = false)
      now = Time.now

      synchronize {
        evictions = []
        site_cookies = Hash.new { |hash, key| hash[key] = [] }

        @jar.each { |domain, paths|
          paths.each { |path, hash|
            hash.delete_if { |name, cookie|
              if cookie.expired?(now)
                @accessed.delete(lookup_key(cookie))
                evictions << Decision.new(
                  cookie, :expired, site_for(cookie),
                  'expired at %s, removed before quota checking' %
                    format_time(cookie.expires))
                true
              elsif session && cookie.session?
                @accessed.delete(lookup_key(cookie))
                evictions << Decision.new(
                  cookie, :session, site_for(cookie),
                  'session cookie removed by cleanup(true)')
                true
              else
                site_cookies[site_for(cookie)] << cookie
                false
              end
            }
          }
        }

        enforce_site_limits(site_cookies, evictions)
        enforce_total_limit(site_cookies, evictions)

        @jar.delete_if { |domain, paths|
          paths.delete_if { |path, hash|
            hash.empty?
          }
          paths.empty?
        }

        @site_counts = Hash.new(0)
        @total_count = 0
        site_cookies.each { |site, cookies|
          next if cookies.empty?
          @site_counts[site] = cookies.size
          @total_count += cookies.size
        }
        @site_counts.default = 0

        @last_cleanup_report = CleanupReport.new(
          now, @max_cookies_per_site, @max_cookies_total,
          evictions.freeze, site_counts(site_cookies))
        @added.clear
        @expired.clear
        @gc_index = 0
      }
      self
    end

    private

    def reclaim_expired
      now = Time.now
      synchronize {
        @jar.each_value { |paths|
          paths.each_value { |hash|
            hash.delete_if { |name, cookie|
              next false unless cookie.expired?(now)
              untrack(cookie)
              @accessed.delete(lookup_key(cookie))
              true
            }
          }
        }
        @jar.delete_if { |domain, paths|
          paths.delete_if { |path, hash| hash.empty? }
          paths.empty?
        }
      }
      self
    end

    def record_rejection(decision)
      @rejection_count += 1
      if @rejections.size >= REJECTION_LOG_SIZE
        @rejections.shift
      end
      @rejections << decision
    end

    def validate_limit(name, value)
      unless value.is_a?(Integer) && value > 0
        raise ArgumentError, '%s must be a positive Integer: %p' % [name, value]
      end
    end

    def validate_site_mode(mode)
      case mode
      when :host, :site, :cookie_scope
        # ok
      else
        unless mode.respond_to?(:call)
          raise ArgumentError,
            'site_mode must be :host, :site, :cookie_scope or a callable: %p' % mode
        end
      end
    end

    def validate_overflow(overflow)
      unless overflow == :evict || overflow == :reject
        raise ArgumentError,
          'overflow must be :evict or :reject: %p' % overflow
      end
    end

    def would_overflow?(site)
      @site_counts[site] >= @max_cookies_per_site ||
        @total_count >= @max_cookies_total
    end

    def track(site)
      @site_counts[site] += 1
      @total_count += 1
    end

    def untrack(cookie)
      site = site_for(cookie)
      if @site_counts.key?(site)
        count = @site_counts[site] - 1
        if count > 0
          @site_counts[site] = count
        else
          @site_counts.delete(site)
        end
      end
      @total_count -= 1 if @total_count > 0
    end

    def site_for(cookie)
      domain = cookie.domain
      return '' if domain.nil?

      site =
        case @site_mode
        when :host
          domain
        when :site
          cached_site([:site, domain]) { registrable_domain(domain) }
        when :cookie_scope
          if cookie.for_domain?
            cached_site([:site, domain]) { registrable_domain(domain) }
          else
            domain
          end
        else
          @site_mode.call(cookie)
        end

      if site.nil?
        raise ArgumentError,
          'site_mode returned nil for cookie %p' % cookie.name
      end
      site.to_s
    end

    def cached_site(key)
      if @site_cache.key?(key)
        @site_cache[key]
      else
        @site_cache[key] = yield
      end
    end

    def registrable_domain(domain)
      DomainName.new(domain).domain || domain
    end

    def lookup_key(cookie)
      [cookie.domain, cookie.path, cookie.name]
    end

    # The last time the cookie was used, or nil if it never has been.
    # This jar records every send in `@accessed`.  A cookie restored
    # from a previous session keeps its stored `accessed_at`; that
    # counts as use only if it is later than `created_at`, because
    # construction sets both to the same instant.
    def last_used(cookie)
      sent = @accessed[lookup_key(cookie)]
      return sent if sent

      accessed = cookie.accessed_at
      created = cookie.created_at
      if accessed && created && accessed > created
        accessed
      end
    end

    def eviction_key(cookie)
      used = last_used(cookie)
      created = cookie.created_at
      [
        used ? 1 : 0,
        (used || created) ? (used || created).to_f : 0.0,
        created ? created.to_f : 0.0,
        cookie.domain.to_s,
        cookie.path.to_s,
        cookie.name.to_s,
      ]
    end

    def describe_use(cookie)
      used = last_used(cookie)
      used ? format_time(used) : 'never used'
    end

    def newest_created_at(cookies)
      time = cookies.map(&:created_at).compact.max
      time ? time.to_f : 0.0
    end

    def format_time(time)
      time ? time.utc.iso8601(6) : 'nil'
    end

    def evict(cookie, reason, site, detail, evictions)
      delete(cookie)
      evictions << Decision.new(cookie, reason, site, detail)
    end

    def enforce_site_limits(site_cookies, evictions)
      site_cookies.each { |site, cookies|
        original = cookies.size
        debt = original - @max_cookies_per_site
        next if debt <= 0

        cookies.sort_by! { |cookie| eviction_key(cookie) }
        cookies.slice!(0, debt).each { |cookie|
          evict(
            cookie, :site_limit, site,
            'site %p holds %d cookies, over the per-site limit of %d; ' \
            'evicted least recently used cookie ' \
            '(last used: %s; created: %s)' % [
              site, original, @max_cookies_per_site,
              describe_use(cookie), format_time(cookie.created_at),
            ],
            evictions)
        }
      }
    end

    def enforce_total_limit(site_cookies, evictions)
      total = site_cookies.each_value.sum(&:size)
      while total > @max_cookies_total
        payer_site, payer_cookies = pick_total_payer(site_cookies)
        break if payer_site.nil?

        need = total - @max_cookies_total
        payer_cookies.sort_by! { |cookie| eviction_key(cookie) }
        victims = payer_cookies.slice!(0, [need, payer_cookies.size].min)
        added = @added[payer_site]
        newest = newest_created_at(payer_cookies + victims)

        victims.each { |cookie|
          evict(
            cookie, :total_limit, payer_site,
            'total %d cookies exceeds the limit of %d; charged to site ' \
            '%p whose newest cookie was created at %s and which added ' \
            '%d new %s since the last cleanup; ' \
            'evicted least recently used cookie ' \
            '(last used: %s; created: %s)' % [
              total, @max_cookies_total, payer_site,
              format_time(Time.at(newest)), added,
              added == 1 ? 'cookie' : 'cookies',
              describe_use(cookie), format_time(cookie.created_at),
            ],
            evictions)
        }

        total = site_cookies.each_value.sum(&:size)
      end
    end

    def pick_total_payer(site_cookies)
      site_cookies
        .select { |site, cookies| !cookies.empty? }
        .max_by { |site, cookies|
          [newest_created_at(cookies), @added[site], site.to_s]
        }
    end

    def site_counts(site_cookies)
      site_cookies.each_with_object({}) { |(site, cookies), counts|
        counts[site] = cookies.size unless cookies.empty?
      }.freeze
    end
  end
end

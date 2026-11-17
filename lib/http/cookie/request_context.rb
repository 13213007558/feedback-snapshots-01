# frozen_string_literal: true
require 'uri'
require 'domain_name'

class HTTP::Cookie
  # Represents the explicit context of an outgoing HTTP request that is
  # needed to decide which cookies are eligible to be sent.
  #
  # A request URL on its own is not enough to evaluate the SameSite
  # attribute of a cookie.  SameSite depends on the relationship
  # between the *top-level site* of the request and the site of the
  # request target, as well as on whether the request is a top-level
  # navigation or a subresource load, its HTTP method, and whether it
  # is the result of a redirect.  Callers that want SameSite-aware
  # cookie selection supply all of those facts through this class and
  # pass the object to HTTP::CookieJar#cookies_for_request (or
  # HTTP::Cookie#valid_for_request?).
  #
  # == Same-site vs. same-origin
  #
  # These two notions are distinct and are never mixed up here:
  #
  # - #same_site? implements the "schemeful same-site" comparison: two
  #   URLs are same-site when they share the same scheme and the same
  #   registrable domain (eTLD+1).  The port and the exact host are
  #   irrelevant, so `https://a.example.com` and
  #   `https://b.example.com:8443` are same-site (but not same-origin).
  #   Public suffix classification is delegated to the domain_name
  #   gem, the same source used for cookie domain matching.
  # - #same_origin? compares scheme, full host and port, as defined by
  #   the Web origin model.  It is exposed for completeness; the
  #   SameSite algorithm only ever uses #same_site?.
  #
  # == Scope of the browser model
  #
  # This class models the well-established Strict / Lax / None
  # behavior shared by current browsers; it deliberately does not try
  # to reproduce every version-specific quirk (for example Chrome's
  # temporary "Lax+POST" mitigation).  The exact rules applied are
  # documented on HTTP::Cookie#valid_for_request?.
  class RequestContext
    # HTTP methods considered "safe" for the purpose of SameSite=Lax.
    # (RFC 6265bis, section 5.2)
    SAFE_METHODS = %w[GET HEAD OPTIONS TRACE].map(&:freeze).freeze

    # The supported SameSite policy values.
    SAMESITE_POLICIES = %i[strict lax none].freeze

    # The parsed target URI of the request.
    attr_reader :url

    # The request method, normalized to an upper-case String.
    attr_reader :method

    # Whether the request is a top-level navigation (true) or a
    # subresource load (false).
    attr_reader :navigation

    # Whether the request was reached by following an HTTP redirect.
    attr_reader :redirected

    # The SameSite policy assumed for cookies that do not carry an
    # explicit SameSite attribute.
    attr_reader :default_samesite

    # call-seq:
    #   RequestContext.new(url:, top_level_site:, method: "GET",
    #                      navigation: false, redirected: false,
    #                      default_samesite: :lax)
    #
    # Constructs a request context.
    #
    # +url+ is the target URL/URI of the request.  +top_level_site+ is
    # the URL/URI of the top-level document (the "site for cookies")
    # in whose context the request is made; only its scheme and
    # registrable domain are used.  Both must be absolute HTTP(S) URIs
    # with a host, or ArgumentError is raised.
    #
    # +method+ defaults to `"GET"`.  +navigation+ marks a top-level
    # navigation as opposed to a subresource load (the default).
    # +redirected+ marks a request produced by following a redirect.
    # +default_samesite+ selects the policy applied to cookies without
    # an explicit SameSite attribute and must be one of +:strict+,
    # +:lax+ (the default, matching modern browsers) or +:none+.
    #
    # Every piece of information required for a SameSite decision is
    # mandatory; there is no implicit or permissive fallback.
    def initialize(url: nil, top_level_site: nil, method: 'GET', navigation: false,
                   redirected: false, default_samesite: :lax)
      raise ArgumentError, 'url is required' if url.nil?
      raise ArgumentError, 'top_level_site is required' if top_level_site.nil?

      @url = self.class.send(:parse_http_uri, url)
      @top_level_uri = self.class.send(:parse_http_uri, top_level_site)

      method = String.try_convert(method) or
        raise TypeError, "method must be a String: #{method.inspect}"
      raise ArgumentError, 'method must not be empty' if method.empty?
      @method = method.upcase

      @navigation = navigation ? true : false
      @redirected = redirected ? true : false

      unless SAMESITE_POLICIES.include?(default_samesite)
        raise ArgumentError,
          'default_samesite must be one of %s: %s' %
            [SAMESITE_POLICIES.inspect, default_samesite.inspect]
      end
      @default_samesite = default_samesite
    end

    # The parsed top-level URI supplied by the caller.
    attr_reader :top_level_uri

    # The schemeful site of the request target as a
    # `[scheme, registrable_domain]` pair.
    def target_site
      self.class.site_for(@url)
    end

    # The schemeful site of the top-level document as a
    # `[scheme, registrable_domain]` pair.
    def top_level_site
      self.class.site_for(@top_level_uri)
    end

    # The Web origin of the request target as a
    # `[scheme, host, port]` triple.
    def target_origin
      self.class.origin_for(@url)
    end

    # The Web origin of the top-level document as a
    # `[scheme, host, port]` triple.
    def top_level_origin
      self.class.origin_for(@top_level_uri)
    end

    # Tests whether the request target and the top-level document are
    # schemefully same-site (same scheme and registrable domain).
    def same_site?
      target_site == top_level_site
    end

    # Tests whether the request target and the top-level document
    # share the same Web origin (same scheme, full host and port).
    def same_origin?
      target_origin == top_level_origin
    end

    # Tests whether this is a top-level navigation request.
    def navigation?
      @navigation
    end

    # Tests whether this is a subresource (non-navigation) request.
    def subresource?
      !@navigation
    end

    # Tests whether the request was reached through a redirect.
    def redirected?
      @redirected
    end

    # Tests whether the request method is a "safe" method.
    def safe_method?
      SAFE_METHODS.include?(@method)
    end

    # Computes the schemeful site of +uri+ (a URI/URL) as a
    # `[scheme, registrable_domain]` pair.
    #
    # The registrable domain is the eTLD+1 as classified by the
    # domain_name gem.  For an IP address the whole address is used;
    # for a bare public suffix or a single-label host the host itself
    # is used.  Ports do not participate in a site.
    def self.site_for(uri)
      uri = send(:parse_http_uri, uri)
      domain_name = DomainName.new(uri.host)
      registrable =
        if domain_name.ipaddr?
          domain_name.hostname
        else
          domain_name.domain || domain_name.hostname
        end
      [uri.scheme.downcase, registrable].freeze
    end

    # Computes the Web origin of +uri+ (a URI/URL) as a
    # `[scheme, host, port]` triple.  An unspecified port is expanded
    # to the default port of the scheme.
    def self.origin_for(uri)
      uri = send(:parse_http_uri, uri)
      [uri.scheme.downcase, uri.host.downcase, uri.port].freeze
    end

    def self.parse_http_uri(uri) # :nodoc:
      parsed =
        begin
          HTTP::Cookie::URIParser.parse(uri)
        rescue URI::InvalidURIError, ArgumentError
          nil
        end
      unless URI::HTTP === parsed && parsed.host && !parsed.host.empty?
        raise ArgumentError,
          "expected an absolute HTTP(S) URI with a host: #{uri.inspect}"
      end
      parsed
    end
    private_class_method :parse_http_uri
  end
end

# :markup: markdown

module HTTP
  autoload :Cookie, "http/cookie"
end

##
# This class is used to manage the Cookies that have been returned from
# any particular website.

class HTTP::CookieJar

  attr_reader :store

  # The SameSite policy applied to cookies without an explicit
  # SameSite attribute during request-aware selection.  See
  # HTTP::Cookie::RequestContext.
  attr_reader :samesite_default

  def get_impl(base, value, *args)
    case value
    when base
      value
    when Symbol
      begin
        base.implementation(value).new(*args)
      rescue IndexError => e
        raise ArgumentError, e.message
      end
    when Class
      if base >= value
        value.new(*args)
      else
        raise TypeError, 'not a subclass of %s: %s' % [base, value]
      end
    else
      raise TypeError, 'invalid object: %s' % value.inspect
    end
  end
  private :get_impl

  # Generates a new cookie jar.
  #
  # Available option keywords are as below:
  #
  # :store
  # : The store class that backs this jar. (default: `:hash`)
  # A symbol addressing a store class, a store class, or an instance
  # of a store class is accepted.  Symbols are mapped to store
  # classes, like `:hash` to HTTP::CookieJar::HashStore and `:mozilla`
  # to HTTP::CookieJar::MozillaStore.
  #
  # Any options given are passed through to the initializer of the
  # specified store class.  For example, the `:mozilla`
  # (HTTP::CookieJar::MozillaStore) store class requires a `:filename`
  # option.  See individual store classes for details.
  #
  # In addition, the following option is consumed by the jar itself:
  #
  # :samesite_default
  # : The SameSite policy assumed for cookies that do not carry an
  # explicit SameSite attribute when #cookies_for_request or
  # #each_for_request is used.  One of `:strict`, `:lax` (default,
  # matching modern browsers) or `:none`.
  def initialize(options = nil)
    opthash = {
      :store => :hash,
      :samesite_default => :lax,
    }
    opthash.update(options) if options
    unless HTTP::Cookie::RequestContext::SAMESITE_POLICIES.include?(opthash[:samesite_default])
      raise ArgumentError,
        ':samesite_default must be one of %s: %s' %
          [HTTP::Cookie::RequestContext::SAMESITE_POLICIES.inspect,
           opthash[:samesite_default].inspect]
    end
    @samesite_default = opthash[:samesite_default]
    @store = get_impl(AbstractStore, opthash[:store], opthash)
  end

  # The copy constructor.  Not all backend store classes support cloning.
  def initialize_copy(other)
    @store = other.instance_eval { @store.dup }
  end

  # Adds a cookie to the jar if it is acceptable, and returns self in
  # any case.  A given cookie must have domain and path attributes
  # set, or ArgumentError is raised.
  #
  # Whether a cookie with the `for_domain` flag on overwrites another
  # with the flag off or vice versa depends on the store used.  See
  # individual store classes for that matter.
  #
  # ### Compatibility Note for Mechanize::Cookie users
  #
  # In HTTP::Cookie, each cookie object can store its origin URI
  # (cf. #origin).  While the origin URI of a cookie can be set
  # manually by #origin=, one is typically given in its generation.
  # To be more specific, HTTP::Cookie.new takes an `:origin` option
  # and HTTP::Cookie.parse takes one via the second argument.
  #
  #       # Mechanize::Cookie
  #       jar.add(origin, cookie)
  #       jar.add!(cookie)    # no acceptance check is performed
  #
  #       # HTTP::Cookie
  #       jar.origin = origin
  #       jar.add(cookie)     # acceptance check is performed
  def add(cookie)
    @store.add(cookie) if
      begin
        cookie.acceptable?
      rescue RuntimeError => e
        raise ArgumentError, e.message
      end
    self
  end
  alias << add

  # Deletes a cookie that has the same name, domain and path as a
  # given cookie from the jar and returns self.
  #
  # How the `for_domain` flag value affects the set of deleted cookies
  # depends on the store used.  See individual store classes for that
  # matter.
  def delete(cookie)
    @store.delete(cookie)
    self
  end

  # Gets an array of cookies sorted by the path and creation time.  If
  # `url` is given, only ones that should be sent to the URL/URI are
  # selected, with the access time of each of them updated.
  def cookies(url = nil)
    each(url).sort
  end

  # Tests if the jar is empty.  If `url` is given, tests if there is
  # no cookie for the URL.
  def empty?(url = nil)
    if url
      each(url) { return false }
      return true
    else
      @store.empty?
    end
  end

  # Iterates over all cookies that are not expired in no particular
  # order.
  #
  # An optional argument `uri` specifies a URI/URL indicating the
  # destination of the cookies being selected.  Every cookie yielded
  # should be good to send to the given URI,
  # i.e. cookie.valid_for_uri?(uri) evaluates to true.
  #
  # If (and only if) the `uri` option is given, last access time of
  # each cookie is updated to the current time.
  #
  # This is the URL-only interface: it does not evaluate the SameSite
  # attribute.  Use #each_for_request for SameSite-aware selection.
  def each(uri = nil, &block) # :yield: cookie
    block_given? or return enum_for(__method__, uri)

    if uri
      uri = HTTP::Cookie::URIParser.parse(uri)
      return self unless URI::HTTP === uri && uri.host
    end

    @store.each(uri, &block)
    self
  end

  # Iterates over the cookies that should be sent in the request
  # described by `request_context` (an HTTP::Cookie::RequestContext),
  # updating the last access time of each yielded cookie.
  #
  # Unlike #each, this evaluates the SameSite attribute of every
  # cookie against the explicit request context; cookies fail closed
  # when the context does not allow them.  The request context is
  # mandatory and validated, so a missing top-level site or a
  # non-HTTP(S) URL raises rather than silently relaxing the rules.
  def each_for_request(request_context, &block) # :yield: cookie
    request_context = build_request_context(request_context)
    block_given? or return enum_for(__method__, request_context)
    @store.each_for_request(request_context, &block)
    self
  end

  # Returns an array of cookies sorted by path and creation time that
  # should be sent in the request described by `request_context` (an
  # HTTP::Cookie::RequestContext or a Hash of its constructor
  # options).  SameSite is evaluated from the explicit request
  # context; see #each_for_request.
  def cookies_for_request(request_context)
    request_context = build_request_context(request_context)
    each_for_request(request_context).sort
  end

  # Tests if there is no cookie to send in the request described by
  # `request_context` (an HTTP::Cookie::RequestContext or a Hash of
  # its constructor options).
  def empty_for_request?(request_context)
    request_context = build_request_context(request_context)
    each_for_request(request_context) { return false }
    true
  end

  def build_request_context(request_context)
    case request_context
    when HTTP::Cookie::RequestContext
      if request_context.default_samesite != @samesite_default
        request_context = HTTP::Cookie::RequestContext.new(
          :url => request_context.url,
          :top_level_site => request_context.top_level_uri,
          :method => request_context.method,
          :navigation => request_context.navigation?,
          :redirected => request_context.redirected?,
          :default_samesite => @samesite_default)
      end
      request_context
    when Hash
      unless request_context.key?(:url) && request_context.key?(:top_level_site)
        raise ArgumentError,
          'a request context Hash needs both :url and :top_level_site'
      end
      HTTP::Cookie::RequestContext.new(
        **request_context.merge(:default_samesite => @samesite_default))
    else
      raise TypeError,
        'expected an HTTP::Cookie::RequestContext or a Hash: %s' %
          request_context.class
    end
  end
  private :build_request_context

  include Enumerable

  # Parses a Set-Cookie field value `set_cookie` assuming that it is
  # sent from a source URL/URI `origin`, and adds the cookies parsed
  # as valid and considered acceptable to the jar.  Returns an array
  # of cookies that have been added.
  #
  # If a block is given, it is called for each cookie and the cookie
  # is added only if the block returns a true value.
  #
  # `jar.parse(set_cookie, origin)` is a shorthand for this:
  #
  #         HTTP::Cookie.parse(set_cookie, origin) { |cookie|
  #           jar.add(cookie)
  #         }
  #
  # See HTTP::Cookie.parse for available options.
  def parse(set_cookie, origin, options = nil) # :yield: cookie
    if block_given?
      HTTP::Cookie.parse(set_cookie, origin, options).tap { |cookies|
        cookies.select! { |cookie|
          yield(cookie) && add(cookie)
        }
      }
    else
      HTTP::Cookie.parse(set_cookie, origin, options) { |cookie|
        add(cookie)
      }
    end
  end

  # call-seq:
  #   jar.save(filename_or_io, **options)
  #   jar.save(filename_or_io, format = :yaml, **options)
  #
  # Saves the cookie jar into a file or an IO in the format specified
  # and returns self.  If a given object responds to #write it is
  # taken as an IO, or taken as a filename otherwise.
  #
  # Available option keywords are below:
  #
  # * `:format`
  #
  #     Specifies the format for saving.  A saver class, a symbol
  #     addressing a saver class, or a pre-generated instance of a
  #     saver class is accepted.
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>:yaml</dt>
  #       <dd>YAML structure (default)</dd>
  #       <dt>:cookiestxt</dt>
  #       <dd>Mozilla's cookies.txt format</dd>
  #     </dl>
  #
  # * `:session`
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>true</dt>
  #       <dd>Save session cookies as well.</dd>
  #       <dt>false</dt>
  #       <dd>Do not save session cookies. (default)</dd>
  #     </dl>
  #
  # All options given are passed through to the underlying cookie
  # saver module's constructor.
  def save(writable, *options)
    opthash = {
      :format => :yaml,
      :session => false,
    }
    case options.size
    when 0
    when 1
      case options = options.first
      when Symbol
        opthash[:format] = options
      else
        if hash = Hash.try_convert(options)
          opthash.update(hash)
        end
      end
    when 2
      opthash[:format], options = options
      if hash = Hash.try_convert(options)
        opthash.update(hash)
      end
    else
      raise ArgumentError, 'wrong number of arguments (%d for 1-3)' % (1 + options.size)
    end

    saver = get_impl(AbstractSaver, opthash[:format], opthash)

    if writable.respond_to?(:write)
      saver.save(writable, self)
    else
      File.open(writable, 'w') { |io|
        saver.save(io, self)
      }
    end

    self
  end

  # call-seq:
  #   jar.load(filename_or_io, **options)
  #   jar.load(filename_or_io, format = :yaml, **options)
  #
  # Loads cookies recorded in a file or an IO in the format specified
  # into the jar and returns self.  If a given object responds to
  # \#read it is taken as an IO, or taken as a filename otherwise.
  #
  # Available option keywords are below:
  #
  # * `:format`
  #
  #     Specifies the format for loading.  A saver class, a symbol
  #     addressing a saver class, or a pre-generated instance of a
  #     saver class is accepted.
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>:yaml</dt>
  #       <dd>YAML structure (default)</dd>
  #       <dt>:cookiestxt</dt>
  #       <dd>Mozilla's cookies.txt format</dd>
  #     </dl>
  #
  # All options given are passed through to the underlying cookie
  # saver module's constructor.
  def load(readable, *options)
    opthash = {
      :format => :yaml,
      :session => false,
    }
    case options.size
    when 0
    when 1
      case options = options.first
      when Symbol
        opthash[:format] = options
      else
        if hash = Hash.try_convert(options)
          opthash.update(hash)
        end
      end
    when 2
      opthash[:format], options = options
      if hash = Hash.try_convert(options)
        opthash.update(hash)
      end
    else
      raise ArgumentError, 'wrong number of arguments (%d for 1-3)' % (1 + options.size)
    end

    saver = get_impl(AbstractSaver, opthash[:format], opthash)

    if readable.respond_to?(:write)
      saver.load(readable, self)
    else
      File.open(readable, 'r') { |io|
        saver.load(io, self)
      }
    end

    self
  end

  # Clears the cookie jar and returns self.
  def clear
    @store.clear
    self
  end

  # Removes expired cookies and returns self.  If `session` is true,
  # all session cookies are removed as well.
  def cleanup(session = false)
    @store.cleanup session
    self
  end
end

require 'http/cookie_jar/abstract_store'
require 'http/cookie_jar/abstract_saver'

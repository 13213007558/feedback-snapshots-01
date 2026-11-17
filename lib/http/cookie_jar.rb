# :markup: markdown

module HTTP
  autoload :Cookie, "http/cookie"
end

##
# This class is used to manage the Cookies that have been returned from
# any particular website.

class HTTP::CookieJar

  attr_reader :store

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
  # :overwrite_protection
  # : An optional OverwriteProtection policy that keeps cookies received
  # over an insecure transport from overwriting, shadowing, or deleting
  # an existing Secure cookie.  `true` enables the policy with its
  # defaults, and a Hash is passed to the policy constructor.  The
  # default is `nil` (disabled).  See HTTP::CookieJar::OverwriteProtection
  # for details.
  def initialize(options = nil)
    opthash = {
      :store => :hash,
    }
    opthash.update(options) if options
    @overwrite_protection = OverwriteProtection.build(
      opthash[:overwrite_protection], :logger => opthash[:logger])
    @store = get_impl(AbstractStore, opthash[:store], opthash)
  end

  # The copy constructor.  Not all backend store classes support cloning.
  def initialize_copy(other)
    @store = other.instance_eval { @store.dup }
    @overwrite_protection = other.overwrite_protection.dup if
      other.overwrite_protection
  end

  # The optional overwrite protection policy in effect, or nil if the
  # policy is disabled.  See HTTP::CookieJar::OverwriteProtection.
  attr_reader :overwrite_protection

  # Adds a cookie to the jar if it is acceptable, and returns self in
  # any case.  A given cookie must have domain and path attributes
  # set, or ArgumentError is raised.
  #
  # Whether a cookie with the `for_domain` flag on overwrites another
  # with the flag off or vice versa depends on the store used.  See
  # individual store classes for that matter.
  #
  # If an overwrite protection policy is configured, a cookie that
  # would overwrite, shadow or delete a Secure cookie received over
  # HTTPS is rejected when it comes from an insecure or unknown origin.
  # See HTTP::CookieJar::OverwriteProtection.
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
    add_cookie(cookie)
    self
  end
  alias << add

  # Adds a cookie if it is acceptable and permitted by the overwrite
  # protection policy, and returns true if it was stored.
  def add_cookie(cookie)
    acceptable = begin
      cookie.acceptable?
    rescue RuntimeError => e
      raise ArgumentError, e.message
    end
    return false unless acceptable

    if @overwrite_protection
      event = @overwrite_protection.check(cookie, @store)
      if event
        @overwrite_protection.record(event)
        return false
      end
    end

    @store.add(cookie)
    true
  end
  private :add_cookie

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
  def each(uri = nil, &block) # :yield: cookie
    block_given? or return enum_for(__method__, uri)

    if uri
      uri = HTTP::Cookie::URIParser.parse(uri)
      return self unless URI::HTTP === uri && uri.host
    end

    @store.each(uri, &block)
    self
  end
  include Enumerable

  # Parses a Set-Cookie field value `set_cookie` assuming that it is
  # sent from a source URL/URI `origin`, and adds the cookies parsed
  # as valid and considered acceptable to the jar.  Returns an array
  # of cookies that have been added.
  #
  # Cookies rejected by an overwrite protection policy are not
  # included in the returned array.
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
    parsed = HTTP::Cookie.parse(set_cookie, origin, options)
    if block_given?
      parsed.select { |cookie|
        yield(cookie) && add_cookie(cookie)
      }
    else
      parsed.select { |cookie| add_cookie(cookie) }
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
require 'http/cookie_jar/overwrite_protection'

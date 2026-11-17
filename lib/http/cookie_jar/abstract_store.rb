# :markup: markdown
require 'monitor'

# An abstract superclass for all store classes.
class HTTP::CookieJar::AbstractStore
  include MonitorMixin

  class << self

    # Gets an implementation class by the name.
    def implementation(symbol)
      case symbol
      when :hash
        HTTP::CookieJar::HashStore
      when :mozilla
        HTTP::CookieJar::MozillaStore
      else
        raise IndexError, 'cookie store unavailable: %s' % symbol.inspect
      end
    end
  end

  # Defines options and their default values.
  def default_options
    # {}
  end
  private :default_options

  # :call-seq:
  #   new(**options)
  #
  # Called by the constructor of each subclass using super().
  #
  # Available option keywords common to all store classes are as
  # below:
  #
  # :snapshot
  # : If true, the store takes a snapshot (see HTTP::Cookie#snapshot)
  # of each cookie on #add, and hands out a snapshot of each stored
  # cookie on #each.  In this mode, mutating a cookie object after it
  # is added, or mutating a cookie object obtained by enumeration,
  # never affects what is stored; only an explicit #add (replace) or
  # #delete changes the contents of the store.  If false (default),
  # stored cookie objects are shared with the caller for backward
  # compatibility.
  def initialize(options = nil)
    super() # MonitorMixin
    options ||= {}
    @logger = options[:logger]
    @snapshot = options[:snapshot] ? true : false
    # Initializes each instance variable of the same name as option
    # keyword.
    default_options.each_pair { |key, default|
      instance_variable_set("@#{key}", options.fetch(key, default))
    }
  end

  # Tests if this store is in snapshot mode.  See the `:snapshot`
  # option of ::new.
  def snapshot?
    @snapshot
  end

  # This is an abstract method that each subclass must override.
  def initialize_copy(other)
    # self
  end

  # Implements HTTP::CookieJar#add().
  #
  # This is an abstract method that each subclass must override.
  def add(cookie)
    # self
  end

  # Implements HTTP::CookieJar#delete().
  #
  # This is an abstract method that each subclass must override.
  def delete(cookie)
    # self
  end

  # Iterates over all cookies that are not expired.
  #
  # An optional argument +uri+ specifies a URI object indicating the
  # destination of the cookies being selected.  Every cookie yielded
  # should be good to send to the given URI,
  # i.e. cookie.valid_for_uri?(uri) evaluates to true.
  #
  # If (and only if) the +uri+ option is given, last access time of
  # each cookie is updated to the current time.
  #
  # This is an abstract method that each subclass must override.
  def each(uri = nil, &block) # :yield: cookie
    # if uri
    #   ...
    # else
    #   synchronize {
    #     ...
    #   }
    # end
    # self
  end
  include Enumerable

  # Implements HTTP::CookieJar#empty?().
  def empty?
    each { return false }
    true
  end

  # Implements HTTP::CookieJar#clear().
  #
  # This is an abstract method that each subclass must override.
  def clear
    # self
  end

  # Implements HTTP::CookieJar#cleanup().
  #
  # This is an abstract method that each subclass must override.
  def cleanup(session = false)
    # if session
    #   select { |cookie| cookie.session? || cookie.expired? }
    # else
    #   select(&:expired?)
    # end.each { |cookie|
    #   delete(cookie)
    # }
    # # subclasses can optionally remove over-the-limit cookies.
    # self
  end
end

require 'http/cookie_jar/hash_store'

unless defined?(JRUBY_VERSION)
  require 'http/cookie_jar/mozilla_store'
end

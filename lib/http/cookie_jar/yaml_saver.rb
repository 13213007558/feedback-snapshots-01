# :markup: markdown
autoload :YAML, 'yaml'
require 'time'

# YAMLSaver saves and loads cookies in the YAML format.  It can load a
# YAML file saved by Mechanize, but the saving format is not
# compatible with older versions of Mechanize (< 2.7).
#
# == Untrusted input
#
# #load always treats the given data as untrusted:
#
# 1. The YAML document is parsed through the restricted entry point
#    #load_yaml, which uses YAML.safe_load with the fixed class
#    whitelist PERMITTED_CLASSES and aliases enabled.  Any tag outside
#    the whitelist (an arbitrary +!ruby/object:...+ in particular)
#    makes the parse fail; no class outside the whitelist is
#    instantiated and no custom object behaviour is executed.
# 2. A whitelisted tag is not trusted.  Every record is rebuilt through
#    the HTTP::Cookie constructor, whose setters validate and normalize
#    the domain, path, value, time and flag fields.  Legacy Mechanize
#    hashes additionally go through #cookie_from_hash, which rejects
#    non-string keys, nested non-Hash structures, time fields that are
#    neither Time nor a parseable time string, non-boolean flags and
#    unknown attribute names.
# 3. Import is all-or-nothing: every record is validated before the jar
#    is touched.  A parse error or a single malformed record raises and
#    leaves the existing jar unchanged, instead of being swallowed and
#    reported as a successful import.
class HTTP::CookieJar::YAMLSaver < HTTP::CookieJar::AbstractSaver
  # The only classes YAML.safe_load is allowed to instantiate.
  # Everything else, including any arbitrary +!ruby/object:...+ tag,
  # raises Psych::DisallowedClass.
  PERMITTED_CLASSES = %w[
    Time
    HTTP::Cookie
    Mechanize::Cookie
    DomainName
  ].freeze

  # Attributes accepted from a legacy Mechanize cookie hash.  Any other
  # key makes the record fail validation.
  COOKIE_ATTRIBUTES = HTTP::Cookie::PERSISTENT_PROPERTIES.map(&:to_sym).freeze

  # Mechanize-only attributes present in old files that have no
  # HTTP::Cookie equivalent.  They are checked for an inert scalar type
  # and then dropped instead of being fed to the cookie constructor.
  IGNORED_MECHANIZE_ATTRIBUTES = %i[
    version
    port
    discard
    comment
    comment_url
    session
    domain_name
  ].freeze

  # :singleton-method: new
  # :call-seq:
  #   new(**options)
  #
  # There is no option keyword supported at the moment.

  ##

  def save(io, jar)
    YAML.dump(@session ? jar.to_a : jar.reject(&:session?), io)
  end

  def load(io, jar)
    data = parse_yaml(io)
    cookies = build_cookies(data)
    cookies.each { |cookie|
      jar.add(cookie)
    }
    self
  end

  private

  def default_options
    {}
  end

  # Parses the YAML document, transparently rewriting the legacy
  # Mechanize::Cookie tag once.  Any parse error (disallowed tag, bad
  # alias/anchor, syntax error, ...) is propagated to the caller.
  def parse_yaml(io)
    load_yaml(io)
  rescue ArgumentError => e
    raise unless e.message.start_with?('undefined class/module Mechanize::')
    # backward compatibility with Mechanize::Cookie
    begin
      io.rewind # hopefully
    rescue Errno::ESPIPE
      raise ArgumentError,
        'legacy Mechanize cookie data cannot be read from a non-rewindable stream'
    end
    yaml = io.read
    # a gross hack: drop the tag so records decode as plain hashes
    yaml.gsub!(%r{^(    [^ ].*:) !ruby/object:Mechanize::Cookie$}, "\\1")
    load_yaml(yaml)
  end

  # The restricted YAML entry point.  safe_load instantiates only
  # PERMITTED_CLASSES; aliases stay enabled because the current save
  # format shares Time objects between created_at and accessed_at.
  def load_yaml(yaml)
    YAML.safe_load(yaml,
      :permitted_classes => PERMITTED_CLASSES,
      :aliases => true)
  end

  # Validates the decoded document and returns the HTTP::Cookie objects
  # it describes without touching the target jar, so that a failure on
  # any record leaves the jar unchanged.
  def build_cookies(data)
    case data
    when Array
      data.map { |record|
        cookie_from_object(record)
      }
    when Hash
      cookies_from_mechanize_hash(data)
    else
      raise ArgumentError,
        "incompatible YAML cookie data: expected an Array or a Hash, got #{data.class}"
    end
  end

  # Handles the current Array form, where each element is already an
  # HTTP::Cookie produced by safe_load.  Anything else is rejected.
  def cookie_from_object(record)
    return record if record.is_a?(HTTP::Cookie)
    raise ArgumentError,
      "invalid YAML cookie record: expected HTTP::Cookie, got #{record.class}"
  end

  # Handles the legacy Mechanize nested-Hash form
  # (domain => path => name => cookie hash).
  def cookies_from_mechanize_hash(data)
    cookies = []
    assert_hash(data, 'top-level cookie data')
    data.each { |domain, paths|
      assert_key(domain, 'domain')
      assert_hash(paths, "paths for #{domain.inspect}")
      paths.each { |path, names|
        assert_key(path, 'path')
        assert_hash(names, "cookies for #{domain.inspect}#{path.inspect}")
        names.each { |name, cookie_hash|
          assert_key(name, 'cookie name')
          cookies << cookie_from_hash(cookie_hash)
        }
      }
    }
    cookies
  end

  # Builds an HTTP::Cookie from a legacy plain-hash record, validating
  # every field instead of trusting the whitelisted object tag.
  def cookie_from_hash(cookie_hash)
    if cookie_hash.respond_to?(:ivars)
      # YAML::Object of Syck
      cookie_hash = cookie_hash.ivars
    end
    assert_hash(cookie_hash, 'cookie record')

    attributes = {}
    cookie_hash.each_pair { |key, value|
      sym =
        case key
        when Symbol
          key
        when String
          key.to_sym
        else
          raise ArgumentError,
            "invalid cookie attribute name #{key.inspect}: expected a String"
        end
      if IGNORED_MECHANIZE_ATTRIBUTES.include?(sym)
        # Mechanize-only metadata with no HTTP::Cookie equivalent.  Make
        # sure an ignored slot cannot smuggle a nested structure (the
        # canonical fields are plain scalars or a DomainName), then drop
        # it; the string/Time fields above are the source of truth.
        assert_ignored_scalar(key, value)
        next
      end
      unless COOKIE_ATTRIBUTES.include?(sym)
        raise ArgumentError,
          "unknown cookie attribute #{key.inspect}"
      end
      validate_attribute(sym, value)
      attributes[sym] = value
    }

    HTTP::Cookie.new(attributes)
  end

  def validate_attribute(key, value)
    case key
    when :name, :value, :domain, :path
      assert_string_or_nil(key, value)
    when :for_domain, :secure, :httponly
      assert_boolean(key, value)
    when :expires, :created_at, :accessed_at
      assert_timeish(key, value)
    when :max_age
      assert_integer_or_nil(key, value)
    end
  end

  def assert_hash(value, what)
    value.is_a?(Hash) or
      raise ArgumentError, "invalid #{what}: expected a Hash, got #{value.class}"
  end

  def assert_key(value, what)
    value.is_a?(String) or
      raise ArgumentError, "invalid #{what} #{value.inspect}: expected a String key"
  end

  def assert_string_or_nil(key, value)
    return if value.nil?
    value.is_a?(String) or
      raise ArgumentError,
        "invalid cookie attribute #{key.inspect}: expected a String, got #{value.class}"
  end

  def assert_boolean(key, value)
    (value.equal?(true) || value.equal?(false)) or
      raise ArgumentError,
        "invalid cookie attribute #{key.inspect}: expected true or false, got #{value.inspect}"
  end

  def assert_timeish(key, value)
    return if value.nil? || value.is_a?(Time)
    # Legacy Mechanize files serialise times as HTTP-date strings.
    # Parse them eagerly so a malformed value fails the whole import
    # instead of reaching the cookie setter as an opaque object.
    if value.is_a?(String)
      begin
        Time.parse(value)
      rescue ArgumentError
        raise ArgumentError,
          "invalid cookie attribute #{key.inspect}: unparsable time #{value.inspect}"
      end
      return
    end
    raise ArgumentError,
      "invalid cookie attribute #{key.inspect}: expected a Time or time String, got #{value.class}"
  end

  def assert_integer_or_nil(key, value)
    return if value.nil?
    value.is_a?(Integer) or
      raise ArgumentError,
        "invalid cookie attribute #{key.inspect}: expected an Integer, got #{value.class}"
  end

  def assert_ignored_scalar(key, value)
    case value
    when nil, true, false, String, Numeric, Symbol, Time, DomainName
    else
      raise ArgumentError,
        "invalid cookie attribute #{key.inspect}: unexpected #{value.class}"
    end
  end
end

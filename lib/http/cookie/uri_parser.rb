require 'ipaddr'

module HTTP::Cookie::URIParser
  module_function

  # A host identity that is safe to use for cookie authorization.
  #
  # +kind+ is one of:
  #
  # :ip      - a canonical IPv4/IPv6 address.
  # :name    - an ordinary DNS host name (IDNA-normalized).
  # :exact   - an ambiguous literal that must only be compared by its
  #            exact text (e.g. non-canonical IPv4 spellings).  No
  #            parent domain may be inferred from it.
  Host = Struct.new(:name, :kind) do
    def exact_only?
      kind == :exact
    end
  end

  # Matches one label of an ambiguous numeric IPv4 spelling such as
  # "0x7f" or "0177".  These are accepted by some URL parsers as IPv4
  # addresses; treating them as DNS names would derive an unrelated
  # parent domain ("0.1") from the display text.
  NUMERIC_LABEL = /\A(?:0[xX][0-9A-Fa-f]+|[0-9]+)\z/

  # Regular Expression taken from RFC 3986 Appendix B
  URIREGEX = %r{
    \A
    (?: (?<scheme> [^:/?\#]+ ) : )?
    (?: // (?<authority> [^/?\#]* ) )?
    (?<path> [^?\#]* )
    (?: \? (?<query> [^\#]* ) )?
    (?: \# (?<fragment> .* ) )?
    \z
  }x

  # Escape RFC 3986 "reserved" characters minus valid characters for path
  # More specifically, gen-delims minus "/" / "?" / "#"
  def escape_path(path)
    path.sub(/\A[^?#]+/) { |p| p.gsub(/[:\[\]@]+/) { |r| CGI.escape(r) } }
  end

  # Parse a URI string or object, relaxing the constraints on the path component
  def parse(uri)
    str = String.try_convert(uri)
    if str && !str.ascii_only?
      str = encode_unicode_host(str) or
        raise URI::InvalidURIError, "URI must be ascii only #{uri.inspect}"
      uri = str
    end
    URI(uri)
  rescue URI::InvalidURIError
    str ||= String.try_convert(uri) or
      raise ArgumentError, "bad argument (expected URI object or URI string)"

    m = URIREGEX.match(str) or raise

    path = m[:path]
    str[m.begin(:path)...m.end(:path)] = escape_path(path)
    uri = URI.parse(str)
    uri.__send__(:set_path, path)
    uri
  end

  # Rewrites a URI string so a Unicode host is represented by its
  # ASCII (IDNA) form.  The IDNA form is the actual host identity; the
  # visible spelling is not.  Returns nil if the host cannot be safely
  # canonicalized.
  def encode_unicode_host(str)
    m = URIREGEX.match(str) or return nil
    authority = m[:authority] or return nil
    return nil if authority.ascii_only?

    userinfo, sep, hostport = authority.rpartition('@')
    prefix = sep.empty? ? '' : userinfo + sep
    return nil if prefix.include?('\\')

    if hostport.start_with?('[')
      # An IPv6/IPFuture literal is ASCII by definition.
      return nil
    end

    if hostport =~ /\A([^:]*):(\d*)\z/
      host, port = $1, $2
      suffix = ':' + port
    else
      host, suffix = hostport, ''
    end
    return nil if host.empty? || host.include?('\\')

    name = DomainName.new(host).hostname
    encoded = prefix + name + suffix
    out = str.dup
    out[m.begin(:authority)...m.end(:authority)] = encoded
    out
  rescue ArgumentError, TypeError
    nil
  end

  # Returns the host identity of `host`, or nil if it is empty or cannot
  # be interpreted.  The returned name is canonical and safe to compare;
  # see Host for the possible kinds.
  def host_identity(host)
    return nil if host.nil?
    str = String.try_convert(host) or return nil
    return nil if str.empty?

    # A bracketed literal is an IP address or an unknown (IPFuture)
    # literal.  Only the former has a canonical identity.
    if m = /\A\[(.*)\]\z/.match(str)
      ip = parse_ip(m[1])
      return ip ? Host.new(ip, :ip) : Host.new(str.downcase, :exact)
    end

    if ip = parse_ip(str)
      return Host.new(ip, :ip)
    end

    # A trailing root dot is part of the DNS representation, so a
    # canonical IP literal followed by one is still that same address.
    if str.end_with?('.') && (ip = parse_ip(str[0...-1]))
      return Host.new(ip, :ip)
    end

    # A percent-encoded host is not a DNS name.  Decoding it or cutting
    # it at a dot would invent an identity the request never had.
    return Host.new(str.downcase, :exact) if str.include?('%')

    # Whitespace and URI syntax (userinfo, port, path, query, scheme,
    # brackets, backslash) cannot appear in a bare host name.
    return Host.new(str.downcase, :exact) if str.match?(/[\s@\/?#\\:\[\]]/)

    name = str.end_with?('.') ? str[0...-1] : str
    # More than one trailing dot, an empty label or an empty name is not
    # a canonical DNS name.
    if name.empty? || name.end_with?('.') || name.split('.', -1).any?(&:empty?)
      return Host.new(str.downcase, :exact)
    end

    # A host made entirely of numeric (decimal/hex) labels may be an
    # alternate spelling of an IPv4 address.  It must not be treated as
    # a DNS name, which would hand out an unrelated parent domain.
    if name.split('.').all? { |label| NUMERIC_LABEL.match?(label) }
      return Host.new(str.downcase, :exact)
    end

    Host.new(DomainName.new(name).hostname, :name)
  rescue ArgumentError, TypeError
    nil
  end

  # Returns the host identity of a URI if (and only if) it is an
  # HTTP(S) URI with a usable host.  Invalid or incomplete URIs have no
  # identity to authorize a cookie with.
  def host_identity_of(uri)
    host_identity_of_with_reason(uri).first
  end

  # Like host_identity_of, but also returns the reason when there is no
  # usable identity.  The reason is a Symbol suitable for logging; it
  # never contains the URI, its host or any cookie data.
  def host_identity_of_with_reason(uri)
    uri = parse(uri)
    return [nil, :non_http_source] unless URI::HTTP === uri

    host = uri.host
    return [nil, :missing_source_host] if host.nil? || host.empty?

    identity = host_identity(host)
    return [nil, :ambiguous_source_host] if identity.nil?

    [identity, nil]
  rescue URI::InvalidURIError, ArgumentError, TypeError
    [nil, :invalid_source_uri]
  end

  # Builds the DomainName object used for parent-domain matching.  The
  # string form of an IPv4-mapped IPv6 address contains dots, so it is
  # given to DomainName in its all-hex form for correct IP detection.
  def domain_name_for(host)
    case host.kind
    when :ip
      ip = IPAddr.new(host.name)
      name = ip.ipv6? && host.name.include?('.') ?
        ip.to_i.to_s(16).rjust(32, '0').scan(/.{4}/).join(':') :
        host.name
      DomainName.new(name)
    when :name
      DomainName.new(host.name)
    end
  rescue ArgumentError, TypeError
    nil
  end

  def parse_ip(str)
    return nil if str.empty?
    ip = IPAddr.new(str)
    ip.ipv4? || ip.ipv6? ? ip.to_s : nil
  rescue ArgumentError, TypeError
    nil
  end
  private_class_method :parse_ip
end

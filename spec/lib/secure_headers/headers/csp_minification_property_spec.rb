# frozen_string_literal: true
require "spec_helper"

# Property-based tests proving that CSP source-list minification (dedup,
# wildcard collapsing, 'none' rejection, scheme stripping and path
# normalization in ContentSecurityPolicy#minify_source_list) never *widens*
# the set of resources a policy allows:
#
#     allowed(minified_header, resource) => allowed(original_config, resource)
#
# i.e. we hunt for "the output got shorter, yet allows more than the input".
#
# CspMinificationModel is an independent, deliberately small model of CSP3
# source-expression matching. Its supported grammar is exactly:
#   * 'none' 'self' 'unsafe-inline' 'unsafe-eval'
#   * nonces: 'nonce-<token>' (lowercase alnum token)
#   * scheme sources: https: data: blob:
#   * the * wildcard (matches http/https URLs only)
#   * host sources: [https://] (*. )?host(:port)?(/path)? with lowercase
#     hosts, exact or trailing-slash-prefix paths
# Anything outside that grammar raises UnsupportedSource and the property
# exits explicitly for that case instead of treating it as allowed.
#
# The protected resource is fixed at https://self.example. That https origin
# is what makes scheme stripping (https://example.com -> example.com)
# semantics-preserving. http:// host sources are therefore *outside* the
# supported grammar: stripping them is historical, expansion-prone behavior
# that is pinned separately at the bottom of this file.
module CspMinificationModel
  class UnsupportedSource < StandardError; end

  PROTECTED_ORIGIN = { scheme: "https", host: "self.example", port: 443 }.freeze
  DEFAULT_PORTS = { "http" => 80, "https" => 443 }.freeze
  NETWORK_SCHEMES = %w(http https).freeze

  module_function

  # source_list: array of source-expression strings (nil/empty = no directive)
  # resource: {type: :url, scheme:, host:, port:, path:}
  #           {type: :inline, nonce:} or {type: :eval}
  def allows?(source_list, resource)
    return false if source_list.nil? || source_list.empty?
    sources = source_list.map { |expr| parse_source(expr) }
    # CSP: 'none' is ignored when other source expressions are present.
    sources = sources.reject { |s| s[:kind] == :none } if sources.length > 1
    return false if sources.any? { |s| s[:kind] == :none }
    sources.any? { |source| source_matches?(source, resource) }
  end

  def parse_source(expr)
    case expr
    when "*" then { kind: :star }
    when "'none'" then { kind: :none }
    when "'self'" then { kind: :self }
    when "'unsafe-inline'" then { kind: :unsafe_inline }
    when "'unsafe-eval'" then { kind: :unsafe_eval }
    when /\A'nonce-([a-z0-9]+)'\z/ then { kind: :nonce, token: Regexp.last_match(1) }
    when /\A(https|data|blob):\z/ then { kind: :scheme, scheme: Regexp.last_match(1) }
    when /\A(?:https:\/\/)?(?:\*\.)?[a-z0-9]+(?:\.[a-z0-9]+)*(?::\d+)?(?:\/[a-z0-9\/]*)?\z/
      parse_host_source(expr)
    else
      raise UnsupportedSource, "unsupported source expression: #{expr.inspect}"
    end
  end

  def parse_host_source(expr)
    scheme = expr.start_with?("https://") ? "https" : nil
    rest = scheme ? expr.delete_prefix("https://") : expr.dup
    wildcard = rest.start_with?("*.")
    rest = rest.delete_prefix("*.")
    host, port, path = split_host_port_path(rest)
    { kind: :host, scheme: scheme, wildcard: wildcard, host: host, port: port, path: path }
  end

  def split_host_port_path(str)
    path = nil
    if (slash = str.index("/"))
      path = str[slash..]
      str = str[0...slash]
    end
    port = nil
    if str =~ /:(\d+)\z/
      port = Regexp.last_match(1).to_i
      str = str[0...str.rindex(":")]
    end
    [str, port, path]
  end

  def source_matches?(source, resource)
    case source[:kind]
    when :star
      resource[:type] == :url && NETWORK_SCHEMES.include?(resource[:scheme])
    when :scheme
      resource[:type] == :url && resource[:scheme] == source[:scheme]
    when :self
      resource[:type] == :url &&
        resource[:scheme] == PROTECTED_ORIGIN[:scheme] &&
        resource[:host] == PROTECTED_ORIGIN[:host] &&
        resource[:port] == PROTECTED_ORIGIN[:port]
    when :unsafe_inline
      resource[:type] == :inline
    when :unsafe_eval
      resource[:type] == :eval
    when :nonce
      resource[:type] == :inline && resource[:nonce] == source[:token]
    when :host
      host_source_matches?(source, resource)
    end
  end

  def host_source_matches?(source, resource)
    return false unless resource[:type] == :url
    return false if resource[:host].nil?
    # A schemeless host source inherits the protected resource's scheme.
    return false unless resource[:scheme] == (source[:scheme] || PROTECTED_ORIGIN[:scheme])
    if source[:wildcard]
      return false unless resource[:host].end_with?(".#{source[:host]}")
    elsif resource[:host] != source[:host]
      return false
    end
    if source[:port]
      return false unless resource[:port] == source[:port]
    elsif resource[:port] != DEFAULT_PORTS[resource[:scheme]]
      return false
    end
    path_matches?(source[:path], resource[:path])
  end

  # CSP3 6.6.2.10: a source path ending in "/" is a prefix match, anything
  # else is an exact match. No path (or the root path "/") matches
  # everything -- which is exactly why chomping a bare trailing "/" off a
  # host source is semantics-preserving.
  def path_matches?(source_path, url_path)
    return true if source_path.nil? || source_path.empty? || source_path == "/"
    url_path = "/" if url_path.nil? || url_path.empty?
    if source_path.end_with?("/")
      url_path.start_with?(source_path)
    else
      url_path == source_path
    end
  end
end

# Generates configs and resources strictly inside (plus a small tail of
# known-unsupported expressions around) the model's grammar.
module CspMinificationGenerator
  PROBE_DIRECTIVES = %i(default_src script_src style_src img_src connect_src font_src frame_src worker_src manifest_src media_src object_src child_src).freeze
  HOSTS = %w(example.com self.example sub.example.com other.com).freeze
  RESOURCE_HOSTS = %w(self.example example.com sub.example.com deep.sub.example.com other.com example.com.evil.com notexample.com).freeze
  SOURCE_PATHS = ["/", "/foo", "/foo/", "/foo/bar"].freeze
  RESOURCE_PATHS = ["/", "/foo", "/foo/", "/foo/bar", "/foobar", "/foo/bar/baz", "/FOO"].freeze
  PORTS = [nil, 80, 443, 8080, 4443].freeze
  NONCE_TOKENS = %w(abc123 xyz789).freeze
  UNSUPPORTED_SOURCES = ["http://example.com", "'strict-dynamic'", "'sha256-abc123'", "wss://example.com"].freeze

  module_function

  def config(rng)
    cfg = {}
    PROBE_DIRECTIVES.each do |directive|
      present = directive == :default_src ? rng.rand < 0.8 : rng.rand < 0.5
      next unless present
      cfg[directive] = rng.rand < 0.06 ? [] : Array.new(rng.rand(1..4)) { source(rng) }
    end
    cfg[:script_nonce] = NONCE_TOKENS.sample(random: rng) if rng.rand < 0.35
    cfg[:style_nonce] = NONCE_TOKENS.sample(random: rng) if rng.rand < 0.35
    cfg[:disable_nonce_backwards_compatibility] = true if rng.rand < 0.25
    cfg[:preserve_schemes] = true if rng.rand < 0.25
    cfg
  end

  def source(rng)
    roll = rng.rand
    case
    when roll < 0.03 then UNSUPPORTED_SOURCES.sample(random: rng)
    when roll < 0.08 then "*"
    when roll < 0.13 then "'none'"
    when roll < 0.22 then "'self'"
    when roll < 0.29 then "'unsafe-inline'"
    when roll < 0.34 then "'unsafe-eval'"
    when roll < 0.41 then "https:"
    when roll < 0.45 then "data:"
    when roll < 0.48 then "blob:"
    else host_source(rng)
    end
  end

  def host_source(rng)
    source = +""
    source << "https://" if rng.rand < 0.4
    source << "*." if rng.rand < 0.3
    source << HOSTS.sample(random: rng)
    source << ":#{[80, 443, 8080, 4443].sample(random: rng)}" if rng.rand < 0.3
    source << SOURCE_PATHS.sample(random: rng) if rng.rand < 0.45
    source
  end

  def resource(rng)
    roll = rng.rand
    if roll < 0.12
      { type: :inline, nonce: [nil, "abc123", "xyz789", "nope"].sample(random: rng) }
    elsif roll < 0.16
      { type: :eval }
    elsif roll < 0.22
      { type: :url, scheme: "data", host: nil, port: nil, path: nil }
    else
      scheme = %w(http https).sample(random: rng)
      {
        type: :url,
        scheme: scheme,
        host: RESOURCE_HOSTS.sample(random: rng),
        port: PORTS.sample(random: rng) || CspMinificationModel::DEFAULT_PORTS[scheme],
        path: RESOURCE_PATHS.sample(random: rng)
      }
    end
  end
end

# Compares the permission set of the original config against the permission
# set of the minified header the gem actually emits, using the model.
module CspMinificationProperty
  module_function

  # The semantic intent of the config for one directive, mirroring the
  # non-minification parts of header building: default-src fallback and
  # nonce population (which the gem skips entirely when '*' is present).
  def baseline_list(config, directive)
    list = config[directive]
    list = config[:default_src] if list.nil? || list.empty?
    return nil if list.nil? || list.empty?
    list = list.dup
    unless list.include?("*")
      nonce = directive == :script_src ? config[:script_nonce] : (config[:style_nonce] if directive == :style_src)
      if nonce
        list << "'nonce-#{nonce}'"
        list << "'unsafe-inline'" unless config[:disable_nonce_backwards_compatibility]
      end
    end
    list
  end

  def parse_header(value)
    return {} if value.nil? || value.empty?
    value.split("; ").each_with_object({}) do |directive, parsed|
      name, *sources = directive.split(" ")
      parsed[name.tr("-", "_").to_sym] = sources
    end
  end

  # A directive that is present with an empty source list denies everything
  # (CSP3: an empty source list matches nothing); only an absent directive
  # falls back to default-src.
  def minified_list(parsed, directive)
    parsed[directive] || (directive == :default_src ? nil : parsed[:default_src])
  end

  # Returns true on widening, false on preservation, :unsupported when the
  # case leaves the modeled grammar (explicit exit, never read as "allowed").
  def check(config, parsed, directive, resource)
    baseline = CspMinificationModel.allows?(baseline_list(config, directive), resource)
    minified = CspMinificationModel.allows?(minified_list(parsed, directive), resource)
    minified && !baseline
  rescue CspMinificationModel::UnsupportedSource
    :unsupported
  end

  def shrink(config, directive, resource)
    best = Marshal.load(Marshal.dump(config))
    changed = true
    rounds = 0
    while changed && rounds < 25
      changed = false
      rounds += 1
      (best.keys - [directive]).each do |key|
        candidate = best.reject { |k, _| k == key }
        next unless widening?(candidate, directive, resource)
        best = candidate
        changed = true
      end
      [directive, :default_src].uniq.each do |d|
        next unless best[d].is_a?(Array)
        best[d].length.times do |i|
          candidate = Marshal.load(Marshal.dump(best))
          candidate[d] = candidate[d].dup
          candidate[d].delete_at(i)
          next unless widening?(candidate, directive, resource)
          best = candidate
          changed = true
          break
        end
      end
    end
    [best, shrink_resource(best, directive, resource)]
  end

  def shrink_resource(config, directive, resource)
    return resource unless resource[:type] == :url
    shrunk = resource
    [{ path: "/" }, { port: CspMinificationModel::DEFAULT_PORTS[resource[:scheme]] }].each do |simp|
      candidate = shrunk.merge(simp)
      shrunk = candidate if widening?(config, directive, candidate)
    end
    shrunk
  end

  def widening?(config, directive, resource)
    parsed = parse_header(SecureHeaders::ContentSecurityPolicy.new(config).value)
    check(config, parsed, directive, resource) == true
  end
end

module SecureHeaders
  describe "CSP source-list minification (property-based semantics preservation)" do
    iterations = (ENV["CSP_PROPERTY_ITERATIONS"] || 250).to_i

    it "never allows more after minification than before (#{iterations} seeded configs)" do
      seed = (ENV["CSP_PROPERTY_SEED"] || Random.new_seed).to_i
      rng = Random.new(seed)
      unsupported_exits = 0

      iterations.times do
        config = CspMinificationGenerator.config(rng)
        parsed = CspMinificationProperty.parse_header(ContentSecurityPolicy.new(config).value)
        resources = Array.new(6) { CspMinificationGenerator.resource(rng) }

        CspMinificationGenerator::PROBE_DIRECTIVES.each do |directive|
          resources.each do |resource|
            result = CspMinificationProperty.check(config, parsed, directive, resource)
            if result == :unsupported
              unsupported_exits += 1
              next
            end
            next unless result

            shrunk_config, shrunk_resource = CspMinificationProperty.shrink(config, directive, resource)
            header = ContentSecurityPolicy.new(shrunk_config).value
            raise RSpec::Expectations::ExpectationNotMetError, <<~MSG
              CSP minification widened the policy: the shorter output allows a resource the input did not.
              reproduce with: CSP_PROPERTY_SEED=#{seed} bundle exec rspec #{__FILE__}
              shrunken config:   #{shrunk_config.inspect}
              directive:         #{directive}
              shrunken resource: #{shrunk_resource.inspect}
              original allows:   false
              minified allows:   true
              minified header:   #{header}
            MSG
          end
        end
      end

      # The generator deliberately emits a tail of unsupported expressions;
      # this proves the explicit-exit path was exercised rather than silently
      # treated as allowed.
      expect(unsupported_exits).to be > 0
    end
  end

  describe CspMinificationModel do
    def url(scheme:, host:, port:, path:)
      { type: :url, scheme: scheme, host: host, port: port, path: path }
    end

    it "treats a trailing-slash source path as a prefix and a bare path as exact" do
      expect(described_class.allows?(["example.com/foo/"], url(scheme: "https", host: "example.com", port: 443, path: "/foo/bar"))).to be(true)
      expect(described_class.allows?(["example.com/foo/"], url(scheme: "https", host: "example.com", port: 443, path: "/foobar"))).to be(false)
      expect(described_class.allows?(["example.com/foo"], url(scheme: "https", host: "example.com", port: 443, path: "/foo"))).to be(true)
      expect(described_class.allows?(["example.com/foo"], url(scheme: "https", host: "example.com", port: 443, path: "/foo/bar"))).to be(false)
    end

    it "matches a root path against everything (the chomp-('/') invariant)" do
      expect(described_class.allows?(["example.com/"], url(scheme: "https", host: "example.com", port: 443, path: "/anything"))).to be(true)
      expect(described_class.allows?(["example.com"], url(scheme: "https", host: "example.com", port: 443, path: "/anything"))).to be(true)
    end

    it "matches *. hosts against subdomains only, never the bare host or a suffix lookalike" do
      expect(described_class.allows?(["*.example.com"], url(scheme: "https", host: "a.example.com", port: 443, path: "/"))).to be(true)
      expect(described_class.allows?(["*.example.com"], url(scheme: "https", host: "example.com", port: 443, path: "/"))).to be(false)
      expect(described_class.allows?(["*.example.com"], url(scheme: "https", host: "example.com.evil.com", port: 443, path: "/"))).to be(false)
    end

    it "requires explicit ports to match and defaults to the url scheme's port" do
      expect(described_class.allows?(["example.com:8080"], url(scheme: "https", host: "example.com", port: 8080, path: "/"))).to be(true)
      expect(described_class.allows?(["example.com:8080"], url(scheme: "https", host: "example.com", port: 443, path: "/"))).to be(false)
      expect(described_class.allows?(["example.com"], url(scheme: "https", host: "example.com", port: 8080, path: "/"))).to be(false)
    end

    it "ignores 'none' alongside other sources and denies when 'none' stands alone" do
      expect(described_class.allows?(["'none'", "example.com"], url(scheme: "https", host: "example.com", port: 443, path: "/"))).to be(true)
      expect(described_class.allows?(["'none'"], url(scheme: "https", host: "example.com", port: 443, path: "/"))).to be(false)
    end

    it "matches nonces only against inline resources carrying the same token" do
      expect(described_class.allows?(["'nonce-abc123'"], { type: :inline, nonce: "abc123" })).to be(true)
      expect(described_class.allows?(["'nonce-abc123'"], { type: :inline, nonce: "xyz789" })).to be(false)
      expect(described_class.allows?(["'nonce-abc123'"], url(scheme: "https", host: "example.com", port: 443, path: "/"))).to be(false)
    end

    it "lets schemeless host sources inherit the https protected-origin scheme" do
      expect(described_class.allows?(["example.com"], url(scheme: "https", host: "example.com", port: 443, path: "/"))).to be(true)
      expect(described_class.allows?(["example.com"], url(scheme: "http", host: "example.com", port: 80, path: "/"))).to be(false)
    end

    it "raises UnsupportedSource for syntax outside the modeled grammar" do
      expect { described_class.parse_source("http://example.com") }.to raise_error(CspMinificationModel::UnsupportedSource)
      expect { described_class.parse_source("'strict-dynamic'") }.to raise_error(CspMinificationModel::UnsupportedSource)
    end
  end

  describe "historical behavior outside the supported grammar" do
    it "pins http:// scheme stripping as known, expansion-prone legacy behavior" do
      csp = ContentSecurityPolicy.new(default_src: %w('none'), img_src: %w(http://example.com))
      expect(csp.value).to eq("default-src 'none'; img-src example.com")

      # The model deliberately refuses to reason about http:// host sources,
      # so the property above exits explicitly for them.
      expect { CspMinificationModel.parse_source("http://example.com") }.to raise_error(CspMinificationModel::UnsupportedSource)

      # Under the model's https protected origin, the stripped output allows
      # https://example.com, which the original http://-only source never did.
      # This is historical compatibility behavior of the gem (secure_headers
      # assumes an https deployment), not a defect in the supported grammar;
      # it is pinned here as executable regression evidence.
      stripped_allows = CspMinificationModel.allows?(
        ["example.com"],
        { type: :url, scheme: "https", host: "example.com", port: 443, path: "/" }
      )
      expect(stripped_allows).to be(true)
    end
  end
end

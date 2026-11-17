# frozen_string_literal: true

# Dependency-upgrade review helper for http-cookie + domain_name.
#
# It loads a *fixed* Public Suffix List excerpt from review/fixtures and
# injects it into DomainName, so a review run never consults the live PSL,
# never resolves a name and never reads a production cookie jar.
#
# The catalog is injected at the single place the cookie code consults:
# DomainName.etld_data (used by DomainName#initialize to compute
# #domain). Everything below therefore exercises the real code path used
# by HTTP::Cookie#domain=, #acceptable?, #acceptable_from_uri? and
# #valid_for_uri?.

# The local preparation installs gems into .gems/, which is not on the
# default load path. Resolve it before requiring the dependency.
REPO_ROOT = File.expand_path('..', __dir__)
GEM_ROOT = File.join(REPO_ROOT, '.gems')
$LOAD_PATH.unshift(File.join(REPO_ROOT, 'lib')) unless $LOAD_PATH.include?(File.join(REPO_ROOT, 'lib'))
if File.directory?(GEM_ROOT)
  require 'rubygems'
  Gem.use_paths(GEM_ROOT, [GEM_ROOT])
end

require 'domain_name'
require 'http/cookie'
require 'http/cookie_jar'

module DomainUpgradeReview
  # Rule kinds, matching domain_name's generated ETLD_DATA encoding
  # (tool/gen_etld_data.rb):
  #   0  => "name" rule (matches name and its subdomains)
  #   -1  => "*.name" wildcard rule
  #   1  => "!name" exception rule
  RULE_PLAIN = 0
  RULE_WILDCARD = -1
  RULE_EXCEPTION = 1

  Section = Struct.new(:line, :section, :rule, :value, keyword_init: true)

  # A parsed, fixed suffix catalog with source labels preserved.
  class Catalog
    attr_reader :path, :sections, :table

    def initialize(path)
      @path = path
      @sections = []
      @table = {}
      parse(File.read(path, encoding: 'UTF-8'))
    end

    # The table shape DomainName#initialize expects.
    def etld_data
      @table
    end

    def rules
      @sections
    end

    # Where did a given suffix rule come from? Used by the report so a
    # classification change can be attributed to a section/rule, not
    # merely to "the database changed".
    def sources_for(key)
      @sections.select { |s| s.rule == key }
    end

    private

    def parse(text)
      section = nil
      text.each_line.with_index(1) do |raw, lineno|
        stripped = raw.strip
        case stripped
        when '// ===BEGIN ICANN DOMAINS==='   then section = :icann; next
        when '// ===END ICANN DOMAINS==='     then section = nil; next
        when '// ===BEGIN PRIVATE DOMAINS===' then section = :private; next
        when '// ===END PRIVATE DOMAINS==='   then section = nil; next
        end

        line = raw.sub(%r{//.*}, '').strip
        next if line.empty?

        rule, value = rule_for(line)
        key = DomainName.normalize(rule)
        @table[key] = value
        @sections << Section.new(line: lineno, section: section, rule: key, value: value)
      end
      raise ArgumentError, "no rules parsed from #{@path}" if @table.empty?
    end

    def rule_for(line)
      case line
      when /\A\*\.(.+)\z/ then [Regexp.last_match(1), RULE_WILDCARD]
      when /\A!(.+)\z/    then [Regexp.last_match(1), RULE_EXCEPTION]
      when /\A[^*!]+\z/   then [line, RULE_PLAIN]
      else raise ArgumentError, "unsupported PSL rule: #{line.inspect}"
      end
    end
  end

  # Temporarily installs a catalog as DomainName's suffix data.
  #
  # DomainName.etld_data is a class method returning a constant; overriding
  # the singleton method (rather than mutating the frozen-ish constant) makes
  # the switch local and always restorable.
  def self.with_catalog(catalog)
    original = DomainName.method(:etld_data)
    DomainName.define_singleton_method(:etld_data) { catalog.etld_data }
    yield
  ensure
    DomainName.singleton_class.send(:remove_method, :etld_data)
    DomainName.define_singleton_method(:etld_data, original)
  end

  # A single parent-domain (or host-only) declaration under one catalog.
  Scenario = Struct.new(
    :id, :group, :set_cookie, :origin, :probe_urls, :note,
    keyword_init: true
  )

  # The fixed scenario matrix. No network names are resolved; every origin
  # and probe URL below is synthetic.
  def self.scenarios
    [
      Scenario.new(
        id: 'web-app-parent',
        group: 'private suffix added in 2024 data',
        set_cookie: 'sid=parent-web-app; Domain=web.app; Path=/',
        origin: 'http://alice.web.app/',
        probe_urls: %w[
          http://alice.web.app/
          http://bob.web.app/
          http://web.app/
        ],
        note: 'web.app is a PRIVATE suffix; Domain=web.app claims the suffix itself'
      ),
      Scenario.new(
        id: 'web-app-host-only',
        group: 'host-only control for the same name',
        set_cookie: 'sid=host-web-app; Path=/',
        origin: 'http://web.app/',
        probe_urls: %w[http://web.app/ http://alice.web.app/],
        note: 'no Domain attribute: host-only to the exact host'
      ),
      Scenario.new(
        id: 'web-app-child-host-only',
        group: 'host-only control for the same name',
        set_cookie: 'sid=host-alice; Path=/',
        origin: 'http://alice.web.app/',
        probe_urls: %w[http://alice.web.app/ http://bob.web.app/],
        note: 'no Domain attribute: host-only to alice.web.app'
      ),
      Scenario.new(
        id: 'co-jp-parent',
        group: 'multi-level ICANN suffix',
        set_cookie: 'sid=co-jp; Domain=example.co.jp; Path=/',
        origin: 'http://shop.example.co.jp/',
        probe_urls: %w[
          http://shop.example.co.jp/
          http://other.example.co.jp/
          http://notexample.co.jp/
        ],
        note: 'example.co.jp is registrable below the co.jp rule'
      ),
      Scenario.new(
        id: 'co-jp-suffix',
        group: 'multi-level ICANN suffix',
        set_cookie: 'sid=co-jp-suffix; Domain=co.jp; Path=/',
        origin: 'http://shop.example.co.jp/',
        probe_urls: %w[http://shop.example.co.jp/],
        note: 'Domain=co.jp claims a suffix; must be refused'
      ),
      Scenario.new(
        id: 'github-io-parent',
        group: 'private suffix already present in both catalogs',
        set_cookie: 'sid=github-parent; Domain=github.io; Path=/',
        origin: 'http://alice.github.io/',
        probe_urls: %w[
          http://alice.github.io/
          http://bob.github.io/
          http://github.io/
        ],
        note: 'PRIVATE suffix in both data versions: unchanged rejection'
      ),
      Scenario.new(
        id: 'github-io-host-only',
        group: 'private suffix already present in both catalogs',
        set_cookie: 'sid=github-host; Path=/',
        origin: 'http://alice.github.io/',
        probe_urls: %w[http://alice.github.io/ http://bob.github.io/],
        note: 'host-only sibling isolation is unchanged'
      ),
      Scenario.new(
        id: 'web-app-child-parent',
        group: 'private suffix added in 2024 data',
        set_cookie: 'sid=child; Domain=alice.web.app; Path=/',
        origin: 'http://api.alice.web.app/',
        probe_urls: %w[
          http://api.alice.web.app/
          http://www.alice.web.app/
          http://bob.web.app/
        ],
        note: 'registrable name BELOW the new suffix still works; only the suffix itself is refused'
      ),
      Scenario.new(
        id: 'github-io-child-parent',
        group: 'private suffix already present in both catalogs',
        set_cookie: 'sid=child; Domain=alice.github.io; Path=/',
        origin: 'http://api.alice.github.io/',
        probe_urls: %w[
          http://api.alice.github.io/
          http://www.alice.github.io/
          http://bob.github.io/
        ],
        note: 'control: registrable name below a private suffix, unchanged'
      ),
      Scenario.new(
        id: 'kawasaki-wildcard',
        group: 'wildcard ICANN rule',
        set_cookie: 'sid=kawasaki; Domain=a.foo.kawasaki.jp; Path=/',
        origin: 'http://www.a.foo.kawasaki.jp/',
        probe_urls: %w[
          http://www.a.foo.kawasaki.jp/
          http://api.a.foo.kawasaki.jp/
          http://www.b.foo.kawasaki.jp/
        ],
        note: '*.kawasaki.jp makes a.foo.kawasaki.jp registrable; b.foo.kawasaki.jp is a different registrable domain'
      ),
      Scenario.new(
        id: 'kawasaki-exception',
        group: 'wildcard exception rule',
        set_cookie: 'sid=city-kawasaki; Domain=city.kawasaki.jp; Path=/',
        origin: 'http://www.city.kawasaki.jp/',
        probe_urls: %w[
          http://www.city.kawasaki.jp/
          http://www.foo.kawasaki.jp/
        ],
        note: '!city.kawasaki.jp re-enables the name below the wildcard'
      ),
      Scenario.new(
        id: 's3-private-parent',
        group: 'private suffix already present in both catalogs',
        set_cookie: 'sid=s3; Domain=s3.amazonaws.com; Path=/',
        origin: 'http://bucket.s3.amazonaws.com/',
        probe_urls: %w[
          http://bucket.s3.amazonaws.com/
          http://other.s3.amazonaws.com/
        ],
        note: 'PRIVATE rule: the suffix itself is not registrable'
      ),
      Scenario.new(
        id: 'local-fallback-parent',
        group: 'unknown/local TLD fallback',
        set_cookie: 'sid=local; Domain=example.local; Path=/',
        origin: 'http://www.example.local/',
        probe_urls: %w[
          http://www.example.local/
          http://other.example.local/
        ],
        note: 'no catalog entry for .local: two-label fallback'
      ),
      Scenario.new(
        id: 'local-fallback-suffix',
        group: 'unknown/local TLD fallback',
        set_cookie: 'sid=local-suffix; Domain=local; Path=/',
        origin: 'http://www.example.local/',
        probe_urls: %w[http://www.example.local/],
        note: 'the fallback still refuses a bare single-label domain'
      ),
    ]
  end

  # Builds a jar for one scenario under the catalog currently installed.
  # The origin is the synthetic declaration source; probes are separate.
  def self.run_scenario(scenario)
    jar = HTTP::CookieJar.new
    accepted = jar.parse(scenario.set_cookie, scenario.origin)
    {
      accepted: accepted,
      sent: probe_values(jar, scenario.probe_urls),
    }
  end

  def self.probe_values(jar, urls)
    urls.to_h { |url| [url, HTTP::Cookie.cookie_value(jar.cookies(url))] }
  end

  # A record persisted before the upgrade, replayed through a real saver.
  #
  # The two formats differ in an important way:
  #   * YAML restores the stored for_domain flag verbatim.
  #   * cookies.txt recomputes it from the stored domain string at load
  #     time (HTTP::Cookie#domain=), so a suffix is silently downgraded.
  # A review that only models one of them will miss the asymmetry.
  Legacy = Struct.new(:id, :file, :format, :note, keyword_init: true)

  def self.legacy_records
    [
      Legacy.new(
        id: 'legacy-yaml-web-app',
        file: 'legacy-web-app.yml',
        format: :yaml,
        note: 'YAML keeps for_domain=true; parent scope is evaluated at send time'
      ),
      Legacy.new(
        id: 'legacy-cookiestxt-web-app',
        file: 'legacy-web-app.cookies.txt',
        format: :cookiestxt,
        note: 'cookies.txt recomputes for_domain on load and downgrades the suffix to host-only'
      ),
    ]
  end

  def self.run_legacy(record, fixture_dir)
    jar = HTTP::CookieJar.new
    jar.load(File.join(fixture_dir, record.file), record.format)
    {
      stored: jar.to_a.map { |c|
        {
          'name' => c.name,
          'domain' => c.domain,
          'for_domain' => c.for_domain?,
          'registrable_domain' => c.domain_name&.domain,
        }
      },
      sent: probe_values(jar, LEGACY_PROBES),
    }
  end

  LEGACY_PROBES = %w[
    http://web.app/
    http://alice.web.app/
    http://bob.web.app/
  ].freeze

  # Re-audits an already-stored record under the new catalog.
  #
  # This is deliberately separate from accepting a new Set-Cookie.
  # A stored record is data, not a fresh assertion: it must not be
  # rewritten merely because its displayed domain string is unchanged,
  # and its old scope must not be treated as evidence of current intent.
  #
  # Returns a recommendation plus the observable send sets that justify it.
  def self.reaudit(record, fixture_dir, before_catalog, after_catalog)
    before = with_catalog(before_catalog) { run_legacy(record, fixture_dir) }
    after  = with_catalog(after_catalog)  { run_legacy(record, fixture_dir) }

    sent_before = before[:sent].select { |_, value| !value.empty? }.keys
    sent_after  = after[:sent].select { |_, value| !value.empty? }.keys

    unchanged_display = before[:stored].map { |c| c['domain'] } ==
                        after[:stored].map { |c| c['domain'] }

    recommendation =
      if sent_after == sent_before
        'keep'
      elsif (sent_after - sent_before).empty?
        # Still delivered somewhere, but the reachable set shrank.
        'keep_narrowed'
      elsif (sent_before - sent_after).empty?
        # Reachable set grew: this is the unsafe direction.
        'quarantine_scope_expanded'
      else
        'quarantine_scope_rewritten'
      end

    {
      'display_domain_unchanged' => unchanged_display,
      'sent_before' => sent_before,
      'sent_after' => sent_after,
      'recommendation' => recommendation,
      'stored_before' => before[:stored],
      'stored_after' => after[:stored],
    }
  end

  # The catalog rule that decides whether +host+ has a registrable domain.
  # This is the citation the report uses when classification changes.
  def self.deciding_rules(catalog, host)
    normalized = DomainName.normalize(host)
    labels = normalized.split('.')
    hits = []
    labels.each_index do |i|
      candidate = labels[i..].join('.')
      entry = catalog.rules.find { |rule| rule.rule == candidate }
      hits << entry if entry
    end
    hits
  end

  # Facts about a domain under the catalog currently installed.
  #
  # `domain_name.domain` is nil exactly when DomainName considers the name
  # a public suffix (or an IP address). http-cookie turns that nil into the
  # host-only flag in HTTP::Cookie#domain=.
  def self.facts(host)
    name = DomainName.new(host)
    {
      hostname: name.hostname,
      registrable_domain: name.domain,
      suffix_or_ip: name.domain.nil?,
      canonical: name.canonical?,
    }
  end

  # Classifies a parent-domain declaration exactly as HTTP::Cookie#domain=
  # will consume it. `for_domain` records the intended declaration, and
  # `effective_for_domain` records what the library actually keeps.
  def self.classify(raw_domain, intended_for_domain)
    cookie = HTTP::Cookie.new('probe', 'v')
    cookie.for_domain = intended_for_domain
    cookie.domain = raw_domain
    {
      declared_domain: cookie.domain,
      intended_for_domain: intended_for_domain,
      effective_for_domain: cookie.for_domain?,
      registrable_domain: cookie.domain_name.domain,
      suffix_or_ip: cookie.domain_name.domain.nil?,
      canonical: cookie.domain_name.canonical?,
    }
  end
end

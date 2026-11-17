# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))

class TestHTTPCookieRequestContext < Test::Unit::TestCase
  RC = HTTP::Cookie::RequestContext

  def new_context(**overrides)
    RC.new(**{
      :url => 'https://shop.example.com/login',
      :top_level_site => 'https://shop.example.com/',
    }.merge(overrides))
  end

  # ------------------------------------------------------------------
  # Construction and validation
  # ------------------------------------------------------------------

  def test_requires_url_and_top_level_site
    assert_raise(ArgumentError) { RC.new(:top_level_site => 'https://x.example') }
    assert_raise(ArgumentError) { RC.new(:url => 'https://x.example') }
  end

  def test_rejects_non_http_urls
    assert_raise(ArgumentError) {
      RC.new(:url => 'file:///tmp/x', :top_level_site => 'https://x.example')
    }
    assert_raise(ArgumentError) {
      RC.new(:url => 'https://x.example', :top_level_site => 'ftp://x.example')
    }
    assert_raise(ArgumentError) {
      RC.new(:url => '/relative/path', :top_level_site => 'https://x.example')
    }
  end

  def test_rejects_bad_default_samesite
    assert_raise(ArgumentError) {
      new_context(:default_samesite => :bogus)
    }
  end

  def test_defaults
    context = new_context
    assert_equal 'GET', context.method
    assert_equal false, context.navigation?
    assert_equal true, context.subresource?
    assert_equal false, context.redirected?
    assert_equal :lax, context.default_samesite
  end

  def test_method_is_normalized_and_validated
    context = new_context(:method => 'post')
    assert_equal 'POST', context.method
    assert_equal false, context.safe_method?

    assert new_context(:method => 'GET').safe_method?
    assert new_context(:method => 'HEAD').safe_method?
    assert new_context(:method => 'OPTIONS').safe_method?
    assert new_context(:method => 'TRACE').safe_method?
    assert_equal false, new_context(:method => 'POST').safe_method?

    assert_raise(TypeError) { new_context(:method => 42) }
    assert_raise(ArgumentError) { new_context(:method => '') }
  end

  # ------------------------------------------------------------------
  # Schemeful same-site vs. same-origin
  # ------------------------------------------------------------------

  def test_site_uses_scheme_and_registrable_domain
    assert_equal ['https', 'example.com'],
      RC.site_for('https://a.b.example.com:8443/path')
    # public suffix classification is respected
    assert_equal ['https', 'example.co.uk'],
      RC.site_for('https://www.example.co.uk/')
    # IP addresses form their own site
    assert_equal ['http', '192.168.0.1'],
      RC.site_for('http://192.168.0.1/')
  end

  def test_scheme_makes_a_schemeful_cross_site
    context = RC.new(
      :url => 'http://shop.example.com/',
      :top_level_site => 'https://shop.example.com/')
    assert_equal false, context.same_site?
  end

  def test_same_site_cross_subdomain_but_not_same_origin
    context = RC.new(
      :url => 'https://sub.shop.example.com:8443/',
      :top_level_site => 'https://www.shop.example.com/')
    # same registrable domain + scheme => same-site ...
    assert_equal true, context.same_site?
    # ... but different host/port => not same-origin
    assert_equal false, context.same_origin?
  end

  def test_same_origin_requires_scheme_host_and_port
    same = RC.new(
      :url => 'https://shop.example.com:443/a',
      :top_level_site => 'https://shop.example.com/b')
    assert_equal true, same.same_origin?
    assert_equal true, same.same_site?

    diff_port = RC.new(
      :url => 'https://shop.example.com:8443/',
      :top_level_site => 'https://shop.example.com/')
    assert_equal true, diff_port.same_site?
    assert_equal false, diff_port.same_origin?
  end

  def test_cross_site
    context = RC.new(
      :url => 'https://shop.example.com/',
      :top_level_site => 'https://other.org/')
    assert_equal false, context.same_site?
    assert_equal false, context.same_origin?
  end

  def test_public_suffix_subdomains_are_different_sites
    # example.co.uk and other.co.uk share the public suffix co.uk but
    # have different registrable domains, so they are cross-site.
    context = RC.new(
      :url => 'https://example.co.uk/',
      :top_level_site => 'https://other.co.uk/')
    assert_equal false, context.same_site?
  end

  # ------------------------------------------------------------------
  # Cookie SameSite attribute
  # ------------------------------------------------------------------

  def test_samesite_accessor
    cookie = HTTP::Cookie.new('a', '1', :domain => 'example.com', :path => '/')
    assert_nil cookie.samesite

    cookie.samesite = 'Lax'
    assert_equal :lax, cookie.samesite
    cookie.samesite = :strict
    assert_equal :strict, cookie.samesite
    cookie.samesite = 'NONE'
    assert_equal :none, cookie.samesite
    cookie.samesite = nil
    assert_nil cookie.samesite

    assert_raise(ArgumentError) { cookie.samesite = 'bogus' }
    assert_raise(TypeError) { cookie.samesite = 42 }
  end

  def test_parse_samesite_attribute
    {
      'Strict' => :strict,
      'Lax' => :lax,
      'None' => :none,
    }.each { |value, expected|
      cookie = HTTP::Cookie.parse(
        "a=1; SameSite=#{value}; Path=/",
        'https://example.com/').first
      assert_equal expected, cookie.samesite
    }
  end

  def test_set_cookie_value_includes_samesite
    cookie = HTTP::Cookie.parse(
      'a=1; SameSite=Lax; Secure; Path=/',
      'https://example.com/').first
    assert_match(/; SameSite=Lax\z/, cookie.set_cookie_value)
  end

  # ------------------------------------------------------------------
  # Selection matrix (the scenarios called out in the task)
  # ------------------------------------------------------------------

  def build_jar
    jar = HTTP::CookieJar.new
    jar.parse('strict=1; SameSite=Strict; Path=/', 'https://example.com/')
    jar.parse('lax=2; SameSite=Lax; Path=/', 'https://example.com/')
    jar.parse('none=3; SameSite=None; Secure; Path=/', 'https://example.com/')
    jar.parse('dflt=4; Path=/', 'https://example.com/')
    jar
  end

  def names(jar, **context_overrides)
    jar.cookies_for_request(new_context(**context_overrides)).map(&:name).sort
  end

  def test_same_site_cross_subdomain_sends_all
    jar = build_jar
    # target host equals the cookie host; top-level site differs only
    # by subdomain, so the request is schemefully same-site.
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://sub.example.com/',
      :method => 'GET', :navigation => true)
    assert_equal %w[dflt lax none strict], result
  end

  def test_cross_site_top_level_get_navigation_sends_lax_and_none
    jar = build_jar
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'GET', :navigation => true)
    assert_equal %w[dflt lax none], result
  end

  def test_cross_site_post_sends_only_none
    jar = build_jar
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'POST', :navigation => true)
    assert_equal %w[none], result

    # a cross-site POST subresource behaves the same way
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'POST', :navigation => false)
    assert_equal %w[none], result
  end

  def test_cross_site_get_subresource_sends_only_none
    jar = build_jar
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'GET', :navigation => false)
    assert_equal %w[none], result
  end

  def test_cross_site_redirected_navigation_fails_closed
    jar = build_jar
    # even a safe top-level navigation does not relax Lax once redirected
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'GET', :navigation => true, :redirected => true)
    assert_equal %w[none], result
  end

  def test_same_site_redirect_still_sends_all
    jar = build_jar
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://sub.example.com/',
      :method => 'POST', :navigation => false, :redirected => true)
    assert_equal %w[dflt lax none strict], result
  end

  def test_strict_never_sent_cross_site_even_on_navigation
    jar = build_jar
    result = names(jar,
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'GET', :navigation => true)
    assert_not_include result, 'strict'
  end

  def test_secure_cookie_still_filtered_by_url_rules
    jar = HTTP::CookieJar.new
    jar.parse('secure=1; SameSite=None; Secure; Path=/', 'https://example.com/')

    over_http = names(jar,
      :url => 'http://example.com/',
      :top_level_site => 'http://other.org/')
    assert_equal [], over_http
  end

  def test_default_samesite_policy_is_configurable
    jar = HTTP::CookieJar.new(:samesite_default => :none)
    jar.parse('dflt=1; Path=/', 'https://example.com/')

    # with a :none default, an unspecified cookie is sent cross-site
    result = jar.cookies_for_request(RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'POST', :navigation => false)).map(&:name)
    assert_equal %w[dflt], result
  end

  def test_invalid_jar_default_samesite_raises
    assert_raise(ArgumentError) { HTTP::CookieJar.new(:samesite_default => :bogus) }
  end

  # ------------------------------------------------------------------
  # URL-only interface keeps its boundary (no SameSite evaluation)
  # ------------------------------------------------------------------

  def test_url_only_interface_ignores_samesite
    jar = build_jar
    # every matching cookie is returned regardless of SameSite
    assert_equal %w[dflt lax none strict],
      jar.cookies('https://example.com/').map(&:name).sort
  end

  def test_request_interface_needs_explicit_context
    jar = build_jar
    assert_raise(ArgumentError) {
      jar.cookies_for_request(:url => 'https://example.com/')
    }
    assert_raise(ArgumentError) {
      jar.cookies_for_request(
        :url => 'https://example.com/',
        :top_level_site => 'file:///nohost')
    }
    assert_raise(TypeError) { jar.cookies_for_request(42) }
  end

  def test_empty_for_request
    jar = HTTP::CookieJar.new
    jar.parse('strict=1; SameSite=Strict; Path=/', 'https://example.com/')

    assert_equal false, jar.empty_for_request?(
      RC.new(:url => 'https://example.com/',
             :top_level_site => 'https://example.com/'))
    assert_equal true, jar.empty_for_request?(
      RC.new(:url => 'https://example.com/',
             :top_level_site => 'https://other.org/',
             :navigation => true))
  end

  def test_each_for_request_updates_accessed_at
    jar = build_jar
    context = RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'GET', :navigation => true)
    # read timestamps without the side effect of the URL-only selector
    times = -> { jar.each.map { |c| [c.name, c.accessed_at] }.to_h }
    before = times.call
    sleep 0.01
    jar.each_for_request(context).to_a
    after = times.call
    # yielded (Lax) cookies get their access time updated
    assert after['lax'] > before['lax']
    # a non-yielded (Strict) cookie is untouched
    assert_equal before['strict'], after['strict']
  end

  def test_request_context_object_can_be_passed_directly
    jar = build_jar
    context = RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'GET', :navigation => true)
    assert_equal %w[dflt lax none],
      jar.cookies_for_request(context).map(&:name).sort
  end

  def test_valid_for_request_on_cookie_directly
    cookie = HTTP::Cookie.parse(
      'a=1; SameSite=Lax; Path=/',
      'https://example.com/').first

    same_site = RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://sub.example.com/')
    assert cookie.valid_for_request?(same_site)

    cross_nav = RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'GET', :navigation => true)
    assert cookie.valid_for_request?(cross_nav)

    cross_post = RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'POST', :navigation => true)
    assert_equal false, cookie.valid_for_request?(cross_post)
  end

  def test_domain_cookie_follows_subdomain_in_same_site
    jar = HTTP::CookieJar.new
    # a domain cookie valid on every host under example.com
    jar.parse('sid=1; Domain=example.com; SameSite=Lax; Path=/',
              'https://example.com/')

    # request to a different host, but same-site top-level document
    context = RC.new(
      :url => 'https://api.example.com/',
      :top_level_site => 'https://www.example.com/')
    assert_equal %w[sid], jar.cookies_for_request(context).map(&:name)

    # same request from a cross-site top-level document drops the Lax cookie
    cross = RC.new(
      :url => 'https://api.example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'POST', :navigation => false)
    assert_equal [], jar.cookies_for_request(cross).map(&:name)
  end

  def test_default_policy_applies_to_cookie_without_samesite
    cookie = HTTP::Cookie.parse(
      'a=1; Path=/', 'https://example.com/').first
    cross_post = RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'POST', :navigation => true)

    assert_equal false, cookie.valid_for_request?(cross_post) # default Lax

    permissive = RC.new(
      :url => 'https://example.com/',
      :top_level_site => 'https://other.org/',
      :method => 'POST', :navigation => true,
      :default_samesite => :none)
    assert cookie.valid_for_request?(permissive)
  end
end

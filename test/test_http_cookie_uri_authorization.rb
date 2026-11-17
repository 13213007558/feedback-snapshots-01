# -*- coding: utf-8 -*-
# frozen_string_literal: false
require File.expand_path('helper', File.dirname(__FILE__))
require 'http/cookie_jar'

# Regression tests for the chain that turns a request URI into cookie
# receive/send authorization.  Display-equivalent strings must not be
# treated as the same host, and a cookie must not be able to widen its
# own scope by declaring a Domain the request never proved.
class TestHTTPCookieURIAuthorization < Test::Unit::TestCase
  class RecordingLogger
    attr_reader :messages

    def initialize
      @messages = []
    end

    def warn(message)
      @messages << message
    end
  end

  def cookie(domain, for_domain: false, path: '/')
    c = HTTP::Cookie.new('k', 'v', :path => path)
    c.for_domain = for_domain
    c.domain = domain if domain
    c
  end

  def test_origin_without_host_is_rejected_instead_of_widening
    [
      ['http:///path', :missing_source_host],
      ['http://', :missing_source_host],
      ['http://user@/path', :missing_source_host],
      ['http://:8080/', :missing_source_host],
      ['http://?q', :missing_source_host],
      ['http:example.com', :missing_source_host],
      ['http:/example.com', :missing_source_host],
      ['//example.com/path', :non_http_source],
      ['/relative/path', :non_http_source],
      ['relative/path', :non_http_source],
      ['example.com', :non_http_source],
      ['file:///tmp/x', :non_http_source],
      ['ftp://example.com/', :non_http_source],
      ['mailto:a@example.com', :non_http_source],
    ].each { |origin, reason|
      c = cookie('example.com')
      assert_equal reason, c.acceptance_failure_reason(origin), origin
      assert_equal false, c.acceptable_from_uri?(origin), origin
      assert_equal false, c.valid_for_uri?(origin), origin
    }
  end

  def test_cookie_with_untrusted_origin_is_not_sent_even_to_matching_domain
    [
      'http:///path',
      'http:example.com',
      '//example.com/',
      'file:///tmp/x',
      'http://example.com%2e/',
    ].each { |origin|
      c = cookie('example.com')
      begin
        c.origin = origin
      rescue ArgumentError, URI::InvalidURIError
        next
      end
      assert_equal false, c.acceptable?, origin
      assert_equal false, c.valid_for_uri?('http://example.com/'), origin
    }
  end

  def test_self_reported_domain_cannot_replace_a_missing_source
    [
      'a=b; domain=example.com; path=/',
      'a=b; domain=.example.com; path=/',
      'a=b; path=/',
    ].each { |set_cookie|
      [
        'http:///',
        'http://user@/',
        'http:example.com',
        '//example.com/',
        'file:///tmp/x',
        'ftp://example.com/',
      ].each { |origin|
        assert_equal [], HTTP::Cookie.parse(set_cookie, origin), "#{set_cookie} @ #{origin}"
        jar = HTTP::CookieJar.new
        assert_equal [], jar.parse(set_cookie, origin), "#{set_cookie} @ #{origin}"
        assert_equal [], jar.cookies('http://example.com/'), "#{set_cookie} @ #{origin}"
      }
    }
  end

  def test_userinfo_does_not_supply_the_host
    c = cookie('example.com')

    assert_equal :domain_mismatch, c.acceptance_failure_reason('http://example.com@evil.com/')
    assert_equal false, c.acceptable_from_uri?('http://example.com@evil.com/')

    # The actual host still works, with or without userinfo/port.
    assert_equal nil, c.acceptance_failure_reason('http://user:pass@example.com/')
    assert_equal nil, c.acceptance_failure_reason('http://user:pass@example.com:8080/')

    # A cookie received from the userinfo-looking text belongs to the
    # real host, not to the text before the @.
    parsed = HTTP::Cookie.parse('a=b', 'http://example.com@evil.com/')
    assert_equal 1, parsed.size
    assert_equal 'evil.com', parsed.first.domain
    assert_equal false, parsed.first.valid_for_uri?('http://example.com/')
    assert_equal true, parsed.first.valid_for_uri?('http://evil.com/')
  end

  def test_port_is_not_part_of_host_identity
    c = cookie('example.com')

    assert_equal nil, c.acceptance_failure_reason('http://example.com:8080/')
    assert_equal nil, c.acceptance_failure_reason('https://example.com:443/')
    assert_equal true, c.valid_for_uri?('http://example.com:8080/path')

    # A port-looking Domain attribute must not smuggle in a different
    # host or a wider domain.
    assert_equal [], HTTP::Cookie.parse('a=b; domain=evil.com:80', 'http://example.com/')
    assert_equal 'example.com', HTTP::Cookie.parse('a=b; domain=example.com:80', 'http://example.com/').first.domain
  end

  def test_ipv4_and_ipv6_literals_keep_exact_rules
    v4 = cookie('192.168.0.1')
    assert_equal nil, v4.acceptance_failure_reason('http://192.168.0.1/')
    assert_equal true, v4.valid_for_uri?('http://192.168.0.1/')
    assert_equal false, v4.valid_for_uri?('http://192.168.0.2/')

    # No parent-domain matching against an IP address.
    wide = cookie('192.168.0.1', for_domain: true)
    assert_equal false, wide.valid_for_uri?('http://0.1/')
    assert_equal false, wide.acceptable_from_uri?('http://0.1/')

    v6 = cookie('::1', for_domain: true)
    assert_equal nil, v6.acceptance_failure_reason('http://[::1]/')
    assert_equal true, v6.valid_for_uri?('http://[::1]/')
    assert_equal true, v6.valid_for_uri?('http://[0:0::1]/')
    assert_equal true, v6.valid_for_uri?('http://[::1]:8080/')
    assert_equal false, v6.valid_for_uri?('http://[::2]/')

    # A bracketed Domain spelling is the same address.
    assert_equal '::1', HTTP::Cookie.parse('a=b; domain=[::1]', 'http://[::1]/').first.domain

    # IPv4-mapped IPv6 is a distinct address from the plain IPv4 form.
    mapped = HTTP::Cookie.new('a', 'b', :domain => '[::ffff:127.0.0.1]', :path => '/')
    assert_equal true, mapped.valid_for_uri?('http://[::ffff:127.0.0.1]/')
    assert_equal false, mapped.valid_for_uri?('http://127.0.0.1/')
    assert_equal false, cookie('127.0.0.1').valid_for_uri?('http://[::ffff:127.0.0.1]/')
  end

  def test_non_canonical_ip_spellings_do_not_gain_a_parent_domain
    # "127.0.0.1." would derive "0.1" if treated as a DNS name.
    parsed = HTTP::Cookie.parse('a=b; domain=0.1', 'http://127.0.0.1./')
    assert_equal [], parsed
    assert_equal [], HTTP::Cookie.parse('a=b; domain=.0.1', 'http://127.0.0.1./')

    # A host-only cookie from the trailing-dot literal is pinned to
    # that same address and never leaks to the invented "0.1".
    host_only = HTTP::Cookie.parse('a=b', 'http://127.0.0.1./').first
    assert_equal '127.0.0.1', host_only.domain
    assert_equal true, host_only.valid_for_uri?('http://127.0.0.1./')
    assert_equal true, host_only.valid_for_uri?('http://127.0.0.1/')
    assert_equal false, host_only.valid_for_uri?('http://0.1/')
    assert_equal false, host_only.valid_for_uri?('http://x.0.1/')

    # The same holds for hex/octal/short IPv4 spellings.
    %w[0x7f.0.0.1 0177.0.0.1 2130706433 127.1 1.2.3.4.5].each { |h|
      c = HTTP::Cookie.new('a', 'b', :domain => '0.1', :path => '/')
      assert_equal false, c.valid_for_uri?("http://#{h}/"), h
      assert_equal :ambiguous_source_host,
        c.acceptance_failure_reason("http://#{h}/"), h
    }
  end

  def test_percent_encoded_host_is_not_decoded_into_a_domain
    # "example.com%2f.evil.com" is one host label, not example.com.
    c = cookie('evil.com', for_domain: true)
    assert_equal :ambiguous_source_host,
      c.acceptance_failure_reason('http://example.com%2f.evil.com/')
    assert_equal false, c.valid_for_uri?('http://example.com%2f.evil.com/')

    c = cookie('example.com', for_domain: true)
    assert_equal false, c.valid_for_uri?('http://example.com%2f.evil.com/')

    [
      ['a=b; domain=evil.com; path=/', 'http://example.com%2f.evil.com/', 'evil.com'],
      ['a=b; domain=example.com; path=/', 'http://evil.com%2f.example.com/', 'example.com'],
      ['a=b; domain=evil.com; path=/', 'http://example.com%00.evil.com/', 'evil.com'],
      ['a=b; domain=0.1; path=/', 'http://127.0.0.1%2e/', '0.1'],
    ].each { |set_cookie, origin, declared_domain|
      assert_equal [], HTTP::Cookie.parse(set_cookie, origin), "#{set_cookie} @ #{origin}"
      lax = cookie(declared_domain, for_domain: true)
      assert_equal false, lax.valid_for_uri?(origin), "#{declared_domain} @ #{origin}"
    }
  end

  def test_unicode_hosts_compare_by_identity_not_display
    ascii = 'xn--exmple-cua.com'
    unicode = 'exämple.com'

    from_ascii = HTTP::Cookie.parse('a=b', "http://#{ascii}/").first
    from_unicode = HTTP::Cookie.parse('a=b', "http://#{unicode}/").first
    assert_equal ascii, from_ascii.domain
    assert_equal ascii, from_unicode.domain
    assert_equal true, from_ascii.valid_for_uri?("http://#{unicode}/")
    assert_equal true, from_unicode.valid_for_uri?("http://#{ascii}/")

    # A look-alike host with the same displayed letters is different.
    lookalike = 'ｅxample.com' # fullwidth e
    assert_equal false, cookie('example.com').valid_for_uri?("http://#{lookalike}/")
    assert_equal [], HTTP::Cookie.parse('a=b; domain=example.com', "http://#{lookalike}/")

    # The same for a Cyrillic "а" and an ideographic dot.
    assert_equal false, cookie('example.com').valid_for_uri?('http://exаmple.com/')
    assert_equal false, cookie('example.com').valid_for_uri?('http://example。com/')

    # A Unicode Domain attribute resolves to the same identity as its
    # ASCII form and works on a matching host only.
    parsed = HTTP::Cookie.parse("a=b; domain=#{unicode}", "http://#{ascii}/")
    assert_equal 1, parsed.size
    assert_equal ascii, parsed.first.domain
    assert_equal true, parsed.first.valid_for_uri?("http://#{ascii}/")
    assert_equal false, parsed.first.valid_for_uri?('http://example.com/')
  end

  def test_display_equivalent_hosts_stay_distinct
    pairs = [
      ['example.com', 'example.com.'],
      ['example.com', 'EXAMPLE.COM'],
      ['127.0.0.1', '127.0.0.1.'],
      ['127.0.0.1', '0x7f.0.0.1'],
      ['::1', '[0:0::1]'],
      ['example.com', 'ｅxample.com'],
    ]

    pairs.each { |a, b|
      first = HTTP::Cookie::URIParser.host_identity(a)
      second = HTTP::Cookie::URIParser.host_identity(b)
      refute_nil first, a
      refute_nil second, b

      if a.include?(':') || b.include?(':')
        # The unbracketed form is not a URI host; compare identities
        # only, and only through the bracketed URI spelling.
        next
      end

      same = first.name == second.name
      assert_equal same, cookie(a).valid_for_uri?("http://#{b}/"), "#{a} -> #{b}"
      assert_equal same, cookie(b).valid_for_uri?("http://#{a}/"), "#{b} -> #{a}"
    }
  end

  def test_explicit_origin_and_post_parse_domain_paths_agree
    cases = [
      ['http://example.com/', 'example.com', true],
      ['http://example.com/', '.example.com', true],
      ['http://sub.example.com/', '.example.com', true],
      ['http://example.com./', 'example.com', true],
      ['http://example.com/', 'example.com.', true],
      ['http://evil.com/', 'example.com', false],
      ['http://example.com@evil.com/', 'example.com', false],
      ['http://example.com%2f.evil.com/', 'evil.com', false],
      ['http://127.0.0.1./', '0.1', false],
      ['http://example.com/', '0.1', false],
      ['http://example.com/', 'com', false],
    ]

    cases.each { |origin, domain, expected|
      explicit = HTTP::Cookie.new('a', 'b',
        :domain => domain, :path => '/', :origin => origin)

      parsed_cookie = HTTP::Cookie.parse("a=b; domain=#{domain}; path=/", origin).first
      post = HTTP::Cookie.new('a', 'b', :path => '/', :origin => origin)
      begin
        post.domain = domain
      rescue ArgumentError
        post = nil
      end

      assert_equal expected, explicit.acceptable?, "explicit #{domain} @ #{origin}"

      if expected
        refute_nil parsed_cookie, "parsed #{domain} @ #{origin}"
        assert_equal true, parsed_cookie.acceptable?, "parsed #{domain} @ #{origin}"
        refute_nil post, "post #{domain} @ #{origin}"
        assert_equal true, post.acceptable?, "post #{domain} @ #{origin}"
      else
        assert_nil parsed_cookie, "parsed #{domain} @ #{origin}"
        if post
          # The setter accepts a syntactically valid declaration; the
          # acceptance check is what rejects it.  Both paths must give
          # the same answer.
          assert_equal false, post.acceptable?, "post #{domain} @ #{origin}"
        end
      end
    }
  end

  def test_origin_with_ambiguous_host_blocks_send_even_when_domain_matches
    c = HTTP::Cookie.new('a', 'b', :domain => 'example.com', :path => '/')
    c.origin = 'http://example.com%2e/'

    assert_equal false, c.acceptable?
    assert_equal false, c.valid_for_uri?('http://example.com/')
    assert_equal :untrusted_origin, c.valid_for_uri_failure_reason('http://example.com/')
  end

  def test_rejection_reasons_are_stable_and_do_not_reveal_values
    logger = RecordingLogger.new
    secret = 'secretname=secretvalue; domain=evil.com'

    assert_equal [], HTTP::Cookie.parse(secret, 'http://victim.com/', :logger => logger)
    assert_equal [], HTTP::Cookie.parse(secret, 'http:///victim', :logger => logger)
    assert_equal [], HTTP::Cookie.parse(secret, 'file:///victim', :logger => logger)

    messages = logger.messages
    refute_empty messages
    messages.each { |message|
      refute_match(/secretname|secretvalue|evil\.com|victim/, message)
      assert_match(/\A(?:Cookie rejected|Cookie source rejected): [a-z_]+\z/, message)
    }

    c = cookie('example.com')
    reasons = {
      'http:///path' => :missing_source_host,
      'http:example.com' => :missing_source_host,
      '//example.com/' => :non_http_source,
      '/rel' => :non_http_source,
      'file:///x' => :non_http_source,
      'http://example.com%2e/' => :ambiguous_source_host,
      'http://evil.com/' => :domain_mismatch,
      'http://example.com/' => nil,
    }
    reasons.each { |uri, expected|
      assert_equal expected, c.acceptance_failure_reason(uri), uri
    }
  end

  def test_jar_only_sends_cookies_whose_source_proves_the_domain
    jar = HTTP::CookieJar.new

    assert_equal 0, jar.parse('a=b; domain=example.com; path=/', 'http://evil.com/').size
    assert_equal 1, jar.parse('a=b; domain=example.com; path=/', 'http://example.com/').size
    assert_equal 0, jar.parse('c=d; domain=example.com; path=/', 'http:///').size
    assert_equal 0, jar.parse('e=f; domain=example.com; path=/', 'file:///tmp/x').size

    assert_equal %w[a], jar.cookies('http://example.com/').map(&:name)
    assert_equal [], jar.cookies('http://evil.com/')
    assert_equal [], jar.cookies('http:///')
    assert_equal [], jar.cookies('file:///tmp/x')
  end

  def test_valid_ip_and_ordinary_domains_still_work
    cookie('example.com').tap { |c|
      %w[
        http://example.com/
        http://example.com:8080/
        HTTPS://EXAMPLE.COM/
        http://example.com./
        http://user:pass@example.com/
      ].each { |uri|
        assert_equal nil, c.acceptance_failure_reason(uri), uri
        assert_equal true, c.valid_for_uri?(uri), uri
      }
    }

    wide = cookie('example.com', for_domain: true)
    assert_equal true, wide.valid_for_uri?('http://sub.example.com/')
    assert_equal true, wide.valid_for_uri?('http://deep.sub.example.com/')

    host_only = cookie('localhost')
    assert_equal true, host_only.valid_for_uri?('http://localhost/')
    assert_equal true, host_only.valid_for_uri?('http://LOCALHOST/')
    assert_equal false, host_only.valid_for_uri?('http://sub.localhost/')

    assert_equal true, cookie('127.0.0.1').valid_for_uri?('http://127.0.0.1/')
    assert_equal true, cookie('::1').valid_for_uri?('http://[::1]/')
    assert_equal true, cookie('[fe80::0123:4567:89ab:cdef]').valid_for_uri?(
      'http://[fe80::0123:4567:89ab:cdef]/')
  end
end

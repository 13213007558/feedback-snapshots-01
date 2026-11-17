# frozen_string_literal: false
require File.expand_path('helper', File.dirname(__FILE__))
require 'tmpdir'

module TestHTTPCookieJar
  class TestAutoloading < Test::Unit::TestCase
    def test_nonexistent_store
      assert_raises(NameError) {
        HTTP::CookieJar::NonexistentStore
      }
    end

    def test_nonexistent_store_in_config
      assert_raise_with_message(ArgumentError, /cookie store unavailable: :nonexistent/) {
        HTTP::CookieJar.new(store: :nonexistent)
      }
    end

    def test_erroneous_store
      assert_raises(NameError) {
        HTTP::CookieJar::ErroneousStore
      }
    end

    def test_nonexistent_saver
      assert_raises(NameError) {
        HTTP::CookieJar::NonexistentSaver
      }
    end

    def test_erroneous_saver
      assert_raises(NameError) {
        HTTP::CookieJar::ErroneousSaver
      }
    end
  end

  module CommonTests
    def setup(options = nil, options2 = nil)
      default_options = {
        :store => :hash,
        :gc_threshold => 1500, # increased by 10 for shorter test time
      }
      new_options  = default_options.merge(options || {})
      new_options2 = new_options.merge(options2 || {})
      @store_type = new_options[:store]
      @gc_threshold = new_options[:gc_threshold]
      @jar  = HTTP::CookieJar.new(new_options)
      @jar2 = HTTP::CookieJar.new(new_options2)
    end

    #def hash_store?
    #  @store_type == :hash
    #end

    def mozilla_store?
      @store_type == :mozilla
    end

    def cookie_values(options = {})
      {
        :name     => 'Foo',
        :value    => 'Bar',
        :path     => '/',
        :expires  => Time.at(Time.now.to_i + 10 * 86400), # to_i is important here
        :for_domain => true,
        :domain   => 'rubyforge.org',
        :origin   => 'http://rubyforge.org/'
      }.merge(options)
    end

    def test_empty?
      assert_equal true, @jar.empty?
      cookie = HTTP::Cookie.new(cookie_values)
      @jar.add(cookie)
      assert_equal false, @jar.empty?
      assert_equal false, @jar.empty?('http://rubyforge.org/')
      assert_equal true, @jar.empty?('http://example.local/')
    end

    def test_two_cookies_same_domain_and_name_different_paths
      url = URI 'http://rubyforge.org/'

      cookie = HTTP::Cookie.new(cookie_values)
      @jar.add(cookie)
      @jar.add(HTTP::Cookie.new(cookie_values(:path => '/onetwo')))

      assert_equal(1, @jar.cookies(url).length)
      assert_equal 2, @jar.cookies(URI('http://rubyforge.org/onetwo')).length
    end

    def test_domain_case
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      @jar.add(HTTP::Cookie.new(cookie_values(:domain => 'RuByForge.Org', :name => 'aaron')))

      assert_equal(2, @jar.cookies(url).length)

      url2 = URI 'http://RuByFoRgE.oRg/'
      assert_equal(2, @jar.cookies(url2).length)
    end

    def test_host_only
      url = URI.parse('http://rubyforge.org/')

      @jar.add(HTTP::Cookie.new(
          cookie_values(:domain => 'rubyforge.org', :for_domain => false)))

      assert_equal(1, @jar.cookies(url).length)

      assert_equal(1, @jar.cookies(URI('http://RubyForge.org/')).length)

      assert_equal(1, @jar.cookies(URI('https://RubyForge.org/')).length)

      assert_equal(0, @jar.cookies(URI('http://www.rubyforge.org/')).length)
    end

    def test_host_only_with_unqualified_hostname
      @jar.add(HTTP::Cookie.new(cookie_values(
        :origin => 'http://localhost/', :domain => 'localhost', :for_domain => false)))

      assert_equal(1, @jar.cookies(URI('http://localhost/')).length)

      assert_equal(1, @jar.cookies(URI('http://Localhost/')).length)

      assert_equal(1, @jar.cookies(URI('https://Localhost/')).length)
    end

    def test_empty_value
      url = URI 'http://rubyforge.org/'
      values = cookie_values(:value => "")

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      @jar.add HTTP::Cookie.new(values.merge(:domain => 'RuByForge.Org',
          :name   => 'aaron'))

      assert_equal(2, @jar.cookies(url).length)

      url2 = URI 'http://RuByFoRgE.oRg/'
      assert_equal(2, @jar.cookies(url2).length)
    end

    def test_add_future_cookies
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      # Add the same cookie, and we should still only have one
      @jar.add(HTTP::Cookie.new(cookie_values))
      assert_equal(1, @jar.cookies(url).length)

      # Make sure we can get the cookie from different paths
      assert_equal(1, @jar.cookies(URI('http://rubyforge.org/login')).length)

      # Make sure we can't get the cookie from different domains
      assert_equal(0, @jar.cookies(URI('http://google.com/')).length)
    end

    def test_add_multiple_cookies
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      # Add the same cookie, and we should still only have one
      @jar.add(HTTP::Cookie.new(cookie_values(:name => 'Baz')))
      assert_equal(2, @jar.cookies(url).length)

      # Make sure we can get the cookie from different paths
      assert_equal(2, @jar.cookies(URI('http://rubyforge.org/login')).length)

      # Make sure we can't get the cookie from different domains
      assert_equal(0, @jar.cookies(URI('http://google.com/')).length)
    end

    def test_add_multiple_cookies_with_the_same_name
      now = Time.now

      cookies = [
        { :value => 'a', :path => '/', },
        { :value => 'b', :path => '/abc/def/', :created_at => now - 1 },
        { :value => 'c', :path => '/abc/def/', :domain => 'www.rubyforge.org', :origin => 'http://www.rubyforge.org/abc/def/', :created_at => now },
        { :value => 'd', :path => '/abc/' },
      ].map { |attrs|
        HTTP::Cookie.new(cookie_values(attrs))
      }

      url = URI 'http://www.rubyforge.org/abc/def/ghi'

      cookies.permutation(cookies.size) { |shuffled|
        @jar.clear
        shuffled.each { |cookie| @jar.add(cookie) }
        assert_equal %w[b c d a], @jar.cookies(url).map { |cookie| cookie.value }
      }
    end

    def test_fall_back_rules_for_local_domains
      url = URI 'http://www.example.local'

      sld_cookie = HTTP::Cookie.new(cookie_values(:domain => '.example.local', :origin => url))
      @jar.add(sld_cookie)

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_add_makes_exception_for_localhost
      url = URI 'http://localhost'

      tld_cookie = HTTP::Cookie.new(cookie_values(:domain => 'localhost', :origin => url))
      @jar.add(tld_cookie)

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_add_cookie_for_the_parent_domain
      url = URI 'http://x.foo.com'

      cookie = HTTP::Cookie.new(cookie_values(:domain => '.foo.com', :origin => url))
      @jar.add(cookie)

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_add_rejects_cookies_with_unknown_domain_or_path
      cookie = HTTP::Cookie.new(cookie_values.reject { |k,v| [:origin, :domain].include?(k) })
      assert_raises(ArgumentError) {
        @jar.add(cookie)
      }

      cookie = HTTP::Cookie.new(cookie_values.reject { |k,v| [:origin, :path].include?(k) })
      assert_raises(ArgumentError) {
        @jar.add(cookie)
      }
    end

    def test_add_does_not_reject_cookies_from_a_nested_subdomain
      url = URI 'http://y.x.foo.com'

      cookie = HTTP::Cookie.new(cookie_values(:domain => '.foo.com', :origin => url))
      @jar.add(cookie)

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_cookie_without_leading_dot_does_not_cause_substring_match
      url = URI 'http://arubyforge.org/'

      cookie = HTTP::Cookie.new(cookie_values(:domain => 'rubyforge.org'))
      @jar.add(cookie)

      assert_equal(0, @jar.cookies(url).length)
    end

    def test_cookie_without_leading_dot_matches_subdomains
      url = URI 'http://admin.rubyforge.org/'

      cookie = HTTP::Cookie.new(cookie_values(:domain => 'rubyforge.org', :origin => url))
      @jar.add(cookie)

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_cookies_with_leading_dot_match_subdomains
      url = URI 'http://admin.rubyforge.org/'

      @jar.add(HTTP::Cookie.new(cookie_values(:domain => '.rubyforge.org', :origin => url)))

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_cookies_with_leading_dot_match_parent_domains
      url = URI 'http://rubyforge.org/'

      @jar.add(HTTP::Cookie.new(cookie_values(:domain => '.rubyforge.org', :origin => url)))

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_cookies_with_leading_dot_match_parent_domains_exactly
      url = URI 'http://arubyforge.org/'

      @jar.add(HTTP::Cookie.new(cookie_values(:domain => '.rubyforge.org')))

      assert_equal(0, @jar.cookies(url).length)
    end

    def test_cookie_for_ipv4_address_matches_the_exact_ipaddress
      url = URI 'http://192.168.0.1/'

      cookie = HTTP::Cookie.new(cookie_values(:domain => '192.168.0.1', :origin => url))
      @jar.add(cookie)

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_cookie_for_ipv6_address_matches_the_exact_ipaddress
      url = URI 'http://[fe80::0123:4567:89ab:cdef]/'

      cookie = HTTP::Cookie.new(cookie_values(:domain => '[fe80::0123:4567:89ab:cdef]', :origin => url))
      @jar.add(cookie)

      assert_equal(1, @jar.cookies(url).length)
    end

    def test_cookies_dot
      url = URI 'http://www.host.example/'

      @jar.add(HTTP::Cookie.new(cookie_values(:domain => 'www.host.example', :origin => url)))

      url = URI 'http://wwwxhost.example/'
      assert_equal(0, @jar.cookies(url).length)
    end

    def test_cookies_no_host
      url = URI 'file:///path/'

      @jar.add(HTTP::Cookie.new(cookie_values(:origin => url)))

      assert_equal(0, @jar.cookies(url).length)
    end

    def test_clear
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values(:origin => url))
      @jar.add(cookie)
      @jar.add(HTTP::Cookie.new(cookie_values(:name => 'Baz', :origin => url)))
      assert_equal(2, @jar.cookies(url).length)

      @jar.clear

      assert_equal(0, @jar.cookies(url).length)
    end

    def test_save_cookies_yaml
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values(:origin => url))
      s_cookie = HTTP::Cookie.new(cookie_values(:name => 'Bar',
          :expires => nil,
          :origin => url))

      @jar.add(cookie)
      @jar.add(s_cookie)
      @jar.add(HTTP::Cookie.new(cookie_values(:name => 'Baz', :for_domain => false, :origin => url)))

      assert_equal(3, @jar.cookies(url).length)

      Dir.mktmpdir do |dir|
        value = @jar.save(File.join(dir, "cookies.yml"))
        assert_same @jar, value

        @jar2.load(File.join(dir, "cookies.yml"))
        cookies = @jar2.cookies(url).sort_by { |cookie| cookie.name }
        assert_equal(2, cookies.length)
        assert_equal('Baz', cookies[0].name)
        assert_equal(false, cookies[0].for_domain)
        assert_equal('Foo', cookies[1].name)
        assert_equal(true,  cookies[1].for_domain)
      end

      assert_equal(3, @jar.cookies(url).length)
    end

    def test_save_load_signature
      Dir.mktmpdir { |dir|
        filename = File.join(dir, "cookies.yml")

        @jar.save(filename, :format => :cookiestxt, :session => true)
        @jar.save(filename, :format => :cookiestxt, :session => true)
        @jar.save(filename, :format => :cookiestxt)
        @jar.save(filename, :cookiestxt, :session => true)
        @jar.save(filename, :cookiestxt)
        @jar.save(filename, HTTP::CookieJar::CookiestxtSaver)
        @jar.save(filename, HTTP::CookieJar::CookiestxtSaver.new)
        @jar.save(filename, :session => true)
        @jar.save(filename)

        assert_raises(ArgumentError) {
          @jar.save()
        }
        assert_raises(ArgumentError) {
          @jar.save(filename, :nonexistent)
        }
        assert_raises(TypeError) {
          @jar.save(filename, { :format => :cookiestxt }, { :session => true })
        }
        assert_raises(ArgumentError) {
          @jar.save(filename, :cookiestxt, { :session => true }, { :format => :cookiestxt })
        }

        @jar.load(filename, :format => :cookiestxt, :linefeed => "\n")
        @jar.load(filename, :format => :cookiestxt, :linefeed => "\n")
        @jar.load(filename, :format => :cookiestxt)
        @jar.load(filename, HTTP::CookieJar::CookiestxtSaver)
        @jar.load(filename, HTTP::CookieJar::CookiestxtSaver.new)
        @jar.load(filename, :cookiestxt, :linefeed => "\n")
        @jar.load(filename, :cookiestxt)
        @jar.load(filename, :linefeed => "\n")
        @jar.load(filename)
        assert_raises(ArgumentError) {
          @jar.load()
        }
        assert_raises(ArgumentError) {
          @jar.load(filename, :nonexistent)
        }
        assert_raises(TypeError) {
          @jar.load(filename, { :format => :cookiestxt }, { :linefeed => "\n" })
        }
        assert_raises(ArgumentError) {
          @jar.load(filename, :cookiestxt, { :linefeed => "\n" }, { :format => :cookiestxt })
        }
      }
    end

    def test_save_session_cookies_yaml
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values)
      s_cookie = HTTP::Cookie.new(cookie_values(:name => 'Bar',
          :expires => nil))

      @jar.add(cookie)
      @jar.add(s_cookie)
      @jar.add(HTTP::Cookie.new(cookie_values(:name => 'Baz')))

      assert_equal(3, @jar.cookies(url).length)

      Dir.mktmpdir do |dir|
        @jar.save(File.join(dir, "cookies.yml"), :format => :yaml, :session => true)

        @jar2.load(File.join(dir, "cookies.yml"))
        assert_equal(3, @jar2.cookies(url).length)
      end

      assert_equal(3, @jar.cookies(url).length)
    end

    def test_save_and_read_cookiestxt
      url = HTTP::Cookie::URIParser.parse('https://rubyforge.org/foo[]/')

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values)
      expires = cookie.expires
      s_cookie = HTTP::Cookie.new(cookie_values(:name => 'Bar',
          :expires => nil))
      cookie2 = HTTP::Cookie.new(cookie_values(:name => 'Baz',
          :value => 'Foo#Baz',
          :path => '/foo[]/',
          :for_domain => false))
      h_cookie = HTTP::Cookie.new(cookie_values(:name => 'Quux',
          :value => 'Foo#Quux',
          :httponly => true))
      ma_cookie = HTTP::Cookie.new(cookie_values(:name => 'Maxage',
          :value => 'Foo#Maxage',
          :max_age => 15000))
      @jar.add(cookie)
      @jar.add(s_cookie)
      @jar.add(cookie2)
      @jar.add(h_cookie)
      @jar.add(ma_cookie)

      assert_equal(5, @jar.cookies(url).length)

      Dir.mktmpdir do |dir|
        filename = File.join(dir, "cookies.txt")
        @jar.save(filename, :cookiestxt)

        content = File.read(filename)

        filename2 = File.join(dir, "cookies2.txt")
        open(filename2, 'w') { |w|
          w.puts '# HTTP Cookie File'
          @jar.save(w, :cookiestxt, :header => nil)
        }
        assert_equal content, File.read(filename2)

        assert_match(/^\.rubyforge\.org\t.*\tFoo\t/, content)
        assert_match(/^rubyforge\.org\t.*\tBaz\t/, content)
        assert_match(/^#HttpOnly_\.rubyforge\.org\t/, content)

        @jar2.load(filename, :cookiestxt) # HACK test the format
        cookies = @jar2.cookies(url)
        assert_equal(4, cookies.length)
        cookies.each { |cookie|
          case cookie.name
          when 'Foo'
            assert_equal 'Bar', cookie.value
            assert_equal expires, cookie.expires
            assert_equal 'rubyforge.org', cookie.domain
            assert_equal true, cookie.for_domain
            assert_equal '/', cookie.path
            assert_equal false, cookie.httponly?
          when 'Baz'
            assert_equal 'Foo#Baz', cookie.value
            assert_equal 'rubyforge.org', cookie.domain
            assert_equal false, cookie.for_domain
            assert_equal '/foo[]/', cookie.path
            assert_equal false, cookie.httponly?
          when 'Quux'
            assert_equal 'Foo#Quux', cookie.value
            assert_equal expires, cookie.expires
            assert_equal 'rubyforge.org', cookie.domain
            assert_equal true, cookie.for_domain
            assert_equal '/', cookie.path
            assert_equal true, cookie.httponly?
          when 'Maxage'
            assert_equal 'Foo#Maxage', cookie.value
            assert_equal nil, cookie.max_age
            assert_in_delta ma_cookie.expires, cookie.expires, 1
          else
            raise
          end
        }
      end

      assert_equal(5, @jar.cookies(url).length)
    end

    def test_load_yaml_mechanize
      @jar.load(test_file('mechanize.yml'), :yaml)

      assert_equal 4, @jar.to_a.size

      com_nid, com_pref = @jar.cookies('http://www.google.com/')

      assert_equal 'NID', com_nid.name
      assert_equal 'Sun, 23 Sep 2063 08:20:15 GMT', com_nid.expires.httpdate
      assert_equal 'google.com', com_nid.domain_name.hostname

      assert_equal 'PREF', com_pref.name
      assert_equal 'Tue, 24 Mar 2065 08:20:15 GMT', com_pref.expires.httpdate
      assert_equal 'google.com', com_pref.domain_name.hostname

      cojp_nid, cojp_pref = @jar.cookies('http://www.google.co.jp/')

      assert_equal 'NID', cojp_nid.name
      assert_equal 'Sun, 23 Sep 2063 08:20:16 GMT', cojp_nid.expires.httpdate
      assert_equal 'google.co.jp', cojp_nid.domain_name.hostname

      assert_equal 'PREF', cojp_pref.name
      assert_equal 'Tue, 24 Mar 2065 08:20:16 GMT', cojp_pref.expires.httpdate
      assert_equal 'google.co.jp', cojp_pref.domain_name.hostname
    end

    def test_expire_cookies
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(cookie_values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      # Add a second cookie
      @jar.add(HTTP::Cookie.new(cookie_values(:name => 'Baz')))
      assert_equal(2, @jar.cookies(url).length)

      # Make sure we can get the cookie from different paths
      assert_equal(2, @jar.cookies(URI('http://rubyforge.org/login')).length)

      # Expire the first cookie
      @jar.add(HTTP::Cookie.new(cookie_values(:expires => Time.now - (10 * 86400))))
      assert_equal(1, @jar.cookies(url).length)

      # Expire the second cookie
      @jar.add(HTTP::Cookie.new(cookie_values( :name => 'Baz', :expires => Time.now - (10 * 86400))))
      assert_equal(0, @jar.cookies(url).length)
    end

    def test_session_cookies
      values = cookie_values(:expires => nil)
      url = URI 'http://rubyforge.org/'

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      # Add a second cookie
      @jar.add(HTTP::Cookie.new(values.merge(:name => 'Baz')))
      assert_equal(2, @jar.cookies(url).length)

      # Make sure we can get the cookie from different paths
      assert_equal(2, @jar.cookies(URI('http://rubyforge.org/login')).length)

      # Expire the first cookie
      @jar.add(HTTP::Cookie.new(values.merge(:expires => Time.now - (10 * 86400))))
      assert_equal(1, @jar.cookies(url).length)

      # Expire the second cookie
      @jar.add(HTTP::Cookie.new(values.merge(:name => 'Baz', :expires => Time.now - (10 * 86400))))
      assert_equal(0, @jar.cookies(url).length)

      # When given a URI with a blank path, CookieJar#cookies should return
      # cookies with the path '/':
      url = URI 'http://rubyforge.org'
      assert_equal '', url.path
      assert_equal(0, @jar.cookies(url).length)
      # Now add a cookie with the path set to '/':
      @jar.add(HTTP::Cookie.new(values.merge(:name => 'has_root_path', :path => '/')))
      assert_equal(1, @jar.cookies(url).length)
    end

    def test_paths
      url = URI 'http://rubyforge.org/login'
      values = cookie_values(:path => "/login", :expires => nil, :origin => url)

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      # Add a second cookie
      @jar.add(HTTP::Cookie.new(values.merge( :name => 'Baz' )))
      assert_equal(2, @jar.cookies(url).length)

      # Make sure we don't get the cookie in a different path
      assert_equal(0, @jar.cookies(URI('http://rubyforge.org/hello')).length)
      assert_equal(0, @jar.cookies(URI('http://rubyforge.org/')).length)

      # Expire the first cookie
      @jar.add(HTTP::Cookie.new(values.merge( :expires => Time.now - (10 * 86400))))
      assert_equal(1, @jar.cookies(url).length)

      # Expire the second cookie
      @jar.add(HTTP::Cookie.new(values.merge( :name => 'Baz',
            :expires => Time.now - (10 * 86400))))
      assert_equal(0, @jar.cookies(url).length)
    end

    def test_non_rfc3986_compliant_paths
      url = HTTP::Cookie::URIParser.parse('http://RubyForge.org/login[]')

      values = cookie_values(:path => "/login[]", :expires => nil, :origin => url)

      # Add one cookie with an expiration date in the future
      cookie = HTTP::Cookie.new(values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length)

      # Add a second cookie
      @jar.add(HTTP::Cookie.new(values.merge( :name => 'Baz' )))
      assert_equal(2, @jar.cookies(url).length)

      # Make sure we don't get the cookie in a different path
      assert_equal(0, @jar.cookies(HTTP::Cookie::URIParser.parse('http://RubyForge.org/hello[]')).length)
      assert_equal(0, @jar.cookies(HTTP::Cookie::URIParser.parse('http://RubyForge.org/')).length)

      # Expire the first cookie
      @jar.add(HTTP::Cookie.new(values.merge( :expires => Time.now - (10 * 86400))))
      assert_equal(1, @jar.cookies(url).length)

      # Expire the second cookie
      @jar.add(HTTP::Cookie.new(values.merge( :name => 'Baz',
            :expires => Time.now - (10 * 86400))))
      assert_equal(0, @jar.cookies(url).length)
    end

    def test_ssl_cookies
      # thanks to michal "ocher" ochman for reporting the bug responsible for this test.
      values = cookie_values(:expires => nil)
      values_ssl = values.merge(:name => 'Baz', :domain => "#{values[:domain]}:443")
      url = URI 'https://rubyforge.org/login'

      cookie = HTTP::Cookie.new(values)
      @jar.add(cookie)
      assert_equal(1, @jar.cookies(url).length, "did not handle SSL cookie")

      cookie = HTTP::Cookie.new(values_ssl)
      @jar.add(cookie)
      assert_equal(2, @jar.cookies(url).length, "did not handle SSL cookie with :443")
    end

    def test_secure_cookie
      nurl = URI 'http://rubyforge.org/login'
      surl = URI 'https://rubyforge.org/login'

      nncookie = HTTP::Cookie.new(cookie_values(:name => 'Foo1', :origin => nurl))
      sncookie = HTTP::Cookie.new(cookie_values(:name => 'Foo1', :origin => surl))
      nscookie = HTTP::Cookie.new(cookie_values(:name => 'Foo2', :secure => true, :origin => nurl))
      sscookie = HTTP::Cookie.new(cookie_values(:name => 'Foo2', :secure => true, :origin => surl))

      @jar.add(nncookie)
      @jar.add(sncookie)
      @jar.add(nscookie)
      @jar.add(sscookie)

      assert_equal('Foo1',      @jar.cookies(nurl).map { |c| c.name }.sort.join(' ') )
      assert_equal('Foo1 Foo2', @jar.cookies(surl).map { |c| c.name }.sort.join(' ') )
    end

    def test_delete
      cookie1 = HTTP::Cookie.new(cookie_values)
      cookie2 = HTTP::Cookie.new(:name => 'Foo', :value => '',
                                 :domain => 'rubyforge.org',
                                 :for_domain => false,
                                 :path => '/')
      cookie3 = HTTP::Cookie.new(:name => 'Foo', :value => '',
                                 :domain => 'rubyforge.org',
                                 :for_domain => true,
                                 :path => '/')

      @jar.add(cookie1)
      @jar.delete(cookie2)

      if mozilla_store?
        assert_equal(1, @jar.to_a.length)
        @jar.delete(cookie3)
      end

      assert_equal(0, @jar.to_a.length)
    end

    def test_accessed_at
      orig = HTTP::Cookie.new(cookie_values(:expires => nil))
      @jar.add(orig)

      time = orig.accessed_at

      assert_in_delta 1.0, time, Time.now, "accessed_at is initialized to the current time"

      cookie, = @jar.to_a

      assert_equal time, cookie.accessed_at, "accessed_at is not updated by each()"

      cookie, = @jar.cookies("http://rubyforge.org/")

      assert_send [cookie.accessed_at, :>, time], "accessed_at is not updated by each(url)"
    end

    def test_max_cookies
      slimit = HTTP::Cookie::MAX_COOKIES_TOTAL + @gc_threshold

      limit_per_domain = HTTP::Cookie::MAX_COOKIES_PER_DOMAIN
      uri = URI('http://www.example.org/')
      date = Time.at(Time.now.to_i + 86400)
      (1..(limit_per_domain + 1)).each { |i|
        @jar << HTTP::Cookie.new(cookie_values(
            :name => 'Foo%d' % i,
            :value => 'Bar%d' % i,
            :domain => uri.host,
            :for_domain => true,
            :path => '/dir%d/' % (i / 2),
            :origin => uri
            )).tap { |cookie|
          cookie.created_at = i == 42 ? date - i : date
        }
      }
      assert_equal limit_per_domain + 1, @jar.to_a.size
      @jar.cleanup
      count = @jar.to_a.size
      assert_equal limit_per_domain, count
      assert_equal [*1..(limit_per_domain + 1)] - [42], @jar.map { |cookie|
        cookie.name[/(\d+)$/].to_i
      }.sort

      hlimit = HTTP::Cookie::MAX_COOKIES_TOTAL

      n = hlimit / limit_per_domain * 2

      (1..n).each { |i|
        (1..(limit_per_domain + 1)).each { |j|
          uri = URI('http://www%d.example.jp/' % i)
          @jar << HTTP::Cookie.new(cookie_values(
              :name => 'Baz%d' % j,
              :value => 'www%d.example.jp' % j,
              :domain => uri.host,
              :for_domain => true,
              :path => '/dir%d/' % (i / 2),
              :origin => uri
              )).tap { |cookie|
            cookie.created_at = i == j ? date - i : date
          }
          count += 1
        }
      }

      assert_send [count, :>, slimit]
      assert_send [@jar.to_a.size, :<=, slimit]
      @jar.cleanup
      assert_equal hlimit, @jar.to_a.size
      assert_equal false, @jar.any? { |cookie|
        cookie.domain == cookie.value
      }
    end

    def test_parse
      set_cookie = [
        "name=Akinori; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
        "country=Japan; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
        "city=Tokyo; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
      ].join(', ')

      cookies = @jar.parse(set_cookie, 'http://rubyforge.org/')
      assert_equal %w[Akinori Japan Tokyo], cookies.map { |c| c.value }
      assert_equal %w[Tokyo Japan Akinori], @jar.to_a.sort_by { |c| c.name }.map { |c| c.value }
    end

    def test_parse_with_block
      set_cookie = [
        "name=Akinori; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
        "country=Japan; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
        "city=Tokyo; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
      ].join(', ')

      cookies = @jar.parse(set_cookie, 'http://rubyforge.org/') { |c| c.name != 'city' }
      assert_equal %w[Akinori Japan], cookies.map { |c| c.value }
      assert_equal %w[Japan Akinori], @jar.to_a.sort_by { |c| c.name }.map { |c| c.value }
    end

    def test_expire_by_each_and_cleanup
      uri = URI('http://www.example.org/')

      ts = Time.now.to_f
      if ts % 1 > 0.5
        sleep 0.5
        ts += 0.5
      end
      expires = Time.at(ts.floor)
      time = expires

      if mozilla_store?
        # MozillaStore only has the time precision of seconds.
        time = expires
        expires -= 1
      end

      0.upto(2) { |i|
        c = HTTP::Cookie.new('Foo%d' % (3 - i), 'Bar', :expires => expires + i, :origin => uri)
        @jar  << c
        @jar2 << c
      }

      assert_equal %w[Foo1 Foo2], @jar.cookies.map(&:name)
      assert_equal %w[Foo1 Foo2], @jar2.cookies(uri).map(&:name)

      sleep_until time + 1

      assert_equal %w[Foo1], @jar.cookies.map(&:name)
      assert_equal %w[Foo1], @jar2.cookies(uri).map(&:name)

      sleep_until time + 2

      @jar.cleanup
      @jar2.cleanup

      assert_send [@jar,  :empty?]
      assert_send [@jar2, :empty?]
    end
  end

  class WithHashStore < Test::Unit::TestCase
    include CommonTests

    def test_new
      jar = HTTP::CookieJar.new(:store => :hash)
      assert_instance_of HTTP::CookieJar::HashStore, jar.store

      assert_raises(ArgumentError) {
        jar = HTTP::CookieJar.new(:store => :nonexistent)
      }

      jar = HTTP::CookieJar.new(:store => HTTP::CookieJar::HashStore.new)
      assert_instance_of HTTP::CookieJar::HashStore, jar.store

      jar = HTTP::CookieJar.new(:store => HTTP::CookieJar::HashStore)
    end

    def test_clone
      jar = @jar.clone
      assert_not_send [
        @jar.store,
        :equal?,
        jar.store
      ]
      assert_not_send [
        @jar.store.instance_variable_get(:@jar),
        :equal?,
        jar.store.instance_variable_get(:@jar)
      ]
      assert_equal @jar.cookies, jar.cookies
    end
  end

  class TestHashStoreCapacity < Test::Unit::TestCase
    ALPHA  = 'https://www.alpha.test/'
    BETA   = 'https://beta.test/'
    EVIL   = 'https://evil.alpha.test/'
    PARENT = 'https://alpha.test/'

    def setup
      @base = Time.now - 600
      @expires = Time.now + 3600
    end

    def new_jar(per_site: 2, total: 4, gc: 1, mode: :cookie_scope,
                overflow: :evict)
      store = HTTP::CookieJar::HashStore.new(
        :gc_threshold => gc,
        :max_cookies_per_site => per_site,
        :max_cookies_total => total,
        :site_mode => mode,
        :overflow => overflow)
      [HTTP::CookieJar.new(:store => store), store]
    end

    def add(jar, name, value, url, created, expires: @expires,
            domain: nil, for_domain: false)
      # accessed_at equals created_at until the jar really sends the
      # cookie, which models a cookie that has never been used.
      jar.add(HTTP::Cookie.new(
        :name => name, :value => value, :origin => url, :path => '/',
        :created_at => created, :accessed_at => created,
        :expires => expires, :domain => domain, :for_domain => for_domain))
    end

    def values(jar, url)
      jar.cookies(url).map(&:cookie_value)
    end

    # Capacity decisions accumulated across automatic cleanups.  Each
    # automatic cleanup replaces #evictions with its own report, so
    # callers append after every write they want to audit.
    def decisions(store)
      @decisions ||= []
    end

    def test_flooding_subdomain_does_not_evict_other_sites
      jar, store = new_jar

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      add(jar, 'sid', 'BETA', BETA, @base + 1)
      # Make both sessions used, as a real client would.
      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal ['sid=BETA'], values(jar, BETA)

      sizes = []
      8.times { |i|
        add(jar, "x#{i}", "EVIL#{i}", EVIL, @base + 100 + i)
        decisions(store).concat(store.evictions)
        sizes << store.capacity_report.sites['evil.alpha.test']
        assert_equal ['sid=ALPHA'], values(jar, ALPHA), 'alpha session must survive'
        assert_equal ['sid=BETA'], values(jar, BETA), 'beta session must survive'
      }

      assert_equal [1, 2, 2, 2, 2, 2, 2, 2], sizes
      assert_equal 2, store.capacity_report.sites['evil.alpha.test']

      reasons = decisions(store).map { |decision| decision.reason }
      assert_equal [:site_limit] * 6, reasons
      assert decisions(store).all? { |decision| decision.site == 'evil.alpha.test' }
      assert_match(/per-site limit of 2/, decisions(store).first.detail)

      # The surviving flood cookies are the most recent pair, not the
      # oldest ones.
      assert_equal ['x6=EVIL6', 'x7=EVIL7'], values(jar, EVIL).sort
    end

    def test_eviction_reason_names_the_charged_site_and_order
      jar, store = new_jar(per_site: 10, total: 4)

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      add(jar, 'sid', 'BETA', BETA, @base + 1)
      add(jar, 'sid2', 'BETA2', BETA, @base + 2)
      values(jar, ALPHA)
      values(jar, BETA)

      3.times { |i|
        add(jar, "y#{i}", "EVIL#{i}", EVIL, @base + 100 + i)
        decisions(store).concat(store.evictions)
      }

      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal ['sid=BETA', 'sid2=BETA2'], values(jar, BETA)
      assert_equal ['y2=EVIL2'], values(jar, EVIL)

      evicted = decisions(store)
      assert_equal [:total_limit] * 2, evicted.map(&:reason)
      assert evicted.all? { |d| d.site == 'evil.alpha.test' }
      assert_match(/total 5 cookies exceeds the limit of 4/,
                   evicted.first.detail)
      assert_match(/charged to site "evil\.alpha\.test" whose newest cookie/,
                   evicted.first.detail)
      assert_match(/evicted least recently used cookie/, evicted.first.detail)
      assert_match(/last used: never used/, evicted.first.detail)
    end

    def test_sent_cookie_ranks_above_unsent_flood
      jar, store = new_jar(per_site: 2, total: 2)

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      add(jar, 'keep', 'ALPHA2', ALPHA, @base + 1)
      values(jar, ALPHA) # both are now sent

      3.times { |i|
        add(jar, "z#{i}", "EVIL#{i}", EVIL, @base + 100 + i)
        decisions(store).concat(store.evictions)
      }

      assert_equal ['keep=ALPHA2', 'sid=ALPHA'], values(jar, ALPHA).sort
      assert_equal [:total_limit], decisions(store).map(&:reason).uniq
      assert decisions(store).all? { |decision| decision.site == 'evil.alpha.test' }
    end

    def test_host_only_and_parent_domain_compete_only_when_shared
      jar, store = new_jar(per_site: 3, total: 8, mode: :cookie_scope)

      add(jar, 'hostonly', 'WWW', ALPHA, @base)
      add(jar, 'parent', 'SITE', PARENT,
          @base + 1, domain: '.alpha.test', for_domain: true)
      values(jar, ALPHA)

      # Host-only flood from the untrusted subdomain stays in its own
      # bucket and cannot touch either cookie.
      3.times { |i| add(jar, "h#{i}", "EVIL#{i}", EVIL, @base + 100 + i) }

      assert_equal ['hostonly=WWW', 'parent=SITE'], values(jar, ALPHA).sort
      assert_equal 1, store.capacity_report.sites['alpha.test']
      assert_equal 1, store.capacity_report.sites['www.alpha.test']

      # A parent-domain flood from the same subdomain shares the
      # `alpha.test` bucket with the parent cookie.
      5.times { |i|
        add(jar, "p#{i}", "EVILP#{i}", EVIL, @base + 200 + i,
            domain: '.alpha.test', for_domain: true)
      }

      sent = values(jar, ALPHA)
      assert_includes sent, 'hostonly=WWW'
      # The parent cookie was sent before the flood, so it outranks the
      # never-sent parent-domain flood.  Only the two newest flood
      # cookies fit in the shared bucket.
      assert_includes sent, 'parent=SITE'
      assert_equal ['hostonly=WWW', 'p3=EVILP3', 'p4=EVILP4', 'parent=SITE'],
                   sent.sort
      assert_equal 3, store.capacity_report.sites['alpha.test']
      assert_equal 1, store.capacity_report.sites['www.alpha.test']
    end

    def test_reject_overflow_keeps_existing_sessions
      jar, store = new_jar(per_site: 1, total: 3, overflow: :reject)

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      add(jar, 'sid', 'BETA', BETA, @base + 1)
      values(jar, ALPHA)
      values(jar, BETA)

      6.times { |i| add(jar, "r#{i}", "EVIL#{i}", EVIL, @base + 100 + i) }

      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal ['sid=BETA'], values(jar, BETA)
      assert_equal ['r0=EVIL0'], values(jar, EVIL)
      assert_equal 5, store.rejection_count
      assert_equal 'evil.alpha.test', store.rejections.first.site
      assert_equal :rejected, store.rejections.first.reason
      assert_equal 5, store.rejections.size
      assert_match(/refused without evicting existing cookies/,
                   store.rejections.first.detail)
      # Rejection is not an eviction.
      assert_equal [], store.evictions
    end

    def test_reject_at_total_capacity_does_not_evict
      jar, store = new_jar(per_site: 10, total: 2, overflow: :reject)

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      add(jar, 'sid', 'BETA', BETA, @base + 1)

      add(jar, 'leak', 'EVIL', EVIL, @base + 100)

      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal ['sid=BETA'], values(jar, BETA)
      assert_equal [], values(jar, EVIL)
      assert_equal 1, store.rejection_count
      assert_equal [], store.evictions
      assert_equal 2, store.capacity_report.total
    end

    def test_reject_reclaims_expired_cookie_instead_of_evicting
      jar, store = new_jar(per_site: 10, total: 2, overflow: :reject)

      add(jar, 'old', 'OLD', ALPHA, @base - 7200, expires: @base - 3600)
      add(jar, 'sid', 'ALPHA', ALPHA, @base)

      # The expired cookie no longer occupies a slot.
      add(jar, 'new', 'NEW', BETA, @base + 1)

      assert_equal 0, store.rejection_count
      assert_equal ['new=NEW'], values(jar, BETA)
      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal 2, store.capacity_report.total
    end

    def test_changing_a_cookie_at_capacity_is_not_a_new_cookie
      jar, store = new_jar(per_site: 1, total: 1, overflow: :reject)

      add(jar, 'sid', 'OLD', ALPHA, @base)
      add(jar, 'sid', 'NEW', ALPHA, @base + 1)

      assert_equal ['sid=NEW'], values(jar, ALPHA)
      assert_equal 0, store.rejection_count
    end

    def test_expired_cookies_are_cleaned_before_quota
      jar, store = new_jar(per_site: 2, total: 2, overflow: :reject)

      add(jar, 'gone', 'OLD', ALPHA, @base - 7200,
          expires: @base - 3600)
      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      add(jar, 'sid2', 'ALPHA2', ALPHA, @base + 1)

      assert_equal 0, store.rejection_count
      # The expired cookie was removed by the policy, not counted as a
      # quota occupant, so the two live cookies fit.
      assert_equal 2, store.capacity_report.total
      assert_equal ['sid2=ALPHA2', 'sid=ALPHA'], values(jar, ALPHA).sort
    end

    def test_eviction_does_not_change_authorization_scope
      jar, = new_jar(per_site: 2, total: 2)

      secure = HTTP::Cookie.new(
        :name => 'tok', :value => 'SECURE', :origin => ALPHA, :path => '/',
        :expires => @expires, :created_at => @base, :secure => true)
      jar.add(secure)
      assert_equal [], jar.cookies(URI('http://www.alpha.test/'))
      assert_equal ['tok=SECURE'], values(jar, 'https://www.alpha.test/')

      3.times { |i| add(jar, "q#{i}", "EVIL#{i}", EVIL, @base + 100 + i) }

      survivor = jar.cookies(ALPHA).first
      assert_equal 'tok', survivor.name
      assert_equal true, survivor.secure?
      assert_equal false, survivor.for_domain?
      assert_equal '/', survivor.path
      assert_equal 0, jar.cookies(URI('http://www.alpha.test/')).size
    end

    def test_site_mode_host_keeps_host_only_buckets_separate
      jar, store = new_jar(per_site: 1, total: 3, mode: :host)

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      4.times { |i| add(jar, "s#{i}", "EVIL#{i}", EVIL, @base + 100 + i) }

      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal ['s3=EVIL3'], values(jar, EVIL)
      assert_equal 'www.alpha.test', store.capacity_report.sites.keys.sort[1]
    end

    def test_site_mode_site_groups_registrable_domain
      jar, store = new_jar(per_site: 2, total: 10, mode: :site)

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      values(jar, ALPHA) # mark the session as sent

      4.times { |i| add(jar, "t#{i}", "EVIL#{i}", EVIL, @base + 100 + i) }

      # www.alpha.test and evil.alpha.test share one bucket, and the
      # sent session outranks the fresh, never-sent flood.
      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal 2, store.capacity_report.sites['alpha.test']
      assert_equal ['t3=EVIL3'], values(jar, EVIL)
    end

    def test_callable_site_mode
      jar, store = new_jar(per_site: 10, total: 10,
                           mode: lambda { |cookie| cookie.domain })

      add(jar, 'sid', 'ALPHA', ALPHA, @base)
      assert_equal ['sid=ALPHA'], values(jar, ALPHA)
      assert_equal 1, store.capacity_report.sites['www.alpha.test']
    end

    def test_option_validation
      assert_raises(ArgumentError) {
        HTTP::CookieJar::HashStore.new(:max_cookies_per_site => 0)
      }
      assert_raises(ArgumentError) {
        HTTP::CookieJar::HashStore.new(:max_cookies_total => -1)
      }
      assert_raises(ArgumentError) {
        HTTP::CookieJar::HashStore.new(:site_mode => :nonsense)
      }
      assert_raises(ArgumentError) {
        HTTP::CookieJar::HashStore.new(:overflow => :drop)
      }
      assert_raises(ArgumentError) {
        HTTP::CookieJar.new(:store => :hash, :max_cookies_total => 0)
      }
    end

    def test_clone_copies_capacity_state
      original, = new_jar(per_site: 5, total: 5)
      add(original, 'sid', 'ALPHA', ALPHA, @base)
      values(original, ALPHA)

      clone = original.clone
      assert_equal ['sid=ALPHA'], values(clone, ALPHA)
      assert_equal 1, clone.store.capacity_report.total
      clone.store.clear
      assert_equal ['sid=ALPHA'], values(original, ALPHA)
    end
  end

  class WithMozillaStore < Test::Unit::TestCase
    include CommonTests

    def setup
      super(
        { :store => :mozilla, :filename => ":memory:" },
        { :store => :mozilla, :filename => ":memory:" })
    end

    def add_and_delete(jar)
      jar.parse("name=Akinori; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
                'http://rubyforge.org/')
      jar.parse("country=Japan; Domain=rubyforge.org; Expires=Sun, 08 Aug 2076 19:00:00 GMT; Path=/",
                'http://rubyforge.org/')
      jar.delete(HTTP::Cookie.new("name", :domain => 'rubyforge.org'))
    end

    def test_clone
      assert_raises(TypeError) {
        @jar.clone
      }
    end

    def test_close
      add_and_delete(@jar)

      assert_not_send [@jar.store, :closed?]
      @jar.store.close
      assert_send [@jar.store, :closed?]
      @jar.store.close	# should do nothing
      assert_send [@jar.store, :closed?]
    end

    def test_finalizer
      db = nil
      loop {
        jar = HTTP::CookieJar.new(:store => :mozilla, :filename => ':memory:')
        add_and_delete(jar)
        db = jar.store.instance_variable_get(:@db)
        class << db
          alias close_orig close
          def close
            STDERR.print "[finalizer is called]"
            STDERR.flush
            close_orig
          end
        end
        break
      }
    end

    def test_upgrade_mozillastore
      Dir.mktmpdir { |dir|
        filename = File.join(dir, 'cookies.sqlite')

        sqlite = SQLite3::Database.new(filename)
        sqlite.execute(<<-'SQL')
          CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            name TEXT,
            value TEXT,
            host TEXT,
            path TEXT,
            expiry INTEGER,
            isSecure INTEGER,
            isHttpOnly INTEGER)
        SQL
        sqlite.execute(<<-'SQL')
          PRAGMA user_version = 1
        SQL

        begin
          st_insert = sqlite.prepare(<<-'SQL')
            INSERT INTO moz_cookies (
              id, name, value, host, path, expiry, isSecure, isHttpOnly
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          SQL

          st_insert.execute(1, 'name1', 'value1', '.example.co.jp', '/', 2312085765, 0, 0)
          st_insert.execute(2, 'name1', 'value2', '.example.co.jp', '/', 2312085765, 0, 0)
          st_insert.execute(3, 'name1', 'value3', 'www.example.co.jp', '/', 2312085765, 0, 0)
        ensure
          st_insert.close if st_insert
        end

        sqlite.close
        jar = HTTP::CookieJar.new(:store => :mozilla, :filename => filename)

        assert_equal 2, jar.to_a.size
        assert_equal 2, jar.cookies('http://www.example.co.jp/').size

        cookie, *rest = jar.cookies('http://host.example.co.jp/')
        assert_send [rest, :empty?]
        assert_equal 'value2', cookie.value
      }
    end
  end if begin
    require 'sqlite3'
    true
  rescue LoadError
    STDERR.puts 'sqlite3 missing?'
    false
  end
end

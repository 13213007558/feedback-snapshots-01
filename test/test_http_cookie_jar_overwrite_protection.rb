# frozen_string_literal: true
require File.expand_path('helper', File.dirname(__FILE__))
require 'tmpdir'

class TestHTTPCookieJarOverwriteProtection < Test::Unit::TestCase
  HTTPS_LOGIN = 'https://example.com/login'
  HTTP_LOGIN = 'http://example.com/login'

  def setup
    @events = []
    @jar = HTTP::CookieJar.new(
      :store => :hash,
      :overwrite_protection => { :audit => @events.method(:<<) })
  end

  def test_policy_is_optional_and_disabled_by_default
    jar = HTTP::CookieJar.new(:store => :hash)
    assert_nil jar.overwrite_protection

    jar.parse('sid=login; Secure; Path=/login', HTTPS_LOGIN)
    jar.parse('sid=shadow; Path=/login', HTTP_LOGIN)

    assert_equal 'sid=shadow', header_for(jar, HTTP_LOGIN)
    assert_equal 'sid=shadow', header_for(jar, HTTPS_LOGIN)
  end

  def test_http_shadow_cannot_replace_https_login_cookie
    @jar.parse('sid=TOPSECRET; Secure; Path=/login', HTTPS_LOGIN)
    added = @jar.parse('sid=SHADOWVALUE; Path=/login', HTTP_LOGIN)

    assert_equal [], added
    assert_equal '', header_for(@jar, HTTP_LOGIN)
    assert_equal 'sid=TOPSECRET', header_for(@jar, HTTPS_LOGIN)
    assert_equal 1, @events.size

    event = @events.first
    assert_equal :cookie_overwrite_rejected, event[:event]
    assert_equal :insecure_overwrite_of_secure_cookie, event[:reason]
    assert_equal false, event[:deletion]
    assert_equal 'sid', event[:incoming][:name]
    assert_equal '/login', event[:incoming][:path]
    assert_equal 'sid', event[:protected].first[:name]
    assert_not_include event.inspect, 'TOPSECRET'
    assert_not_include event.inspect, 'SHADOWVALUE'
  end

  def test_https_may_replace_https_login_cookie
    @jar.parse('sid=login; Secure; Path=/login', HTTPS_LOGIN)
    @jar.parse('sid=login2; Secure; Path=/login', HTTPS_LOGIN)

    assert_equal 'sid=login2', header_for(@jar, HTTPS_LOGIN)
    assert_empty @events
  end

  def test_login_https_shadow_and_disjoint_path_values_end_to_end
    # The HTTPS login identity.
    @jar.parse('sid=LOGINVALUE; Secure; Path=/login', HTTPS_LOGIN)
    # An HTTP shadow for the same name and path must not win.
    @jar.parse('sid=SHADOWVALUE; Path=/login', HTTP_LOGIN)
    # Unrelated values with disjoint paths are still stored.
    @jar.parse('sid=APIVALUE; Path=/api', 'http://example.com/api')
    @jar.parse('theme=dark; Path=/login', HTTP_LOGIN)

    assert_equal 'sid=LOGINVALUE; theme=dark', header_for(@jar, HTTPS_LOGIN)
    assert_equal 'theme=dark', header_for(@jar, HTTP_LOGIN)
    assert_equal 'sid=APIVALUE', header_for(@jar, 'http://example.com/api/v1')
    assert_equal 1, @events.size
    assert_equal :insecure_overwrite_of_secure_cookie, @events.first[:reason]
  end

  def test_http_root_shadow_of_secure_subpath_is_rejected
    @jar.parse('sid=login; Secure; Path=/admin', 'https://example.com/admin')
    added = @jar.parse('sid=shadow; Path=/', 'http://example.com/')

    assert_equal [], added
    assert_equal 'sid=login', header_for(@jar, 'https://example.com/admin')
    assert_equal '', header_for(@jar, 'https://example.com/')
    assert_equal 1, @events.size
    assert_equal :insecure_shadowing_of_secure_cookie, @events.first[:reason]
  end

  def test_domain_suffix_that_is_not_a_subdomain_does_not_collide
    @jar.parse('sid=login; Secure; Path=/', 'https://example.com/')
    @jar.parse('sid=other; Path=/', 'http://notexample.com/')

    assert_equal 'sid=login', header_for(@jar, 'https://example.com/')
    assert_equal 'sid=other', header_for(@jar, 'http://notexample.com/')
    assert_empty @events
  end

  def test_http_cookie_with_another_name_is_stored
    @jar.parse('sid=login; Secure; Path=/login', HTTPS_LOGIN)
    @jar.parse('theme=dark; Path=/login', HTTP_LOGIN)

    assert_equal 'sid=login; theme=dark', header_for(@jar, HTTPS_LOGIN)
    assert_equal 'theme=dark', header_for(@jar, HTTP_LOGIN)
    assert_empty @events
  end

  def test_http_cookie_with_disjoint_path_is_stored
    @jar.parse('sid=login; Secure; Path=/login', HTTPS_LOGIN)
    added = @jar.parse('sid=public; Path=/public', HTTP_LOGIN)

    assert_equal %w[public], added.map(&:value)
    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 'sid=public', header_for(@jar, 'http://example.com/public')
    assert_equal 'sid=login', header_for(@jar, 'https://example.com/login')
    assert_empty @events
  end

  def test_http_deletion_cannot_delete_https_login_cookie
    @jar.parse('sid=login; Secure; Path=/login', HTTPS_LOGIN)
    added = @jar.parse('sid=; Max-Age=0; Path=/login', HTTP_LOGIN)

    assert_equal [], added
    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 1, @events.size
    assert_equal :insecure_deletion_of_secure_cookie, @events.first[:reason]
    assert_equal true, @events.first[:deletion]
  end

  def test_programmatic_cookie_without_origin_is_treated_as_untrusted
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    @jar.add(HTTP::Cookie.new('sid', 'shadow',
                              :domain => 'example.com', :path => '/'))

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 1, @events.size
  end

  def test_plain_cookies_are_not_protected
    @jar.parse('pref=old; Path=/', HTTP_LOGIN)
    @jar.parse('pref=new; Path=/', HTTP_LOGIN)
    @jar.parse('pref=; Max-Age=0; Path=/', HTTP_LOGIN)

    assert_equal '', header_for(@jar, HTTP_LOGIN)
    assert_empty @events
  end

  def test_http_deletion_of_a_cookie_with_a_disjoint_path_is_stored_normally
    @jar.parse('sid=login; Secure; Path=/login', HTTPS_LOGIN)
    @jar.parse('sid=; Max-Age=0; Path=/other', HTTP_LOGIN)

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_empty @events
  end

  def test_host_only_shadow_of_parent_domain_secure_cookie_is_rejected
    @jar.parse('sid=login; Secure; Domain=example.com; Path=/', HTTPS_LOGIN)
    @jar.parse('sid=shadow; Path=/', 'http://www.example.com/')

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 'sid=login', header_for(@jar, 'https://www.example.com/')
    assert_equal '', header_for(@jar, 'http://www.example.com/')
    assert_equal 1, @events.size
    assert_equal :insecure_shadowing_of_secure_cookie, @events.first[:reason]
  end

  def test_parent_domain_shadow_of_host_only_secure_cookie_is_rejected
    @jar.parse('sid=login; Secure; Path=/', 'https://www.example.com/')
    @jar.parse('sid=shadow; Domain=example.com; Path=/', 'http://www.example.com/')

    assert_equal 'sid=login', header_for(@jar, 'https://www.example.com/')
    assert_equal '', header_for(@jar, 'http://www.example.com/')
    assert_equal 1, @events.size
    assert_equal :insecure_shadowing_of_secure_cookie, @events.first[:reason]
  end

  def test_http_deletion_of_the_exact_parent_domain_entry_is_rejected
    @jar.parse('sid=login; Secure; Domain=example.com; Path=/', HTTPS_LOGIN)
    @jar.parse('sid=; Max-Age=0; Domain=example.com; Path=/', 'http://example.com/')

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 1, @events.size
    assert_equal :insecure_deletion_of_secure_cookie, @events.first[:reason]
  end

  def test_parent_domain_shadow_from_another_subdomain_is_rejected
    @jar.parse('sid=login; Secure; Path=/', 'https://a.example.com/')
    @jar.parse('sid=shadow; Domain=example.com; Path=/', 'http://b.example.com/')

    assert_equal 'sid=login', header_for(@jar, 'https://a.example.com/')
    assert_equal '', header_for(@jar, 'https://b.example.com/')
    assert_equal 1, @events.size
    assert_equal :insecure_shadowing_of_secure_cookie, @events.first[:reason]
  end

  def test_different_subdomain_host_only_cookies_do_not_collide
    @jar.parse('sid=login; Secure; Path=/', 'https://a.example.com/')
    @jar.parse('sid=other; Path=/', 'http://b.example.com/')

    assert_equal 'sid=login', header_for(@jar, 'https://a.example.com/')
    assert_equal 'sid=other', header_for(@jar, 'http://b.example.com/')
    assert_empty @events
  end

  def test_cookie_for_an_unrelated_domain_is_stored
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    @jar.parse('sid=other; Path=/', 'http://other.example.net/')

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 'sid=other', header_for(@jar, 'http://other.example.net/')
    assert_empty @events
  end

  def test_add_uses_the_same_policy
    secure = HTTP::Cookie.new('sid', 'login', :secure => true, :origin => HTTPS_LOGIN)
    shadow = HTTP::Cookie.new('sid', 'shadow', :origin => HTTP_LOGIN)
    @jar.add(secure)
    @jar.add(shadow)

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 1, @events.size
  end

  def test_rejected_cookie_leaves_the_original_object_intact
    secure = HTTP::Cookie.new('sid', 'login', :secure => true, :origin => HTTPS_LOGIN)
    @jar.add(secure)
    created_at = secure.created_at
    @jar.add(HTTP::Cookie.new('sid', 'shadow', :origin => HTTP_LOGIN))

    stored = @jar.to_a
    assert_equal 1, stored.size
    assert_same secure, stored.first
    assert_equal 'login', stored.first.value
    assert_equal 'example.com', stored.first.domain
    assert_equal '/', stored.first.path
    assert_equal true, stored.first.secure?
    assert_equal created_at, stored.first.created_at
  end

  def test_policy_can_be_enabled_with_defaults
    jar = HTTP::CookieJar.new(:store => :hash, :overwrite_protection => true)
    assert_instance_of HTTP::CookieJar::OverwriteProtection, jar.overwrite_protection

    jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    jar.parse('sid=shadow; Path=/', 'http://example.com/')
    assert_equal 'sid=login', header_for(jar, HTTPS_LOGIN)
  end

  def test_logger_audit_does_not_include_values
    output = +''
    logger = Object.new
    logger.define_singleton_method(:warn) { |message| output << message }

    jar = HTTP::CookieJar.new(
      :store => :hash,
      :overwrite_protection => { :logger => logger })
    jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    jar.parse('sid=shadow; Path=/', 'http://example.com/')

    assert_match(/insecure_overwrite_of_secure_cookie/, output)
    assert_match(/sid@example\.com/, output)
    assert_not_include output, 'login'
    assert_not_include output, 'shadow'
  end

  def test_rejected_count
    assert_equal 0, @jar.overwrite_protection.rejected_count
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    @jar.parse('sid=shadow; Path=/', 'http://example.com/')
    assert_equal 1, @jar.overwrite_protection.rejected_count
  end

  def test_secure_cookie_claimed_from_http_is_not_trusted
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    @jar.parse('sid=shadow; Secure; Path=/', 'http://example.com/')

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 1, @events.size
  end

  def test_programmatic_cookie_without_origin_can_replace_secure_cookie
    @jar.add(HTTP::Cookie.new('sid', 'login', :secure => true, :origin => HTTPS_LOGIN))
    @jar.add(HTTP::Cookie.new('sid', 'server', :secure => true,
                              :domain => 'example.com', :path => '/'))

    assert_equal 'sid=server', header_for(@jar, HTTPS_LOGIN)
    assert_empty @events
  end

  def test_protect_secure_can_be_turned_off
    jar = HTTP::CookieJar.new(
      :store => :hash,
      :overwrite_protection => { :protect_secure => false })
    jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    jar.parse('sid=shadow; Path=/', 'http://example.com/')

    assert_equal 'sid=shadow', header_for(jar, HTTPS_LOGIN)
  end

  def test_false_disables_the_policy
    jar = HTTP::CookieJar.new(:store => :hash, :overwrite_protection => false)
    assert_nil jar.overwrite_protection
  end

  def test_parse_with_block_only_returns_stored_cookies
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    cookies = @jar.parse('sid=shadow; Path=/; Expires=Sun, 08 Aug 2076 19:00:00 GMT',
                         'http://example.com/') { |cookie| cookie.name == 'sid' }

    assert_equal [], cookies
    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
  end

  def test_jar_clone_keeps_the_policy
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    clone = @jar.clone
    assert_instance_of HTTP::CookieJar::OverwriteProtection, clone.overwrite_protection
    assert_not_same @jar.overwrite_protection, clone.overwrite_protection

    clone.parse('sid=shadow; Path=/', 'http://example.com/')
    assert_equal 'sid=login', header_for(clone, HTTPS_LOGIN)
    assert_equal 1, clone.overwrite_protection.rejected_count
    assert_equal 0, @jar.overwrite_protection.rejected_count
  end

  def test_audit_event_is_frozen_and_contains_no_value_key
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    @jar.parse('sid=shadow; Path=/', 'http://example.com/')

    event = @events.first
    assert_send [event, :frozen?]
    assert_send [event[:incoming], :frozen?]
    assert_send [event[:protected], :frozen?]
    assert_not_include event[:incoming].keys, :value
    assert_not_include event[:protected].first.keys, :value
  end

  def test_http_host_only_deletion_cannot_delete_secure_host_only_cookie
    @jar.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
    @jar.parse('sid=; Max-Age=0; Path=/', HTTP_LOGIN)

    assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    assert_equal 1, @events.size
    assert_equal :insecure_deletion_of_secure_cookie, @events.first[:reason]
  end

  def test_http_deletion_for_another_subdomain_is_stored_normally
    @jar.parse('sid=login; Secure; Path=/', 'https://a.example.com/')
    @jar.parse('sid=; Max-Age=0; Path=/', 'http://b.example.com/')

    assert_equal 'sid=login', header_for(@jar, 'https://a.example.com/')
    assert_empty @events
  end

  def test_loaded_cookies_are_subject_to_the_policy
    Dir.mktmpdir { |dir|
      filename = File.join(dir, 'cookies.yml')
      source = HTTP::CookieJar.new(:store => :hash)
      source.parse('sid=login; Secure; Path=/', HTTPS_LOGIN)
      source.save(filename, :session => true)

      @jar.load(filename)
      assert_equal 'sid=login', header_for(@jar, HTTPS_LOGIN)
    }
  end

  def test_invalid_policy_option
    assert_raises(TypeError) {
      HTTP::CookieJar.new(:overwrite_protection => :nonsense)
    }
  end

  private

  def header_for(jar, url)
    HTTP::Cookie.cookie_value(jar.cookies(url))
  end
end

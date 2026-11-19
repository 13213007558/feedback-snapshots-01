require_relative "../spec_helper"

describe "conditional_sessions plugin with route_csrf" do
  # Build a cookie jar from Set-Cookie headers, applying deletions for
  # expired cookies.  The shared CookieJar helper only tracks a single
  # Set-Cookie value, which is insufficient for responses that set or
  # delete multiple cookies.
  def perform(path, method: 'GET', cookies: {}, form: nil)
    env = {'REQUEST_METHOD'=>method}
    input = form ? Rack::Utils.build_query(form) : ''
    env['rack.input'] = rack_input(input)
    env['CONTENT_TYPE'] = 'application/x-www-form-urlencoded' if form
    env['HTTP_COOKIE'] = cookies.map{|k, v| "#{k}=#{v}"}.join('; ') unless cookies.empty?

    res = req(path, env)
    body = res[2].to_a.join
    set_cookies = Array(res[1][RodaResponseHeaders::SET_COOKIE])

    jar = cookies.dup
    set_cookies.each do |cookie|
      name, value = cookie.split(';', 2).first.split('=', 2)
      if cookie =~ /max-age=0/i || cookie =~ /expires=Thu, 01 Jan 1970/
        jar.delete(name)
      elsif value
        jar[name] = value
      end
    end

    [res, body, jar]
  end

  def token_from(html)
    html[/value="([^"]+)"/, 1]
  end

  def deleted_cookies(set_cookie_headers, name)
    Array(set_cookie_headers).select{|c| c.start_with?("#{name}=")}
  end

  before do
    app(:bare) do
      plugin :caching
      plugin :cookies
      plugin :route_csrf, :secret=>'c'*64, :secret_cookie=>true
      plugin :conditional_sessions, :secret=>'1'*64 do
        case path_info
        when '/public', '/health', '/withdraw'
          :none
        when '/login', '/consent'
          cookies['visitor_consent'] ? :sessions : :csrf
        else
          cookies['visitor_consent'] ? :sessions : :none
        end
      end

      route do |r|
        r.get('public') do
          r.etag('public-v1')
          "public:#{session_mode}:#{use_sessions?}:#{use_csrf?}:#{env.key?('rack.session') ? 'loaded' : 'not-loaded'}"
        end

        r.get('health'){'health'}

        r.get('login'){r.etag('login-v1'); csrf_tag('/login')}

        r.post('login') do
          check_csrf!
          if use_sessions?
            session['user'] = 'alice'
            'login-session'
          else
            'login-form-only'
          end
        end

        r.get('account'){"account:#{session['user']}:#{session_mode}"}

        r.get('consent') do
          response.set_cookie('visitor_consent', '1')
          "consent:#{session_mode}"
        end

        r.post('withdraw') do
          loaded = env.key?('rack.session')
          expire_session
          delete_csrf_secret_cookie
          response.delete_cookie('visitor_consent')
          "withdraw:#{session_mode}:#{loaded ? 'loaded' : 'not-loaded'}"
        end
      end
    end
  end

  it "serves sessionless pages without cookies or session access" do
    res, body, jar = perform('/public')
    body.must_equal 'public:none:false:false:not-loaded'
    res[1][RodaResponseHeaders::SET_COOKIE].must_be_nil
    jar.must_equal({})

    res, body, jar = perform('/public')
    body.must_equal 'public:none:false:false:not-loaded'
    res[1][RodaResponseHeaders::SET_COOKIE].must_be_nil
    jar.must_equal({})
  end

  it "does not load or rewrite a submitted session on sessionless pages" do
    _, _, jar = perform('/consent')
    _, _, jar = perform('/login', cookies: jar)
    token = token_from(perform('/login', cookies: jar)[1])
    _, body, jar = perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    body.must_equal 'login-session'
    jar.key?('roda.session').must_equal true

    res, body, next_jar = perform('/public', cookies: jar)
    body.must_equal 'public:none:false:false:not-loaded'
    res[1][RodaResponseHeaders::SET_COOKIE].must_be_nil
    next_jar.must_equal jar

    # Conditional requests used by caches do not add or refresh cookies either
    etag = res[1][RodaResponseHeaders::ETAG]
    etag.wont_be_nil
    res = req('/public', 'HTTP_COOKIE'=>jar.map{|k, v| "#{k}=#{v}"}.join('; '), 'HTTP_IF_NONE_MATCH'=>etag)
    res[0].must_equal 304
    res[1][RodaResponseHeaders::SET_COOKIE].must_be_nil
  end

  it "does not accept a session CSRF token from another browser on form-only pages" do
    _, _, jar = perform('/login')
    token = token_from(perform('/login', cookies: jar)[1])

    proc do
      perform('/login', method: 'POST', cookies: {}, form: {'_csrf'=>token})
    end.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    _, body, jar = perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    body.must_equal 'login-form-only'
  end

  it "uses a dedicated CSRF cookie without creating a session on form-only pages" do
    res, html, jar = perform('/login')
    set_cookies = Array(res[1][RodaResponseHeaders::SET_COOKIE])
    set_cookies.length.must_equal 1
    set_cookies[0].must_match(/\A_roda_csrf=/)
    set_cookies[0].must_match(/; path=\//)
    set_cookies[0].must_match(/; httponly/)
    set_cookies[0].must_match(/; samesite=lax/)
    set_cookies[0].wont_match(/roda\.session=/)
    jar.key?('roda.session').must_equal false

    token = token_from(html)
    token.length.must_equal 84
    jar.key?('_roda_csrf').must_equal true

    res, body, jar = perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    body.must_equal 'login-form-only'
    res[1][RodaResponseHeaders::SET_COOKIE].must_be_nil
    jar.key?('roda.session').must_equal false
  end

  it "requires the CSRF cookie and a token generated from the same cookie" do
    _, html, jar = perform('/login')
    token = token_from(html)

    proc do
      perform('/login', method: 'POST', cookies: {}, form: {'_csrf'=>token})
    end.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    # A token generated for one CSRF cookie is not valid with another
    _, _, other_jar = perform('/login')
    proc do
      perform('/login', method: 'POST', cookies: other_jar, form: {'_csrf'=>token})
    end.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken

    # A token is required even with the correct cookie
    proc do
      perform('/login', method: 'POST', cookies: jar, form: {})
    end.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "uses the normal session and session CSRF secret on consented pages" do
    _, _, jar = perform('/consent')
    res, html, jar = perform('/login', cookies: jar)
    res[1][RodaResponseHeaders::SET_COOKIE].to_s.wont_match(/_roda_csrf=/)
    jar.key?('roda.session').must_equal true
    jar.wont_include('_roda_csrf')

    token = token_from(html)
    _, body, jar = perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    body.must_equal 'login-session'

    _, body, = perform('/account', cookies: jar)
    body.must_equal 'account:alice:sessions'

    # The session based token is not valid once the session is unavailable
    jar.delete('roda.session')
    proc do
      perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    end.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "clears the session, CSRF, and consent cookies when consent is withdrawn" do
    _, _, jar = perform('/consent')
    _, _, jar = perform('/login', cookies: jar)
    token = token_from(perform('/login', cookies: jar)[1])
    _, body, jar = perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    body.must_equal 'login-session'

    # Create a CSRF-only cookie for a visitor that no longer has consent,
    # while still holding the session cookie created earlier
    jar.delete('visitor_consent')
    _, _, jar = perform('/login', cookies: jar)
    jar.key?('roda.session').must_equal true
    jar.key?('_roda_csrf').must_equal true
    jar.key?('visitor_consent').must_equal false

    res, body, jar = perform('/withdraw', method: 'POST', cookies: jar)
    body.must_equal 'withdraw:none:not-loaded'

    set_cookies = res[1][RodaResponseHeaders::SET_COOKIE]
    ['roda.session', '_roda_csrf', 'visitor_consent'].each do |name|
      cookies = deleted_cookies(set_cookies, name)
      cookies.length.must_equal 1
      cookies[0].must_match(/\A#{Regexp.escape(name)}=;/)
      cookies[0].must_match(/; max-age=0/)
      cookies[0].must_match(/; expires=Thu, 01 Jan 1970/)
    end

    jar.must_equal({})
    proc{perform('/account', cookies: jar)}.must_raise Roda::RodaError
  end

  it "does not rotate the CSRF cookie on a cached form page" do
    _, _, jar = perform('/login')
    nonce = jar['_roda_csrf']
    nonce.wont_be_nil

    res, html, next_jar = perform('/login', cookies: jar)
    res[0].must_equal 200
    res[1][RodaResponseHeaders::SET_COOKIE].must_be_nil
    next_jar['_roda_csrf'].must_equal nonce

    etag = res[1][RodaResponseHeaders::ETAG]
    etag.wont_be_nil
    res = req('/login', 'HTTP_COOKIE'=>jar.map{|k, v| "#{k}=#{v}"}.join('; '), 'HTTP_IF_NONE_MATCH'=>etag)
    res[0].must_equal 304
    res[1][RodaResponseHeaders::SET_COOKIE].must_be_nil
  end

  it "expires cookies on withdrawal while consent is still present" do
    _, _, jar = perform('/consent')
    _, _, jar = perform('/login', cookies: jar)
    token = token_from(perform('/login', cookies: jar)[1])
    _, _, jar = perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    jar.key?('visitor_consent').must_equal true
    jar.key?('roda.session').must_equal true

    res, body, jar = perform('/withdraw', method: 'POST', cookies: jar)
    body.must_equal 'withdraw:none:not-loaded'

    set_cookies = res[1][RodaResponseHeaders::SET_COOKIE]
    ['roda.session', 'visitor_consent'].each do |name|
      deleted_cookies(set_cookies, name).length.must_equal 1
    end
    jar.must_equal({})
  end

  it "does not write the session back after expiring it in session mode" do
    app(:bare) do
      plugin :cookies
      plugin :route_csrf, :secret=>'c'*64, :secret_cookie=>true
      plugin :conditional_sessions, :secret=>'1'*64 do
        cookies['visitor_consent'] ? :sessions : :none
      end

      route do |r|
        r.get('consent'){response.set_cookie('visitor_consent', '1')}
        r.get('set'){session['key'] = 'value'; 'set'}
        r.post('withdraw') do
          session['key']
          expire_session
          session.empty?.to_s
        end
      end
    end

    _, _, jar = perform('/consent')
    _, _, jar = perform('/set', cookies: jar)
    jar.key?('roda.session').must_equal true

    res, body, jar = perform('/withdraw', method: 'POST', cookies: jar)
    body.must_equal 'true'

    set_cookies = Array(res[1][RodaResponseHeaders::SET_COOKIE])
    deleted_cookies(set_cookies, 'roda.session').length.must_equal 1
    set_cookies.none?{|c| c.start_with?('roda.session=') && !c.include?('max-age=0')}.must_equal true
  end

  it "expires cookies on withdrawal even when no cookies were submitted" do
    res, body, jar = perform('/withdraw', method: 'POST')
    body.must_equal 'withdraw:none:not-loaded'
    jar.must_equal({})

    ['roda.session', '_roda_csrf', 'visitor_consent'].each do |name|
      deleted_cookies(res[1][RodaResponseHeaders::SET_COOKIE], name).length.must_equal 1
    end
  end

  it "does not allow CSRF protection without :secret_cookie in sessionless form mode" do
    app(:bare) do
      plugin :route_csrf, :secret=>'c'*64
      plugin :conditional_sessions, :secret=>'1'*64 do
        :csrf
      end

      route do |r|
        r.get('login'){csrf_tag('/login')}
      end
    end

    proc{body('/login')}.must_raise Roda::RodaError
  end

  it "rejects tokens in requests where no session or CSRF cookie is available" do
    app(:bare) do
      plugin :route_csrf, :secret=>'c'*64, :secret_cookie=>true
      plugin :conditional_sessions, :secret=>'1'*64 do
        path_info == '/public' ? :none : :csrf
      end

      route do |r|
        r.get('token'){csrf_tag('/login')}
        r.post('login'){check_csrf!; 'ok'}
        r.post('public'){check_csrf!; 'ok'}
        r.get('public'){csrf_tag('/login')}
      end
    end

    # /public is :none, so generating a token there is an error
    proc{body('/public')}.must_raise Roda::RodaError

    # A token generated elsewhere cannot be validated in :none mode
    _, html, jar = perform('/token')
    token = token_from(html)
    proc do
      perform('/public', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    end.must_raise Roda::RodaPlugins::RouteCsrf::InvalidToken
  end

  it "supports the :secret_cookie option without the conditional_sessions plugin" do
    app(:bare) do
      plugin :route_csrf, :secret=>'c'*64, :secret_cookie=>{:name=>'custom_csrf'}
      route do |r|
        r.get('login'){csrf_tag('/login')}
        r.post('login') do
          check_csrf!
          "ok:#{env.key?('rack.session') ? 'loaded' : 'not-loaded'}"
        end
      end
    end

    res, html, jar = perform('/login')
    Array(res[1][RodaResponseHeaders::SET_COOKIE]).length.must_equal 1
    jar.key?('custom_csrf').must_equal true
    jar.key?('roda.session').must_equal false

    token = token_from(html)
    _, body, jar = perform('/login', method: 'POST', cookies: jar, form: {'_csrf'=>token})
    body.must_equal 'ok:not-loaded'
  end

  it "allows configuring the CSRF cookie name and options" do
    app(:bare) do
      plugin :route_csrf, :secret=>'c'*64,
        :secret_cookie=>{:name=>'csrf_nonce', :cookie_options=>{:path=>'/login', :same_site=>:strict}}
      route do |r|
        r.get('token'){csrf_tag('/login')}
      end
    end

    res, = perform('/token')
    cookie = Array(res[1][RodaResponseHeaders::SET_COOKIE])[0]
    cookie.must_match(/\Acsrf_nonce=/)
    cookie.must_match(/; path=\/login/)
    cookie.must_match(/; samesite=strict/)
  end

  it "requires a strong :secret when :secret_cookie is used" do
    proc do
      app(:bare) do
        plugin :route_csrf, :secret_cookie=>true
      end
    end.must_raise Roda::RodaError

    proc do
      app(:bare) do
        plugin :route_csrf, :secret=>'short', :secret_cookie=>true
      end
    end.must_raise Roda::RodaError
  end

  it "treats a plugin block returning true or false as :sessions and :none" do
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64 do
        path_info != '/public'
      end
      route do |r|
        r.get('public'){"#{session_mode}:#{use_sessions?}:#{use_csrf?}"}
        r.get('page'){"#{session_mode}:#{use_sessions?}:#{use_csrf?}"}
      end
    end

    body('/public').must_equal 'none:false:false'
    body('/page').must_equal 'sessions:true:true'
  end

  it "allows sessions for all requests when loaded without a block" do
    app(:bare) do
      plugin :conditional_sessions, :secret=>'1'*64
      route do |r|
        r.get('page'){"#{session_mode}:#{use_sessions?}:#{use_csrf?}"}
      end
    end

    body('/page').must_equal 'sessions:true:true'
  end
end

# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/recursive'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/urlmap'
  require_relative '../lib/rack/request'
end

describe Rack::Recursive do
  before do
  @app1 = lambda { |env|
    res = Rack::Response.new
    res["x-path-info"] = env["PATH_INFO"]
    res["x-query-string"] = env["QUERY_STRING"]
    res.finish do |inner_res|
      inner_res.write "App1"
    end
  }

  @app2 = lambda { |env|
    Rack::Response.new.finish do |res|
      res.write "App2"
      _, _, body = env['rack.recursive.include'].call(env, "/app1")
      body.each { |b|
        res.write b
      }
    end
  }

  @app3 = lambda { |env|
    raise Rack::ForwardRequest.new("/app1")
  }

  @app4 = lambda { |env|
    raise Rack::ForwardRequest.new("http://example.org/app1/quux?meh")
  }
  end

  def recursive(map)
    Rack::Lint.new Rack::Recursive.new(Rack::URLMap.new(map))
  end

  it "allow for subrequests" do
    res = Rack::MockRequest.new(recursive("/app1" => @app1,
                                          "/app2" => @app2)).
      get("/app2")

    res.must_be :ok?
    res.body.must_equal "App2App1"
  end

  it "raise error on requests not below the app" do
    app = Rack::URLMap.new("/app1" => @app1,
                           "/app" => recursive("/1" => @app1,
                                               "/2" => @app2))

    lambda {
      Rack::MockRequest.new(app).get("/app/2")
    }.must_raise(ArgumentError).
      message.must_match(/can only include below/)
  end

  it "support forwarding" do
    app = recursive("/app1" => @app1,
                    "/app3" => @app3,
                    "/app4" => @app4)

    res = Rack::MockRequest.new(app).get("/app3")
    res.must_be :ok?
    res.body.must_equal "App1"

    res = Rack::MockRequest.new(app).get("/app4")
    res.must_be :ok?
    res.body.must_equal "App1"
    res["x-path-info"].must_equal "/quux"
    res["x-query-string"].must_equal "meh"
  end
end

describe Rack::InternalPolicy do
  it "rejects allowed paths that do not start with a slash" do
    lambda {
      Rack::InternalPolicy.new(allowed_paths: ["internal"])
    }.must_raise ArgumentError
  end

  it "treats a nil allowed_paths as allowing every internal path" do
    policy = Rack::InternalPolicy.new

    policy.allows_path?("/anything/here").must_equal true
    policy.allows_path?("relative").must_equal false
  end

  it "only matches whole path prefixes, never sibling prefixes" do
    policy = Rack::InternalPolicy.new(allowed_paths: ["/internal"])

    policy.allows_path?("/internal").must_equal true
    policy.allows_path?("/internal/open").must_equal true
    policy.allows_path?("/internal-secret").must_equal false
  end

  it "propagates only the named identity facts" do
    env = {
      "rack.internal.identity.role" => "admin",
      "rack.internal.identity.org" => "acme",
      "HTTP_AUTHORIZATION" => "Bearer token"
    }
    policy = Rack::InternalPolicy.new(
      identity_facts: ["rack.internal.identity.role"])

    propagated = policy.propagate_identity(env)

    propagated.must_equal "rack.internal.identity.role" => "admin"
    policy.allows_identity?("rack.internal.identity.org").must_equal false
  end

  it "does not synthesize identity facts absent from the outer request" do
    policy = Rack::InternalPolicy.new(
      identity_facts: ["rack.internal.identity.role"])

    policy.propagate_identity({}).must_equal({})
  end

  it "rejects identity fact keys that do not name an env key" do
    lambda {
      Rack::InternalPolicy.new(identity_facts: ["role"])
    }.must_raise ArgumentError
  end
end

describe Rack::Recursive, "internal forwarding policy" do
  IDENTITY_ROLE = "rack.internal.identity.role"

  before do
    # Two internal pages with different permissions. The open page is
    # reachable by every permitted subrequest; the secret page requires
    # an explicit verified role fact and stays outside the include scope.
    @open_page = lambda { |env|
      request = Rack::Request.new(env)
      [200, {"content-type" => "text/plain"}, [
        "open " \
        "path=#{request.path_info} " \
        "get=#{request.GET.inspect} " \
        "post=#{request.POST.inspect} " \
        "auth=#{env['HTTP_AUTHORIZATION'].inspect} " \
        "cookie=#{request.cookies.inspect} " \
        "role=#{env[IDENTITY_ROLE].inspect}"
      ]]
    }

    @secret_page = lambda { |env|
      request = Rack::Request.new(env)
      [200, {"content-type" => "text/plain"}, [
        "secret role=#{env[IDENTITY_ROLE].inspect} get=#{request.GET.inspect}"
      ]]
    }

    # Raises a ForwardRequest towards the open page.
    @forwarding_page = lambda { |env|
      raise Rack::ForwardRequest.new("/internal/open?forwarded=yes", env)
    }

    # Nested hop: forwards to the forwarding page, which forwards again.
    @nested_page = lambda { |env|
      raise Rack::ForwardRequest.new("/internal/forwarding", env)
    }

    # Mutates the subrequest env and then raises, used to prove that
    # exception exits cannot leak changes into the outer request.
    @exploding_page = lambda { |env|
      env["HTTP_X_MUTATED"] = "inside"
      env[IDENTITY_ROLE] = "forged"
      env["PATH_INFO"] = "/hijacked"
      raise "subrequest failed"
    }

    @entry_page = lambda { |env|
      request = Rack::Request.new(env)
      outer_before = [request.GET.dup, request.POST.dup, request.cookies.dup]
      include_call = env["rack.recursive.include"]

      parts = ["outer-before=#{outer_before.inspect}"]

      status, _, body = include_call.call(env, "/internal/open?included=1")
      body.each { |chunk| parts << chunk }

      begin
        include_call.call(env, "/internal/secret")
        parts << "secret-allowed"
      rescue Rack::ForwardingDenied
        parts << "secret-denied=Rack::ForwardingDenied"
      end

      # Re-reading the outer request must still expose the outer
      # request's own parsed parameters, never the subrequest's data.
      outer_request = Rack::Request.new(env)
      parts << "outer-after-get=#{outer_request.GET.inspect}"
      parts << "outer-after-post=#{outer_request.POST.inspect}"
      parts << "outer-after-cookies=#{outer_request.cookies.inspect}"
      parts << "outer-auth=#{env['HTTP_AUTHORIZATION'].inspect}"
      parts << "outer-role=#{env[IDENTITY_ROLE].inspect}"

      [status, {"content-type" => "text/plain"}, [parts.join(" | ")]]
    }

    @exception_page = lambda { |env|
      snapshot = [env[IDENTITY_ROLE], env["PATH_INFO"], env["HTTP_X_MUTATED"]]
      begin
        env["rack.recursive.include"].call(env, "/internal/exploding")
      rescue RuntimeError
      end
      after = [env[IDENTITY_ROLE], env["PATH_INFO"], env["HTTP_X_MUTATED"]]
      [200, {"content-type" => "text/plain"},
        ["snapshot=#{snapshot.inspect} after=#{after.inspect}"]]
    }
  end

  def build_app(policy, map)
    Rack::Lint.new(Rack::Recursive.new(Rack::URLMap.new(map), policy))
  end

  def policy(allowed: ["/internal/open", "/internal/forwarding",
                      "/internal/nested", "/internal/exploding"],
             facts: [IDENTITY_ROLE])
    Rack::InternalPolicy.new(allowed_paths: allowed, identity_facts: facts)
  end

  def full_map
    {
      "/entry" => @entry_page,
      "/exception" => @exception_page,
      "/internal/open" => @open_page,
      "/internal/secret" => @secret_page,
      "/internal/forwarding" => @forwarding_page,
      "/internal/nested" => @nested_page,
      "/internal/exploding" => @exploding_page
    }
  end

  it "isolates include parameters and denies borrowing them for a forbidden page" do
    app = build_app(policy, full_map)
    res = Rack::MockRequest.new(app).post(
      "/entry?outer=1",
      input: "bodyparam=2",
      "HTTP_AUTHORIZATION" => "Bearer outer-secret",
      "HTTP_COOKIE" => "session=outer-session",
      IDENTITY_ROLE => "admin"
    )

    res.must_be :ok?
    body = res.body

    # The included page parses its own query string, not the outer one,
    # and starts from an empty request body.
    body.must_include 'get={"included" => "1"}'
    body.must_include "post={}"

    # Credentials and the outer cookie never cross the internal boundary.
    body.must_include "auth=nil"
    body.must_include "cookie={}"

    # Explicitly allowed verified identity facts do propagate.
    body.must_include 'role="admin"'

    # The second internal page is outside the policy scope: it must not
    # be reachable by reusing the include entry point.
    body.must_include "secret-denied=Rack::ForwardingDenied"

    # The outer request keeps its own parsed data after the subrequests.
    body.must_include 'outer-after-get={"outer" => "1"}'
    body.must_include 'outer-after-post={"bodyparam" => "2"}'
    body.must_include 'outer-after-cookies={"session" => "outer-session"}'
    body.must_include 'outer-auth="Bearer outer-secret"'
    body.must_include 'outer-role="admin"'
  end

  it "strips caches so a changed query string or body is re-parsed" do
    poison_page = lambda { |env|
      # Force the outer request to memoize parsed data before including.
      request = Rack::Request.new(env)
      request.GET
      request.POST
      request.cookies

      status, _, body = env["rack.recursive.include"].call(
        env, "/internal/open?fresh=yes")
      result = +""
      body.each { |chunk| result << chunk }
      [status, {"content-type" => "text/plain"}, [result]]
    }

    app = build_app(
      Rack::InternalPolicy.new(allowed_paths: ["/internal/open"]),
      "/poison" => poison_page, "/internal/open" => @open_page)

    res = Rack::MockRequest.new(app).post(
      "/poison?stale=1",
      input: "stalebody=1",
      "HTTP_COOKIE" => "stalecookie=1")

    res.must_be :ok?
    res.body.must_include 'get={"fresh" => "yes"}'
    res.body.must_include "post={}"
    res.body.must_include "cookie={}"
  end

  it "applies the policy to ForwardRequest without inheriting credentials or caches" do
    app = build_app(policy, full_map)
    res = Rack::MockRequest.new(app).post(
      "/internal/forwarding?outer=1",
      input: "bodyparam=2",
      "HTTP_AUTHORIZATION" => "Bearer outer-secret",
      "HTTP_COOKIE" => "session=outer-session",
      IDENTITY_ROLE => "admin")

    res.must_be :ok?
    # The new query string is re-parsed rather than borrowed from the
    # outer request's cached GET hash.
    res.body.must_include 'get={"forwarded" => "yes"}'
    # The body is re-read from the subrequest's own rack.input.
    res.body.must_include 'post={"bodyparam" => "2"}'
    res.body.must_include "auth=nil"
    res.body.must_include "cookie={}"
    res.body.must_include 'role="admin"'
  end

  it "re-parses a forwarded query string even when the outer request cached GET" do
    caching_page = lambda { |env|
      request = Rack::Request.new(env)
      request.GET
      request.POST
      raise Rack::ForwardRequest.new("/internal/open?fresh=yes", env)
    }

    app = build_app(
      Rack::InternalPolicy.new(allowed_paths: ["/internal/open"]),
      "/caching" => caching_page, "/internal/open" => @open_page)

    res = Rack::MockRequest.new(app).post(
      "/caching?stale=1", input: "bodyparam=2",
      "HTTP_COOKIE" => "stalecookie=1")

    res.must_be :ok?
    # The fresh query string is re-parsed; the outer cached GET hash
    # ("stale") is never reused by the subrequest.
    res.body.must_include 'get={"fresh" => "yes"}'
    res.body.must_include "cookie={}"
  end

  it "re-applies the policy across nested forwarding" do
    app = build_app(policy, full_map)
    res = Rack::MockRequest.new(app).get(
      "/internal/nested",
      "HTTP_AUTHORIZATION" => "Bearer outer-secret",
      IDENTITY_ROLE => "admin")

    res.must_be :ok?
    res.body.must_include 'get={"forwarded" => "yes"}'
    res.body.must_include "auth=nil"
    res.body.must_include 'role="admin"'
  end

  it "denies a nested hop that escapes the allowed target scope" do
    escape_page = lambda { |env|
      raise Rack::ForwardRequest.new("/internal/secret", env)
    }
    app = build_app(
      policy(allowed: ["/internal/entry", "/internal/escape"]),
      "/internal/entry" => lambda { |env|
        raise Rack::ForwardRequest.new("/internal/escape", env)
      },
      "/internal/escape" => escape_page,
      "/internal/secret" => @secret_page)

    lambda {
      Rack::MockRequest.new(app).get("/internal/entry")
    }.must_raise Rack::ForwardingDenied
  end

  it "keeps the outer env untouched when a subrequest exits by raising" do
    app = build_app(policy, full_map)
    res = Rack::MockRequest.new(app).get(
      "/exception", IDENTITY_ROLE => "admin")

    res.must_be :ok?
    res.body.must_equal(
      'snapshot=["admin", "", nil] after=["admin", "", nil]')
  end

  it "drops identity facts outside the allowlist, including client-forged ones" do
    app = build_app(policy(facts: []), full_map)

    res = Rack::MockRequest.new(app).post(
      "/entry?outer=1",
      input: "bodyparam=2",
      IDENTITY_ROLE => "forged")

    res.must_be :ok?
    res.body.must_include "role=nil"
    res.body.must_include 'outer-role="forged"'
  end

  it "can explicitly allow a credential header as a verified identity fact" do
    app = build_app(policy(facts: ["HTTP_AUTHORIZATION"]), full_map)

    res = Rack::MockRequest.new(app).get(
      "/entry", "HTTP_AUTHORIZATION" => "Bearer verified")

    res.must_be :ok?
    res.body.must_include 'auth="Bearer verified"'
  end

  it "ignores credentials and identity facts smuggled through a ForwardRequest env" do
    open_sink = lambda { |env|
      [200, {"content-type" => "text/plain"}, [
        "auth=#{env['HTTP_AUTHORIZATION'].inspect} " \
        "api=#{env['HTTP_X_API_KEY'].inspect} " \
        "role=#{env[IDENTITY_ROLE].inspect}"
      ]]
    }
    smuggler = lambda { |env|
      forged = env.merge(
        "HTTP_AUTHORIZATION" => "Bearer smuggled",
        "HTTP_X_API_KEY" => "stolen-key",
        IDENTITY_ROLE => "superadmin")
      raise Rack::ForwardRequest.new("/internal/open", forged)
    }

    app = build_app(
      policy(allowed: ["/internal/open"]),
      "/go" => smuggler, "/internal/open" => open_sink)

    res = Rack::MockRequest.new(app).get(
      "/go", IDENTITY_ROLE => "member", "HTTP_X_API_KEY" => "outer-key")

    res.must_be :ok?
    res.body.must_include "auth=nil"
    res.body.must_include "api=nil"
    # The verified outer fact survives; the forged escalation does not.
    res.body.must_include 'role="member"'
  end

  it "accepts policy options as keyword arguments without a policy object" do
    app = Rack::Lint.new(Rack::Recursive.new(
      Rack::URLMap.new(full_map),
      allowed_paths: ["/internal/open", "/internal/forwarding",
                      "/internal/nested", "/internal/exploding"],
      identity_facts: [IDENTITY_ROLE]))

    res = Rack::MockRequest.new(app).get("/entry", IDENTITY_ROLE => "admin")
    res.must_be :ok?
    res.body.must_include "secret-denied=Rack::ForwardingDenied"
    res.body.must_include 'role="admin"'
  end
end

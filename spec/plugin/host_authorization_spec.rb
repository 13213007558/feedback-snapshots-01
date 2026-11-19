require_relative "../spec_helper"
require "rack/builder"

describe "host_authorization plugin" do 
  it "allows configuring authorized hosts" do
    app do |r|
      r.get 'x' do
        '2'
      end
      check_host_authorization!
      '1'
    end
    app.plugin :host_authorization, 'foo.example.com'

    status.must_equal 403
    body.must_equal ''
    status('/x').must_equal 200
    body('/x').must_equal '2'
    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com').must_equal 403
    status('HTTP_HOST'=>'foo.example.com:80').must_equal 200
    status('HTTP_HOST'=>'bar.example.com:80').must_equal 403

    app.plugin :host_authorization, /\A(foo|bar)\.example\.com\z/
    status.must_equal 403
    body.must_equal ''
    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com').must_equal 403

    app.plugin :host_authorization, %w'foo.example.com bar.example.com'
    status.must_equal 403
    body.must_equal ''
    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com').must_equal 403

    app.plugin :host_authorization, %w'foo.example.com bar.example.com'
    status.must_equal 403
    body.must_equal ''
    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com').must_equal 403

    status('HTTP_HOST'=>'foo.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com').must_equal 403

    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'bar.example.com').must_equal 403
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com, bar.example.com').must_equal 403
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'bar.example.com, x.example.com').must_equal 403
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com, bar.example.com:80').must_equal 403

    app.plugin :host_authorization, %w'foo.example.com bar.example.com', :check_forwarded=>true
    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com').must_equal 403

    status('HTTP_HOST'=>'foo.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com').must_equal 403

    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'bar.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com, bar.example.com').must_equal 200
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'bar.example.com, x.example.com').must_equal 403
    status('HTTP_HOST'=>'baz.example.com', 'HTTP_X_FORWARDED_HOST'=>'x.example.com, bar.example.com:80').must_equal 200

    app.plugin :host_authorization, 'foo.example.com' do |r|
      response.status = 401
      '2'
    end

    status.must_equal 401
    body.must_equal '2'
    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'bar.example.com').must_equal 401
    status('HTTP_HOST'=>'foo.example.com:80').must_equal 200
    status('HTTP_HOST'=>'bar.example.com:80').must_equal 401
  end

  it "supports wildcard strings for authorized hosts" do
    app do |r|
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, '*.example.com'

    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'foo.bar.example.com').must_equal 200
    status('HTTP_HOST'=>'foo.example.com:80').must_equal 200
    status('HTTP_HOST'=>'example.com').must_equal 403
    status('HTTP_HOST'=>'foo.example.org').must_equal 403
    status('HTTP_HOST'=>'fooexample.com.evil.example').must_equal 403
    status('HTTP_HOST'=>'foo.example.com.evil.example').must_equal 403

    app.plugin :host_authorization, %w'www.example.com ?oo.example.org'
    status('HTTP_HOST'=>'www.example.com').must_equal 200
    status('HTTP_HOST'=>'foo.example.org').must_equal 200
    status('HTTP_HOST'=>'fooo.example.org').must_equal 403
    status('HTTP_HOST'=>'www.example.org').must_equal 403
    status('HTTP_HOST'=>'FOO.example.org').must_equal 403
  end

  it "treats wildcard characters in deferred and rejected hosts consistently" do
    app do |r|
      check_host_authorization!
      'ok'
    end

    app.plugin :host_authorization, '*.example.com',
      defer_hosts: '*.internal.example.com',
      reject_hosts: ['admin.example.com', '*.deny.example.com']

    status('HTTP_HOST'=>'www.example.com').must_equal 200
    status('HTTP_HOST'=>'admin.example.com').must_equal 403
    status('HTTP_HOST'=>'x.deny.example.com').must_equal 403
    status('HTTP_HOST'=>'api.internal.example.com').must_equal 200
    status('HTTP_HOST'=>'api.internal.example.org').must_equal 403
  end

  it "defers configured hosts without modifying the request environment" do
    env = nil
    app do |r|
      env = r.env
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, '*.example.com', defer_hosts: '*.internal.example.com'

    body('HTTP_HOST'=>'api.internal.example.com').must_equal 'ok'
    env.keys.grep(/host_authorization/).must_be_empty
    env.keys.grep(/roda\./).must_be_empty
  end

  it "calls the on_reject handler with the rejected host and request environment" do
    rejected = []
    env = nil
    app do |r|
      env = r.env
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, 'foo.example.com',
      on_reject: proc{|host, request_env| rejected << [host, request_env]}

    status('HTTP_HOST'=>'bar.example.com:8080').must_equal 403
    rejected.length.must_equal 1
    rejected[0][0].must_equal 'bar.example.com'
    rejected[0][1].must_be_same_as env
    env.keys.grep(/host_authorization/).must_be_empty

    rejected.clear
    status('HTTP_HOST'=>'foo.example.com').must_equal 200
    rejected.must_be_empty

    rejected.clear
    status('HTTP_HOST'=>'bar.example.com').must_equal 403
    rejected.length.must_equal 1
    rejected[0][0].must_equal 'bar.example.com'
  end

  it "does not call the on_reject handler for deferred hosts" do
    rejected = []
    app do |r|
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, '*.example.com',
      defer_hosts: '*.internal.example.com',
      on_reject: proc{|host, _| rejected << host}

    body('HTTP_HOST'=>'api.internal.example.com').must_equal 'ok'
    rejected.must_be_empty
  end

  it "rejects hosts in reject_hosts even when they match authorized or deferred hosts" do
    rejected = []
    app do |r|
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, '*.example.com',
      defer_hosts: '*.internal.example.com',
      reject_hosts: 'admin.example.com',
      on_reject: proc{|host, _| rejected << host}

    status('HTTP_HOST'=>'admin.example.com').must_equal 403
    rejected.must_equal ['admin.example.com']

    rejected.clear
    app.plugin :host_authorization, '*.example.com',
      defer_hosts: 'admin.example.com',
      reject_hosts: 'admin.example.com',
      on_reject: proc{|host, _| rejected << host}
    status('HTTP_HOST'=>'admin.example.com').must_equal 403
    rejected.must_equal ['admin.example.com']
  end

  it "checks forwarded hosts unless they are rejected" do
    app do |r|
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, 'foo.example.com',
      reject_hosts: 'deny.example.com',
      check_forwarded: true

    status('HTTP_HOST'=>'bad.example.com', 'HTTP_X_FORWARDED_HOST'=>'foo.example.com').must_equal 200
    status('HTTP_HOST'=>'bad.example.com', 'HTTP_X_FORWARDED_HOST'=>'deny.example.com').must_equal 403
    status('HTTP_HOST'=>'foo.example.com', 'HTTP_X_FORWARDED_HOST'=>'deny.example.com').must_equal 200
  end

  it "allows configuring host policy without an authorized host" do
    app do |r|
      check_host_authorization!
      'ok'
    end
    app.plugin :host_authorization, defer_hosts: 'pass.example.com', reject_hosts: 'deny.example.com'

    status('HTTP_HOST'=>'pass.example.com').must_equal 200
    status('HTTP_HOST'=>'deny.example.com').must_equal 403
    status('HTTP_HOST'=>'other.example.com').must_equal 403
  end

  it "raises an error if on_reject is not callable" do
    proc do
      app(:bare){plugin :host_authorization, 'foo.example.com', on_reject: 'not callable'}
    end.must_raise Roda::RodaError
  end

  it "assigns host policy ownership when two apps are mounted in a rack stack" do
    backend_calls = []
    frontend_rejections = []

    backend = app(:bare) do
      plugin :host_authorization, 'backend.example.com',
        on_reject: proc{|host, env| backend_calls << [:backend_reject, host, env]}

      route do |r|
        check_host_authorization!
        backend_calls << [:backend, r.host, r.env]
        "backend:#{r.host}"
      end
    end

    frontend = app(:bare) do
      plugin :middleware
      plugin :host_authorization, 'frontend.example.com',
        defer_hosts: ['backend.example.com', '*.other.org'],
        reject_hosts: 'blocked.example.com',
        on_reject: proc{|host, env| frontend_rejections << [host, env]}

      route do |r|
        check_host_authorization!

        r.get 'front' do
          "frontend:#{r.host}"
        end
      end
    end

    rack_app = Rack::Builder.new do
      use frontend
      run backend
    end.to_app

    call = lambda do |path, host|
      env = req_env('PATH_INFO'=>path, 'HTTP_HOST'=>host)
      res = rack_app.call(env)
      body = String.new
      res[2].each{|part| body << part}
      res[2].close if res[2].respond_to?(:close)
      [env, [res[0], res[1], body]]
    end

    env, res = call.call('/front', 'frontend.example.com')
    res[0].must_equal 200
    res[2].must_equal 'frontend:frontend.example.com'
    backend_calls.must_be_empty
    frontend_rejections.must_be_empty

    backend_calls.clear
    env, res = call.call('/anything', 'backend.example.com:8080')
    res[0].must_equal 200
    res[2].must_equal 'backend:backend.example.com'
    backend_calls.length.must_equal 1
    backend_calls[0][0].must_equal :backend
    backend_calls[0][1].must_equal 'backend.example.com'
    backend_calls[0][2].must_be_same_as env
    env['HTTP_HOST'].must_equal 'backend.example.com:8080'
    env['PATH_INFO'].must_equal '/anything'
    env['SCRIPT_NAME'].must_equal ''
    env.key?('roda.forward_next').must_equal false
    frontend_rejections.must_be_empty
    env.keys.grep(/host_authorization/).must_be_empty

    backend_calls.clear
    env, res = call.call('/front', 'blocked.example.com')
    res[0].must_equal 403
    res[2].must_equal ''
    backend_calls.must_be_empty
    frontend_rejections.length.must_equal 1
    frontend_rejections[0][0].must_equal 'blocked.example.com'
    frontend_rejections[0][1].must_be_same_as env
    env.keys.grep(/host_authorization/).must_be_empty
    env.key?('roda.forward_next').must_equal false
    env['HTTP_HOST'].must_equal 'blocked.example.com'
    env['PATH_INFO'].must_equal '/front'

    frontend_rejections.clear
    backend_calls.clear
    env, res = call.call('/anything', 'foo.other.org')
    res[0].must_equal 403
    res[2].must_equal ''
    backend_calls.length.must_equal 1
    backend_calls[0][0].must_equal :backend_reject
    backend_calls[0][1].must_equal 'foo.other.org'
    frontend_rejections.must_be_empty
    env.keys.grep(/host_authorization/).must_be_empty
    env.key?('roda.forward_next').must_equal false

    frontend_rejections.clear
    backend_calls.clear
    env, res = call.call('/anything', 'unlisted.example.org')
    res[0].must_equal 403
    res[2].must_equal ''
    backend_calls.must_be_empty
    frontend_rejections.length.must_equal 1
    frontend_rejections[0][0].must_equal 'unlisted.example.org'
    frontend_rejections[0][1].must_be_same_as env
    env.keys.grep(/host_authorization/).must_be_empty
    env.key?('roda.forward_next').must_equal false

    frontend_rejections.clear
    backend_calls.clear
    env, res = call.call('/anything', 'other.example.org')
    res[0].must_equal 403
    res[2].must_equal ''
    backend_calls.must_be_empty
    frontend_rejections.length.must_equal 1
    frontend_rejections[0][0].must_equal 'other.example.org'
    frontend_rejections[0][1].must_be_same_as env
    env.keys.grep(/host_authorization/).must_be_empty
    env.key?('roda.forward_next').must_equal false
  end
end

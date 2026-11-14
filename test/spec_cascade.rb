# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/cascade'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/rewindable_input'
  require_relative '../lib/rack/urlmap'
  require_relative '../lib/rack/files'
end

describe Rack::Cascade do
  def cascade(*args)
    Rack::Lint.new Rack::Cascade.new(*args)
  end

  docroot = File.expand_path(File.dirname(__FILE__))
  app1 = Rack::Files.new(docroot)

  app2 = Rack::URLMap.new("/crash" => lambda { |env| raise "boom" })

  app3 = Rack::URLMap.new("/foo" => lambda { |env|
                            [200, { "content-type" => "text/plain" }, [""]]})

  it "dispatch onward on 404 and 405 by default" do
    cascade = cascade([app1, app2, app3])
    Rack::MockRequest.new(cascade).get("/cgi/test").must_be :ok?
    Rack::MockRequest.new(cascade).get("/foo").must_be :ok?
    Rack::MockRequest.new(cascade).get("/toobad").must_be :not_found?
    Rack::MockRequest.new(cascade).get("/cgi/../..").must_be :client_error?

    # Put is not allowed by Rack::Files so it'll 405.
    Rack::MockRequest.new(cascade).put("/foo").must_be :ok?
  end

  it "dispatch onward on whatever is passed" do
    cascade = cascade([app1, app2, app3], [404, 403])
    Rack::MockRequest.new(cascade).get("/cgi/../bla").must_be :not_found?
  end

  it "include? returns whether app is included" do
    cascade = Rack::Cascade.new([app1, app2])
    cascade.include?(app1).must_equal true
    cascade.include?(app2).must_equal true
    cascade.include?(app3).must_equal false
  end

  it "return 404 if empty" do
    Rack::MockRequest.new(cascade([])).get('/').must_be :not_found?
  end

  it "uses new response object if empty" do
    app = Rack::Cascade.new([])
    res = app.call('/')
    s, h, body = res
    s.must_equal 404
    h['content-type'].must_equal 'text/plain'
    body.must_be_empty

    res[0] = 200
    h['content-type'] = 'text/html'
    body << "a"

    res = app.call('/')
    s, h, body = res
    s.must_equal 404
    h['content-type'].must_equal 'text/plain'
    body.must_be_empty
  end

  it "returns final response if all responses are cascaded" do
   app = Rack::Cascade.new([])
   app << lambda { |env| [405, {}, []] }
   app.call({})[0].must_equal 405
  end

  it "append new app" do
    cascade = Rack::Cascade.new([], [404, 403])
    Rack::MockRequest.new(cascade).get('/').must_be :not_found?
    cascade << app2
    Rack::MockRequest.new(cascade).get('/cgi/test').must_be :not_found?
    Rack::MockRequest.new(cascade).get('/cgi/../bla').must_be :not_found?
    cascade << app1
    Rack::MockRequest.new(cascade).get('/cgi/test').must_be :ok?
    Rack::MockRequest.new(cascade).get('/cgi/../..').must_be :client_error?
    Rack::MockRequest.new(cascade).get('/foo').must_be :not_found?
    cascade << app3
    Rack::MockRequest.new(cascade).get('/foo').must_be :ok?
  end

  it "close the body on cascade" do
    body = StringIO.new
    closer = lambda { |env| [404, {}, body] }
    cascade = Rack::Cascade.new([closer, app3], [404])
    Rack::MockRequest.new(cascade).get("/foo").must_be :ok?
    body.must_be :closed?
  end

  describe "with isolate: true" do
    def isolated_cascade(apps, cascade_for = [404, 405])
      Rack::Lint.new Rack::Cascade.new(apps, cascade_for, isolate: true)
    end

    # A raw cascade without Lint, for tests that drive the env and bodies
    # directly so they can assert on stream/body lifecycle that Lint or
    # MockRequest would otherwise close.
    def raw_isolated_cascade(apps, cascade_for = [404])
      Rack::Cascade.new(apps, cascade_for, isolate: true)
    end

    it "does not leak REMOTE_USER set by a rejecting app into the next app" do
      seen = nil
      # Candidate one "authenticates" a privileged user then rejects.
      attacker = lambda do |env|
        env['REMOTE_USER'] = 'admin'
        [404, {}, ['not here']]
      end
      # Candidate two must observe the pre-cascade environment, not admin.
      victim = lambda do |env|
        seen = env['REMOTE_USER']
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      cascade = isolated_cascade([attacker, victim])
      res = Rack::MockRequest.new(cascade).get("/foo", 'REMOTE_USER' => 'guest')
      res.must_be :ok?
      seen.must_equal 'guest'
    end

    it "restores the original env after every rejecting application" do
      attacker = lambda do |env|
        env['REMOTE_USER'] = 'admin'
        env['PATH_INFO'] = '/taken-over'
        env['INJECTED_KEY'] = 'stowaway'
        [404, {}, []]
      end
      observed = nil
      victim = lambda do |env|
        observed = env.dup
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      cascade = isolated_cascade([attacker, victim])
      Rack::MockRequest.new(cascade).get("/foo", 'REMOTE_USER' => 'guest')

      observed['REMOTE_USER'].must_equal 'guest'
      observed['PATH_INFO'].must_equal '/foo'
      observed.key?('INJECTED_KEY').must_equal false
    end

    it "does not share mutable parameter caches between applications" do
      # A shallow env.dup would still share this nested hash.
      attacker = lambda do |env|
        env['rack.request.query_hash'] ||= {}
        env['rack.request.query_hash']['role'] = 'admin'
        env['rack.request.query_hash']['nested'] = { 'priv' => true }
        [404, {}, []]
      end
      seen = nil
      victim = lambda do |env|
        seen = env['rack.request.query_hash']
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      cascade = isolated_cascade([attacker, victim])
      Rack::MockRequest.new(cascade).get("/foo")

      seen.must_be_nil

      # And the caller-owned env must not have been mutated either.
      env = Rack::MockRequest.env_for("/foo")
      raw_isolated_cascade([attacker, victim]).call(env)
      env.key?('rack.request.query_hash').must_equal false
    end

    it "keeps nested hashes independent even when the key pre-existed" do
      attacker = lambda do |env|
        env['rack.request.cookie_hash']['poison'] = 'yes'
        [404, {}, []]
      end
      seen = nil
      victim = lambda do |env|
        seen = env['rack.request.cookie_hash'].dup
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      cascade = isolated_cascade([attacker, victim])
      Rack::MockRequest.new(cascade).get("/foo",
        'rack.request.cookie_hash' => { 'keep' => 'me' })

      seen.must_equal('keep' => 'me')
      seen.key?('poison').must_equal false
    end

    it "commits the accepting application's env back onto the shared env" do
      winner = lambda do |env|
        env['REMOTE_USER'] = 'authenticated'
        env['rack.request.query_hash'] = { 'q' => '1' }
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      env = Rack::MockRequest.env_for("/foo")
      raw_isolated_cascade([winner]).call(env)

      env['REMOTE_USER'].must_equal 'authenticated'
      env['rack.request.query_hash'].must_equal('q' => '1')
    end

    it "rewinds the consumed request body so the next app can read it" do
      consumed = nil
      # Read the whole body, then reject.
      reader = lambda do |env|
        consumed = env['rack.input'].read
        [404, {}, []]
      end
      second_read = nil
      victim = lambda do |env|
        second_read = env['rack.input'].read
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      env = Rack::MockRequest.env_for(
        "/foo", method: 'POST', input: 'payload-bytes'
      )
      env['rack.input'] = Rack::RewindableInput.new(env['rack.input'])

      status, = raw_isolated_cascade([reader, victim]).call(env)

      status.must_equal 200
      consumed.must_equal 'payload-bytes'
      second_read.must_equal 'payload-bytes'
    end

    it "does not blow up when the input stream is not rewindable" do
      # A minimal SPEC input stream exposing only gets/each/read (no rewind).
      plain = Object.new
      payload = 'abc'.dup
      plain.define_singleton_method(:read) { |*| payload.slice!(0..) || '' }
      plain.define_singleton_method(:gets) { nil }
      plain.define_singleton_method(:each) { |&block| block.call(payload) }

      rejecter = lambda { |env| env['rack.input'].read; [404, {}, []] }
      winner = lambda do |env|
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      env = Rack::MockRequest.env_for("/foo")
      env['rack.input'] = plain
      status, = raw_isolated_cascade([rejecter, winner]).call(env)
      status.must_equal 200
    end

    it "closes the rejecting body and leaves the final body for the server" do
      # Track close calls explicitly: the cascade must close a rejected body
      # when it discards the response, but the winning body is handed to the
      # server and must not be closed by the cascade.
      rejected_body = Object.new
      rejected_closed = false
      rejected_body.define_singleton_method(:close) { rejected_closed = true }
      rejected_body.define_singleton_method(:each) do |&block|
        block.call("dropped")
      end

      final_body = Object.new
      final_closed = false
      final_body.define_singleton_method(:close) { final_closed = true }
      final_body.define_singleton_method(:each) do |&block|
        block.call("kept")
      end

      rejecter = lambda { |env| [404, {}, rejected_body] }
      winner = lambda do |env|
        [200, { 'content-type' => 'text/plain' }, final_body]
      end

      status, _headers, body =
        raw_isolated_cascade([rejecter, winner]).
          call(Rack::MockRequest.env_for("/foo"))

      status.must_equal 200
      rejected_closed.must_equal true
      final_closed.must_equal false
      body.must_equal final_body
    end

    it "reaps tempfiles created by a rejecting application" do
      original = Tempfile.new("original")
      created = Tempfile.new("created")
      created_path = created.path

      rejecter = lambda do |env|
        env['rack.tempfiles'] << created
        [404, {}, []]
      end
      seen_tempfiles = nil
      winner = lambda do |env|
        seen_tempfiles = env['rack.tempfiles'].dup
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      env = Rack::MockRequest.env_for("/foo", 'rack.tempfiles' => [original])
      raw_isolated_cascade([rejecter, winner]).call(env)

      created.must_be :closed?
      File.exist?(created_path).must_equal false
      seen_tempfiles.must_equal [original]
      original.wont_be :closed?
      original.close!
    end

    it "stops a rejecting app from establishing auth facts for the next app" do
      # End-to-end version of the threat: the first app writes an identity,
      # mutates parameter/session caches, registers a tempfile and consumes
      # the body, then rejects.  The successor must start from a clean slate
      # and the rejected resources must be reclaimed.
      leaked_tempfile = Tempfile.new("leak")
      leaked_path = leaked_tempfile.path
      rejected_body = Object.new
      rejected_closed = false
      rejected_body.define_singleton_method(:close) { rejected_closed = true }
      rejected_body.define_singleton_method(:each) { |&block| block.call("x") }

      attacker = lambda do |env|
        env['REMOTE_USER'] = 'root'
        env['rack.request.query_hash'] = { 'escalated' => true }
        env['rack.session'] = { 'user' => 'root' }
        env['rack.tempfiles'] << leaked_tempfile
        env['rack.input'].read
        [404, {}, rejected_body]
      end

      successor_view = nil
      successor = lambda do |env|
        successor_view = {
          remote_user: env['REMOTE_USER'],
          query_hash: env['rack.request.query_hash'],
          session: env['rack.session'],
          tempfiles: env['rack.tempfiles'].dup,
        }
        [200, { 'content-type' => 'text/plain' }, ['granted-to-guest']]
      end

      env = Rack::MockRequest.env_for(
        "/foo", method: 'POST', input: 'body',
        'REMOTE_USER' => 'guest', 'rack.session' => { 'user' => 'guest' },
        'rack.tempfiles' => []
      )
      env['rack.input'] = Rack::RewindableInput.new(env['rack.input'])

      status, _headers, body =
        raw_isolated_cascade([attacker, successor]).call(env)

      status.must_equal 200
      successor_view[:remote_user].must_equal 'guest'
      successor_view[:query_hash].must_be_nil
      successor_view[:session].must_equal('user' => 'guest')
      successor_view[:tempfiles].must_equal []
      rejected_closed.must_equal true
      leaked_tempfile.must_be :closed?
      File.exist?(leaked_path).must_equal false
      body.each.to_a.must_equal ['granted-to-guest']

      # The caller-visible env is also back to its original facts.
      env['REMOTE_USER'].must_equal 'guest'
      env['rack.session'].must_equal('user' => 'guest')
      env.key?('rack.request.query_hash').must_equal false
    end

    it "preserves Hash/Array subclasses instead of flattening them" do
      session_class = Class.new(Hash)
      attacker = lambda do |env|
        env['rack.session']['user'] = 'root'
        env['rack.session']['nested'] = { 'priv' => true }
        [404, {}, []]
      end
      seen = nil
      victim = lambda do |env|
        seen = env['rack.session']
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      session = session_class.new
      session['user'] = 'guest'
      env = Rack::MockRequest.env_for("/foo", 'rack.session' => session)
      raw_isolated_cascade([attacker, victim]).call(env)

      seen.must_be_kind_of session_class
      seen['user'].must_equal 'guest'
      seen.key?('nested').must_equal false
      env['rack.session'].must_be_kind_of session_class
    end

    it "leaves rack.input and rack.errors as the shared stream objects" do
      stream_refs = nil
      inspector = lambda do |env|
        stream_refs = [env['rack.input'], env['rack.errors']]
        [200, { 'content-type' => 'text/plain' }, ['ok']]
      end

      env = Rack::MockRequest.env_for("/foo")
      input = env['rack.input']
      errors = env['rack.errors']
      raw_isolated_cascade([inspector]).call(env)

      stream_refs.must_equal [input, errors]
    end
  end
end

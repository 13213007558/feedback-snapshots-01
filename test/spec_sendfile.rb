# frozen_string_literal: true

require_relative 'helper'
require 'fileutils'
require 'tmpdir'

separate_testing do
  require_relative '../lib/rack/sendfile'
  require_relative '../lib/rack/lint'
  require_relative '../lib/rack/mock_request'
end

# Stand-in for the proxy's own path interpretation: decodes the
# x-accel-redirect URI exactly once and maps the external prefix back to
# the internal file location, the way nginx `alias` would resolve it.
class AccelProxyStandin
  def initialize(routes)
    @routes = routes
  end

  def resolve(uri)
    path = Rack::Utils.unescape_path(uri)
    route = @routes.select { |external, _| path.start_with?(external) }.
      max_by { |external, _| external.length }
    route && route[1] + path[route[0].length..]
  end
end

describe Rack::Sendfile do
  def sendfile_body(filename = "rack_sendfile")
    FileUtils.touch File.join(Dir.tmpdir,  filename)
    res = ['Hello World']
    res.define_singleton_method(:to_path) { File.join(Dir.tmpdir,  filename) }
    res
  end

  def simple_app(body = sendfile_body)
    lambda { |env| [200, { 'content-type' => 'text/plain' }, body] }
  end

  def sendfile_app(body, mappings = [], variation = nil)
    Rack::Lint.new Rack::Sendfile.new(simple_app(body), variation, mappings)
  end

  def request(headers = {}, body = sendfile_body, mappings = [], variation = nil)
    yield Rack::MockRequest.new(sendfile_app(body, mappings, variation)).get('/', headers)
  end

  def open_file(path)
    Class.new(File) do
      unless method_defined?(:to_path)
        alias :to_path :path
      end
    end.open(path, 'wb+')
  end

  it "does nothing when no x-sendfile-type header present" do
    request do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-sendfile'
    end
  end

  it "does nothing and logs to rack.errors when incorrect x-sendfile-type header present" do
    io = StringIO.new
    # Configure with wrong variation type
    request({ 'rack.errors' => io }, sendfile_body, [], 'X-Banana') do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-sendfile'

      io.rewind
      io.read.must_equal "Unknown x-sendfile variation: \"X-Banana\"\n"
    end
  end

  it "sets x-sendfile response header and discards body" do
    request({}, sendfile_body, [], 'X-Sendfile') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-sendfile'].must_equal File.join(Dir.tmpdir,  "rack_sendfile")
    end
  end

  it "closes body when x-sendfile used" do
    body = sendfile_body
    closed = false
    body.define_singleton_method(:close){closed = true}
    request({}, body, [], 'X-Sendfile') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-sendfile'].must_equal File.join(Dir.tmpdir,  "rack_sendfile")
    end
    closed.must_equal true
  end

  it "sets x-lighttpd-send-file response header and discards body" do
    request({}, sendfile_body, [], 'X-Lighttpd-Send-File') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-lighttpd-send-file'].must_equal File.join(Dir.tmpdir,  "rack_sendfile")
    end
  end

  it "sets x-accel-redirect response header and discards body" do
    headers = {
      'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/foo/bar/"
    }
    request(headers, sendfile_body, [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/foo/bar/rack_sendfile'
    end
  end

  it "does not do a regexp substitution on the internal path" do
    tmpdir = Dir.tmpdir.dup
    tmpdir[1..2] = ".*"
    headers = {
      'HTTP_X_ACCEL_MAPPING' => "#{tmpdir}/=/foo/bar/"
    }
    body = sendfile_body
    expected = Rack::Utils.escape_path(File.expand_path(body.to_path)).gsub('?', '%3F')
    request(headers, body, [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal expected
    end
  end

  it "sets x-accel-redirect response header to percent-encoded path" do
    headers = {
      'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/foo/bar%/"
    }
    request(headers, sendfile_body('file_with_%_?_symbol'), [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/foo/bar%25/file_with_%25_%3F_symbol'
    end
  end

  it 'writes to rack.error when no x-accel-mapping is specified' do
    request({}, sendfile_body, [], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-accel-redirect'
      response.errors.must_include 'x-accel-mapping'
    end
  end

  it 'does nothing when body does not respond to #to_path' do
    request({}, ['Not a file...'], [], 'X-Sendfile') do |response|
      response.body.must_equal 'Not a file...'
      response.headers.wont_include 'x-sendfile'
    end
  end

  it "sets x-accel-redirect response header and discards body when initialized with multiple mappings" do
    begin
      dir1 = Dir.mktmpdir
      dir2 = Dir.mktmpdir

      first_body = open_file(File.join(dir1, 'rack_sendfile'))
      first_body.puts 'hello world'

      second_body = open_file(File.join(dir2, 'rack_sendfile'))
      second_body.puts 'goodbye world'

      mappings = [
        ["#{dir1}/", '/foo/bar/'],
        ["#{dir2}/", '/wibble/']
      ]

      request({}, first_body, mappings, 'X-Accel-Redirect') do |response|
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['content-length'].must_equal '0'
        response.headers['x-accel-redirect'].must_equal '/foo/bar/rack_sendfile'
      end

      request({}, second_body, mappings, 'X-Accel-Redirect') do |response|
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['content-length'].must_equal '0'
        response.headers['x-accel-redirect'].must_equal '/wibble/rack_sendfile'
      end
    ensure
      FileUtils.remove_entry_secure dir1
      FileUtils.remove_entry_secure dir2
    end
  end

  it "sets x-accel-redirect response header and discards body when initialized with multiple mappings via header" do
    begin
      dir1 = Dir.mktmpdir
      dir2 = Dir.mktmpdir
      dir3 = Dir.mktmpdir

      first_body = open_file(File.join(dir1, 'rack_sendfile'))
      first_body.puts 'hello world'

      second_body = open_file(File.join(dir2, 'rack_sendfile'))
      second_body.puts 'goodbye world'

      third_body = open_file(File.join(dir3, 'rack_sendfile'))
      third_body.puts 'hello again world'

      # Now we need to explicitly enable x-accel-redirect in the constructor
      app = Rack::Lint.new Rack::Sendfile.new(simple_app(first_body), "X-Accel-Redirect", [])
      
      headers = {
        'HTTP_X_ACCEL_MAPPING' => "#{dir1}/=/foo/bar/, #{dir2}/=/wibble/"
      }

      response = Rack::MockRequest.new(app).get('/', headers)
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/foo/bar/rack_sendfile'

      app = Rack::Lint.new Rack::Sendfile.new(simple_app(second_body), "X-Accel-Redirect", [])
      response = Rack::MockRequest.new(app).get('/', headers)
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal '/wibble/rack_sendfile'

      app = Rack::Lint.new Rack::Sendfile.new(simple_app(third_body), "X-Accel-Redirect", [])
      response = Rack::MockRequest.new(app).get('/', headers)
      response.must_be :ok?
      response.body.must_be :empty?
      response.headers['content-length'].must_equal '0'
      response.headers['x-accel-redirect'].must_equal "#{dir3}/rack_sendfile"
    ensure
      FileUtils.remove_entry_secure dir1
      FileUtils.remove_entry_secure dir2
      FileUtils.remove_entry_secure dir3
    end
  end

  # Security tests for CVE mitigation
  describe "security: information disclosure prevention" do
    it "ignores HTTP_X_SENDFILE_TYPE header to prevent attacker-controlled sendfile activation" do
      # Attacker tries to enable x-sendfile via header
      request 'HTTP_X_SENDFILE_TYPE' => 'x-sendfile' do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-sendfile'
      end
    end

    it "ignores HTTP_X_SENDFILE_TYPE header attempting to enable x-accel-redirect" do
      # Attacker tries to enable x-accel-redirect via header with mapping
      headers = {
        'HTTP_X_SENDFILE_TYPE' => 'x-accel-redirect',
        'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/attacker/path/"
      }
      request headers do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-accel-redirect'
      end
    end

    it "ignores HTTP_X_ACCEL_MAPPING when x-accel-redirect is not explicitly enabled" do
      # Even if attacker sends mapping header, it should be ignored without explicit config
      headers = {
        'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/attacker/path/"
      }
      request headers do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-accel-redirect'
      end
    end

    it "ignores HTTP_X_ACCEL_MAPPING when application-level mappings are configured" do
      # When app provides mappings, header should be ignored for security
      begin
        dir = Dir.mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'test'
        
        app_mappings = [["#{dir}/", '/app/mapping/']]
        app = Rack::Lint.new Rack::Sendfile.new(simple_app(body), "X-Accel-Redirect", app_mappings)
        
        headers = {
          'HTTP_X_ACCEL_MAPPING' => "#{dir}/=/attacker/path/"
        }
        
        response = Rack::MockRequest.new(app).get('/', headers)
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['x-accel-redirect'].must_equal '/app/mapping/rack_sendfile'
        response.headers['x-accel-redirect'].wont_equal '/attacker/path/rack_sendfile'
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "allows HTTP_X_ACCEL_MAPPING only when x-accel-redirect explicitly enabled with no app mappings" do
      # This is the safe use case: explicit config + no app mappings = allow header
      begin
        dir = Dir.mktmpdir
        body = open_file(File.join(dir, 'rack_sendfile'))
        body.puts 'test'
        
        app = Rack::Lint.new Rack::Sendfile.new(simple_app(body), "X-Accel-Redirect", [])
        
        headers = {
          'HTTP_X_ACCEL_MAPPING' => "#{dir}/=/safe/nginx/mapping/"
        }
        
        response = Rack::MockRequest.new(app).get('/', headers)
        response.must_be :ok?
        response.body.must_be :empty?
        response.headers['x-accel-redirect'].must_equal '/safe/nginx/mapping/rack_sendfile'
      ensure
        FileUtils.remove_entry_secure dir
      end
    end

    it "does not allow x-lighttpd-send-file activation via header" do
      # Verify other sendfile types also can't be enabled via headers
      request 'HTTP_X_SENDFILE_TYPE' => 'x-lighttpd-send-file' do |response|
        response.must_be :ok?
        response.body.must_equal 'Hello World'
        response.headers.wont_include 'x-lighttpd-send-file'
      end
    end

    it "requires explicit middleware configuration for any sendfile variation" do
      # Test that sendfile.type env var still works (internal, not from HTTP headers)
      body = sendfile_body
      app = lambda { |env| [200, { 'content-type' => 'text/plain' }, body] }
      middleware = Rack::Lint.new Rack::Sendfile.new(app)
      
      env = Rack::MockRequest.env_for('/', { 'sendfile.type' => 'x-sendfile' })
      status, headers = middleware.call(env)
      
      status.must_equal 200
      headers['x-sendfile'].must_equal File.join(Dir.tmpdir, "rack_sendfile")
      headers['content-length'].must_equal '0'
    end
  end

  it "ignores x-accel-mapping header when x-accel-redirect is not configured via the constructor" do
    headers = {
      'sendfile.type' => 'X-Accel-Redirect',
      'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/foo/bar/"
    }
    request(headers) do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-accel-redirect'
      response.errors.must_include 'x-accel-mapping'
    end
  end

  it "ignores x-accel-mapping header when mappings are configured but none match" do
    headers = {
      'HTTP_X_ACCEL_MAPPING' => "#{Dir.tmpdir}/=/foo/bar/"
    }
    request(headers, sendfile_body, [["/nonexistent/", "/foo/"]], 'X-Accel-Redirect') do |response|
      response.must_be :ok?
      response.body.must_equal 'Hello World'
      response.headers.wont_include 'x-accel-redirect'
      response.errors.must_include 'x-accel-mapping'
    end
  end

  describe "strict mapping mode" do
    # In-memory response body: the content lives in memory, only #to_path
    # points at the file the proxy should serve.
    def memory_body(path)
      body = ['in-memory response']
      body.define_singleton_method(:to_path) { path }
      body
    end

    def with_approved_tree
      root = Dir.mktmpdir
      yield root
    ensure
      FileUtils.remove_entry_secure root
    end

    def strict_request(path, mappings, headers = {})
      FileUtils.mkdir_p File.dirname(path)
      FileUtils.touch path
      captured_env = nil
      app = lambda do |env|
        captured_env = env
        [200, { 'content-type' => 'text/plain' }, memory_body(path)]
      end
      middleware = Rack::Lint.new(Rack::Sendfile.new(app, 'X-Accel-Redirect', mappings, strict: true))
      response = Rack::MockRequest.new(middleware).get('/', headers)
      [response, captured_env]
    end

    it "matches mappings only on complete path segment boundaries" do
      with_approved_tree do |root|
        mappings = [["#{root}/approved/private", "/internal/private"]]

        response, env = strict_request("#{root}/approved/private/report.txt", mappings)
        response.headers['x-accel-redirect'].must_equal '/internal/private/report.txt'
        env['sendfile.mapping'].must_equal ["#{root}/approved/private", "/internal/private"]

        # "/private-a" is not a subdirectory of "/private" and must not match.
        response, env = strict_request("#{root}/approved/private-a/secret.txt", mappings)
        response.headers['x-accel-redirect'].must_be_nil
        env['sendfile.mapping'].must_be_nil
        response.body.must_equal 'in-memory response'
      end
    end

    it "prefers the longest overlapping prefix and reports the mapping used" do
      with_approved_tree do |root|
        mappings = [
          ["#{root}/approved/private", "/internal/general"],
          ["#{root}/approved/private/sub", "/internal/specific"]
        ]

        response, env = strict_request("#{root}/approved/private/sub/file.txt", mappings)
        response.headers['x-accel-redirect'].must_equal '/internal/specific/file.txt'
        env['sendfile.mapping'].must_equal ["#{root}/approved/private/sub", "/internal/specific"]

        response, env = strict_request("#{root}/approved/private/other.txt", mappings)
        response.headers['x-accel-redirect'].must_equal '/internal/general/other.txt'
        env['sendfile.mapping'].must_equal ["#{root}/approved/private", "/internal/general"]
      end
    end

    it "matches case-insensitively while preserving the case of the remaining path" do
      with_approved_tree do |root|
        mappings = [["#{root}/APPROVED/Private/", "/internal/"]]
        response, env = strict_request("#{root}/approved/pRIVATE/Report.TXT", mappings)
        response.headers['x-accel-redirect'].must_equal '/internal/Report.TXT'
        env['sendfile.mapping'].must_equal ["#{root}/APPROVED/Private/", "/internal/"]
      end
    end

    it "escapes percent, question mark and special filenames exactly once" do
      with_approved_tree do |root|
        mappings = [["#{root}/approved/private/", "/internal/"]]
        proxy = AccelProxyStandin.new([["/internal/", "#{root}/approved/private/"]])

        path = "#{root}/approved/private/100%legit?.txt"
        response, _ = strict_request(path, mappings)
        uri = response.headers['x-accel-redirect']
        uri.must_equal '/internal/100%25legit%3F.txt'
        uri.wont_include '?'
        proxy.resolve(uri).must_equal path

        # A filename that literally contains "%2e%2e%2f" decodes to itself,
        # not to "../", so the proxy stays inside the approved location.
        path = "#{root}/approved/private/%2e%2e%2fsecret.txt"
        response, _ = strict_request(path, mappings)
        uri = response.headers['x-accel-redirect']
        uri.must_equal '/internal/%252e%252e%252fsecret.txt'
        proxy.resolve(uri).must_equal path
      end
    end

    it "produces URIs the proxy resolves back to the approved file" do
      with_approved_tree do |root|
        mappings = [["#{root}/approved/private/", "/internal/"]]
        proxy = AccelProxyStandin.new([["/internal/", "#{root}/approved/private/"]])
        path = "#{root}/approved/private/annual report 2026.txt"

        response, _ = strict_request(path, mappings)
        uri = response.headers['x-accel-redirect']
        uri.must_match(/\A\/internal\//)
        proxy.resolve(uri).must_equal path
      end
    end

    it "does not re-map the result through a second mapping" do
      with_approved_tree do |root|
        mappings = [
          ["#{root}/approved/a/", "/approved/b/"],
          ["/approved/b/", "/elsewhere/"]
        ]
        response, env = strict_request("#{root}/approved/a/file.txt", mappings)
        response.headers['x-accel-redirect'].must_equal '/approved/b/file.txt'
        env['sendfile.mapping'].must_equal ["#{root}/approved/a/", "/approved/b/"]
      end
    end

    it "inserts backslash sequences in the replacement literally" do
      with_approved_tree do |root|
        mappings = [["#{root}/approved/", '/internal\1/']]
        response, _ = strict_request("#{root}/approved/file.txt", mappings)
        response.headers['x-accel-redirect'].must_equal '/internal%5C1/file.txt'
      end
    end

    it "ignores the x-accel-mapping header even when no mappings are configured" do
      with_approved_tree do |root|
        path = "#{root}/approved/private/report.txt"
        headers = { 'HTTP_X_ACCEL_MAPPING' => "#{root}/approved/=/attacker/" }
        response, env = strict_request(path, [], headers)
        response.headers['x-accel-redirect'].must_be_nil
        env['sendfile.mapping'].must_be_nil
        response.errors.must_include 'no approved x-accel-mapping'
        response.body.must_equal 'in-memory response'
      end
    end

    it "never exposes the local absolute path when no mapping matches" do
      with_approved_tree do |root|
        path = "#{root}/approved/private/secret.txt"
        mappings = [["#{root}/approved/public/", "/files/"]]
        response, env = strict_request(path, mappings)
        response.headers['x-accel-redirect'].must_be_nil
        response.headers.each_value do |value|
          value.wont_include path
        end
        env['sendfile.mapping'].must_be_nil
        response.body.must_equal 'in-memory response'
      end
    end
  end
end

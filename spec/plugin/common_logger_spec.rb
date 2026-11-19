require_relative "../spec_helper"

describe "common_logger plugin" do
  def cl_app(&block)
    app(:common_logger, &block)
    @logger = rack_input
    @app.plugin :common_logger, @logger
  end

  it 'logs requests to given logger/stream' do
    cl_app(&:path_info)

    body("HTTP_VERSION"=>'HTTP/1.0').must_equal '/'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/1.0" 200 1 0.\d\d\d\d\n\z/)

    unless ENV["LINT"]
      @logger.rewind
      @logger.truncate(0)
      body("HTTP_VERSION"=>"HTTP\n1.0").must_equal '/'
      @logger.rewind
      @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\\xa1.0" 200 1 0.\d\d\d\d\n\z/)
    end

    @logger.rewind
    @logger.truncate(0)
    body('/b', 'REMOTE_ADDR'=>'1.1.1.2', 'QUERY_STRING'=>'foo=bar', "HTTP_VERSION"=>'HTTP/1.0').must_equal '/b'
    @logger.rewind
    @logger.read.must_match(/\A1\.1\.1\.2 - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/b\?foo=bar HTTP\/1.0" 200 2 0.\d\d\d\d\n\z/)

    @logger.rewind
    @logger.truncate(0)
    body('/b', 'REMOTE_ADDR'=>'1.1.1.2', 'QUERY_STRING'=>'foo=bar', "HTTP_VERSION"=>'HTTP/1.0', "SCRIPT_NAME"=>"/a").must_equal '/b'
    @logger.rewind
    @logger.read.must_match(/\A1\.1\.1\.2 - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/a\/b\?foo=bar HTTP\/1.0" 200 2 0.\d\d\d\d\n\z/)

    logger = Struct.new(:logger) do
      def <<(m) logger << m; end
    end.new(@logger)
    @app.plugin :common_logger, logger
    @logger.rewind
    @logger.truncate(0)
    body("HTTP_VERSION"=>'HTTP/1.0').must_equal '/'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/1.0" 200 1 0.\d\d\d\d\n\z/)
  end

  it 'handles empty PATH_INFO' do
    cl_app(&:path_info)
    body('', 'HTTP_X_FORWARDED_FOR'=>'1.1.1.1', 'REMOTE_USER'=>'je', 'REQUEST_METHOD'=>'POST', 'QUERY_STRING'=>'', "HTTP_VERSION"=>'HTTP/1.1').must_equal ''
    @logger.rewind
    @logger.read.must_match(/\A1\.1\.1\.1 - je \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "POST  HTTP\/1.1" 200 - 0.\d\d\d\d\n\z/)
  end unless ENV['LINT']

  it 'skips timer information if not available' do
    cl_app do |r|
      @_request_timer = nil
      r.path_info
    end

    body("HTTP_VERSION"=>'HTTP/1.0').must_equal '/'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/1.0" 200 1 -\n\z/)
  end

  it 'skips length information if not available' do
    cl_app do |r|
      r.halt [500, {}, []]
    end

    body("HTTP_VERSION"=>'HTTP/1.0').must_equal ''
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/1.0" 500 - 0.\d\d\d\d\n\z/)
  end

  it 'does not log if an error is raised' do
    cl_app do |r|
      raise "foo"
    end

    begin
      body
    rescue => e
    end
    e.must_be_instance_of(RuntimeError)
    e.message.must_equal 'foo'
  end

  it 'logs errors if used with error_handler' do
    cl_app do |r|
      raise "foo"
    end
    @app.plugin :error_handler do |_|
      "bad"
    end

    body("HTTP_VERSION"=>'HTTP/1.0').must_equal 'bad'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/1.0" 500 3 0.\d\d\d\d\n\z/)
  end

  it 'escapes' do
    cl_app(&:path_info)

    body("HTTP_VERSION"=>"HTTP/\x801.0".dup.force_encoding('BINARY')).must_equal '/'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/\\x801.0" 200 1 0.\d\d\d\d\n\z/)
  end unless ENV['LINT']

  it 'logs using the given method' do
    cl_app do |r|
      r.halt [500, {}, []]
    end
    @logger = (Class.new(SimpleDelegator) do
      def debug(str)
        write "DEBUG #{str}"
      end
    end).new(rack_input)
    @app.plugin :common_logger, @logger, :method=>:debug

    body("HTTP_VERSION"=>'HTTP/1.0').must_equal ''
    @logger.rewind
    @logger.read.must_match(/\ADEBUG - - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/1.0" 500 - 0.\d\d\d\d\n\z/)
  end

  it 'respects the use_request_ip_option' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, use_request_ip: true
    @app::RodaRequest.send(:define_method, :ip){"1.2.3.4"}

    body("HTTP_VERSION"=>'HTTP/1.0').must_equal '/'
    @logger.rewind
    @logger.read.must_match(/\A1.2.3.4 - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/ HTTP\/1.0" 200 1 0.\d\d\d\d\n\z/)

  end

  it 'logs the path returned by the log_path callable' do
    cl_app do |r|
      r.get 'downloads', String do |id|
        id
      end
      r.get('missing'){r.halt [404, {}, ['not found']]}
      'index'
    end
    @app.plugin :common_logger, @logger, log_path: proc{|request| request.path == "/" ? "/category/home" : "/category#{request.path[/\A\/[^\/]+/]}"}

    body('/downloads/abc123', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'abc123'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/category\/downloads HTTP\/1.0" 200 6 0.\d\d\d\d\n\z/)

    @logger.rewind
    @logger.truncate(0)
    body('HTTP_VERSION'=>'HTTP/1.0').must_equal 'index'
    @logger.rewind
    @logger.read.must_match(/"GET \/category\/home HTTP\/1.0" 200 5 /)
  end

  it 'uses the log_path_fallback if log_path returns an unusable value' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, log_path: proc{|_| nil}, log_path_fallback: '[unknown]'

    body('/secret/abc', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/secret/abc'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \[unknown\] HTTP\/1.0" 200 11 0.\d\d\d\d\n\z/)
  end

  it 'uses the log_path_fallback if log_path raises' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, :log_path=>proc{|_| raise 'foo'}

    body('/secret/abc', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/secret/abc'
    @logger.rewind
    @logger.read.must_match(/"GET - HTTP\/1.0" 200 11 0.\d\d\d\d\n\z/)
  end

  it 'supports a hash for log_path, and uses the fallback for unmatched paths' do
    cl_app do |r|
      r.get('downloads', String){|id| id}
      r.get('unmatched'){r.halt [404, {}, ['not found']]}
      'index'
    end
    @app.plugin :common_logger, @logger, log_path: {/\A\/downloads\/[0-9a-f]+\z/ => '/downloads/:id'}, log_path_fallback: '-'

    body('/downloads/abc123', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'abc123'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/downloads\/:id HTTP\/1.0" 200 6 0.\d\d\d\d\n\z/)

    @logger.rewind
    @logger.truncate(0)
    body('/unmatched', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'not found'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET - HTTP\/1.0" 404 - 0.\d\d\d\d\n\z/)
  end

  it 'supports string keys in a log_path hash, including prefix keys ending in /' do
    cl_app do |r|
      r.get('health'){'ok'}
      r.on('downloads'){r.get(String){|id| id}}
      'index'
    end
    @app.plugin :common_logger, @logger, log_path: {'/health'=>'/health', '/downloads/'=>'/downloads/:id'}, log_path_fallback: '-'

    body('/health', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'ok'
    @logger.rewind
    @logger.read.must_match(/"GET \/health HTTP\/1.0" 200 2 /)

    @logger.rewind
    @logger.truncate(0)
    body('/downloads/secret-token', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'secret-token'
    @logger.rewind
    @logger.read.must_match(/"GET \/downloads\/:id HTTP\/1.0" 200 12 /)

    @logger.rewind
    @logger.truncate(0)
    body('/other', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'index'
    @logger.rewind
    @logger.read.must_match(/"GET - HTTP\/1.0" 200 5 /)
  end

  it 'supports callables that accept no arguments for log_path' do
    cl_app(&:path_info)
    callable = Class.new{def call(*); '/zero'; end}.new
    @app.plugin :common_logger, @logger, log_path: callable

    body('/private', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/private'
    @logger.rewind
    @logger.read.must_match(/"GET \/zero HTTP\/1.0" 200 8 /)
  end

  it 'accepts a block for log_path' do
    logger = rack_input
    app(:bare) do
      plugin :common_logger, logger, log_path_fallback: '[filtered]' do |request|
        request.path_info.start_with?('/downloads/') ? '/downloads/:id' : nil
      end
      route{|r| r.path_info}
    end

    body('/downloads/abc', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/downloads/abc'
    logger.rewind
    logger.read.must_match(/"GET \/downloads\/:id HTTP\/1.0" 200 14 /)

    logger.rewind
    logger.truncate(0)
    body('/other', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/other'
    logger.rewind
    logger.read.must_match(/"GET \[filtered\] HTTP\/1.0" 200 6 /)
  end

  it 'does not modify the request path when log_path is used' do
    cl_app do |r|
      "/#{r.path_info}#{r.remaining_path}#{env['SCRIPT_NAME']}"
    end
    @app.plugin :common_logger, @logger, log_path: proc{|request| request.path_info}, log_path_fallback: '?'

    env = req_env('PATH_INFO'=>'/b', 'SCRIPT_NAME'=>'/a', 'QUERY_STRING'=>'foo=bar', 'HTTP_VERSION'=>'HTTP/1.0')
    res = @app.call(env)
    res[2].each{}
    res[2].close if res[2].respond_to?(:close)
    env['SCRIPT_NAME'].must_equal '/a'
    env['PATH_INFO'].must_equal '/b'
    env['QUERY_STRING'].must_equal 'foo=bar'
    @logger.rewind
    @logger.read.must_match(/"GET \/b HTTP\/1.0" 200 7 /)
  end

  it 'does not include the query string when log_path is used' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, log_path: proc{'/fixed'}

    body('/b', 'QUERY_STRING'=>'secret=value', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/b'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/fixed HTTP\/1.0" 200 2 0.\d\d\d\d\n\z/)
  end

  it 'logs the fallback for log_path when an error is raised and error_handler is used' do
    cl_app do |r|
      r.get('error'){raise 'foo'}
      'ok'
    end
    @app.plugin :error_handler do |_|
      'bad'
    end
    @app.plugin :common_logger, @logger, log_path: proc{|request| request.path_info == '/error' ? raise('bar') : '/ok'}

    body('/error', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'bad'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET - HTTP\/1.0" 500 3 0.\d\d\d\d\n\z/)
  end

  it 'does not log when log_path is configured but an error is raised without error_handler' do
    cl_app do |r|
      raise 'foo'
    end
    @app.plugin :common_logger, @logger, log_path: proc{'/x'}

    proc{body('/x')}.must_raise(RuntimeError)
    @logger.rewind
    @logger.read.must_be_empty
  end

  it 'raises for invalid log_path and log_path_fallback options' do
    cl_app(&:path_info)

    proc{@app.plugin :common_logger, @logger, log_path: 1}.must_raise(Roda::RodaError)
    proc{@app.plugin :common_logger, @logger, log_path: proc{}, log_path_fallback: 1}.must_raise(Roda::RodaError)
  end

  it 'keeps log_path and log_path_fallback options across configure calls' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, log_path: proc{'/fixed'}, log_path_fallback: '[filtered]'
    @app.plugin :common_logger, @logger

    body('/b', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/b'
    @logger.rewind
    @logger.read.must_match(/"GET \/fixed HTTP\/1.0" 200 2 /)
  end

  it 'raises when log_path is used without plugin-level log path configuration' do
    cl_app do |r|
      log_path '/x'
      'x'
    end
    proc{body('/x')}.must_raise(Roda::RodaError)
  end

  it 'uses the path set by log_path in the route block' do
    cl_app do |r|
      r.on 'downloads', String do |id|
        log_path '/downloads/:id'
        id
      end
      r.get('unmatched'){r.halt [404, {}, ['not found']]}
      'index'
    end
    @app.plugin :common_logger, @logger, log_path_fallback: '-'

    body('/downloads/abc123', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'abc123'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/downloads\/:id HTTP\/1.0" 200 6 0.\d\d\d\d\n\z/)

    @logger.rewind
    @logger.truncate(0)
    body('/unmatched', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'not found'
    @logger.rewind
    @logger.read.must_match(/"GET - HTTP\/1.0" 404 - 0.\d\d\d\d\n\z/)

    @logger.rewind
    @logger.truncate(0)
    body('/other', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'index'
    @logger.rewind
    @logger.read.must_match(/"GET - HTTP\/1.0" 200 5 /)
  end

  it 'prefers the path set by log_path in the route block over the plugin log_path option' do
    cl_app do |r|
      r.on 'downloads', String do |id|
        log_path '/route/:id'
        id
      end
      r.get('other'){'other'}
      'index'
    end
    @app.plugin :common_logger, @logger, log_path: proc{'/plugin'}

    body('/downloads/abc', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'abc'
    @logger.rewind
    @logger.read.must_match(/"GET \/route\/:id HTTP\/1.0" 200 3 /)

    @logger.rewind
    @logger.truncate(0)
    body('/other', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'other'
    @logger.rewind
    @logger.read.must_match(/"GET \/plugin HTTP\/1.0" 200 5 /)
  end

  it 'supports r.log_path in the route block' do
    cl_app do |r|
      r.on 'downloads', String do |id|
        r.log_path '/downloads/:id'
        id
      end
      'index'
    end
    @app.plugin :common_logger, @logger, log_path_fallback: '-'

    body('/downloads/def456', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'def456'
    @logger.rewind
    @logger.read.must_match(/"GET \/downloads\/:id HTTP\/1.0" 200 6 /)
  end

  it 'does not affect routing when log_path is set in the route block' do
    cl_app do |r|
      r.on 'downloads', String do |id|
        log_path '/downloads/:id'
        "/#{id}/#{r.remaining_path}/#{r.path}"
      end
    end
    @app.plugin :common_logger, @logger, log_path_fallback: '-'

    body('/downloads/abc', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/abc///downloads/abc'
    @logger.rewind
    @logger.read.must_match(/"GET \/downloads\/:id HTTP\/1.0" 200 20 /)
  end

  it 'keeps the route-provided path when the route raises and error_handler is used' do
    cl_app do |r|
      r.on 'downloads', String do |_id|
        log_path '/downloads/:id'
        raise 'failure'
      end
      'index'
    end
    @app.plugin :error_handler do |_|
      'bad'
    end
    @app.plugin :common_logger, @logger, log_path_fallback: '-'

    body('/downloads/secret-token', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 'bad'
    @logger.rewind
    @logger.read.must_match(/\A- - - \[\d\d\/[A-Z][a-z]{2}\/\d\d\d\d:\d\d:\d\d:\d\d [-+]\d\d\d\d\] "GET \/downloads\/:id HTTP\/1.0" 500 3 0.\d\d\d\d\n\z/)
  end

  it 'uses the fallback for the default 404 response' do
    cl_app do |r|
      r.get('known'){'known'}
    end
    @app.plugin :common_logger, @logger, log_path_fallback: '[unmatched]'

    status('/private/secret', 'HTTP_VERSION'=>'HTTP/1.0').must_equal 404
    @logger.rewind
    @logger.read.must_match(/"GET \[unmatched\] HTTP\/1.0" 404 - 0.\d\d\d\d\n\z/)
  end

  it 'hex escapes unprintable characters in the log_path value' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, log_path: proc{"/x\ny"}

    body('/b', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/b'
    @logger.rewind
    @logger.read.must_include("GET /x\\xay HTTP/1.0")
  end

  it 'uses the default fallback of - for unusable log_path values' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, log_path: proc{|_| :not_a_string}

    body('/private/abc', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/private/abc'
    @logger.rewind
    @logger.read.must_match(/"GET - HTTP\/1.0" 200 12 0.\d\d\d\d\n\z/)
  end

  it 'does not let log_path errors affect the request' do
    cl_app(&:path_info)
    @app.plugin :common_logger, @logger, log_path: proc{|_| raise 'boom'}, log_path_fallback: '?'

    status('/private/abc').must_equal 200
    body('/private/abc', 'HTTP_VERSION'=>'HTTP/1.0').must_equal '/private/abc'
  end
end

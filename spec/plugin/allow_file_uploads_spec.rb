require_relative "../spec_helper"

begin
  require_relative '../../lib/roda/plugins/disallow_file_uploads'
  require_relative '../../lib/roda/plugins/allow_file_uploads'
rescue LoadError
  warn "Rack #{Rack.release} used, skipping allow_file_uploads plugin test"
else
describe "allow_file_uploads plugin" do
  def multipart_body(parts, boundary = "AaB03x")
    body = parts.map do |headers, content|
      headers = headers.map{|k, v| "#{k}: #{v}\r\n"}.join
      "--#{boundary}\r\n#{headers}\r\n#{content}\r\n"
    end.join
    body << "--#{boundary}--\r\n"
    body
  end

  def multipart_env(path, parts)
    body = multipart_body(parts)
    {
      'PATH_INFO'=>path,
      'rack.input'=>rack_input(body),
      'CONTENT_TYPE'=>"multipart/form-data; boundary=AaB03x",
      'CONTENT_LENGTH'=>body.bytesize.to_s,
      'REQUEST_METHOD'=>'POST'
    }
  end

  def file_part(name, filename, content)
    [{'Content-Disposition'=>"form-data; name=\"#{name}\"; filename=\"#{filename}\"", 'Content-Type'=>'text/plain'}, content]
  end

  def field_part(name, value)
    [{'Content-Disposition'=>"form-data; name=\"#{name}\""}, value]
  end

  # Record tempfile creations by wrapping Rack's default tempfile factory,
  # so tests can check when temporary upload files are created.
  def record_tempfiles
    created = []
    parser = Rack::Multipart::Parser
    original = parser::TEMPFILE_FACTORY
    spy = lambda{|filename, content_type| created << filename; original.call(filename, content_type)}
    parser.send(:remove_const, :TEMPFILE_FACTORY)
    parser.const_set(:TEMPFILE_FACTORY, spy)
    yield created
  ensure
    parser.send(:remove_const, :TEMPFILE_FACTORY)
    parser.const_set(:TEMPFILE_FACTORY, original)
  end

  before do
    route_log = []
    @route_log = route_log
    app do |r|
      r.post "tickets", Integer, "attachment" do |ticket_id|
        r.allow_file_uploads
        file = r.params['file']
        route_log << :attachment
        "ticket #{ticket_id}: note=#{r.params['note']} file=#{file[:filename]} content=#{file[:tempfile].read}"
      end

      r.post "profile" do
        route_log << :profile
        "profile: name=#{r.params['name']} bio=#{r.params['bio']}"
      end

      r.post "api", "data" do
        route_log << :api
        "api: content_type=#{r.env['CONTENT_TYPE']}"
      end
    end
    app.plugin :disallow_file_uploads
    app.plugin :allow_file_uploads
  end

  it "allows file uploads only in routes calling r.allow_file_uploads" do
    record_tempfiles do |created|
      body(multipart_env('/tickets/1/attachment', [field_part('note', 'hello'), file_part('file', 'bar.txt', 'foo')])).
        must_equal 'ticket 1: note=hello file=bar.txt content=foo'
      created.must_equal ['bar.txt']
      @route_log.must_equal [:attachment]
    end
  end

  it "raises and does not create a tempfile for file uploads to other routes" do
    record_tempfiles do |created|
      proc{body(multipart_env('/profile', [field_part('name', 'foo'), file_part('file', 'bar.txt', 'foo')]))}.
        must_raise Roda::RodaPlugins::DisallowFileUploads::Error
      created.must_equal []
      @route_log.must_equal [:profile]
    end
  end

  it "keeps multipart form fields usable on routes without file uploads" do
    record_tempfiles do |created|
      body(multipart_env('/profile', [field_part('name', 'foo'), field_part('bio', 'bar')])).
        must_equal 'profile: name=foo bio=bar'
      created.must_equal []
    end
  end

  it "keeps urlencoded forms usable" do
    record_tempfiles do |created|
      body('PATH_INFO'=>'/profile', 'rack.input'=>rack_input('name=foo&bio=bar'),
           'CONTENT_TYPE'=>'application/x-www-form-urlencoded', 'CONTENT_LENGTH'=>'15', 'REQUEST_METHOD'=>'POST').
        must_equal 'profile: name=foo bio=bar'
      created.must_equal []
    end
  end

  it "does not affect JSON requests" do
    record_tempfiles do |created|
      body('PATH_INFO'=>'/api/data', 'rack.input'=>rack_input('{"a":1}'),
           'CONTENT_TYPE'=>'application/json', 'CONTENT_LENGTH'=>'7', 'REQUEST_METHOD'=>'POST').
        must_equal 'api: content_type=application/json'
      created.must_equal []
      @route_log.must_equal [:api]
    end
  end
end
end

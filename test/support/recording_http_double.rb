# frozen_string_literal: true

# A test double for the slice of the Net::HTTP interface that the OAuth
# client integration relies on. Instead of opening a socket it records the
# exact bytes each request would put on the wire, so tests can assert what
# was actually sent.
class RecordingHttpDouble
  RecordedRequest = Struct.new(:method, :target, :headers, :body, :raw_bytes)
  FakeResponse = Struct.new(:code, :body)

  attr_reader :address, :port, :recorded

  def initialize(address = "example.com", port = 80, use_ssl: false)
    @address = address
    @port = port
    @use_ssl = use_ssl
    @recorded = []
  end

  def use_ssl?
    @use_ssl
  end

  def request(req)
    body = req.body
    if body.nil? && req.body_stream
      # Like Net::HTTP, the stream is consumed and not rewound.
      body = req.body_stream.read
    end
    headers = {}
    req.each_header { |key, value| headers[key] = value }
    raw = +"#{req.method} #{req.path} HTTP/1.1\r\n"
    headers.each { |key, value| raw << "#{key}: #{value}\r\n" }
    raw << "\r\n"
    raw << body.to_s
    @recorded << RecordedRequest.new(req.method, req.path, headers, body, raw)
    FakeResponse.new("200", "recorded")
  end
end

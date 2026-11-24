# frozen_string_literal: true

require "socket"
require "digest"
require "securerandom"
require "openssl"

# A fully in-process Digest authentication server used to prove that the
# client's digest response is bound to the exact bytes transmitted on the wire.
#
# Each client TCP-like connection is backed by a Socket.pair (a connected UNIX
# stream socket pair), so no TCP port has to be bound and the test stays local
# and hermetic. A background thread services every connection the client opens,
# sharing the nonce / stale bookkeeping across them.
#
# It implements enough of RFC 2617 / RFC 7616 to validate the Authorization
# header, including the `auth-int` quality of protection (which hashes the
# entity body) and a `stale=true` re-challenge that hands out a fresh nonce.
class DigestServer
  REALM = "upload-realm"
  USER  = "admin"
  PASS  = "secret"

  # @return [Array<String>] raw request messages received, in order
  attr_reader :requests

  # @return [Array<String>] request bodies received, in order
  attr_reader :bodies

  # @return [Exception, nil] any error raised while serving
  attr_reader :server_error

  # @param qop [String, nil] qop list to advertise in the challenge
  # @param stale_on_first_auth [Boolean] reject the first authorized request
  #   with stale=true and a fresh nonce so the client retries once
  def initialize(qop: "auth", stale_on_first_auth: false)
    @qop = qop
    @stale_on_first_auth = stale_on_first_auth
    @requests = []
    @bodies = []
    @server_error = nil
    @pairs = Queue.new
    @mutex = Mutex.new
    @nonce = SecureRandom.hex(16)
    @rechallenged = false
  end

  # Create a fresh connected pair and return the client end. The server end is
  # queued for the serving thread. Acts as the HTTP client's socket_class.
  def open(_host = nil, _port = nil, **)
    client_socket, server_socket = Socket.pair(:UNIX, :STREAM, 0)
    @pairs << server_socket
    client_socket
  end

  # Start the background serving thread.
  def start
    @thread = Thread.new { serve_loop }
    self
  end

  def join
    @thread.join
  end

  def stop
    @stopping = true
    @pairs << :stop
  end

  private

  def serve_loop
    loop do
      socket = @pairs.pop
      break if socket == :stop

      handle_connection(socket)
    end
  rescue StandardError => e
    @server_error = e
  end

  def handle_connection(socket)
    message = read_request(socket)
    return socket.close unless message

    @mutex.synchronize do
      @requests << message
      request = parse(message)
      @bodies << request[:body]

      status, headers = evaluate(request, @nonce)

      if status == 200
        write_response(socket, 200, {}, "accepted")
      elsif @stale_on_first_auth && authenticated?(request) && !@rechallenged
        @rechallenged = true
        @nonce = SecureRandom.hex(16)
        write_response(socket, 401, challenge_header(@nonce, stale: true))
      else
        write_response(socket, status, headers)
      end
    end
  rescue StandardError => e
    @server_error = e
  ensure
    socket.close unless socket.closed?
  end

  def challenge_header(nonce, stale: false)
    header = %(Digest realm="#{REALM}", nonce="#{nonce}")
    header << %(, qop="#{@qop}") if @qop
    header << %(, stale=true) if stale
    { "WWW-Authenticate" => header }
  end

  # Read one full request message, draining headers then the declared body.
  def read_request(socket)
    head = +""
    head << socket.readline until head.end_with?("\r\n\r\n")
    return nil if head.empty?

    length = content_length(head)
    body = length.to_i.positive? ? read_exactly(socket, length) : ""
    head << body
  rescue EOFError, IOError
    nil
  end

  def read_exactly(socket, length)
    buffer = +"".b
    buffer << socket.read(length - buffer.bytesize) while buffer.bytesize < length
    buffer
  end

  def content_length(head)
    match = head[/Content-Length:\s*(\d+)/i, 1]
    match && match.to_i
  end

  def parse(message)
    head, body = message.split("\r\n\r\n", 2)
    lines = head.split("\r\n")
    method, full_uri, = lines.first.split(" ", 3)
    path = full_uri.to_s.split("?", 2).first
    headers = {}
    lines[1..].each do |line|
      key, value = line.split(":", 2)
      headers[key.downcase] = value.to_s.strip
    end
    { method: method, path: path, headers: headers, body: body.to_s }
  end

  def evaluate(request, expected_nonce)
    auth = request[:headers]["authorization"]
    return [401, challenge_header(expected_nonce)] unless auth&.start_with?("Digest ")

    params = parse_digest(auth)
    return [400, {}] unless valid_digest?(request, params, expected_nonce)

    [200, {}]
  end

  def authenticated?(request)
    request[:headers]["authorization"]&.start_with?("Digest ") == true
  end

  def parse_digest(header)
    params = {}
    header.sub(/\ADigest\s+/i, "").scan(/(\w+)=(?:"([^"]*)"|([\w-]+))/) do |key, quoted, bare|
      params[key] = quoted || bare
    end
    params
  end

  def valid_digest?(request, params, expected_nonce)
    return false unless params["username"] == USER
    return false unless params["realm"] == REALM
    return false unless params["nonce"] == expected_nonce
    return false unless params["uri"] == request[:path]

    algorithm = params.fetch("algorithm", "MD5")
    qop = params["qop"]
    ha1 = ha1(algorithm, params)
    ha2 = ha2(algorithm, request, qop)
    expected = response_hash(algorithm, ha1, ha2, params, qop)

    secure_compare(expected, params.fetch("response", ""))
  end

  def ha1(algorithm, params)
    base = digest(algorithm, "#{USER}:#{REALM}:#{PASS}")
    if algorithm.end_with?("-sess")
      digest(algorithm, "#{base}:#{params['nonce']}:#{params['cnonce']}")
    else
      base
    end
  end

  def ha2(algorithm, request, qop)
    if qop == "auth-int"
      name = algorithm.sub(/-sess\z/i, "")
      entity = Digest.const_get(name).hexdigest(request[:body])
      digest(algorithm, "#{request[:method]}:#{request[:path]}:#{entity}")
    else
      digest(algorithm, "#{request[:method]}:#{request[:path]}")
    end
  end

  def response_hash(algorithm, ha1, ha2, params, qop)
    if qop
      digest(algorithm, "#{ha1}:#{params['nonce']}:#{params['nc']}:#{params['cnonce']}:#{qop}:#{ha2}")
    else
      digest(algorithm, "#{ha1}:#{params['nonce']}:#{ha2}")
    end
  end

  def digest(algorithm, data)
    Digest.const_get(algorithm.sub(/-sess\z/i, "")).hexdigest(data)
  end

  def secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    OpenSSL.fixed_length_secure_compare(a, b)
  rescue
    false
  end

  def write_response(socket, status, headers, body = "")
    reason = status == 200 ? "OK" : "Unauthorized"
    lines = ["HTTP/1.1 #{status} #{reason}"]
    headers.each { |key, value| lines << "#{key}: #{value}" }
    lines << "Content-Length: #{body.bytesize}"
    lines << "Connection: keep-alive"
    socket.write(lines.join("\r\n") << "\r\n\r\n" << body)
  end
end

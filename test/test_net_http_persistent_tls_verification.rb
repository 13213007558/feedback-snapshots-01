require 'rubygems'
require 'minitest/autorun'
require 'net/http/persistent'
require 'socket'
require 'tmpdir'
require 'fileutils'

HAVE_OPENSSL = defined?(OpenSSL::SSL) unless defined?(HAVE_OPENSSL)

##
# Offline TLS verification regression suite.
#
# These tests exist to prove that Net::HTTP::Persistent really performs
# certificate chain and hostname verification on the wire -- not merely that
# a CA file happens to be stored in a configuration object.  A throwaway CA
# and a TLS server bound to the loopback interface record every actual
# handshake and every received request, so each assertion is backed by
# handshake evidence:
#
# * a request carrying credentials may only reach the server after a
#   successful, verified handshake;
# * a failed verification must mean the server never saw the request.
#
# The single transport-double test at the bottom only checks that settings
# propagate to the Net::HTTP object; it is not verification evidence.

##
# Generates a throwaway CA hierarchy for the regression suite:
#
# * a CA that signs the server certificates (+ca_file+ / +ca_cert+)
# * a second CA that signs nothing (+untrusted_ca_file+)
# * a server certificate for +localhost+ signed by the first CA
# * a server certificate for +not-localhost.example+ signed by the first CA
#   (valid chain, wrong hostname)
# * a self-signed server certificate for +localhost+ (no chain to any CA)

class TLSRegressionFixtures # :nodoc:
  attr_reader :ca_cert, :ca_file,
              :untrusted_ca_cert, :untrusted_ca_file,
              :good_key, :good_cert,
              :wrong_host_key, :wrong_host_cert,
              :self_signed_key, :self_signed_cert

  def self.create
    @instance ||= new
  end

  def initialize
    @dir = Dir.mktmpdir 'net-http-persistent-tls-regression'
    at_exit { FileUtils.remove_entry @dir }

    ca_key, @ca_cert = self_signed_ca 'net-http-persistent regression CA', 1
    _, @untrusted_ca_cert =
      self_signed_ca 'net-http-persistent untrusted CA', 2

    @ca_file           = write_pem 'ca.pem', @ca_cert
    @untrusted_ca_file = write_pem 'untrusted-ca.pem', @untrusted_ca_cert

    @good_key, @good_cert = issue_server_cert \
      ca_key, @ca_cert, 3, 'localhost', 'DNS:localhost'

    @wrong_host_key, @wrong_host_cert = issue_server_cert \
      ca_key, @ca_cert, 4, 'not-localhost.example', 'DNS:not-localhost.example'

    @self_signed_key  = OpenSSL::PKey::RSA.new 2048
    @self_signed_cert = self_signed_server_cert @self_signed_key, 5
  end

  private

  def self_signed_ca common_name, serial
    key  = OpenSSL::PKey::RSA.new 2048
    cert = base_certificate key.public_key, serial

    cert.subject = OpenSSL::X509::Name.parse "/CN=#{common_name}"
    cert.issuer  = cert.subject

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate  = cert

    cert.add_extension factory.create_extension 'basicConstraints', 'CA:TRUE', true
    cert.add_extension factory.create_extension 'keyUsage', 'keyCertSign,cRLSign', true
    cert.add_extension factory.create_extension 'subjectKeyIdentifier', 'hash'

    cert.sign key, OpenSSL::Digest::SHA256.new

    [key, cert]
  end

  def issue_server_cert ca_key, ca_cert, serial, common_name, san
    key  = OpenSSL::PKey::RSA.new 2048
    cert = base_certificate key.public_key, serial

    cert.subject = OpenSSL::X509::Name.parse "/CN=#{common_name}"
    cert.issuer  = ca_cert.subject

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate  = ca_cert

    cert.add_extension factory.create_extension 'basicConstraints', 'CA:FALSE', true
    cert.add_extension factory.create_extension 'keyUsage',
                       'digitalSignature,keyEncipherment', true
    cert.add_extension factory.create_extension 'extendedKeyUsage', 'serverAuth', true
    cert.add_extension factory.create_extension 'subjectAltName', san, false
    cert.add_extension factory.create_extension 'subjectKeyIdentifier', 'hash'
    cert.add_extension factory.create_extension 'authorityKeyIdentifier', 'keyid:always'

    cert.sign ca_key, OpenSSL::Digest::SHA256.new

    [key, cert]
  end

  def self_signed_server_cert key, serial
    cert = base_certificate key.public_key, serial

    cert.subject = OpenSSL::X509::Name.parse '/CN=localhost'
    cert.issuer  = cert.subject

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate  = cert

    cert.add_extension factory.create_extension 'basicConstraints', 'CA:FALSE', true
    cert.add_extension factory.create_extension 'extendedKeyUsage', 'serverAuth', true
    cert.add_extension factory.create_extension 'subjectAltName', 'DNS:localhost', false
    cert.add_extension factory.create_extension 'subjectKeyIdentifier', 'hash'

    cert.sign key, OpenSSL::Digest::SHA256.new

    cert
  end

  def base_certificate public_key, serial
    cert = OpenSSL::X509::Certificate.new
    cert.version    = 2
    cert.serial     = serial
    cert.public_key = public_key
    cert.not_before = Time.now - 60
    cert.not_after  = Time.now + 86_400
    cert
  end

  def write_pem name, cert
    path = File.join @dir, name
    File.write path, cert.to_pem
    path
  end
end

##
# A TLS server bound to the loopback interface only.  It records every
# handshake attempt (success or failure with the error) and every HTTP
# request it receives, providing the on-the-wire evidence for the
# regression tests.

class RecordingTLSServer # :nodoc:
  Handshake = Struct.new :success, :error

  attr_reader :port

  def initialize key:, cert:
    @handshakes         = []
    @requests           = []
    @open_sockets       = []
    @connection_threads = []
    @mutex              = Mutex.new

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = cert
    context.key  = key

    # Force a full handshake with certificate presentation on every
    # connection, so that a resumed session can never skip verification and
    # mask whether changed client settings actually took effect.
    context.options |= OpenSSL::SSL::OP_NO_TICKET
    context.session_cache_mode = OpenSSL::SSL::SSLContext::SESSION_CACHE_OFF

    @context  = context
    @listener = TCPServer.new '127.0.0.1', 0 # loopback only
    @port     = @listener.addr[1]

    @accept_thread = Thread.new { accept_loop }
  end

  def handshakes
    @mutex.synchronize { @handshakes.dup }
  end

  def requests
    @mutex.synchronize { @requests.dup }
  end

  def received_request? pattern
    requests.any? { |request| request =~ pattern }
  end

  def stop
    @listener.close rescue IOError
    @accept_thread.join 5

    @mutex.synchronize { @open_sockets.dup }.each do |socket|
      socket.close rescue nil
    end

    @mutex.synchronize { @connection_threads.dup }.each do |thread|
      thread.join 5
    end
  end

  private

  def accept_loop
    loop do
      socket = @listener.accept
      thread = Thread.new(socket) { |accepted| serve accepted }
      thread.report_on_exception = false
      @mutex.synchronize { @connection_threads << thread }
    end
  rescue IOError, Errno::EBADF
    # listener closed by #stop
  end

  def serve tcp_socket
    ssl = OpenSSL::SSL::SSLSocket.new tcp_socket, @context
    ssl.sync_close = true
    @mutex.synchronize { @open_sockets << ssl }

    begin
      ssl.accept
    rescue OpenSSL::SSL::SSLError, SystemCallError, IOError => error
      record_handshake false, error
      return
    end

    record_handshake true, nil

    while (request = read_request ssl)
      @mutex.synchronize { @requests << request }
      ssl.write "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
    end
  rescue OpenSSL::SSL::SSLError, SystemCallError, IOError
    # connection dropped by the client
  ensure
    ssl.close rescue nil
  end

  def record_handshake success, error
    @mutex.synchronize { @handshakes << Handshake.new(success, error) }
  end

  def read_request ssl
    request = +''

    while (line = ssl.gets "\r\n")
      request << line
      break if line == "\r\n"
    end

    request.empty? ? nil : request
  rescue OpenSSL::SSL::SSLError, SystemCallError, IOError
    nil
  end
end

class TestNetHttpPersistentTLSVerification < Minitest::Test
  ##
  # Credentials sent with every probe request.  If verification fails the
  # server must never see them.

  AUTH_HEADER = 'Bearer tls-regression-probe'

  def self.fixtures
    @fixtures ||= TLSRegressionFixtures.new
  end

  def fixtures
    self.class.fixtures
  end

  def setup
    skip 'OpenSSL is missing' unless HAVE_OPENSSL

    ENV.delete 'http_proxy'
    ENV.delete 'HTTP_PROXY'
    ENV.delete 'http_proxy_user'
    ENV.delete 'HTTP_PROXY_USER'
    ENV.delete 'http_proxy_pass'
    ENV.delete 'HTTP_PROXY_PASS'
    ENV.delete 'no_proxy'
    ENV.delete 'NO_PROXY'

    @http    = Net::HTTP::Persistent.new name: 'tls-verification-regression'
    @servers = []
  end

  def teardown
    @http.shutdown rescue nil
    @servers.each(&:stop) if @servers
  end

  ##
  # ca_file + explicit hostname verification: a valid chain to the CA and a
  # matching hostname must complete the handshake and deliver the request.

  def test_ca_file_valid_chain_and_matching_hostname
    server = start_server key: fixtures.good_key, cert: fixtures.good_cert

    @http.ca_file         = fixtures.ca_file
    @http.verify_hostname = true

    uri      = uri_for server
    response = @http.request uri, authorized_get(uri)

    assert_equal '200', response.code

    handshake = server.handshakes.last
    assert handshake && handshake.success,
           'TLS handshake should have succeeded'
    assert server.received_request?(auth_pattern),
           'server must have received the authorized request over the verified connection'
  end

  ##
  # ca_file: a self-signed server certificate has no chain to the CA, so the
  # handshake itself must fail and no credentials may be sent.

  def test_ca_file_rejects_self_signed_server_certificate
    server = start_server key:  fixtures.self_signed_key,
                          cert: fixtures.self_signed_cert

    @http.ca_file = fixtures.ca_file

    uri   = uri_for server
    error = assert_raises(OpenSSL::SSL::SSLError) do
      @http.request uri, authorized_get(uri)
    end
    assert_match(/certificate verify failed|self.signed/i, error.message)

    wait_for { server.handshakes.any? }

    assert server.handshakes.none?(&:success),
           'handshake must fail for an untrusted self-signed certificate'
    assert_empty server.requests,
                 'credentials must never be sent over an unverified connection'
  end

  ##
  # Default configuration (no ca_file, no cert_store, no verify_mode
  # changes) must also reject a self-signed certificate.

  def test_default_configuration_rejects_self_signed_server_certificate
    server = start_server key:  fixtures.self_signed_key,
                          cert: fixtures.self_signed_cert

    uri = uri_for server
    assert_raises(OpenSSL::SSL::SSLError) do
      @http.request uri, authorized_get(uri)
    end

    wait_for { server.handshakes.any? }

    assert server.handshakes.none?(&:success)
    assert_empty server.requests
  end

  ##
  # ca_file + explicit VERIFY_PEER: the chain to our CA is valid but the
  # certificate is for a different hostname.  The TLS handshake completes
  # (the chain verifies), then the hostname check must abort the connection
  # before any request is sent.

  def test_valid_chain_with_non_matching_hostname_is_rejected
    skip 'net/http does not support verify_hostname' unless
      Net::HTTP.method_defined?(:verify_hostname=)

    server = start_server key:  fixtures.wrong_host_key,
                          cert: fixtures.wrong_host_cert

    @http.ca_file     = fixtures.ca_file
    @http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    # verify_hostname is deliberately left at its default: the default must
    # be secure.

    uri   = uri_for server
    error = assert_raises(OpenSSL::SSL::SSLError) do
      @http.request uri, authorized_get(uri)
    end
    assert_match(/does not match|hostname/i, error.message)

    wait_for { server.handshakes.any? }

    assert server.handshakes.last.success,
           'the chain is valid, so the TLS handshake itself completes'
    assert_empty server.requests,
                 'hostname mismatch must abort before any request (and its credentials) is sent'
  end

  ##
  # Counterpart to the previous test: with verify_hostname disabled the
  # same valid-chain/wrong-hostname certificate is accepted.  This proves
  # the rejection above came from the hostname check, not the chain check.

  def test_valid_chain_with_wrong_hostname_passes_only_when_hostname_check_disabled
    skip 'net/http does not support verify_hostname' unless
      Net::HTTP.method_defined?(:verify_hostname=)

    server = start_server key:  fixtures.wrong_host_key,
                          cert: fixtures.wrong_host_cert

    @http.ca_file         = fixtures.ca_file
    @http.verify_hostname = false

    uri      = uri_for server
    response = @http.request uri, authorized_get(uri)

    assert_equal '200', response.code
    assert server.received_request?(auth_pattern)
  end

  ##
  # cert_store: a store holding our CA must verify the good server
  # certificate.

  def test_cert_store_valid_chain_and_matching_hostname
    store = OpenSSL::X509::Store.new
    store.add_cert fixtures.ca_cert

    @http.cert_store = store

    server = start_server key: fixtures.good_key, cert: fixtures.good_cert

    uri      = uri_for server
    response = @http.request uri, authorized_get(uri)

    assert_equal '200', response.code
    assert server.received_request?(auth_pattern)
  end

  ##
  # cert_store: the same store must reject the self-signed certificate.

  def test_cert_store_rejects_self_signed_server_certificate
    store = OpenSSL::X509::Store.new
    store.add_cert fixtures.ca_cert

    @http.cert_store = store

    server = start_server key:  fixtures.self_signed_key,
                          cert: fixtures.self_signed_cert

    uri = uri_for server
    assert_raises(OpenSSL::SSL::SSLError) do
      @http.request uri, authorized_get(uri)
    end

    wait_for { server.handshakes.any? }

    assert server.handshakes.none?(&:success)
    assert_empty server.requests
  end

  ##
  # ca_file + verify_callback: the callback must run during the real
  # handshake and see the chain preverify against our CA.

  def test_verify_callback_is_invoked_during_real_handshake
    server = start_server key: fixtures.good_key, cert: fixtures.good_cert

    calls = []

    @http.ca_file = fixtures.ca_file
    @http.verify_callback = proc do |preverify_ok, store_context|
      calls << [preverify_ok, store_context]
      preverify_ok
    end

    uri      = uri_for server
    response = @http.request uri, authorized_get(uri)

    assert_equal '200', response.code
    refute_empty calls, 'verify_callback must run during the real handshake'
    assert calls.all? { |preverify_ok, _| preverify_ok },
           'every chain element should preverify against our CA'
    assert calls.any? { |_, ctx|
             ctx.is_a?(OpenSSL::X509::StoreContext) &&
               ctx.current_cert.to_der == fixtures.good_cert.to_der
           }, 'the callback should see the server certificate being verified'
  end

  ##
  # ca_file + verify_callback: a callback that rejects must fail the
  # handshake even though the chain is otherwise valid.

  def test_verify_callback_can_reject_an_otherwise_valid_chain
    server = start_server key: fixtures.good_key, cert: fixtures.good_cert

    @http.ca_file = fixtures.ca_file
    @http.verify_callback = proc { |_preverify_ok, _store_context| false }

    uri = uri_for server
    assert_raises(OpenSSL::SSL::SSLError) do
      @http.request uri, authorized_get(uri)
    end

    wait_for { server.handshakes.any? }

    assert server.handshakes.none?(&:success)
    assert_empty server.requests
  end

  ##
  # Pooled connections: after a connection is established and returned to
  # the pool, changing the CA must take effect on the next request.  The
  # pooled connection must not carry the old trust settings over.

  def test_pooled_connection_is_reverified_after_ca_change
    server = start_server key: fixtures.good_key, cert: fixtures.good_cert

    @http.ca_file = fixtures.ca_file

    uri      = uri_for server
    response = @http.request uri, authorized_get(uri)

    assert_equal '200', response.code
    assert_equal 1, server.requests.size

    generation = @http.ssl_generation
    @http.ca_file = fixtures.untrusted_ca_file
    assert_operator @http.ssl_generation, :>, generation,
                    'changing ca_file must invalidate pooled TLS connections'

    error = assert_raises(OpenSSL::SSL::SSLError) do
      @http.request uri, authorized_get(uri)
    end
    assert_match(/certificate verify failed/i, error.message)

    wait_for { server.handshakes.size >= 2 }

    refute server.handshakes.last.success,
           'the reconnected pooled connection must verify against the new CA'
    assert_equal 1, server.requests.size,
                 'no further request may leak after the CA stopped trusting the server'
  end

  ##
  # Pooled connections: a connection opened with verification disabled must
  # pick up verification once the caller enables it.

  def test_pooled_connection_picks_up_verification_enabled_after_verify_none
    server = start_server key:  fixtures.self_signed_key,
                          cert: fixtures.self_signed_cert

    @http.verify_mode = OpenSSL::SSL::VERIFY_NONE # caller-chosen, insecure

    uri      = uri_for server
    response = @http.request uri, authorized_get(uri)

    assert_equal '200', response.code
    assert_equal 1, server.requests.size

    @http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    @http.ca_file     = fixtures.ca_file

    assert_raises(OpenSSL::SSL::SSLError) do
      @http.request uri, authorized_get(uri)
    end

    wait_for { server.handshakes.size >= 2 }

    assert_equal 1, server.handshakes.count(&:success),
                 'only the first (unverified) connection may complete a handshake'
    assert_equal 1, server.requests.size,
                 'enabling verification must stop further requests to the untrusted peer'
  end

  ##
  # RISK DEMONSTRATION -- this is NOT a verification pass.
  #
  # verify_mode = VERIFY_NONE is a caller choice that disables chain and
  # hostname checks.  This test documents the consequence honestly: the
  # handshake "succeeds" against a certificate nothing trusts, and the
  # client's credentials are delivered to that unverified peer.

  def test_verify_none_sends_credentials_to_unverified_peer
    server = start_server key:  fixtures.self_signed_key,
                          cert: fixtures.self_signed_cert

    @http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    uri      = uri_for server
    response = @http.request uri, authorized_get(uri)

    assert_equal '200', response.code
    assert server.received_request?(auth_pattern),
           'RISK: with VERIFY_NONE the client sends credentials to an unverified peer'
  end

  ##
  # Transport-double check only: verifies that settings propagate from
  # Net::HTTP::Persistent to the Net::HTTP connection object.  This is NOT
  # verification evidence -- the handshake tests above provide that.

  def test_ssl_settings_propagate_to_connection_object
    callback = proc { |preverify_ok, _ctx| preverify_ok }
    store    = OpenSSL::X509::Store.new
    store.add_cert fixtures.ca_cert

    @http.ca_file         = fixtures.ca_file
    @http.verify_callback = callback
    @http.verify_depth    = 2

    if Net::HTTP.method_defined?(:verify_hostname=)
      @http.verify_hostname = true
    end

    connection = Net::HTTP.new 'localhost', 443
    @http.ssl connection

    assert connection.use_ssl?
    assert_equal OpenSSL::SSL::VERIFY_PEER, connection.verify_mode
    assert_equal fixtures.ca_file, connection.ca_file
    assert_equal callback, connection.verify_callback
    assert_equal 2, connection.verify_depth
    assert_equal true, connection.verify_hostname if
      connection.respond_to?(:verify_hostname)

    @http.cert_store = store

    connection = Net::HTTP.new 'localhost', 443
    @http.ssl connection

    assert_same store, connection.cert_store
  end

  private

  def start_server key:, cert:
    server = RecordingTLSServer.new key: key, cert: cert
    @servers << server
    server
  rescue Errno::EPERM => e
    skip "loopback TCP bind not permitted in this environment: #{e.message}"
  end

  def uri_for server
    URI "https://localhost:#{server.port}/protected"
  end

  def authorized_get uri
    request = Net::HTTP::Get.new uri
    request['Authorization'] = AUTH_HEADER
    request
  end

  def auth_pattern
    /Authorization: #{Regexp.escape AUTH_HEADER}/
  end

  def wait_for timeout: 5
    deadline = Time.now + timeout

    until yield
      flunk 'timed out waiting for the TLS server' if Time.now > deadline
      sleep 0.01
    end
  end
end

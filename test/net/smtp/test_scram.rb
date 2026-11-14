# frozen_string_literal: true

require 'net/smtp'
require 'test/unit'

unless defined?(OpenSSL::VERSION)
  warn "#{__FILE__}: openssl library not loaded; skipping"
  return
end

module Net
  class TestSCRAM < Test::Unit::TestCase
    SERVER_KEY  = File.expand_path('../fixtures/server.key', __dir__)
    SERVER_CERT = File.expand_path('../fixtures/server.crt', __dir__)

    USER = 'account'
    PASSWORD = 'password'
    SALT = 'salt-scram-256'.b
    ITERATIONS = 4096
    DIGEST = 'SHA256'
    MIN_ITERATIONS = Net::SMTP::AuthSCRAM::MIN_ITERATIONS
    MAX_ITERATIONS = Net::SMTP::AuthSCRAM::MAX_ITERATIONS

    # A Net::SMTP whose TCP transport is one end of a socket pair and whose
    # TLS upgrade runs in-process, exercising a real TLS handshake without
    # binding a network port.  The client-side SSL endpoint is created and
    # connected before #start; tcp_socket yields it directly (so it is never
    # double-wrapped) and tlsconnect simply returns the same object, matching
    # the pattern in test_starttls.rb.
    class PairedSMTP < SMTP
      def initialize(transport, use_tls:)
        @transport = transport
        super('localhost', 25, starttls: false)
        enable_tls if use_tls
      end

      def tcp_socket(*)
        @transport
      end

      def tlsconnect(_socket, _context)
        @transport
      end
    end

    # Minimal, independent SCRAM-SHA-256 server.  Every value is computed
    # from the RFC 5802 / RFC 7677 formulas itself; it never calls the
    # client code and keeps its own copy of the transcript.
    class ReferenceScramServer
      attr_reader :commands, :mail_seen

      def initialize(io, mechanism:, cbind_type: nil, cbind_data: ''.b,
                     iterations: ITERATIONS, tamper: nil)
        @io = io
        @mechanism = mechanism
        @cbind_type = cbind_type
        @cbind_data = cbind_data
        @iterations = iterations
        @tamper = tamper
        @commands = []
        @mail_seen = false
        @server_nonce_tail = 'SERVER-NONCE-0123456789'
      end

      def run
        @io.puts "220 ready\r\n"
        while (line = @io.gets)
          line = line.chomp
          @commands << line.dup
          case line
          when /\AEHLO / then advertise
          when /\AAUTH / then handle_auth(line)
          when /\AMAIL FROM:/
            @mail_seen = true
            @io.puts "250 2.1.0 Ok\r\n"
          when /\ARCPT TO:/ then @io.puts "250 2.1.0 Ok\r\n"
          when 'DATA'
            @io.puts "354 end\r\n"
            @io.gets
            @io.puts "250 queued\r\n"
          when 'QUIT'
            @io.puts "221 bye\r\n"
            break
          else
            @io.puts "502 not recognized\r\n"
          end
        end
      rescue Errno::ECONNRESET, Errno::EPIPE, IOError, OpenSSL::SSL::SSLError
        nil
      end

      private

      def advertise
        @io.puts "250-fakeserver\r\n"
        @io.puts "250-AUTH #{@mechanism}\r\n"
        @io.puts "250 8BITMIME\r\n"
      end

      def b64(str) = [str].pack('m0')
      def hmac(key, data) = OpenSSL::HMAC.digest(DIGEST, key, data)

      def salted_password
        OpenSSL::KDF.pbkdf2_hmac(PASSWORD, salt: SALT, iterations: @iterations,
                                 length: 32, hash: DIGEST)
      end

      def handle_auth(line)
        gs2_and_bare = line.split[2].unpack1('m0')
        _gs2_header, client_first_bare = split_gs2(gs2_and_bare)
        cnonce = attr(client_first_bare, 'r')
        full_nonce = "#{cnonce}#{@server_nonce_tail}"

        server_first =
          if @tamper == :echo_nonce
            "r=#{cnonce},s=#{b64(SALT)},i=#{@iterations}"
          elsif @tamper == :duplicate_attr
            "r=#{full_nonce},r=#{full_nonce},s=#{b64(SALT)},i=#{@iterations}"
          elsif @tamper == :bad_salt_base64
            "r=#{full_nonce},s=AAA=BBB=,i=#{@iterations}"
          elsif @tamper == :missing_salt
            "r=#{full_nonce},i=#{@iterations}"
          elsif @tamper == :mandatory_extension
            "m=ext1,r=#{full_nonce},s=#{b64(SALT)},i=#{@iterations}"
          else
            "r=#{full_nonce},s=#{b64(SALT)},i=#{@iterations}"
          end
        @io.puts "334 #{b64(server_first)}\r\n"

        client_final_line = @io.gets or return
        @commands << client_final_line.chomp.dup
        client_final = client_final_line.chomp.unpack1('m0')
        without_proof, proof_b64 = split_proof(client_final)

        expected_gs2 = @cbind_type ? "p=#{@cbind_type},," : 'n,,'
        expected_cbind = b64(expected_gs2 + @cbind_data)
        unless attr(without_proof, 'c') == expected_cbind
          return fail_exchange('channel-bindings-dont-match')
        end

        auth_message = "#{client_first_bare},#{server_first},#{without_proof}"
        sp = salted_password
        client_key = hmac(sp, 'Client Key')
        stored_key = OpenSSL::Digest.digest(DIGEST, client_key)
        client_signature = hmac(stored_key, auth_message)
        recovered = xor(proof_b64.unpack1('m0'), client_signature)

        unless OpenSSL::Digest.digest(DIGEST, recovered) == stored_key
          return fail_exchange('invalid-proof')
        end

        verifier = hmac(hmac(sp, 'Server Key'), auth_message)
        verifier = OpenSSL::Random.random_bytes(verifier.bytesize) if @tamper == :bad_verifier

        if @tamper == :skip_verifier
          # A bare 235 with no 334 server-final-message: illegal for a
          # client that still needs to verify the server.
          @io.puts "235 2.7.0 Authentication successful\r\n"
          return
        end

        @io.puts "334 #{b64("v=#{b64(verifier)}")}\r\n"
        @io.gets # client empty SASL response
        @io.puts "235 2.7.0 Authentication successful\r\n"
      end

      def fail_exchange(reason)
        @io.puts "334 #{b64("e=#{reason}")}\r\n"
        @io.gets
        @io.puts "535 5.7.8 authentication failure\r\n"
      end

      def split_gs2(message)
        prefix, _, bare = message.partition(',,')
        ["#{prefix},,", bare]
      end

      def split_proof(message)
        idx = message.rindex(',p=')
        [message[0...idx], message[(idx + 3)..]]
      end

      def attr(message, name)
        message.split(',').find { |p| p.start_with?("#{name}=") }&.split('=', 2)&.last
      end

      def xor(left, right)
        left.bytes.zip(right.bytes).map { |a, b| a ^ b }.pack('C*')
      end
    end

    def teardown
      @server_thread&.exit&.join
      @client_socket&.close
      @server_socket&.close
    end

    # Builds a paired connection.  When tls_version is given, both ends of a
    # real TLS handshake are created up front and connected concurrently;
    # the server then derives its channel binding from that same live
    # connection before any SMTP traffic flows.  Returns the client-side
    # SSLSocket (or the raw socket) and a shared reference hash.
    def start_pair(mechanism:, tls_version: OpenSSL::SSL::TLS1_3_VERSION,
                   cbind_type: nil, cbind_override: nil, **opts)
      raw_server, raw_client = UNIXSocket.pair
      @server_socket, @client_socket = raw_server, raw_client
      server_ref = {}

      client_tls = nil
      if tls_version
        server_ctx = OpenSSL::SSL::SSLContext.new
        server_ctx.cert = OpenSSL::X509::Certificate.new(File.read(SERVER_CERT))
        server_ctx.key = OpenSSL::PKey.read(File.read(SERVER_KEY))
        server_ctx.min_version = server_ctx.max_version = tls_version
        server_tls = OpenSSL::SSL::SSLSocket.new(raw_server, server_ctx)

        client_ctx = OpenSSL::SSL::SSLContext.new
        client_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        client_ctx.min_version = client_ctx.max_version = tls_version
        client_tls = OpenSSL::SSL::SSLSocket.new(raw_client, client_ctx)

        handshake = Thread.new { server_tls.accept }
        client_tls.connect
        handshake.join
        server_ref[:tls] = server_tls
      end

      @server_thread = Thread.new do
        io = server_ref[:tls] || raw_server
        tls = server_ref[:tls]
        cbind_data =
          if cbind_override
            cbind_override.call(tls)
          elsif cbind_type
            derive_binding(tls, cbind_type)
          else
            ''.b
          end

        server = ReferenceScramServer.new(
          io, mechanism: mechanism, cbind_type: cbind_type,
              cbind_data: cbind_data, **opts
        )
        server_ref[:server] = server
        server.run
      end

      [client_tls || raw_client, server_ref]
    end

    def derive_binding(tls, type)
      case type
      when 'tls-exporter' then tls.export_keying_material('EXPORTER-Channel-Binding', 32, '')
      when 'tls-unique'
        # tls-unique is the first Finished message of the handshake, i.e.
        # the client's Finished (RFC 5929 3.1).  This helper runs on the
        # server side, where the client Finished is #peer_finished_message;
        # the client code under test uses #finished_message, so both derive
        # the same bytes independently.
        tls.peer_finished_message
      when 'tls-server-end-point'
        # This runs on the TLS server side, where #peer_cert refers to the
        # (absent) client certificate.  The binding hashes the server's own
        # certificate exactly as presented in its Certificate message.
        OpenSSL::Digest::SHA256.digest(
          OpenSSL::X509::Certificate.new(File.read(SERVER_CERT)).to_der)
      end
    end

    # Blocks until the server thread has published the given reference key
    # (for example, its reference SCRAM server), avoiding a read/write race.
    def wait_for(ref, key, timeout: 5)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      sleep(0.001) until ref.key?(key) || Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      assert ref.key?(key), "timed out waiting for server reference #{key}"
      ref[key]
    end

    def build_smtp(transport, _tls_version = nil)
      use_tls = transport.is_a?(OpenSSL::SSL::SSLSocket)
      smtp = PairedSMTP.new(transport, use_tls: use_tls)
      smtp.open_timeout = 5
      smtp.read_timeout = 5
      smtp
    end

    def start_and_finish(transport, version, authtype, secret: PASSWORD)
      smtp = build_smtp(transport, version)
      smtp.start(user: USER, secret: secret, authtype: authtype)
      assert smtp.started?
      smtp.finish
      smtp
    end

    # ---- Legitimate logins ------------------------------------------------

    def test_bare_scram_sha256_login
      socket, = start_pair(mechanism: 'SCRAM-SHA-256')
      assert_nothing_raised { start_and_finish(socket, OpenSSL::SSL::TLS1_3_VERSION, :scram_sha_256) }
    end

    def test_plus_tls_exporter_login_tls13
      socket, = start_pair(mechanism: 'SCRAM-SHA-256-PLUS', cbind_type: 'tls-exporter')
      start_and_finish(socket, OpenSSL::SSL::TLS1_3_VERSION, :scram_sha_256_tls_exporter)
    end

    def test_plus_tls_unique_login_tls12
      socket, = start_pair(mechanism: 'SCRAM-SHA-256-PLUS',
                           tls_version: OpenSSL::SSL::TLS1_2_VERSION,
                           cbind_type: 'tls-unique')
      start_and_finish(socket, OpenSSL::SSL::TLS1_2_VERSION, :scram_sha_256_tls_unique)
    end

    def test_plus_tls_server_end_point_login
      socket, = start_pair(mechanism: 'SCRAM-SHA-256-PLUS',
                           cbind_type: 'tls-server-end-point')
      start_and_finish(socket, OpenSSL::SSL::TLS1_3_VERSION,
                       :scram_sha_256_tls_server_end_point)
    end

    # ---- Channel binding conditions / no silent downgrade -----------------

    def test_plus_rejected_without_tls
      @server_socket, @client_socket = UNIXSocket.pair
      thread = Thread.new(@server_socket) do |raw|
        ReferenceScramServer.new(raw, mechanism: 'SCRAM-SHA-256-PLUS',
                                 cbind_type: 'tls-exporter').run
      end
      smtp = PairedSMTP.new(@client_socket, use_tls: false)
      smtp.disable_tls
      smtp.read_timeout = 5
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256_tls_exporter)
      end
      assert_match(/TLS connection/, error.message)
      assert ! smtp.started?
      thread.exit
    end

    def test_tls_exporter_rejected_on_tls12
      socket, = start_pair(mechanism: 'SCRAM-SHA-256-PLUS',
                           tls_version: OpenSSL::SSL::TLS1_2_VERSION,
                           cbind_type: 'tls-exporter')
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_2_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256_tls_exporter)
      end
      assert_match(/TLS 1.3/, error.message)
    end

    def test_tls_unique_rejected_on_tls13
      socket, = start_pair(mechanism: 'SCRAM-SHA-256-PLUS', cbind_type: 'tls-unique')
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256_tls_unique)
      end
      assert_match(/not defined for TLS 1.3/, error.message)
    end

    def test_plus_does_not_downgrade_to_bare
      # Server offers only the bare mechanism; a -PLUS client must fail,
      # not silently authenticate without channel binding.
      socket, = start_pair(mechanism: 'SCRAM-SHA-256',
                           tls_version: OpenSSL::SSL::TLS1_2_VERSION)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_2_VERSION)
      assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256_tls_exporter)
      end
      assert ! smtp.started?
    end

    # ---- Proof bound to the actual connection -----------------------------

    def test_exporter_binding_differs_between_connections
      _socket_a, ref_a = start_pair(mechanism: 'SCRAM-SHA-256-PLUS', cbind_type: 'tls-exporter')
      _socket_b, ref_b = start_pair(mechanism: 'SCRAM-SHA-256-PLUS', cbind_type: 'tls-exporter')
      wait_for(ref_a, :tls)
      wait_for(ref_b, :tls)
      assert_not_equal derive_binding(ref_a[:tls], 'tls-exporter'),
                       derive_binding(ref_b[:tls], 'tls-exporter')
    end

    def test_proof_from_other_connection_rejected
      # Connection A is a fully valid -PLUS login; capture its real binding.
      socket_a, ref_a = start_pair(mechanism: 'SCRAM-SHA-256-PLUS', cbind_type: 'tls-exporter')
      start_and_finish(socket_a, OpenSSL::SSL::TLS1_3_VERSION, :scram_sha_256_tls_exporter)
      binding_a = derive_binding(ref_a[:tls], 'tls-exporter')

      # Connection B's server is handed connection A's channel binding, so
      # the client's proof (bound to B's own TLS connection) cannot match.
      socket_b, ref_b = start_pair(mechanism: 'SCRAM-SHA-256-PLUS',
                                   cbind_type: 'tls-exporter',
                                   cbind_override: ->(_tls) { binding_a })
      smtp_b = build_smtp(socket_b, OpenSSL::SSL::TLS1_3_VERSION)
      assert_raise(Net::SMTPAuthenticationError) do
        smtp_b.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256_tls_exporter)
      end
      assert ! smtp_b.started?
      assert ! ref_b[:server].mail_seen
    end

    # ---- Malformed / hostile server messages ------------------------------

    def test_duplicate_attribute_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', tamper: :duplicate_attr)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
    end

    def test_malformed_salt_base64_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', tamper: :bad_salt_base64)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      assert_match(/base64/, error.message)
    end

    def test_missing_salt_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', tamper: :missing_salt)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      assert_match(/missing attribute s/, error.message)
    end

    def test_mandatory_extension_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', tamper: :mandatory_extension)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      assert_match(/extension/, error.message)
    end

    def test_nonce_not_extended_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', tamper: :echo_nonce)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      assert_match(/nonce/, error.message)
    end

    def test_iteration_below_minimum_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', iterations: MIN_ITERATIONS - 1)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      assert_match(/minimum/, error.message)
    end

    def test_iteration_above_maximum_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', iterations: MAX_ITERATIONS + 1)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
    end

    def test_bad_server_verifier_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', tamper: :bad_verifier)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      error = assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      assert_match(/server proof/, error.message)
      assert ! smtp.started?
    end

    def test_success_without_verifier_rejected
      socket, = start_pair(mechanism: 'SCRAM-SHA-256', tamper: :skip_verifier)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      assert ! smtp.started?
    end

    def test_no_mail_sent_on_failure
      socket, ref = start_pair(mechanism: 'SCRAM-SHA-256', iterations: 1)
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      assert_raise(Net::SCRAMError) do
        smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      end
      server = ref[:server]
      assert_not_nil server
      assert ! server.mail_seen
      assert_equal([], server.commands.grep(/\AMAIL/))
    end

    def test_no_password_or_derived_key_in_log
      require 'stringio'
      socket, = start_pair(mechanism: 'SCRAM-SHA-256')
      smtp = build_smtp(socket, OpenSSL::SSL::TLS1_3_VERSION)
      smtp.set_debug_output(StringIO.new(log = +''))
      smtp.start(user: USER, secret: PASSWORD, authtype: :scram_sha_256)
      salted = OpenSSL::KDF.pbkdf2_hmac(PASSWORD, salt: SALT, iterations: ITERATIONS,
                                        length: 32, hash: DIGEST)
      assert_not_match(/#{Regexp.escape(PASSWORD)}/, log)
      assert_not_match(/#{salted.unpack1('H*')}/, log)
      assert_not_match(/#{Regexp.escape([salted].pack('m0'))}/, log)
      smtp.finish
    end
  end
end

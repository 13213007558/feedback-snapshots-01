# frozen_string_literal: true

require_relative "../../lib/helper"

# This file is for directly testing both implicit TLS connection and the
# STARTTLS command.
#
# Note that, although the default for test connections is plain-text, some other
# test files also use TLS connections when the TLS state affects the behavior
# of the methods being tested.
class IMAP_TLS_Test < Net::IMAP::TestCase
  CA_FILE = File.expand_path("../fixtures/cacert.pem", __dir__)
  SERVER_KEY = File.expand_path("../fixtures/server.key", __dir__)
  SERVER_CERT = File.expand_path("../fixtures/server.crt", __dir__)

  include Net::IMAP::TestCase::SimpleTCPServerHelper

  if defined?(OpenSSL)
    def test_imaps_unknown_ca
      assert_local_raise(OpenSSL::SSL::SSLError) do
        imaps_test do |port|
          begin
            Net::IMAP.new("localhost",
                          :port => port,
                          :ssl => true)
          rescue SystemCallError
            skip $!
          end
        end
      end
    end

    def assert_tls_unstarted(imap)  = assert_tls_stage imap, :unstarted
    def assert_tls_incomplete(imap) = assert_tls_stage imap, :incomplete
    def assert_tls_unverified(imap) = assert_tls_stage imap, :unverified
    def assert_tls_verified(imap)   = assert_tls_stage imap, :verified

    STAGES = %i[unstarted incomplete unverified verified].freeze

    INSPECT_INCLUDES = {
      unstarted:  " PLAINTEXT (TLS NOT STARTED) disconnected",
      incomplete: " TLS (NOT ESTABLISHED) disconnected",
      unverified: " TLS (NOT VERIFIED) disconnected",
      verified:   " TLS disconnected",
    }

    def assert_tls_stage(imap, stage)
      socket, connected, verified = Array.new(3) { _1 < STAGES.index(stage) }
      assert imap.ssl_ctx_params.frozen?, "#ssl_ctx_params should be frozen"
      assert_kind_of Hash, imap.ssl_ctx_params,
                     "#ssl_ctx_params should be a Hash"
      assert_kind_of OpenSSL::SSL::SSLContext, imap.ssl_ctx,
                     "#ssl_ctx should be an OpenSSL::SSL::SSLContext"
      assert_equal socket, imap.tls_socket?,
                   "#tls_socket? should be #{socket}"
      assert_equal connected, imap.tls_connected?,
                   "#tls_connected? should be #{connected}"
      assert_equal verified, imap.tls_verified?,
                   "#tls_verified? should be #{verified}"
      assert_include imap.inspect, INSPECT_INCLUDES.fetch(stage)
    end

    def test_imaps_with_ca_file
      # Assert verified *after* the imaps_test and assert_nothing_raised blocks.
      # Otherwise, failures can't logout and need to wait for the timeout.
      verified, imap = :unknown, nil
      ssl_ctx_params = { ca_file: CA_FILE }
      assert_nothing_raised do
        begin
          imaps_test do |port|
            imap = Net::IMAP.new("localhost",
                                port: port,
                                ssl: ssl_ctx_params)
            verified = imap.tls_verified?
            imap
          rescue SystemCallError
            skip $!
          end
        rescue OpenSSL::SSL::SSLError => e
          raise e unless /darwin/ =~ RUBY_PLATFORM
        end
      end
      assert_equal true, verified
      assert_tls_verified imap
      assert_equal ssl_ctx_params, imap.ssl_ctx_params
      refute_same  ssl_ctx_params, imap.ssl_ctx_params
      refute ssl_ctx_params.frozen?
      assert_equal(CA_FILE, imap.ssl_ctx.ca_file)
      assert_equal(OpenSSL::SSL::VERIFY_PEER, imap.ssl_ctx.verify_mode)
      assert imap.ssl_ctx.verify_hostname
    end

    def test_imaps_verify_none
      # Assert verified *after* the imaps_test and assert_nothing_raised blocks.
      # Otherwise, failures can't logout and need to wait for the timeout.
      verified, imap = :unknown, nil
      assert_nothing_raised do
        begin
          imaps_test do |port|
            imap = Net::IMAP.new(
              server_addr,
              port: port,
              ssl: { :verify_mode => OpenSSL::SSL::VERIFY_NONE }
            )
            verified = imap.tls_verified?
            imap
          end
        rescue OpenSSL::SSL::SSLError => e
          raise e unless /darwin/ =~ RUBY_PLATFORM
        end
      end
      assert_equal false, verified
      assert_tls_unverified imap
      assert_equal({verify_mode: OpenSSL::SSL::VERIFY_NONE},
                   imap.ssl_ctx_params)
      assert_equal(nil, imap.ssl_ctx.ca_file)
      assert_equal(OpenSSL::SSL::VERIFY_NONE, imap.ssl_ctx.verify_mode)
    end

    def test_imaps_post_connection_check
      assert_local_raise(OpenSSL::SSL::SSLError) do
        imaps_test do |port|
          # server_addr is different from the hostname in the certificate,
          # so the following code should raise a SSLError.
          Net::IMAP.new(server_addr,
                        :port => port,
                        :ssl => { :ca_file => CA_FILE })
        end
      end
    end

    def test_starttls_unknown_ca
      omit "This test is not working with Windows" if RUBY_PLATFORM =~ /mswin|mingw/

      imap = nil
      ex = nil
      starttls_test do |port|
        imap = Net::IMAP.new("localhost", port: port)
        begin
          imap.starttls
        rescue => ex
        end
        imap
      end
      assert_kind_of(OpenSSL::SSL::SSLError, ex)
      assert_local_backtrace ex
      assert_tls_incomplete imap
      assert_equal({}, imap.ssl_ctx_params)
      assert_equal(nil, imap.ssl_ctx.ca_file)
      assert_equal(OpenSSL::SSL::VERIFY_PEER, imap.ssl_ctx.verify_mode)
    end

    def test_starttls
      initial_verified, initial_ctx, initial_params = :unknown, :unknown, :unknown
      imap = nil
      starttls_test do |port|
        imap = Net::IMAP.new("localhost", :port => port)
        initial_verified = imap.tls_verified?
        initial_params   = imap.ssl_ctx_params
        initial_ctx      = imap.ssl_ctx
        imap.starttls(:ca_file => CA_FILE)
        imap
      end
      assert_equal false, initial_verified
      assert_equal false, initial_params
      assert_equal nil,   initial_ctx
      assert_tls_verified imap
      assert_equal({ca_file: CA_FILE}, imap.ssl_ctx_params)
    rescue SystemCallError
      skip $!
    ensure
      if imap && !imap.disconnected?
        imap.disconnect
      end
    end

    def test_starttls_stripping_not_ok
      imap = nil
      server = create_tcp_server
      port = server.addr[1]
      start_server do
        sock = server.accept
        begin
          sock.print("* OK test server\r\n")
          sock.gets
          sock.print("RUBY0001 BUG unhandled command\r\n")
        ensure
          sock.close
          server.close
        end
      end
      begin
        imap = Net::IMAP.new("localhost", :port => port)
        assert_reraised(Net::IMAP::InvalidResponseError, imap:) do
          imap.starttls(:ca_file => CA_FILE)
        end
        assert imap.disconnected?
      ensure
        imap.disconnect if imap && !imap.disconnected?
      end

      assert_tls_unstarted imap
      assert_equal({ca_file: CA_FILE},        imap.ssl_ctx_params)
      assert_equal(CA_FILE,                   imap.ssl_ctx.ca_file)
      assert_equal(OpenSSL::SSL::VERIFY_PEER, imap.ssl_ctx.verify_mode)
    end

    def test_starttls_stripping_ok_sent_before_response
      # to coordinate between threads (better than sleep)
      server_to_client, client_to_server = Queue.new, Queue.new
      rcvr_to_client = Queue.new
      imap = nil
      server = create_tcp_server
      port = server.addr[1]
      start_server do
        sock = server.accept
        begin
          sock.print("* OK test server\r\n")
          assert_equal :send_malicious_response, client_to_server.pop
          sock.print("RUBY0001 OK hahaha, fooled you!\r\n")
          server_to_client << :malicious_response_sent
          sock.gets
        ensure
          sock.close
          server.close
        end
      end
      timeout = 5
      timeout *= EnvUtil.timeout_scale || 1 if defined?(EnvUtil.timeout_scale)
      begin
        Timeout.timeout(timeout) do
          imap = Net::IMAP.new("localhost", :port => port)
          imap.add_response_handler do |resp| rcvr_to_client << resp end
          client_to_server << :send_malicious_response
          assert_equal :malicious_response_sent, server_to_client.pop
          # Wait until the receive thread has parsed the injected response and
          # stored it in @tagged_responses, so finish_sending_command can see it.
          # (handle_response stores the tagged response before calling handlers.)
          rcvr_to_client.pop
          assert_local_raise(Net::IMAP::InvalidTaggedResponseError) do
            imap.starttls(:ca_file => CA_FILE)
          end
          assert imap.disconnected?
        end
      ensure
        imap.disconnect if imap && !imap.disconnected?
      end
      assert_tls_unstarted imap
      assert_equal({ca_file: CA_FILE},        imap.ssl_ctx_params)
      assert_equal(CA_FILE,                   imap.ssl_ctx.ca_file)
      assert_equal(OpenSSL::SSL::VERIFY_PEER, imap.ssl_ctx.verify_mode)
    end

    # An in-memory transport lets us control the exact interleaving of
    # responses, without waiting on a real network or a real mail service.
    #
    # It records the byte offset where TLS was started and every write, so
    # tests can assert that STARTTLS switched protocols immediately after the
    # matching tagged response, and only after _that_ response.
    class MemoryTransport
      attr_reader :writes, :read_bytes, :tls_starts

      def initialize(greeting)
        @monitor     = Monitor.new
        @read_cond   = @monitor.new_cond
        @write_cond  = @monitor.new_cond
        @buffer      = +""
        @closed      = false
        @writes      = []
        @read_bytes  = 0
        @tls_starts  = []
        feed(greeting)
      end

      def feed(data)
        synchronize do
          @buffer << data
          @read_cond.broadcast
        end
      end

      def wait_until(timeout: 5)
        timeout *= EnvUtil.timeout_scale || 1 if defined?(EnvUtil.timeout_scale)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        synchronize do
          until yield
            now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            remaining = deadline - now
            flunk "timed out waiting for transport" if remaining <= 0
            @write_cond.wait(remaining)
          end
        end
      end

      def gets(separator = "\n", _limit = nil)
        synchronize do
          loop do
            if (index = @buffer.index(separator))
              line = @buffer.slice!(0, index + separator.bytesize)
              @read_bytes += line.bytesize
              return line
            end
            return nil if @closed
            @read_cond.wait
          end
        end
      end

      def print(data)
        synchronize do
          raise IOError, "closed stream" if @closed
          @writes << data
          @write_cond.broadcast
        end
        data.bytesize
      end

      def to_io; self end

      def shutdown(*)
        synchronize do
          @closed = true
          @read_cond.broadcast
          @write_cond.broadcast
        end
      end

      def close
        synchronize do
          @closed = true
          @read_cond.broadcast
          @write_cond.broadcast
        end
      end

      def closed?; synchronize { @closed } end

      def record_tls_start
        synchronize do
          @tls_starts << {read_bytes: @read_bytes, writes: @writes.dup.freeze}
        end
      end

      def write_string; synchronize { @writes.join } end

      private

      def synchronize(&) = @monitor.synchronize(&)
    end

    class MemoryIMAP < Net::IMAP
      def initialize(transport)
        @transport = transport
        super("memory.invalid", port: 143)
      end

      private

      def tcp_socket(*) = @transport

      def start_tls_session
        @transport.record_tls_start
      end
    end

    def run_starttls_on_memory_transport(transport)
      imap = MemoryIMAP.new(transport)
      error = nil
      client = Thread.new do
        imap.starttls(verify_mode: OpenSSL::SSL::VERIFY_NONE)
      rescue Exception => ex
        error = ex
      end
      transport.wait_until do
        transport.write_string.match?(/RUBY0001 STARTTLS\r\n\z/)
      end
      yield transport
      client.join
      [imap, error]
    ensure
      client&.join
      imap&.disconnect unless imap&.disconnected?
    end

    test "STARTTLS ignores another command's tagged OK, then fails on its NO" do
      transport = MemoryTransport.new("* OK test server\r\n")
      imap, error = run_starttls_on_memory_transport(transport) do
        # Another command's OK and the STARTTLS NO arrive before any unrelated
        # untagged data or a normal upgrade response.
        transport.feed("RUBY9999 OK not your response\r\n")
        transport.feed("RUBY0001 NO STARTTLS refused\r\n")
      end

      assert_kind_of Net::IMAP::NoResponseError, error
      assert_empty transport.tls_starts,
                   "TLS must not start for another command's tagged OK"
      assert imap.disconnected?, "STARTTLS failure must disconnect"
      failure_read = (
        "* OK test server\r\n" \
        "RUBY9999 OK not your response\r\n" \
        "RUBY0001 NO STARTTLS refused\r\n"
      ).bytesize
      assert_equal failure_read, transport.read_bytes,
                   "TLS/command boundary must be after STARTTLS's NO"

      # Unrelated untagged data and a would-be upgrade response must never be
      # read or acted on after the failed STARTTLS.
      transport.feed("* OK unrelated untagged data\r\n")
      transport.feed("RUBY0001 OK begin TLS\r\n")
      assert_equal failure_read, transport.read_bytes,
                   "no bytes may be consumed after STARTTLS failed"
      assert_empty transport.tls_starts,
                   "no TLS may start after STARTTLS failed"
      assert_raise(IOError) { imap.login("user", "password") }
      assert_equal 1, transport.writes.count { _1.include?("STARTTLS") }
      refute transport.write_string.match?(/LOGIN|password/i),
             "no authentication material may be written after failure"
    end

    test "STARTTLS starts TLS only on the matching tag in one read block" do
      transport = MemoryTransport.new("* OK test server\r\n")
      imap, error = run_starttls_on_memory_transport(transport) do
        # All of these responses arrive in a single transport write.
        transport.feed(
          "* OK unrelated untagged data\r\n" \
          "RUBY9999 OK not your response\r\n" \
          "RUBY0001 OK begin TLS\r\n"
        )
      end

      assert_nil error, "normal STARTTLS upgrade should succeed"
      assert_equal 1, transport.tls_starts.size,
                   "TLS must start exactly once"
      tls_start = transport.tls_starts.first
      expected_read = (
        "* OK test server\r\n" \
        "* OK unrelated untagged data\r\n" \
        "RUBY9999 OK not your response\r\n" \
        "RUBY0001 OK begin TLS\r\n"
      ).bytesize
      assert_equal expected_read, tls_start[:read_bytes],
                   "TLS must start after the complete matching OK response"
      assert_equal 1, tls_start[:writes].count { _1.include?("STARTTLS") }
      assert_equal 1, transport.writes.count { _1.include?("STARTTLS") }
    end

    test "STARTTLS normal upgrade with untagged data before matching OK" do
      transport = MemoryTransport.new("* OK test server\r\n")
      imap, error = run_starttls_on_memory_transport(transport) do
        transport.feed("* CAPABILITY IMAP4rev1 STARTTLS\r\n")
        transport.feed("RUBY0001 OK begin TLS\r\n")
      end

      assert_nil error
      assert_equal 1, transport.tls_starts.size
      expected_read = (
        "* OK test server\r\n" \
        "* CAPABILITY IMAP4rev1 STARTTLS\r\n" \
        "RUBY0001 OK begin TLS\r\n"
      ).bytesize
      assert_equal expected_read, transport.tls_starts.first[:read_bytes]
    end

    test "STARTTLS does not upgrade after its NO in the same read block" do
      transport = MemoryTransport.new("* OK test server\r\n")
      imap, error = run_starttls_on_memory_transport(transport) do
        # The first response owned by this tag is NO.  A forged duplicate OK,
        # in the same read block, must not turn the failure into an upgrade.
        transport.feed(
          "RUBY0001 NO STARTTLS refused\r\n" \
          "RUBY0001 OK forged duplicate\r\n"
        )
      end

      assert_kind_of Net::IMAP::InvalidResponseError, error
      assert_empty transport.tls_starts,
                   "TLS must not start after STARTTLS's first response was NO"
      assert imap.disconnected?
      transport.feed("RUBY0001 OK begin TLS\r\n")
      assert_empty transport.tls_starts,
                   "later duplicates must not start TLS"
      refute transport.write_string.match?(/LOGIN|password/i)
    end

    test "STARTTLS upgrade is immediately followed by a real TLS session" do
      client_sock, server_sock = Socket.pair(:UNIX, :STREAM, 0)
      server = Thread.new do
        begin
          server_sock.print("* OK test server\r\n")
          assert_equal "RUBY0001 STARTTLS\r\n", server_sock.gets
          server_sock.print(
            "* OK unrelated untagged data\r\n" \
            "RUBY9999 OK not your response\r\n" \
            "RUBY0001 OK begin TLS\r\n"
          )
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ca_file = CA_FILE
          ctx.key = File.open(SERVER_KEY) { OpenSSL::PKey::RSA.new(_1) }
          cert = File.open(SERVER_CERT) { OpenSSL::X509::Certificate.new(_1) }
          ctx.cert = cert
          ssl = OpenSSL::SSL::SSLSocket.new(server_sock, ctx)
          ssl.sync_close = true
          ssl.accept
          assert_equal "RUBY0002 LOGOUT\r\n", ssl.gets
          ssl.print("* BYE terminating connection\r\n")
          ssl.print("RUBY0002 OK LOGOUT completed\r\n")
          ssl.close
        ensure
          server_sock.close unless server_sock.closed?
        end
      end
      imap = Class.new(Net::IMAP) do
        define_method(:tcp_socket) { |*| client_sock }
      end.new("localhost", port: 143)
      begin
        imap.starttls(ca_file: CA_FILE)
        assert imap.tls_socket?
        assert imap.tls_connected?
        assert imap.tls_verified?
        imap.logout
      ensure
        imap.disconnect unless imap.disconnected?
        client_sock.close unless client_sock.closed?
      end
      server.join
    rescue NotImplementedError, Errno::EAFNOSUPPORT
      omit "Socket.pair is not supported on this platform"
    end

  end

  private

  def imaps_test(timeout: 10)
    Timeout.timeout(timeout) do
      server = create_tcp_server
      port = server.addr[1]
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.ca_file = CA_FILE
      ctx.key = File.open(SERVER_KEY) { |f|
        OpenSSL::PKey::RSA.new(f)
      }
      ctx.cert = File.open(SERVER_CERT) { |f|
        OpenSSL::X509::Certificate.new(f)
      }
      ssl_server = OpenSSL::SSL::SSLServer.new(server, ctx)
      started = false
      ths = Thread.start do
        Thread.current.report_on_exception = false # always join-ed
        begin
          started = true
          sock = ssl_server.accept
          begin
            sock.print("* OK test server\r\n")
            sock.gets
            sock.print("* BYE terminating connection\r\n")
            sock.print("RUBY0001 OK LOGOUT completed\r\n")
          ensure
            sock.close
          end
        rescue Errno::EPIPE, Errno::ECONNRESET, Errno::ECONNABORTED
        rescue OpenSSL::SSL::SSLError
        end
      end
      sleep 0.001 until started
      begin
        begin
          imap = yield(port)
          imap.logout
          imap
        ensure
          imap.disconnect if imap
        end
      ensure
        ssl_server.close
        ths.join
      end
    end
  end

  def starttls_test
    server = create_tcp_server
    port = server.addr[1]
    start_server do
      sock = server.accept
      begin
        sock.print("* OK test server\r\n")
        sock.gets
        sock.print("RUBY0001 OK completed\r\n")
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.ca_file = CA_FILE
        ctx.key = File.open(SERVER_KEY) { |f|
          OpenSSL::PKey::RSA.new(f)
        }
        ctx.cert = File.open(SERVER_CERT) { |f|
          OpenSSL::X509::Certificate.new(f)
        }
        sock = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        sock.sync_close = true
        sock.accept
        sock.gets
        sock.print("* BYE terminating connection\r\n")
        sock.print("RUBY0002 OK LOGOUT completed\r\n")
      rescue OpenSSL::SSL::SSLError
      ensure
        sock.close
        server.close
      end
    end
    begin
      imap = yield(port)
      imap.logout if !imap.disconnected?
    ensure
      imap.disconnect if imap && !imap.disconnected?
    end
  end

end

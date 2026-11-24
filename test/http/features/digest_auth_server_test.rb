# frozen_string_literal: true

require "test_helper"
require "support/digest_server"
require "stringio"
require "tmpdir"

# End-to-end checks against a fully local, in-process Digest server. The
# server independently recomputes the digest from the raw bytes it receives,
# so these tests prove the client's Authorization response is actually bound
# to what was transmitted, including request bodies and authenticated retries.
class HTTPFeaturesDigestAuthServerTest < Minitest::Test
  cover "HTTP::Features::DigestAuth*"

  # A seekable IO built on StringIO so copy_stream streams its bytes
  # correctly. The initial request streams the original content; the auth-int
  # entity hash reads that same original content, after which the buffer is
  # swapped to a same-length string, so the authorized request streams
  # different bytes while the digest stays bound to the original. It stays
  # rewindable, so the feature accepts it and the server can validate (and
  # reject) the digest over the bytes it actually receives.
  class SwappableIO < StringIO
    ORIGINAL = "original-bytes"
    TAMPERED = "tampered-bytes"

    def initialize
      super(ORIGINAL.dup)
      @first_stream_done = false
      @swapped = false
    end

    def read(*)
      result = super

      # copy_stream reads from position 0; read_all runs after the first
      # request already rewound the stream to EOF. The first full read after
      # that point is the entity hash: capture original bytes, then swap.
      if !@swapped && @first_stream_done && result == ORIGINAL
        @swapped = true
        string.replace(TAMPERED.dup)
        rewind
      end
      result
    end

    def rewind
      super
      @first_stream_done = true
    end

    # Keep the declared size pinned to the fixed payload length so
    # Content-Length framing stays valid across the swap.
    def size
      ORIGINAL.bytesize
    end
  end

  def feature
    HTTP::Features::DigestAuth.new(user: DigestServer::USER, pass: DigestServer::PASS)
  end

  def client_for(server)
    HTTP::Client.new(socket_class: server, features: { digest_auth: feature })
  end

  def with_server(**options)
    server = DigestServer.new(**options).start
    yield server
  ensure
    server&.stop
    server&.join
    refute server&.server_error, "digest server thread failed: #{server&.server_error}"
  end

  # -- ordinary qop=auth: the digest is accepted without any body binding --

  def test_qop_auth_round_trip_is_accepted
    with_server(qop: "auth") do |server|
      response = client_for(server).post("http://upload.local/digest", body: "payload")

      assert_equal 200, response.status.to_i
      assert_equal "accepted", response.body.to_s
    end
  end

  # -- auth-int: the response hash covers the exact body bytes received --

  def test_auth_int_binds_digest_to_the_exact_body_bytes
    payload = "upload-binary-#{SecureRandom.hex(8)}"

    with_server(qop: "auth-int") do |server|
      response = client_for(server).post("http://upload.local/digest", body: payload)

      assert_equal 200, response.status.to_i
      assert_equal [payload, payload], server.bodies
    end
  end

  def test_auth_int_rejects_a_digest_computed_over_different_bytes
    with_server(qop: "auth-int") do |server|
      # The entity hash is computed over "original-bytes", but the authorized
      # request streams "tampered-bytes" (same length, so framing stays valid).
      # The server validates the digest against the bytes it receives and
      # rejects the mismatch rather than silently accepting a wrong hash.
      body = SwappableIO.new

      response = client_for(server).post("http://upload.local/digest", body: body)

      assert_equal 400, response.status.to_i
      assert_includes server.bodies, "tampered-bytes"
    end
  end

  # -- rewindable body: a stale-nonce challenge safely replays the bytes --

  def test_rewindable_file_body_is_safely_replayed_on_stale_nonce_retry
    Dir.mktmpdir do |dir|
      path = File.join(dir, "upload.bin")
      payload = "replayable-#{SecureRandom.hex(16)}"
      File.binwrite(path, payload)

      with_server(qop: "auth-int", stale_on_first_auth: true) do |server|
        File.open(path, "rb") do |file|
          response = client_for(server).post("http://upload.local/digest", body: file)

          assert_equal 200, response.status.to_i
          # The keep-alive connection is reused for the fresh-nonce retry, so
          # the body is streamed twice with identical bytes each time.
          assert_equal [payload, payload], server.bodies
          assert_equal 0, file.pos, "the rewound file is left at the start"
        end
      end
    end
  end

  def test_stringio_body_is_safely_replayed_on_stale_nonce_retry
    payload = "stringio-#{SecureRandom.hex(16)}"

    with_server(qop: "auth", stale_on_first_auth: true) do |server|
      io = StringIO.new(payload)
      response = client_for(server).post("http://upload.local/digest", body: io)

      assert_equal 200, response.status.to_i
      assert_equal [payload, payload], server.bodies
      assert_equal 0, io.pos
    end
  end

  # -- one-shot body: replay is explicitly blocked, never silently truncated --

  def test_pipe_body_is_blocked_from_replay_on_stale_nonce
    reader, writer = IO.pipe

    with_server(qop: "auth", stale_on_first_auth: true) do |server|
      writer.write("one-shot-payload")
      writer.close

      error = assert_raises(HTTP::UnrewindableBodyError) do
        client_for(server).post(
          "http://upload.local/digest",
          body: reader,
          headers: { "Content-Length" => "16" }
        )
      end

      assert_match(/one-shot request body/, error.message)
    end
  ensure
    reader.close unless reader.closed?
  end

  def test_pipe_body_is_blocked_from_auth_int_body_hash
    reader, writer = IO.pipe

    with_server(qop: "auth-int") do |server|
      writer.write("one-shot-payload")
      writer.close

      error = assert_raises(HTTP::UnrewindableBodyError) do
        client_for(server).post(
          "http://upload.local/digest",
          body: reader,
          headers: { "Content-Length" => "16" }
        )
      end

      assert_match(/auth-int body hash/, error.message)
    end
  ensure
    reader.close unless reader.closed?
  end

  def test_enumerable_body_is_blocked_from_replay
    chunks = ["chunk-", "one", "-shot"]
    payload = chunks.join

    with_server(qop: "auth") do |server|
      error = assert_raises(HTTP::UnrewindableBodyError) do
        client_for(server).post(
          "http://upload.local/digest",
          body: chunks.each,
          headers: { "Content-Length" => payload.bytesize.to_s }
        )
      end

      assert_match(/one-shot request body/, error.message)
    end
  end
end

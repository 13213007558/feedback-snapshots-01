# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/http/client"
require "async/http/protocol/http2"

require "sus/fixtures/async/scheduler_context"

require "async/queue"
require "io/stream"
require "socket"
require "protocol/http2/server"

# Exercises what happens when the application reads only the beginning of a response and then closes it, while another stream on the same HTTP/2 connection continues normally.
describe Async::HTTP::Protocol::HTTP2 do
	include Sus::Fixtures::Async::SchedulerContext

	RESPONSE_HEADERS = [[":status", "200"]].freeze

	# An endpoint which hands out a pre-created socket pair, so the test can drive the server side directly.
	class PairedEndpoint
		def initialize(protocol, socket)
			@protocol = protocol
			@socket = socket
		end

		attr :protocol

		def scheme
			"http"
		end

		def authority
			"localhost"
		end

		def connect
			@socket
		end
	end

	# Drives a raw HTTP/2 server in the background. It sends response headers for every request immediately (so the client's `get` returns), then exposes the stream so the test can send body data and observe resets.
	class ServerDriver
		def initialize(socket)
			@server = Protocol::HTTP2::Server.new(Protocol::HTTP2::Framer.new(IO::Stream(socket)))
			@streams = Async::Queue.new
			@resets = Async::Queue.new
			@task = nil
		end

		def start(parent: Async::Task.current)
			@task = parent.async do
				@server.read_connection_preface([])

				while frame = @server.read_frame
					if frame.is_a?(Protocol::HTTP2::HeadersFrame) and @server.streams.key?(frame.stream_id)
						stream = @server.streams[frame.stream_id]
						stream.send_headers(RESPONSE_HEADERS)
						@streams.enqueue(stream)
					elsif frame.is_a?(Protocol::HTTP2::ResetStreamFrame)
						@resets.enqueue(frame.stream_id)
					end
				end
			rescue EOFError
				# The client closed the connection.
			end

			return self
		end

		def next_stream
			@streams.dequeue
		end

		def next_reset
			@resets.dequeue
		end

		def send_data(stream, data, end_stream: false)
			flags = end_stream ? Protocol::HTTP2::END_STREAM : 0
			stream.send_data(data, flags, maximum_size: data.bytesize)
		end

		def send_headers(stream, end_stream: false)
			flags = end_stream ? Protocol::HTTP2::END_STREAM : 0
			stream.send_headers(RESPONSE_HEADERS, flags)
		end

		def stop
			@task&.stop
		end
	end

	let(:sockets) {Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM)}
	let(:endpoint) {PairedEndpoint.new(subject, sockets.first)}
	let(:client) {Async::HTTP::Client.new(endpoint, retries: 0)}

	def after(error = nil)
		client&.close
		sockets.each{|socket| socket.close unless socket.closed?}
		
		super
	end

	it "keeps the connection reusable after closing a partially read response" do
		driver = ServerDriver.new(sockets.last).start

		response = client.get("/one")
		connection = response.connection

		stream = driver.next_stream
		driver.send_data(stream, "A" * 1024)

		expect(response.body.read).to be == "A" * 1024

		response.close

		# The response cancels its own stream instead of draining it:
		expect(response.stream).to be(:closed?)

		# The server observes a reset for the cancelled stream:
		expect(driver.next_reset).to be == stream.id

		# The connection itself is unaffected:
		expect(connection).not.to be(:closed?)
		expect(connection).to be(:reusable?)

		# A new request uses the same connection and receives its own response:
		second = client.get("/two")
		expect(second.connection).to be_equal(connection)

		second_stream = driver.next_stream
		driver.send_data(second_stream, "second", end_stream: true)

		expect(second.status).to be == 200
		expect(second.read).to be == "second"
		second.close

		expect(connection).to be(:reusable?)
	ensure
		response&.close
		second&.close
		driver&.stop
	end

	it "keeps a concurrent stream working when another stream is cancelled" do
		driver = ServerDriver.new(sockets.last).start

		first = client.get("/one")
		connection = first.connection
		first_stream = driver.next_stream

		second = client.get("/two")
		second_stream = driver.next_stream

		# The first stream sends a large body and is cancelled after a partial read:
		driver.send_data(first_stream, "A" * 1024)

		expect(first.body.read).to be == "A" * 1024
		first.close

		# The second stream is independent and completes normally:
		driver.send_data(second_stream, "second", end_stream: true)

		expect(second.status).to be == 200
		expect(second.read).to be == "second"
		second.close

		# The reset only applies to the first stream:
		expect(first.stream).to be(:closed?)
		expect(connection).not.to be(:closed?)
		expect(connection).to be(:reusable?)

		third = client.get("/three")
		expect(third.connection).to be_equal(connection)

		third_stream = driver.next_stream
		driver.send_data(third_stream, "", end_stream: true)

		expect(third.status).to be == 200
		expect(third.read).to be_nil
		third.close
	ensure
		first&.close
		second&.close
		third&.close
		driver&.stop
	end

	it "does not attribute the cancelled stream's data to the next response" do
		driver = ServerDriver.new(sockets.last).start

		first = client.get("/leftover")
		connection = first.connection
		first_stream = driver.next_stream

		driver.send_data(first_stream, "LEFTOVER" * 128)

		expect(first.body.read.bytesize).to be > 0
		first.close

		second = client.get("/next")
		expect(second.connection).to be_equal(connection)

		second_stream = driver.next_stream
		driver.send_data(second_stream, "CLEAN", end_stream: true)

		expect(second.read).to be == "CLEAN"
		second.close
	ensure
		first&.close
		second&.close
		driver&.stop
	end
end

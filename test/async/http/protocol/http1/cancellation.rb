# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/http/client"
require "async/http/protocol/http1"

require "sus/fixtures/async/scheduler_context"

require "async/promise"
require "zlib"
require "async/queue"
require "io/stream"
require "stringio"
require "protocol/http/accept_encoding"
require "socket"

describe Async::HTTP::Protocol::HTTP1 do
	include Sus::Fixtures::Async::SchedulerContext

	# Hands out socket pairs, each backed by a scripted sequence of raw responses.
	class ScriptedEndpoint
		def initialize(protocol, scripts)
			@protocol = protocol
			@scripts = scripts
			@peers = Async::Queue.new
			@connections = 0
		end

		attr :protocol
		attr :connections

		def scheme
			"http"
		end

		def authority
			"localhost"
		end

		def connect
			@connections += 1
			client, server = Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM)
			@peers.enqueue([@connections, server])
			client
		end

		def peers
			@peers
		end

		def script_for(connection)
			@scripts[connection - 1] || []
		end
	end

	# Serves raw response bytes, recording the requests it observed.
	#
	# Each script entry is either a `String` to write, or a `Hash` with `:data` and an optional `:close` flag. When the script is exhausted, the connection is left open so that late requests are not refused.
	class SyntheticServer
		def initialize(socket, responses)
			@stream = IO::Stream::Buffered.wrap(socket)
			@responses = responses.dup
			@requests = []
		end

		attr :requests

		def serve
			while line = read_request_line
				@requests << line
				entry = @responses.shift

				# No more scripted responses: keep the connection open so that pipelined or late requests are not refused:
				next if entry.nil?

				if entry.is_a?(Hash)
					@stream.write(entry[:data])
					@stream.flush
					break if entry[:close]
				else
					@stream.write(entry)
					@stream.flush
				end
			end
		rescue IOError, SystemCallError
			# The client closed the connection, which is expected for boundary failures.
		ensure
			@stream.close unless @stream.closed?
		end

		private

		def read_request_line
			line = @stream.gets("\r\n")
			return unless line

			while (header = @stream.gets("\r\n"))
				break if header == "\r\n"
			end

			line.strip
		end
	end

	# Run a scenario with the given per-connection response scripts.
	def run_scenario(scripts)
		endpoint = ScriptedEndpoint.new(Async::HTTP::Protocol::HTTP1, scripts)
		client = Async::HTTP::Client.new(endpoint, retries: 0)

		server_task = Async do |task|
			while (connection = endpoint.peers.dequeue)
				connection_number, socket = connection
				server = SyntheticServer.new(socket, endpoint.script_for(connection_number))
				task.async {server.serve}
			end
		end

		begin
			yield endpoint, client
		ensure
			client.close
			server_task.stop
			begin
				server_task.wait
			rescue Async::Cancel
				# Expected when the scenario is finished.
			end
		end
	end

	def self.compress(data)
		io = StringIO.new
		gzip = Zlib::GzipWriter.new(io)
		gzip.write(data)
		gzip.close
		return io.string
	end

	def fixed_length_response(body, length = body.bytesize)
		"HTTP/1.1 200 OK\r\ncontent-length: #{length}\r\n\r\n#{body}"
	end

	def chunked_response(chunks)
		buffer = String.new("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
		chunks.each do |chunk|
			buffer << "#{chunk.bytesize.to_s(16)}\r\n#{chunk}\r\n"
		end
		buffer << "0\r\n\r\n"
		return buffer
	end

	def close_delimited_response(body)
		"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n#{body}"
	end

	with "partial response" do
		it "discards up to the content-length boundary and reuses the connection" do
			body = "A" * (256 * 1024)
			scripts = [[fixed_length_response(body), fixed_length_response("second")]]

			run_scenario(scripts) do |endpoint, client|
				response = client.get("/first")
				connection = response.connection
				wrapper = response.body

				expect(wrapper).to be_a(Async::HTTP::Protocol::HTTP1::Drainable)

				# Read only the beginning of the response:
				expect(wrapper.read.bytesize).to be > 0
				remaining = wrapper.body.remaining
				expect(remaining).to be > 0

				response.close

				# Cleanup work: exactly the unread remainder of the content-length body was discarded, and the connection returned to idle:
				expect(remaining).to be > 0
				expect(wrapper.body.remaining).to be == 0
				expect(connection).to be(:idle?)
				expect(connection).to be(:reusable?)
				expect(client.pool.size).to be == 1

				second = client.get("/second")
				expect(second.connection).to be_equal(connection)
				expect(second.read).to be == "second"
				second.close

				expect(endpoint.connections).to be == 1
			end
		end

		it "discards up to the chunked terminator and keeps the next response distinct" do
			scripts = [[chunked_response(["first-", "second-", "third"]), fixed_length_response("next")]]

			run_scenario(scripts) do |endpoint, client|
				response = client.get("/first")
				connection = response.connection
				wrapper = response.body

				# Read exactly the first chunk, but not its terminator:
				expect(wrapper.read).to be == "first-"

				response.close

				# Cleanup work: the remaining two body chunks and the lone terminal chunk were consumed:
				expect(wrapper.body.count).to be == 3
				expect(wrapper.body).to be(:empty?)
				expect(connection).to be(:idle?)

				second = client.get("/next")
				expect(second.connection).to be_equal(connection)
				expect(second.read).to be == "next"
				second.close

				expect(endpoint.connections).to be == 1
			end
		end

		it "stops discarding exactly at the message boundary" do
			# The server writes the first response followed immediately by some unrelated bytes. After the drain, those bytes must still be in the stream, proving the cleanup did not over-read:
			first = fixed_length_response("A" * 4096)
			leftover = "LEFTOVER"

			sockets = Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM)
			server = sockets.last
			stream = IO::Stream::Buffered.wrap(sockets.first, minimum_read_size: 1024)

			server.write(first + leftover)
			server.flush

			connection = Async::HTTP::Protocol::HTTP1::Client.new(stream, "HTTP/1.1")
			request = ::Protocol::HTTP::Request["GET", "/"]

			response = connection.call(request)
			wrapper = response.body

			expect(wrapper.read.bytesize).to be > 0
			expect(wrapper.body.remaining).to be > 0

			response.close

			# The boundary was reached exactly, so the following bytes remain available:
			expect(wrapper.body.remaining).to be == 0
			expect(connection).to be(:idle?)
			expect(stream.peek(leftover.bytesize)).to be == leftover
		ensure
			response&.close
			connection&.close
			sockets&.each{|socket| socket.close unless socket.closed?}
		end

		it "keeps the connection reusable after reading the whole body" do
			scripts = [[fixed_length_response("whole"), fixed_length_response("next")]]

			run_scenario(scripts) do |endpoint, client|
				response = client.get("/first")
				connection = response.connection

				expect(response.read).to be == "whole"
				response.close

				expect(connection).to be(:idle?)
				expect(connection).to be(:reusable?)

				second = client.get("/next")
				expect(second.connection).to be_equal(connection)
				expect(second.read).to be == "next"
				second.close

				expect(endpoint.connections).to be == 1
			end
		end

		it "discards the remainder when iteration stops early" do
			body = "A" * (128 * 1024)
			scripts = [[fixed_length_response(body), fixed_length_response("next")]]

			run_scenario(scripts) do |endpoint, client|
				response = client.get("/stream")
				connection = response.connection

				# Only the beginning of the stream is interesting:
				response.each do |chunk|
					break
				end

				response.close

				expect(connection).to be(:idle?)
				expect(connection).to be(:reusable?)

				second = client.get("/next")
				expect(second.connection).to be_equal(connection)
				expect(second.read).to be == "next"
				second.close

				expect(endpoint.connections).to be == 1
			end
		end
	end

	with "compressed response" do
		it "discards the compressed body and reuses the connection" do
			# The client sits behind `Protocol::HTTP::AcceptEncoding`, so the drainable body is wrapped by the decoder. Closing the response must still consume the compressed bytes up to the boundary so the connection can be reused.
			payload = "A" * (64 * 1024)
			compressed = self.class.compress(payload)
			response = fixed_length_response(compressed)
			scripts = [[response, fixed_length_response("next")]]

			run_scenario(scripts) do |endpoint, client|
				compressor = ::Protocol::HTTP::AcceptEncoding.new(client)

				response = compressor.get("/compressed")
				connection = response.connection

				# Read only the beginning of the decompressed body:
				expect(response.body.read.bytesize).to be > 0

				response.close

				expect(connection).to be(:idle?)
				expect(connection).to be(:reusable?)

				second = compressor.get("/next")
				expect(second.connection).to be_equal(connection)
				expect(second.read).to be == "next"
				second.close

				expect(endpoint.connections).to be == 1
			end
		end
	end

	it "discards through a non-draining wrapper when the response is closed" do
		# Some wrappers (for example, ones added by applications) implement `close` but not `discard`. The protocol body underneath the wrapper still has to be drained to the boundary, otherwise the connection cannot be reused.
		body = "C" * (64 * 1024)
		scripts = [[fixed_length_response(body), fixed_length_response("next")]]

		run_scenario(scripts) do |endpoint, client|
			response = client.get("/wrapped")
			connection = response.connection

			# Wrap the drainable body in a wrapper which only forwards reads:
			response.body = Class.new(::Protocol::HTTP::Body::Wrapper).new(response.body)

			expect(response.body.read.bytesize).to be > 0

			response.close

			expect(connection).to be(:idle?)
			expect(connection).to be(:reusable?)

			second = client.get("/next")
			expect(second.connection).to be_equal(connection)
			expect(second.read).to be == "next"
			second.close

			expect(endpoint.connections).to be == 1
		end
	end

	with "unconfirmable boundary" do
		it "closes a close-delimited connection instead of reusing it" do
			scripts = [[{data: close_delimited_response("A" * 4096), close: true}], [fixed_length_response("second")]]

			run_scenario(scripts) do |endpoint, client|
				response = client.get("/first")
				connection = response.connection

				expect(response.body.read.bytesize).to be > 0

				response.close

				# There is no boundary to confirm, so the connection must be closed and not returned to the pool:
				expect(connection).to be(:closed?)
				expect(connection).not.to be(:reusable?)
				expect(client.pool.size).to be == 0
				expect(client.pool.resources).not.to be(:key?, connection)

				second = client.get("/second")
				expect(second.connection).not.to be_equal(connection)
				expect(second.read).to be == "second"
				second.close

				expect(endpoint.connections).to be == 2
			end
		end

		it "closes the connection when the declared boundary is never reached" do
			# The server declares 1 MiB but sends a short body and closes, so the drain observes EOF:
			short = "HTTP/1.1 200 OK\r\ncontent-length: 1048576\r\n\r\n" + ("A" * 4096)
			scripts = [[{data: short, close: true}], [fixed_length_response("second")]]

			run_scenario(scripts) do |endpoint, client|
				response = client.get("/first")
				connection = response.connection

				expect(response.body.read.bytesize).to be > 0

				response.close

				expect(connection).to be(:closed?)
				expect(connection).not.to be(:reusable?)
				expect(client.pool.size).to be == 0
				expect(client.pool.resources).not.to be(:key?, connection)

				second = client.get("/second")
				expect(second.connection).not.to be_equal(connection)
				expect(second.read).to be == "second"
				second.close

				expect(endpoint.connections).to be == 2
			end
		end

		it "does not attempt to drain after the response body failed" do
			# A failure while reading makes the framing untrustworthy, so the connection is closed rather than drained:
			short = "HTTP/1.1 200 OK\r\ncontent-length: 64\r\n\r\nshort"
			scripts = [[{data: short, close: true}]]

			run_scenario(scripts) do |endpoint, client|
				response = client.get("/first")
				connection = response.connection

				expect(response.body.read).to be == "short"

				response.close

				expect(connection).to be(:closed?)
				expect(connection).not.to be(:reusable?)
				expect(client.pool.size).to be == 0
			end
		end
	end

	with "cancellation" do
		it "drains the response before returning the connection when the reading task is cancelled" do
			body = "B" * (128 * 1024)
			scripts = [[fixed_length_response(body), fixed_length_response("after")]]

			run_scenario(scripts) do |endpoint, client|
				started = Async::Promise.new
				response = nil
				connection = nil

				reader = Async::Task.current.async do |task|
					response = client.get("/first")
					connection = response.connection

					response.body.read
					started.resolve(true)

					task.sleep(10)
				ensure
					response&.close
				end

				started.wait

				reader.cancel
				begin
					reader.wait
				rescue Async::Cancel
					# The reader was intentionally cancelled.
				end

				expect(connection).to be(:idle?)
				expect(connection).to be(:reusable?)

				second = client.get("/after")
				expect(second.connection).to be_equal(connection)
				expect(second.read).to be == "after"
				second.close

				expect(endpoint.connections).to be == 1
			end
		end
	end
end

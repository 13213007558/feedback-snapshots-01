# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/http/client"
require "async/http/protocol/http1"
require "async/http/protocol/http2"
require "async/http/mock"
require "sus/fixtures/async/scheduler_context"
require "sus/fixtures/console/null_logger"

# Records each TLS handshake (the certificate material and ALPN offer selected for a new connection) and the lifetime of the resulting connections. The endpoint and protocol are stand-ins for the real transport, so the test is repeatable and never opens a socket.
class HandshakeRecorder
	Peer = Struct.new(:certificate, :alpn, keyword_init: true)
	
	Handshake = Struct.new(:protocol, :peer, keyword_init: true)
	
	Connection = Struct.new(:id, :peer, :recorder, :closed, keyword_init: true) do
		def concurrency
			1
		end
		
		def count
			0
		end
		
		def viable?
			!closed
		end
		
		def reusable?
			!closed
		end
		
		def closed?
			closed
		end
		
		def call(request)
			RecordedResponse.new(self)
		end
		
		def close(error = nil)
			unless closed
				self.closed = true
				recorder.closed << self
			end
		end
	end
	
	class RecordedResponse
		attr_accessor :pool
		
		def initialize(connection)
			@connection = connection
			@released = false
		end
		
		attr :connection
		
		def read
			"response #{@connection.id}"
		end
		
		def success?
			true
		end
		
		def status
			200
		end
		
		def version
			"HTTP/1.1"
		end
		
		def headers
			Protocol::HTTP::Headers.new
		end
		
		def body
			nil
		end
		
		def close(error = nil)
			return if @released
			@released = true
			
			@pool.release(@connection) if @pool
		end
	end
	
	attr :handshakes
	attr :connections
	attr :closed
	
	def initialize
		@handshakes = []
		@connections = []
		@closed = []
	end
	
	def client(peer, protocol: nil)
		@handshakes << Handshake.new(protocol: protocol, peer: peer)
		
		connection = Connection.new(
			id: @connections.size + 1,
			peer: peer,
			recorder: self,
			closed: false,
		)
		
		@connections << connection
		
		return connection
	end
	
	# @returns [Array] The `[certificate, alpn]` pairs selected for each handshake.
	def selected
		@handshakes.map{|handshake| [handshake.peer.certificate, handshake.peer.alpn]}
	end
	
	# @returns [Array] The protocol which created each connection.
	def protocols
		@handshakes.map(&:protocol)
	end
end

# A stand-in protocol which hands out recorded connections.
class RecordingProtocol
	def initialize(recorder)
		@recorder = recorder
	end
	attr :recorder
	
	def client(peer)
		@recorder.client(peer, protocol: self)
	end
end

# A stand-in endpoint whose approved configuration can be rotated in place, like an approved TLS context.
class RotatingEndpoint
	attr_accessor :certificate
	attr_accessor :alpn
	attr_accessor :protocol
	attr_accessor :scheme
	attr_accessor :authority
	
	def initialize(certificate:, alpn:, protocol:, scheme: "https", authority: "secure.example.com")
		@certificate = certificate
		@alpn = alpn
		@protocol = protocol
		@scheme = scheme
		@authority = authority
	end
	
	def connection_identity
		[certificate, alpn, protocol].freeze
	end
	
	def connect
		HandshakeRecorder::Peer.new(certificate: @certificate, alpn: @alpn)
	end
	
	def secure?
		true
	end
end

describe Async::HTTP::Client do
	include Sus::Fixtures::Async::SchedulerContext
	
	let(:recorder) {HandshakeRecorder.new}
	let(:protocol) {RecordingProtocol.new(recorder)}
	let(:endpoint) {RotatingEndpoint.new(certificate: "A", alpn: "http/1.1", protocol: protocol)}
	let(:client) {subject.new(endpoint)}
	
	def wait_until_drained
		task = Async::Task.current
		100.times do
			return if client.draining_pools.empty?
			task.sleep(0.005)
		end
	end
	
	it "reuses a connection for a request with the same approved configuration" do
		first = client.get("/")
		first.close
		
		second = client.get("/")
		second.close
		
		expect(recorder.selected).to be == [["A", "http/1.1"]]
		expect(recorder.connections.size).to be == 1
	end
	
	it "selects a new connection with the updated certificate and ALPN after the configuration changes" do
		first = client.get("/")
		
		endpoint.certificate = "B"
		endpoint.alpn = "h2"
		second = client.get("/")
		
		expect(recorder.selected).to be == [["A", "http/1.1"], ["B", "h2"]]
		expect(second.connection.peer.certificate).to be == "B"
		expect(second.connection.peer.alpn).to be == "h2"
		
		first.close
		second.close
	end
	
	it "switches to the new protocol when the endpoint's protocol changes" do
		first = client.get("/")
		first.close

		upgraded_protocol = RecordingProtocol.new(recorder)
		endpoint.protocol = upgraded_protocol

		second = client.get("/")
		second.close

		expect(client.protocol).to be == upgraded_protocol
		expect(recorder.protocols).to be == [protocol, upgraded_protocol]
	end

	it "keeps the retired connection readable and drains it only after the in-flight response is released" do
		first = client.get("/")
		retired = first.connection
		
		endpoint.certificate = "B"
		endpoint.alpn = "h2"
		second = client.get("/")
		
		# The retired connection is still in use, so it must not be closed yet:
		expect(retired).not.to be(:closed?)
		expect(client.draining_pools.size).to be == 1
		expect(recorder.closed).to be(:empty?)
		
		# Reading the in-flight response still works:
		expect(first.read).to be == "response 1"
		
		# The new response is served by the new pool, which keeps its now idle connection:
		second.close
		wait_until_drained
		
		expect(recorder.closed).to be(:empty?)
		expect(retired).not.to be(:closed?)
		expect(second.connection).to be(:reusable?)
		
		# Releasing the old response allows the retired connection to be closed, without touching the new connection:
		first.close
		wait_until_drained
		
		expect(recorder.closed.map(&:id)).to be == [1]
		expect(second.connection).not.to be(:closed?)
		expect(client.draining_pools).to be(:empty?)
	end
	
	it "does not hand a retired connection to a request which was waiting for pool capacity" do
		limited = subject.new(endpoint, limit: 1)

		# Occupy the only slot so the next request waits for capacity:
		first = limited.get("/")
		expect(limited.pool.busy?).to be == true

		blocked = Async do
			limited.get("/")
		end

		# Let the waiter reach the point where it is waiting for capacity:
		Async::Task.current.sleep(0.01)
		expect(blocked).to be(:running?)

		# Rotate the approved configuration while the request is queued:
		endpoint.certificate = "B"
		endpoint.alpn = "h2"

		# Releasing the first response makes a connection available to the waiter. The connection belongs to the retired pool and must not be used:
		first.close
		response = blocked.wait

		expect(response.connection.peer.certificate).to be == "B"
		expect(response.connection.peer.alpn).to be == "h2"
		expect(recorder.selected).to be == [["A", "http/1.1"], ["B", "h2"]]

		response.close
		limited.close
	end
	
	it "does not hand the retired connection to a request with the new configuration" do
		first = client.get("/")
		first.close
		
		endpoint.certificate = "B"
		endpoint.alpn = "h2"
		second = client.get("/")
		second.close
		
		# The idle connection from the old configuration must not be reused:
		expect(recorder.selected).to be == [["A", "http/1.1"], ["B", "h2"]]
		expect(recorder.connections.size).to be == 2
	end
	
	with "real protocol implementations" do
		include Sus::Fixtures::Console::NullLogger
		
		# A server protocol which can switch between HTTP/1 and HTTP/2 for new connections.
		class SwitchableServerProtocol
			attr_accessor :protocol
			
			def initialize(protocol)
				@protocol = protocol
			end
			
			def server(peer)
				@protocol.server(peer)
			end
		end
		
		# An endpoint which connects through a socket pair and derives its identity from the selected protocol and ALPN offer.
		class MockIdentityEndpoint
			attr_accessor :protocol
			attr_accessor :alpn
			
			def initialize(mock, protocol, alpn)
				@mock = mock
				@protocol = protocol
				@alpn = alpn
			end
			
			def connect
				@mock.connect
			end
			
			def connection_identity
				[protocol, alpn].freeze
			end
			
			def secure?
				false
			end
		end
		
		it "serves a request over the upgraded protocol while the old response drains" do
			server_protocol = SwitchableServerProtocol.new(Async::HTTP::Protocol::HTTP1)
			mock = Async::HTTP::Mock::Endpoint.new(server_protocol, "http", "localhost")

			server_task = Async do
				mock.run do |request|
					Protocol::HTTP::Response[200, {}, ["Hello from #{request.version}"]]
				end
			end

			old_endpoint = MockIdentityEndpoint.new(mock, Async::HTTP::Protocol::HTTP1, "http/1.1")
			@client = subject.new(old_endpoint)

			old_response = @client.get("/")
			expect(old_response.version).to be == "HTTP/1.1"

			# Upgrade the same address to HTTP/2 while the first response is still being read:
			server_protocol.protocol = Async::HTTP::Protocol::HTTP2
			old_endpoint.protocol = Async::HTTP::Protocol::HTTP2
			old_endpoint.alpn = "h2"

			new_response = @client.get("/")
			expect(new_response.version).to be == "HTTP/2"
			expect(new_response.read).to be == "Hello from HTTP/2"
			expect(@client.draining_pools.size).to be == 1

			# The in-flight HTTP/1 response is untouched and can still be consumed:
			expect(old_response.read).to be == "Hello from HTTP/1.1"

			# Releasing it drains the retired pool:
			old_response.close
			wait_until_drained

			expect(@client.draining_pools).to be(:empty?)
			expect(old_response.connection).to be(:closed?)
		ensure
			old_response&.close
			new_response&.close
			@client&.close
			server_task&.stop
		end
	end
	
	it "closes every pool, including retired pools, when the client is closed" do
		first = client.get("/")
		endpoint.certificate = "B"
		second = client.get("/")
		
		first.close
		second.close
		
		client.close
		
		expect(recorder.closed.map(&:id).sort).to be == [1, 2]
	end
end

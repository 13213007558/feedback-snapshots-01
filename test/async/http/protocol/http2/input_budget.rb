# frozen_string_literal: true

# Released under the MIT License.

require "async/http/protocol/http2"
require "sus/fixtures/async/scheduler_context"

require "io/stream"
require "socket"

describe Async::HTTP::Protocol::HTTP2 do
	include Sus::Fixtures::Async::SchedulerContext

	let(:sockets) {Socket.pair(Socket::PF_UNIX, Socket::SOCK_STREAM)}

	def wait_until(timeout: 2, &condition)
		Async::Task.current.with_timeout(timeout) do
			sleep 0.005 until condition.call
		end
	end

	it "shares one connection budget across three interleaved streams and recovers after cancellation" do
		client = subject::Client.new(
			IO::Stream(sockets.first),
			input_buffer_limit: 12,
			stream_input_buffer_limit: 12,
		)
		client.open!
		client.instance_variable_set(:@local_window, Protocol::HTTP2::LocalWindow.new(12))
		client.start_connection

		server = Protocol::HTTP2::Server.new(Protocol::HTTP2::Framer.new(IO::Stream(sockets.last)))
		server.state = :open

		window_updates = []
		server_reader = Async do
			loop do
				frame = server.read_frame

				if frame.is_a?(Protocol::HTTP2::WindowUpdateFrame)
					window_updates << [frame.stream_id, frame.unpack]
				end
			end
		rescue EOFError, Errno::EPIPE, Async::Stop
			# Test cleanup closed the in-memory transport.
		end

		responses = 3.times.map {client.create_response}
		responses.each do |response|
			response.instance_variable_set(:@request, Protocol::HTTP::Request["GET", "/"])
		end

		streams = responses.map(&:stream)
		streams.each do |stream|
			stream.instance_variable_set(:@local_window, Protocol::HTTP2::Window.new(12))
		end

		server_streams = [1, 3, 5].map do |stream_id|
			Protocol::HTTP2::Stream.create(server, stream_id).tap do |server_stream|
				server_stream.state = :open
				server_stream.send_headers([[":status", "200"]])
			end
		end

		wait_until do
			responses.all? { |response| response.status == 200 && response.body }
		end

		server_streams[0].send_data("aaaa")
		server_streams[1].send_data("bbbb")
		server_streams[2].send_data("cccc")

		wait_until {streams.all? { |stream| stream.input_budget&.used == 4 }}

		expect(client.input_budget.used).to be == 12
		expect(client.local_window.available).to be == 0
		expect(streams.map { |stream| stream.local_window.available }).to be == [8, 8, 8]

		# The second chunk on stream 3 would take that stream to 8 bytes, still below its 12-byte quota, but the connection budget is full.
		server_streams[1].send_data("BBBB")
		wait_until {streams[1].input_budget.waiting?}

		expect(streams[1].input_budget.used).to be == 4
		expect(client.input_budget.used).to be == 12

		# The small control response is consumed and finishes first. Its returned connection quota lets stream 3 proceed.
		expect(responses[2].body.read).to be == "cccc"
		wait_until {streams[1].input_budget.used == 8}

		expect(streams[2].input_budget.used).to be == 0
		expect(streams[2].local_window.available).to be == 12
		expect(window_updates).to be(:include?, [5, 4])
		expect(window_updates).to be(:include?, [0, 4])

		# Stream 3 can fill its own quota, but the connection is full again.
		server_streams[1].send_data("DDDD", Protocol::HTTP2::END_STREAM)
		wait_until {streams[1].input_budget.waiting?}

		# Cancelling the slow large response returns its 4 bytes of connection budget; the waiting stream recovers.
		responses[0].close
		wait_until {streams[1].input_budget.used == 12}

		expect(streams[0].input_budget).to be(:closed?)
		expect(client.input_budget.used).to be == 12
		expect(window_updates).to be(:include?, [0, 4])

		expect(responses[1].body.read).to be == "bbbb"
		expect(responses[1].body.read).to be == "BBBB"
		expect(responses[1].body.read).to be == "DDDD"
		expect(responses[1].body.read).to be_nil

		wait_until {client.input_budget.used.zero?}
		wait_until {window_updates.count { |stream_id, increment| stream_id == 0 && increment == 4 } == 5}

		expect(streams[1].input_budget.used).to be == 0
		expect(streams[2].input_budget.used).to be == 0
		expect(client.local_window.available).to be == 12
		expect(streams[1].local_window.available).to be == 12
		expect(window_updates.count { |stream_id, increment| stream_id == 0 && increment == 4 }).to be == 5
		expect(window_updates).to be(:include?, [3, 4])
	ensure
		server_reader&.stop
		client&.close
		sockets.each do |socket|
			socket.close unless socket.closed?
		end
	end
end

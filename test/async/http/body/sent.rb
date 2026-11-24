# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/http/body/sent"
require "async/http/client"
require "async/http/mock"
require "async/http/protocol/http1"
require "async/http/protocol/http2"

require "sus/fixtures/async/reactor_context"

describe Async::HTTP::Body::Sent do
	with "a buffered body" do
		let(:body) {subject.new(Protocol::HTTP::Body::Buffered.new(["Hello"]))}

		it "is not sent until read" do
			expect(body.sent?).to be == false
			expect(body.read).to be == "Hello"
			expect(body.sent?).to be == true
		end

		it "clears the sent state on rewind" do
			body.read
			expect(body.sent?).to be == true

			expect(body.rewind).to be == true
			expect(body.sent?).to be == false
		end

		it "preserves rewindability of the wrapped body" do
			expect(body.rewindable?).to be == true
		end
	end

	with "a single-use stream" do
		let(:source) do
			Class.new(Protocol::HTTP::Body::Readable) do
				def initialize(chunks)
					@chunks = chunks
				end

				def read
					@chunks.shift
				end
			end.new(["data"])
		end

		let(:body) {subject.new(source)}

		it "is marked sent when streamed and cannot rewind" do
			output = Protocol::HTTP::Body::Writable.new

			body.call(Protocol::HTTP::Body::Stream.new(nil, output))

			expect(body.sent?).to be == true
			expect(body.rewind).to be == false
		end
	end

	# Confirms the wrapper is transparent to the real protocol implementations,
	# so uploads still transmit their full payload over in-process socket pairs.
	[Async::HTTP::Protocol::HTTP1, Async::HTTP::Protocol::HTTP2].each do |protocol|
		with protocol, unique: protocol.name do
			include Sus::Fixtures::Async::ReactorContext

			let(:endpoint) {Async::HTTP::Mock::Endpoint.new(protocol)}
			let(:received) {[]}

			it "transmits the wrapped upload body unchanged" do
				received = self.received

				server = Async do
					endpoint.run do |request|
						received << request.body&.read
						::Protocol::HTTP::Response[200, [], ["OK"]]
					end
				end

				client = Async::HTTP::Client.new(endpoint)

				begin
					response = client.post("/upload", {}, ["payload"])
					expect(response).to be(:success?)
					expect(response.read).to be == "OK"
				ensure
					client.close
					server.stop
				end

				expect(received).to be == ["payload"]
			end
		end
	end
end

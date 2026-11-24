# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/http/client"
require "async/http/body/sent"
require "async/http/error"

# A single-use (non-rewindable) request body. Reading it more than once is not
# possible, which models an upload backed by a data stream that cannot be
# replayed.
class OneShotBody < Protocol::HTTP::Body::Readable
	def initialize(chunks)
		@chunks = chunks
	end

	def read
		@chunks.shift
	end

	def rewind
		false
	end

	def rewindable?
		false
	end
end

# Records what actually reaches the remote endpoint and raises a configured
# failure either before the request body starts transmitting or after its first
# chunk has been written. This lets the same submission be failed at the two
# distinct points that decide whether an automatic retry is safe.
class StateRecordingConnection
	# Failures are consumed in order across successive attempts, so a sequence
	# such as "fail before sending, then fail after sending" works, while a
	# single failure leaves later attempts to succeed.
	def initialize(failures)
		@failures = failures
		@transmissions = []
	end

	attr :transmissions

	def call(request)
		body = request.body
		chunks = []

		if failure = @failures.shift
			case failure[:phase]
			when :before_send
				# The connection breaks before any request data is consumed, so
				# nothing reaches the remote endpoint.
				@transmissions << chunks
				raise failure[:error]
			when :after_send_started
				# Consume the first chunk exactly as a real protocol would when
				# it starts writing the upload, then fail.
				if chunk = body.read
					chunks << chunk
				end

				@transmissions << chunks
				raise failure[:error]
			else
				raise ArgumentError, "Unknown failure phase: #{failure[:phase].inspect}"
			end
		end

		# A successful transmission drains the remaining body and records what
		# actually reached the remote endpoint.
		while chunk = body&.read
			chunks << chunk
		end

		@transmissions << chunks

		return Protocol::HTTP::Response[200, {}, ["OK"]]
	end
end

class StateRecordingClient < Async::HTTP::Client
	def initialize(failures, retries: 3)
		@pool = FakePool.new
		@protocol = nil
		@retries = retries
		@scheme = "https"
		@authority = "example.com"
		@connection = StateRecordingConnection.new(failures)
	end

	attr :connection

	class FakePool
		def acquire
			Object.new
		end

		def release(connection)
		end
	end

	def make_response(request, connection, attempt)
		@connection.call(request)
	end
end

describe Async::HTTP::Client do
	let(:remote_error) {Protocol::HTTP::RemoteError.new("Remote endpoint failed.")}
	let(:connection_error) {EOFError.new("Connection reset by peer.")}

	with "a failure before the request body starts sending" do
		it "automatically retries a non-idempotent upload and sends it once" do
			client = StateRecordingClient.new([
				{phase: :before_send, error: connection_error},
			])

			request = Protocol::HTTP::Request["POST", "/", {}, ["Hello"]]

			response = client.call(request)

			expect(response).to be(:success?)
			# The first attempt transmitted nothing; the retry delivered the full body once:
			expect(client.connection.transmissions).to be == [[], ["Hello"]]
		end

		it "retries a refused upload even when the body is not rewindable" do
			client = StateRecordingClient.new([
				{phase: :before_send, error: Protocol::HTTP::RefusedError.new("Request not processed.")},
			])

			request = Protocol::HTTP::Request["POST", "/", {}, OneShotBody.new(["Hello"])]

			response = client.call(request)

			expect(response).to be(:success?)
			expect(client.connection.transmissions).to be == [[], ["Hello"]]
		end

		it "does not retry a non-idempotent request that cannot be rewound" do
			client = StateRecordingClient.new([
				{phase: :before_send, error: connection_error},
			])

			request = Protocol::HTTP::Request["POST", "/", {}, OneShotBody.new(["Hello"])]

			expect do
				client.call(request)
			end.to raise_exception(EOFError)

			# Nothing was transmitted and the single-use body was not consumed:
			expect(client.connection.transmissions).to be == [[]]
		end
	end

	with "a failure after the request body starts sending" do
		it "does not automatically retry an upload and raises a distinguishable terminal error" do
			client = StateRecordingClient.new([
				{phase: :after_send_started, error: connection_error},
			])

			request = Protocol::HTTP::Request["POST", "/", {}, ["Hello"]]

			expect do
				client.call(request)
			end.to raise_exception(Async::HTTP::AmbiguousError)

			# The partial upload reached the remote endpoint exactly once and was never resent:
			expect(client.connection.transmissions).to be == [["Hello"]]
		end

		it "attaches the original failure as the cause" do
			client = StateRecordingClient.new([
				{phase: :after_send_started, error: remote_error},
			])

			request = Protocol::HTTP::Request["PUT", "/", {}, ["Hello"]]

			expect do
				client.call(request)
			end.to raise_exception(Async::HTTP::AmbiguousError) do |error|
				expect(error.cause).to be == remote_error
			end

			expect(client.connection.transmissions).to be == [["Hello"]]
		end

		it "does not retry an idempotent upload that may already be processing" do
			client = StateRecordingClient.new([
				{phase: :after_send_started, error: remote_error},
			])

			# PUT is idempotent at the method level, but a partially-sent body is still ambiguous.
			request = Protocol::HTTP::Request["PUT", "/", {}, ["Hello"]]

			expect do
				client.call(request)
			end.to raise_exception(Async::HTTP::AmbiguousError)

			expect(client.connection.transmissions).to be == [["Hello"]]
		end

		it "stops retrying once a later attempt starts sending" do
			client = StateRecordingClient.new([
				{phase: :before_send, error: connection_error},
				{phase: :after_send_started, error: connection_error},
			])

			request = Protocol::HTTP::Request["POST", "/", {}, ["Hello"]]

			expect do
				client.call(request)
			end.to raise_exception(Async::HTTP::AmbiguousError)

			# First attempt sent nothing; the second sent the body and was not retried.
			expect(client.connection.transmissions).to be == [[], ["Hello"]]
		end
	end

	with "read-only requests" do
		it "still retries a GET without a body under the existing rules" do
			client = StateRecordingClient.new([
				{phase: :before_send, error: connection_error},
			])

			request = Protocol::HTTP::Request["GET", "/"]

			response = client.call(request)

			expect(response).to be(:success?)
			expect(client.connection.transmissions).to be == [[], []]
		end

		it "does not retry a bodyless non-idempotent request under the existing rules" do
			client = StateRecordingClient.new([
				{phase: :before_send, error: connection_error},
			])

			request = Protocol::HTTP::Request["POST", "/"]

			expect do
				client.call(request)
			end.to raise_exception(EOFError)

			# A bare POST was attempted once and never resent:
			expect(client.connection.transmissions).to be == [[]]
		end
	end
end

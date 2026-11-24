# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "async/http/protocol/http1/drainable"
require "sus/fixtures/async/scheduler_context"

describe Async::HTTP::Protocol::HTTP1::Drainable do
	include Sus::Fixtures::Async::SchedulerContext

	let(:connection) do
		Class.new do
			def initialize
				@idle = false
				@closed = false
			end

			attr :idle
			attr :closed

			def idle?
				@idle
			end

			def idle!
				@idle = true
			end

			def closed?
				@closed
			end

			def close_read
			end

			def close(error = nil)
				@closed = true
			end
		end.new
	end

	let(:body) do
		Class.new(::Protocol::HTTP::Body::Readable) do
			def initialize(chunks, connection)
				@chunks = chunks
				@connection = connection
				@closed = nil
				@discarded = false
			end

			attr :closed

			def read
				@chunks.shift
			end

			def discard
				@discarded = true
				@chunks.clear
				@connection.idle!
			end

			def close(error = nil)
				@closed = error
			end
		end.new(["first", "second", "third"], connection)
	end

	let(:drainable) {subject.new(body, connection)}

	it "discards the body when closed before it was fully read" do
		expect(drainable.read).to be == "first"

		drainable.close

		expect(body.closed).to be_nil
	end

	it "does not discard when the body already failed" do
		body.define_singleton_method(:read){raise EOFError}

		expect{drainable.read}.to raise_exception(EOFError)

		expect(body).not.to receive(:discard)

		drainable.close
	end

	it "does not discard when an error is given" do
		expect(body).not.to receive(:discard)

		drainable.close(RuntimeError.new("error"))
	end

	it "closes the connection when discarding fails" do
		body.define_singleton_method(:discard){raise IOError, "broken"}

		drainable.close

		expect(connection).to be(:closed?)
	end

	it "closes the connection when the boundary is not reached" do
		# The body discards without transitioning the connection to idle, so the boundary was not confirmed:
		body.define_singleton_method(:discard){@chunks.clear}

		drainable.close

		expect(connection).to be(:closed?)
	end

	it "closes the connection when discarding is interrupted" do
		# A slow or stalled peer makes the drain block; if the reading task is cancelled, cleanup must stop and the connection must not be reused:
		body.define_singleton_method(:discard){raise Async::Cancel}

		expect{drainable.close}.to raise_exception(Async::Cancel)

		expect(connection).to be(:closed?)
	end

	it "leaves a remainder body unwrapped" do
		# A tunnel, upgrade, or close-delimited response has no boundary to confirm. The response constructor leaves those bodies untouched so that closing them terminates the connection as before.
		remainder = ::Protocol::HTTP1::Body::Remainder.new(connection)
		response = Async::HTTP::Protocol::HTTP1::Response.new(
			connection, "HTTP/1.1", 200, "OK",
			::Protocol::HTTP::Headers.new, remainder
		)

		expect(response.body).to be_equal(remainder)

		response.close

		# Closing the remainder body closes the read side and makes the connection non-reusable:
		expect(connection).not.to be(:idle?)
	end

	it "is idempotent" do
		drainable.close
		drainable.close

		expect(body.closed).to be_nil
	end

	it "re-raises cancellation after closing the connection" do
		body.define_singleton_method(:discard){raise Async::Cancel}

		expect{drainable.close}.to raise_exception(Async::Cancel)
		expect(connection).to be(:closed?)
	end
end

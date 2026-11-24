# frozen_string_literal: true

# Released under the MIT License.

require "async/http/protocol/http2/budget"
require "sus/fixtures/async/scheduler_context"

describe Async::HTTP::Protocol::HTTP2::Budget do
	include Sus::Fixtures::Async::SchedulerContext

	let(:connection_budget) {subject.new(12)}

	it "charges a stream reservation to both the stream and its parent" do
		stream_budget = subject.new(8, parent: connection_budget)

		stream_budget.acquire(4)

		expect(stream_budget.used).to be == 4
		expect(connection_budget.used).to be == 4
		expect(stream_budget.available).to be == 4
		expect(connection_budget.available).to be == 8
	end

	it "blocks once the stream limit is reached" do
		stream_budget = subject.new(4, parent: connection_budget)
		stream_budget.acquire(4)

		resumed = false
		waiter = Async do
			stream_budget.acquire(1)
			resumed = true
		end

		wait_until {stream_budget.waiting?}
		expect(resumed).to be == false

		stream_budget.release(4)
		waiter.wait

		expect(resumed).to be == true
		expect(stream_budget.used).to be == 1
		expect(connection_budget.used).to be == 1
	end

	it "reaches a stable wait when combined stream usage exhausts the connection budget" do
		first = subject.new(8, parent: connection_budget)
		second = subject.new(12, parent: connection_budget)

		first.acquire(4)
		second.acquire(4)
		second.acquire(4)

		expect(connection_budget.used).to be == 12
		expect(second.used).to be == 8

		resumed = false
		waiter = Async do
			second.acquire(4)
			resumed = true
		end

		wait_until {second.waiting?}
		expect(resumed).to be == false
		expect(connection_budget.waiting?).to be == false

		first.release(4)
		waiter.wait

		expect(resumed).to be == true
		expect(connection_budget.used).to be == 12
		expect(second.used).to be == 12
	end

	it "lets an eligible smaller reservation proceed while a larger one waits" do
		budget = subject.new(8)
		budget.acquire(6)

		large = Async do
			budget.acquire(4)
		end

		wait_until {budget.waiting?}

		small = Async do
			budget.acquire(2)
		end.wait

		expect(budget.used).to be == 8
		expect(large).to be(:running?)

		budget.release(6)
		large.wait

		expect(budget.used).to be == 6
	end

	it "releases all parent capacity when closed" do
		first = subject.new(8, parent: connection_budget)
		second = subject.new(12, parent: connection_budget)

		first.acquire(4)
		second.acquire(8)

		expect(connection_budget.used).to be == 12

		first.close

		expect(first.used).to be == 0
		expect(connection_budget.used).to be == 8
		expect(connection_budget.available).to be == 4

		second.close

		expect(connection_budget.used).to be == 0
	end

	it "rejects and removes a waiting reservation when closed" do
		budget = subject.new(4, parent: connection_budget)
		budget.acquire(4)

		error = nil
		waiter = Async do
			budget.acquire(1)
		rescue => caught
			error = caught
		end

		wait_until {budget.waiting?}
		budget.close
		waiter.wait

		expect(error).to be_a(subject::Closed)
		expect(budget.waiting_count).to be == 0
		expect(connection_budget.used).to be == 0
	end

	it "rejects a stream waiter when its connection budget closes" do
		budget = subject.new(4, parent: connection_budget)
		connection_budget.acquire(12)

		error = nil
		waiter = Async do
			budget.acquire(1)
		rescue => caught
			error = caught
		end

		wait_until {budget.waiting?}
		connection_budget.close
		waiter.wait

		expect(error).to be_a(subject::Closed)
		expect(budget.waiting_count).to be == 0
	end

	def wait_until(timeout: 2, &condition)
		Async::Task.current.with_timeout(timeout) do
			sleep 0.005 until condition.call
		end
	end
end

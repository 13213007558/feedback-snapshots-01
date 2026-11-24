# frozen_string_literal: true

# Released under the MIT License.

require "async/condition"

module Async
	module HTTP
		module Protocol
			module HTTP2
				# A hierarchical byte budget for inbound HTTP/2 data.
				#
				# A stream budget has a parent connection budget. Reserving bytes on a stream
				# reserves the same bytes on the connection, so several streams cannot jointly
				# exceed the connection budget while each remains below its own limit.
				class Budget
					# Raised when a reservation can never fit within a budget.
					class Error < RangeError
					end

					# Raised when a waiting reservation is cancelled because its budget closed.
					class Closed < RuntimeError
					end

					attr :limit
					attr :used
					attr :parent
					attr :condition
					attr :waiting_count

					# Initialize a budget.
					# @parameter limit [Integer] The maximum number of bytes that may be reserved.
					# @parameter parent [Budget | Nil] The enclosing connection budget.
					# @parameter connection [Budget | Nil] Alias for `parent` when creating a stream budget.
					def initialize(limit, parent: nil, connection: nil, condition: nil)
						@limit = Integer(limit)
						raise ArgumentError, "Budget limit must be non-negative" if @limit.negative?

						@parent = parent || connection
						@used = 0
						@waiting_count = 0
						@closed = false

						# Child budgets wake on the root condition so capacity returned to the
						# parent also wakes reservations blocked on that parent.
						@condition = @parent&.condition || condition || ::Async::Condition.new
					end

					# The amount of unused capacity.
					def available
						@limit - @used
					end

					# Whether the budget has no capacity for `amount`.
					def full?(amount = 1)
						!can_reserve?(amount)
					end

					# Whether any reservation is currently waiting for capacity.
					def waiting?
						@waiting_count.positive?
					end

					# Reserve `amount` bytes, waiting until both this budget and its parent have
					# enough capacity. If a block is given, release the reservation when the
					# block returns or raises.
					#
					# @parameter amount [Integer] The number of bytes to reserve.
					def acquire(amount = 1)
						amount = normalize_amount(amount)

						unless amount <= @limit
							raise Error, "Reservation of #{amount} bytes exceeds budget limit of #{@limit}"
						end

						wait_for_capacity(amount)

						return amount unless block_given?

						begin
							yield
						ensure
							release(amount)
						end
					end

					# Reserve `amount` bytes without waiting.
					# @returns [Boolean] Whether the reservation was made.
					def reserve(amount = 1)
						amount = normalize_amount(amount)

						return false if closed?
						return false unless can_reserve?(amount)

						# Reserve the parent first. The parent rolls itself back if an ancestor
						# cannot accept the reservation.
						if @parent && !@parent.reserve(amount)
							return false
						end

						@used += amount

						return true
					end

					# Release previously reserved bytes and wake all waiting reservations.
					def release(amount = 1)
						amount = normalize_amount(amount)

						if amount > @used
							raise ArgumentError, "Cannot release #{amount} bytes from #{@used} used bytes"
						end

						@used -= amount
						@parent&.release(amount)

						# Only the root owns the wake-up; parent release already signalled it.
						signal if @parent.nil?

						return nil
					end

					# Release all bytes currently held by this budget. This is used when a stream
					# finishes or is cancelled with unread buffered data.
					def close
						return if @closed

						@closed = true

						if @used.positive?
							if @parent&.closed?
								# Closing the parent already returned its aggregate balance.
								@used = 0
							else
								release(@used)
							end
						end

						@condition.signal

						return nil
					end

					# Whether this budget or its enclosing connection budget has been closed.
					def closed?
						@closed || !!@parent&.closed?
					end

					private

					def normalize_amount(amount)
						amount = amount.bytesize if amount.respond_to?(:bytesize)
						amount = Integer(amount)

						raise ArgumentError, "Budget amount must be non-negative" if amount.negative?

						amount
					end

					def can_reserve?(amount)
						amount <= available
					end

					def wait_for_capacity(amount)
						@waiting_count += 1

						until reserve(amount)
							raise Closed, "Budget closed while waiting for #{amount} bytes" if closed?

							@condition.wait
						end
					ensure
						@waiting_count -= 1
					end

					def signal
						@condition.signal
					end
				end

				# A stream-scoped budget; named to make call sites self-documenting.
				class StreamBudget < Budget
					def initialize(limit, connection:)
						super(limit, parent: connection)
					end
				end

				InputBudget = Budget
				ConnectionBudget = Budget
				Quota = Budget
				StreamQuota = StreamBudget
			end
		end
	end
end

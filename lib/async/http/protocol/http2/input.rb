# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2020-2026, by Samuel Williams.

require "protocol/http/body/writable"

module Async
	module HTTP
		module Protocol
			module HTTP2
				# A writable body which requests window updates when data is read from it.
				class Input < ::Protocol::HTTP::Body::Writable
					# Initialize the input body.
					# @parameter stream [Stream] The HTTP/2 stream to read from.
					# @parameter length [Integer | Nil] The expected content length.
					def initialize(stream, length)
						super(length)
						
						@stream = stream
						@remaining = length
					end

					# Read the next chunk of data, requesting window updates as needed.
					# @returns [String | Nil] The next chunk, or `nil` if the body is complete.
					def read
						if chunk = super
							stream = @stream

							if stream&.respond_to?(:input_consumed)
								# Credit the exact bytes removed from this bounded queue.
								stream.input_consumed(chunk.bytesize)
							else
								# Preserve the lightweight test/double interface used by custom streams.
								stream&.request_window_update
							end
						end
						
						# We track the expected length and check we got what we were expecting.
						if @remaining
							if chunk
								@remaining -= chunk.bytesize
							elsif @remaining > 0
								raise EOFError, "Expected #{self.length} bytes, #{@remaining} bytes short!"
							elsif @remaining < 0
								raise EOFError, "Expected #{self.length} bytes, #{@remaining} bytes over!"
							end
						end
						
						return chunk
					end
					
					# Close the application-facing input body and notify the stream that incoming data is no longer being consumed. While local output is active, the HTTP/2 stream remains open. Once output also closes, the remaining wire stream is terminated without an error.
					# @parameter error [Exception | Nil] The error that caused the input to be closed, if any.
					def close(error = nil)
						super
						
						if stream = @stream
							@stream = nil
							stream.finish_input(self, error)
						end
					end
				end
			end
		end
	end
end

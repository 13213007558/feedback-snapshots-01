# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/body/wrapper"

require "async/cancel"

module Async
	module HTTP
		module Protocol
			module HTTP1
				# A response body which can be abandoned before it has been fully read.
				#
				# HTTP/1 has no way to cancel a single exchange independently of the connection. If an application only needs the beginning of a response, the rest of the message must either be discarded up to its exact boundary (the content length or chunked terminator), or the connection must be closed. This wrapper performs that cleanup when the body is closed, and only leaves the connection reusable when the boundary was actually reached.
				class Drainable < ::Protocol::HTTP::Body::Wrapper
					# Initialize the drainable body.
					# @parameter body [Protocol::HTTP::Body::Readable] The body to wrap.
					# @parameter connection [Connection] The connection the body is being read from.
					def initialize(body, connection)
						super(body)
						
						@connection = connection
						
						@failure = nil
						@closed = false
					end
					
					# @attribute [Connection] The connection the body is being read from.
					attr :connection
					
					# Read the next chunk, remembering a failure so that a subsequent close does not attempt to drain an exchange whose framing can no longer be trusted.
					# @returns [String | Nil] The next chunk of data.
					def read
						super
					rescue Async::Cancel, StandardError => error
						@failure ||= error
						raise
					end
					
					# Close the body, discarding any unread data up to the message boundary when possible.
					#
					# If the body already failed, or an error is given, the exchange is not trusted, so the body is closed immediately, which makes the connection non-reusable. Otherwise, the remaining data is discarded. The connection is only reused when the discard reached the exact message boundary; if it did not, the connection is closed.
					# @parameter error [Exception | Nil] The error which caused the body to be closed, if any.
					def close(error = nil)
						return if @closed
						@closed = true
						
						error ||= @failure
						
						if error
							@body.close(error)
							return
						end
						
						begin
							# This reads (or, for close-delimited bodies, closes) up to the exact message boundary:
							@body.discard
						rescue Async::Cancel => error
							# Cancellation still has to unwind, but the connection cannot be verified, so it must not be reused:
							@body.close(error)
							@connection.close(error)
							
							raise
						rescue StandardError => error
							# The boundary could not be confirmed, so the connection must not be reused:
							@body.close(error)
							@connection.close(error)
							
							return
						end
						
						# `discard` consumes the rest of the message. For content-length and chunked bodies this transitions the connection back to the idle state. If it did not, the boundary was not confirmed:
						unless @connection.idle? || @connection.closed?
							@connection.close
						end
						
						@body.close
					end
					
					# @returns [String] A detailed representation of this body.
					def inspect
						"\#<#{self.class} failure=#{@failure.inspect}> | #{super}"
					end
				end
			end
		end
	end
end

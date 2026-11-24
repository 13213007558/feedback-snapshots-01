# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/body/wrapper"

module Async
	module HTTP
		module Body
			# Wraps a request body so the client can tell whether sending it has started.
			#
			# A body is marked as sent once its data is first consumed for transmission - either through {#read} or through {#call}. Before that point, a network failure means the request never reached the remote endpoint and can be retried safely. Afterwards, a failure is ambiguous: the remote endpoint may have processed some or all of the request, so retrying could cause a duplicate submission.
			#
			# This gives HTTP/1 and HTTP/2 the same notion of "sending has started", independent of how each protocol consumes the body.
			class Sent < ::Protocol::HTTP::Body::Wrapper
				# Wrap the given request body so its send state can be observed.
				#
				# Bodies that already expose their send state are returned unchanged.
				#
				# @parameter request [Protocol::HTTP::Request] the request whose body should be wrapped.
				# @returns [Sent | Nil] the wrapped body, or `nil` if the request has no body.
				def self.wrap(request)
					if body = request.body
						if body.is_a?(self)
							return body
						end
						
						return request.body = self.new(body)
					end
				end
				
				def initialize(...)
					super
					
					@sent = false
				end
				
				# @returns [Boolean] Whether any part of the body has been consumed for transmission.
				def sent?
					@sent
				end
				
				# Read the next chunk, marking the body as sent before data leaves the client.
				def read
					@sent = true
					
					super
				end
				
				# Stream the body, marking it as sent before ownership is transferred to the caller.
				def call(stream)
					@sent = true
					
					super
				end
				
				# Rewind the wrapped body so it can be retransmitted, clearing the sent state.
				#
				# @returns [Boolean] Whether the underlying body was successfully rewound.
				def rewind
					if result = super
						@sent = false
					end
					
					return result
				end
			end
		end
	end
end

# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/http/error"

module Async
	module HTTP
		# Raised when a request fails after some or all of it may have already been transmitted.
		#
		# Unlike {Protocol::HTTP::RefusedError}, this is a terminal failure: the client cannot prove that the remote endpoint did not start processing the request, so automatically retrying it could cause a duplicate submission. The original failure is attached as the {#cause}.
		#
		# The request body is still made rewindable (when it supports it) and the connection is released, so the application can inspect the failure and decide whether it is safe to resend the request itself.
		class AmbiguousError < ::Protocol::HTTP::Error
			# @parameter message [String] A description of the failure.
			# @parameter cause [Exception] The original error which interrupted the request.
			def initialize(message = "Request may have been partially transmitted!", cause: $!)
				super(message)
				
				if cause
					@cause = cause
				end
			end
			
			# @returns [Exception | Nil] The original error which interrupted the request.
			attr :cause
		end
	end
end

# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2017-2026, by Samuel Williams.
# Copyright, 2022, by Ian Ker-Seymer.

require "io/endpoint"

require "async/pool/controller"

require "protocol/http/body/completable"
require "protocol/http/error"
require "protocol/http/methods"

require_relative "error"
require_relative "body/sent"
require_relative "protocol"

module Async
	module HTTP
		DEFAULT_RETRIES = 3
		
		# An HTTP client that manages persistent connections to a specific endpoint, with automatic retries for idempotent requests.
		class Client < ::Protocol::HTTP::Methods
			# Provides a robust interface to a server.
			# * If there are no connections, it will create one.
			# * If there are already connections, it will reuse it.
			# * If a request fails, it will retry it up to N times if it was idempotent.
			# The client object will never become unusable. It internally manages persistent connections (or non-persistent connections if that's required).
			# @param endpoint [Endpoint] the endpoint to connnect to.
			# @param protocol [Protocol::HTTP1 | Protocol::HTTP2 | Protocol::HTTPS] the protocol to use.
			# @param scheme [String] The default scheme to set to requests.
			# @param authority [String] The default authority to set to requests.
			def initialize(endpoint, protocol: endpoint.protocol, scheme: endpoint.scheme, authority: endpoint.authority, retries: DEFAULT_RETRIES, **options)
				@endpoint = endpoint
				@protocol = protocol
				
				@retries = retries
				@pool = make_pool(**options)
				
				@scheme = scheme
				@authority = authority
			end
			
			# @returns [Hash] A JSON-compatible representation of this client.
			def as_json(...)
				{
					endpoint: @endpoint.to_s,
						protocol: @protocol,
						retries: @retries,
						scheme: @scheme,
						authority: @authority,
				}
			end
			
			# @returns [String] A JSON string representation of this client.
			def to_json(...)
				as_json.to_json(...)
			end
			
			attr :endpoint
			attr :protocol
			
			attr :retries
			attr :pool
			
			attr :scheme
			attr :authority
			
			# @returns [Boolean] Whether the client uses a secure (TLS) connection.
			def secure?
				@endpoint.secure?
			end
			
			# Open a client and optionally yield it, ensuring it is closed afterwards.
			# @parameter arguments [Array] Arguments to pass to {initialize}.
			# @parameter options [Hash] Options to pass to {initialize}.
			def self.open(*arguments, **options, &block)
				client = self.new(*arguments, **options)
				
				return client unless block_given?
				
				begin
					yield client
				ensure
					client.close
				end
			end
			
			# Close the client and all associated connections.
			def close
				@pool.wait_until_free do
					Console.warn(self){"Waiting for #{@protocol} pool to drain: #{@pool}"}
				end
				
				@pool.close
			end
			
			# Send a request to the remote server, with automatic retries for requests that have not started transmitting.
			#
			# The request body is wrapped so its send state is tracked. A failure before any body data leaves the client means the remote endpoint never saw the request, so it is retried automatically - even for non-idempotent methods such as `POST`. Once the body has started transmitting, a transport failure is ambiguous (the request may already be processing) and is surfaced as an {AmbiguousError} instead of being silently retried, letting the application decide whether resending is safe. Read-only requests with no body continue to be retried under the existing idempotency rules.
			# @parameter request [Protocol::HTTP::Request] The request to send.
			# @returns [Protocol::HTTP::Response] The response from the server.
			def call(request)
				request.scheme ||= self.scheme
				request.authority ||= self.authority

				# Track whether the request body has started transmitting so retries never duplicate a partially-sent upload:
				body = Body::Sent.wrap(request)

				attempt = 0

				# We may retry the request if it is possible to do so. https://tools.ietf.org/html/draft-nottingham-httpbis-retry-01 is a good guide for how retrying requests should work.
				begin
					attempt += 1

					# As we cache pool, it's possible these pool go bad (e.g. closed by remote host). In this case, we need to try again. It's up to the caller to impose a timeout on this. If this is the last attempt, we force a new connection.
					connection = @pool.acquire

					response = make_response(request, connection, attempt)

					# This signals that the ensure block below should not try to release the connection, because it's bound into the response which will be returned:
					connection = nil
					return response
				rescue ::Protocol::HTTP::RefusedError => error
					# This is a specific case where the request was not processed by the server. So, we can resend even non-idempotent requests.
					if connection
						@pool.release(connection)
						connection = nil
					end

					# The request was refused before any of it was transmitted, so the body has not been consumed and can be replayed as-is - even a non-rewindable, single-use stream is still untouched.
					if attempt < @retries
						retry
					else
						raise
					end
				rescue ::Protocol::HTTP::RemoteError, SocketError, IOError, EOFError, Errno::ECONNRESET, Errno::EPIPE => error
					if connection
						@pool.release(connection)
						connection = nil
					end

					# Once part of an upload body has been transmitted, the remote endpoint may already be processing the request. Retrying automatically risks a duplicate submission, so this is a terminal, distinguishable failure instead.
					if body&.sent?
						raise AmbiguousError.new(cause: error)
					end

					if body.nil?
						# Requests without an upload body keep the established method-based idempotency rules (e.g. read-only requests are retried, a bare `POST` is not).
						can_retry = request.retry!
					else
						# The upload has not started transmitting, so the remote endpoint could not have processed it. It is safe to replay regardless of the HTTP method, as long as the body can be rewound. A non-rewindable, single-use data stream cannot be sent twice, so its original error is raised instead.
						can_retry = request.rewind!
					end

					if attempt < @retries and can_retry
						retry
					else
						raise
					end
				ensure
					if connection
						@pool.release(connection)
					end
				end
			end
			
			# @returns [String] A summary of this client.
			def inspect
				"#<#{self.class} authority=#{@authority.inspect}>"
			end
			
			protected
			
			def make_response(request, connection, attempt)
				response = request.call(connection)
				
				response.pool = @pool
				
				return response
			end
			
			def assign_default_tags(tags)
				tags[:endpoint] = @endpoint.to_s
				tags[:protocol] = @protocol.to_s
			end
			
			def make_pool(**options)
				if connection_limit = options.delete(:connection_limit)
					warn "The connection_limit: option is deprecated, please use limit: instead.", uplevel: 2
					options[:limit] = connection_limit
				end
				
				self.assign_default_tags(options[:tags] ||= {})
				
				Async::Pool::Controller.wrap(**options) do
					Console.debug(self){"Making connection to #{@endpoint.inspect}"}
					
					@protocol.client(@endpoint.connect)
				end
			end
		end
	end
end

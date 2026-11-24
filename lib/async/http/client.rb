# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2017-2026, by Samuel Williams.
# Copyright, 2022, by Ian Ker-Seymer.

require "io/endpoint"

require "async/pool/controller"

require "protocol/http/body/completable"
require "protocol/http/error"
require "protocol/http/methods"

require_relative "protocol"

module Async
	module HTTP
		DEFAULT_RETRIES = 3
		
		# A sentinel used to distinguish an unspecified protocol, scheme or authority from an explicit value.
		UNSPECIFIED = Object.new.freeze
		private_constant :UNSPECIFIED
		
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
			def initialize(endpoint, protocol: UNSPECIFIED, scheme: UNSPECIFIED, authority: UNSPECIFIED, retries: DEFAULT_RETRIES, **options)
				@endpoint = endpoint
				@protocol = protocol
				@scheme = scheme
				@authority = authority
				
				# Whether the caller explicitly chose each value, or whether it should follow the endpoint:
				@protocol_specified = !protocol.equal?(UNSPECIFIED)
				@scheme_specified = !scheme.equal?(UNSPECIFIED)
				@authority_specified = !authority.equal?(UNSPECIFIED)
				
				@retries = retries
				
				# These options are reused if the approved connection identity changes and a new pool is required:
				@options = options
				
				@policy = Thread::Mutex.new
				@draining_pools = []
				
				apply_endpoint_defaults!
				
				# The pool is bound to the approved connection identity (certificate material, verification, ALPN and protocol). When that identity changes, we rotate to a new pool so that requests never reuse a connection established with a different approved configuration.
				@identity = connection_identity
				@pool = make_pool(**@options)
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
			
			# @attribute [Array] The connection identity used by the current pool.
			attr :identity
			
			attr :scheme
			attr :authority
			
			# Replace the endpoint used for subsequent requests.
			#
			# The connection pool is rotated if the approved connection identity changes, so new requests use the updated certificate material and ALPN configuration, while connections from the previous pool are allowed to drain before they are closed. Protocol, scheme and authority which were not explicitly specified when the client was created are re-resolved from the new endpoint.
			# @parameter endpoint [Endpoint | Interface(:connect)] The new endpoint.
			def endpoint=(endpoint)
				@endpoint = endpoint
				apply_endpoint_defaults!
				refresh_pool!
			end
			
			# @returns [Array] The identity of the connections which may be reused by this client.
			def connection_identity
				if @endpoint.nil?
					identity = nil
				elsif @endpoint.respond_to?(:connection_identity)
					identity = @endpoint.connection_identity
				elsif @endpoint.respond_to?(:key)
					identity = @endpoint.key
				else
					identity = @endpoint.object_id
				end
				
				[identity, @protocol, @scheme, @authority].freeze
			end
			
			# @attribute [Array<Async::Pool::Controller>] Pools which are no longer used for new requests, but may still be draining active connections.
			def draining_pools
				@policy.synchronize{@draining_pools.dup}
			end
			
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
			#
			# Pools which were rotated out because the approved connection identity changed are drained here too: their in-flight responses are allowed to finish, then the connections are closed.
			def close
				pools = @policy.synchronize do
					@draining_pools + [@pool]
				end
				
				pools.each do |pool|
					wait_for_pool(pool)
					pool.close
				end
			end
			
			# Re-check the approved connection identity and rotate the pool if it changed since the current pool was created.
			#
			# This is deliberately called before each request is dispatched, so that an in-place update of the endpoint (for example, replacing the certificate on an `OpenSSL::SSL::SSLContext` or changing the offered ALPN protocols) is observed even if the caller did not explicitly assign a new endpoint.
			# @returns [Boolean] Whether the pool was rotated.
			def refresh_pool!
				# Subclasses may supply their own pool without an endpoint (for example, a test double), in which case there is nothing to rotate:
				return false if @endpoint.nil? or @policy.nil?

				# Re-resolve any values which follow the endpoint, so that an in-place protocol change (for example, an HTTP/1 to HTTP/2 upgrade) is observed as well:
				apply_endpoint_defaults!

				identity = self.connection_identity
				retired = nil

				@policy.synchronize do
					return false if identity.eql?(@identity)

					retired = @pool
					@identity = identity
					@pool = make_pool(**@options)
				end

				if retired
					Console.debug(self){"Connection identity changed, draining retired pool: #{retired}"}
					drain(retired)
				end

				return true
			end
			
			# Send a request to the remote server, with automatic retries for idempotent requests.
			# @parameter request [Protocol::HTTP::Request] The request to send.
			# @returns [Protocol::HTTP::Response] The response from the server.
			def call(request)
				request.scheme ||= self.scheme
				request.authority ||= self.authority
				
				# Pick up any approved configuration change before selecting a connection:
				refresh_pool!
				
				attempt = 0
				pool = nil
				
				# We may retry the request if it is possible to do so. https://tools.ietf.org/html/draft-nottingham-httpbis-retry-01 is a good guide for how retrying requests should work.
				begin
					attempt += 1
					
					# Capture the pool for this attempt. If the identity changes while we are waiting, the next attempt will use the new pool.
					pool = @pool

					# A pool may be retired while this request is waiting for capacity. Any connection it hands back was established with the previous approved identity, so it must not be used. Release it (which lets the retired pool drain) and select a connection from the current pool instead. Nothing has been written yet, so this is safe even for a request which cannot be rewound.
					while connection = pool.acquire
						# The configuration may have changed while this request was waiting for capacity, or while the connection was being established. Re-check the identity now that we hold a connection, and if it changed, rotate the pool and put this connection back. Nothing has been written yet, so this is safe even for a request which cannot be rewound:
						refresh_pool!

						break if pool.equal?(@pool)

						pool.release(connection)
						connection = nil
						pool = @pool
					end

					unless connection
						raise ::Protocol::HTTP::RefusedError, "Connection identity changed while waiting for a connection!"
					end

					response = make_response(request, connection, attempt)
					
					# Bind the response to the pool which owns this connection, so that the connection is released to the correct (possibly retired) pool:
					response.pool = pool if response.respond_to?(:pool=)
					
					# This signals that the ensure block below should not try to release the connection, because it's bound into the response which will be returned:
					connection = nil
					return response
				rescue ::Protocol::HTTP::RefusedError
					# This is a specific case where the request was not processed by the server. So, we can resend even non-idempotent requests.
					if connection
						pool.release(connection)
						connection = nil
					end
					
					if attempt < @retries and request.rewind!
						refresh_pool!
						retry
					else
						raise
					end
				rescue ::Protocol::HTTP::RemoteError, SocketError, IOError, EOFError, Errno::ECONNRESET, Errno::EPIPE
					if connection
						pool.release(connection)
						connection = nil
					end
					
					if attempt < @retries and request.retry!
						refresh_pool!
						retry
					else
						raise
					end
				ensure
					if connection
						pool.release(connection)
					end
				end
			end
			
			# @returns [String] A summary of this client.
			def inspect
				"#<#{self.class} authority=#{@authority.inspect}>"
			end
			
			protected
			
			# Wait until the pool has no connections in use.
			#
			# Within a reactor this waits cooperatively, so that another fiber can release an in-flight connection; `Async::Pool::Controller#wait_until_free` instead blocks the reactor thread and would deadlock. Outside a reactor there is nothing to cooperate with, so the pool's own wait is used.
			def wait_for_pool(pool)
				if pool.busy?
					Console.warn(self){"Waiting for #{@protocol} pool to drain: #{pool}"}
					
					if task = Task.current?
						while pool.busy?
							task.sleep(0.01)
						end
					else
						pool.wait_until_free
					end
				end
			end
			
			# Resolve any protocol, scheme or authority which the caller did not specify explicitly from the current endpoint, so that an updated endpoint can change the negotiated protocol (for example, HTTP/1 to HTTP/2).
			def apply_endpoint_defaults!
				return if @endpoint.nil?

				if !@protocol_specified and @endpoint.respond_to?(:protocol)
					@protocol = @endpoint.protocol
				end

				if !@scheme_specified and @endpoint.respond_to?(:scheme)
					@scheme = @endpoint.scheme
				end

				if !@authority_specified and @endpoint.respond_to?(:authority)
					@authority = @endpoint.authority
				end
			end
			
			def make_response(request, connection, attempt)
				return request.call(connection)
			end
			
			# Drain a pool which is no longer used for new requests.
			#
			# Idle connections are closed immediately. Connections which are still serving a response are left alone until the response is released, so that requests which are already in progress can finish. The pool itself is closed once it has no connections in use.
			# @parameter pool [Async::Pool::Controller] The retired pool.
			def drain(pool)
				@policy.synchronize do
					@draining_pools << pool unless @draining_pools.include?(pool)
				end

				# Close any connections which are not currently in use. Connections in use are unaffected:
				pool.prune(0)

				if task = Task.current?
					task.async(transient: true, annotation: "#{self.class} draining retired pool") do
						drain_in_background(task, pool)
					end
				elsif !pool.busy?
					# Outside a reactor there is no other fiber to release the connections, so close the pool immediately if it is already idle. Otherwise leave it to be drained when the client is closed.
					close_drained_pool(pool)
				end
			end

			# Wait cooperatively for the pool to become idle, then close it. We must not use `Async::Pool::Controller#wait_until_free` here, because it waits on a thread condition variable and would block the reactor while a response is still being read.
			def drain_in_background(task, pool)
				while pool.busy?
					task.sleep(0.01)
				end

				close_drained_pool(pool)
			end
			
			def close_drained_pool(pool)
				pool.close
			ensure
				@policy.synchronize{@draining_pools.delete(pool)}
			end
			
			def assign_default_tags(tags, endpoint = @endpoint, protocol = @protocol)
				tags[:endpoint] = endpoint.to_s
				tags[:protocol] = protocol.to_s
			end
			
			def make_pool(**options)
				if connection_limit = options.delete(:connection_limit)
					warn "The connection_limit: option is deprecated, please use limit: instead.", uplevel: 2
					options[:limit] = connection_limit
				end

				# Bind the endpoint, protocol and approved identity to the pool at creation time. A retired pool therefore cannot establish a connection using a newer approved configuration, even if a request was waiting for capacity when the configuration changed:
				endpoint = @endpoint
				protocol = @protocol
				identity = @identity

				self.assign_default_tags(options[:tags] ||= {}, endpoint, protocol)

				Async::Pool::Controller.wrap(**options) do
					if identity and endpoint.respond_to?(:connection_identity)
						unless endpoint.connection_identity.eql?(identity[0])
							# The approved configuration changed while this request was waiting for a connection. No connection has been established yet, so the request can be retried on the current pool:
							raise ::Protocol::HTTP::RefusedError, "Connection identity changed while waiting for a connection!"
						end
					end

					Console.debug(self){"Making connection to #{endpoint.inspect}"}

					protocol.client(endpoint.connect)
				end
			end
		end
	end
end

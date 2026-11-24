# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2019-2026, by Samuel Williams.
# Copyright, 2021-2022, by Adam Daniels.
# Copyright, 2024, by Thomas Morgan.
# Copyright, 2024, by Igor Sidorov.
# Copyright, 2024, by Hal Brodigan.
# Copyright, 2025, by William T. Nelson.

require "io/endpoint"
require "io/endpoint/host_endpoint"
require "io/endpoint/ssl_endpoint"

require_relative "protocol/http"
require_relative "protocol/https"

require "digest"
require "openssl"
require "uri"

module Async
	module HTTP
		# Represents a way to connect to a remote HTTP server.
		class Endpoint < ::IO::Endpoint::Generic
			SCHEMES = {
				"http" => URI::HTTP,
				"https" => URI::HTTPS,
				"ws" => URI::WS,
				"wss" => URI::WSS,
			}
			
			# Parse a URL string into an endpoint.
			# @parameter string [String] The URL to parse.
			# @parameter endpoint [IO::Endpoint::Generic | Nil] An optional underlying endpoint to use.
			# @parameter options [Hash] Additional options to pass to {initialize}.
			# @returns [Endpoint] The parsed endpoint.
			def self.parse(string, endpoint = nil, **options)
				url = URI.parse(string).normalize
				
				return self.new(url, endpoint, **options)
			end
			
			# Construct an endpoint with a specified scheme, hostname, optional path, and options.
			#
			# @parameter scheme [String] The scheme to use, e.g. "http" or "https".
			# @parameter hostname [String] The hostname to connect to (or bind to).
			# @parameter *options [Hash] Additional options, passed to {initialize}.
			def self.for(scheme, hostname, path = "/", **options)
				# TODO: Consider using URI.for once it becomes available:
				uri_klass = SCHEMES.fetch(scheme.downcase) do
					raise ArgumentError, "Unsupported scheme: #{scheme.inspect}"
				end
				
				self.new(
					uri_klass.new(scheme, nil, hostname, nil, nil, path, nil, nil, nil).normalize,
					**options
				)
			end
			
			# Coerce the given object into an endpoint.
			# @parameter url [String | Endpoint] The URL or endpoint to convert.
			def self.[](url)
				if url.is_a?(Endpoint)
					return url
				else
					Endpoint.parse(url.to_s)
				end
			end
			
			# @option scheme [String] the scheme to use, overrides the URL scheme.
			# @option hostname [String] the hostname to connect to (or bind to), overrides the URL hostname (used for SNI).
			# @option port [Integer] the port to bind to, overrides the URL port.
			# @option ssl_context [OpenSSL::SSL::SSLContext] the context to use for TLS.
			# @option tls_configuration [IO::Endpoint::TLS::Configuration] the transport-neutral TLS configuration.
			# @option alpn_protocols [Array(String)] the alpn protocols to negotiate.
			def initialize(url, endpoint = nil, **options)
				super(**options)
				
				raise ArgumentError, "URL must be absolute (include scheme, host): #{url}" unless url.absolute?
				
				@url = url
				
				if endpoint
					# Remember the original endpoint so that `#update` can rebuild the TLS wrapper against the same underlying transport:
					@underlying_endpoint = endpoint
					@endpoint = self.build_endpoint(endpoint)
				else
					@underlying_endpoint = nil
					@endpoint = nil
				end
			end
			
			# @returns [URI] The URL representation of this endpoint, including port if non-default.
			def to_url
				url = @url.dup
				
				unless default_port?
					url.port = self.port
				end
				
				return url
			end
			
			# @returns [String] A short string representation of this endpoint.
			def to_s
				"\#<#{self.class} #{self.to_url} #{@options}>"
			end
			
			# @returns [String] A detailed string representation of this endpoint.
			def inspect
				"\#<#{self.class} #{self.to_url} #{@options.inspect}>"
			end
			
			attr :url
			
			# @returns [Addrinfo] The address of the underlying endpoint.
			def address
				endpoint.address
			end
			
			# @returns [Boolean] Whether this endpoint uses a secure protocol (HTTPS or WSS).
			def secure?
				["https", "wss"].include?(self.scheme)
			end
			
			# @returns [Protocol] The protocol to use for this endpoint.
			def protocol
				@options.fetch(:protocol) do
					if secure?
						Protocol::HTTPS
					else
						Protocol::HTTP
					end
				end
			end
			
			# @returns [Integer] The default port for this endpoint's scheme.
			def default_port
				secure? ? 443 : 80
			end
			
			# @returns [Boolean] Whether the endpoint's port is the default for its scheme.
			def default_port?
				port == default_port
			end
			
			# @returns [Integer] The port number for this endpoint.
			def port
				@options[:port] || @url.port || default_port
			end
			
			# The hostname is the server we are connecting to:
			def hostname
				@options[:hostname] || @url.hostname
			end
			
			# @returns [String] The URL scheme, e.g. `"http"` or `"https"`.
			def scheme
				@options[:scheme] || @url.scheme
			end
			
			# @returns [String] The authority component (hostname and optional port).
			def authority(ignore_default_port = true)
				if ignore_default_port and default_port?
					@url.hostname
				else
					"#{@url.hostname}:#{port}"
				end
			end
			
			# Return the path and query components of the given URL.
			def path
				buffer = @url.path || "/"
				
				if query = @url.query
					buffer = "#{buffer}?#{query}"
				end
				
				return buffer
			end
			
			# @returns [Array(String)] The ALPN protocol names for TLS negotiation.
			def alpn_protocols
				@options.fetch(:alpn_protocols){self.protocol.names}
			end
			
			# @returns [Boolean] Whether the endpoint refers to a localhost address.
			def localhost?
				@url.hostname =~ /^(.*?\.)?localhost\.?$/
			end
			
			# We don't try to validate peer certificates when talking to localhost because they would always be self-signed.
			def ssl_verify_mode
				if self.localhost?
					OpenSSL::SSL::VERIFY_NONE
				else
					OpenSSL::SSL::VERIFY_PEER
				end
			end
			
			# @returns [OpenSSL::SSL::SSLContext] The SSL context for TLS connections.
			def ssl_context
				@options[:ssl_context] || OpenSSL::SSL::SSLContext.new.tap do |context|
					if alpn_protocols = self.alpn_protocols
						context.alpn_protocols = alpn_protocols
					end
					
					context.set_params(
						verify_mode: self.ssl_verify_mode
					)
				end
			end
			
			# @returns [IO::Endpoint::TLS::Configuration | Nil] The transport-neutral TLS configuration.
			def tls_configuration
				@options[:tls_configuration]
			end
			
			# A content-derived identity for connections to this endpoint.
			#
			# The identity describes the approved certificate material, verification policy, negotiated protocols and ALPN offer. It is deliberately derived from the current values of the options rather than from object identity, because an approved TLS configuration may be updated in place (for example, by replacing the certificate on an `OpenSSL::SSL::SSLContext`). Connections created for one identity must not be reused for another, and the client uses this value to select the appropriate connection pool.
			#
			# Only digests of certificate and key material are included, never the material itself.
			#
			# @returns [Array] A frozen, comparable identity.
			def connection_identity
				[
					scheme,
					hostname,
					port,
					protocol_identity,
					tls_identity,
				].freeze
			end

			# @returns [Array] The approved certificate material, verification policy and ALPN offer used when establishing a connection.
			def tls_identity
				tls_connection_identity
			end
			
			# Apply an update to the endpoint's options, such as a new approved TLS configuration or ALPN protocol list.
			#
			# The resolved underlying endpoint is rebuilt so that subsequent connections use the updated configuration. Existing connections are not modified; use {Client#refresh_pool!} (or simply make another request, which refreshes automatically) to rotate the connection pool when {#connection_identity} changes.
			#
			# @parameter options [Hash] The options to merge into the current options.
			# @returns [Endpoint] This endpoint.
			def update(**options)
				@options = @options.merge(options).freeze
				@endpoint = nil
				
				return self
			end
			
			# Build a suitable endpoint, optionally wrapping in TLS for secure connections.
			# @parameter endpoint [IO::Endpoint::Generic | Nil] An optional underlying endpoint to wrap.
			# @returns [IO::Endpoint::Generic] The constructed endpoint.
			def build_endpoint(endpoint = nil)
				endpoint ||= tcp_endpoint
				
				if secure?
					# Wrap it in SSL:
					return ::IO::Endpoint::SSLEndpoint.new(endpoint,
						ssl_context: self.ssl_context,
						tls_configuration: self.tls_configuration,
						hostname: @url.hostname,
						timeout: self.timeout,
					)
				end
				
				return endpoint
			end
			
			# @returns [IO::Endpoint::Generic] The resolved endpoint, built on demand.
			def endpoint
				@endpoint ||= build_endpoint(@underlying_endpoint)
			end
			
			# Set the underlying endpoint, wrapping it as needed.
			# @parameter endpoint [IO::Endpoint::Generic] The endpoint to assign.
			def endpoint=(endpoint)
				@underlying_endpoint = endpoint
				@endpoint = build_endpoint(endpoint)
			end
			
			# Bind to the endpoint.
			def bind(*arguments, &block)
				endpoint.bind(*arguments, &block)
			end
			
			# Connect to the endpoint.
			def connect(&block)
				endpoint.connect(&block)
			end
			
			# Enumerate all resolved endpoints.
			# @yields {|endpoint| ...} Each resolved endpoint.
			# 	@parameter endpoint [Endpoint] The resolved endpoint.
			def each
				return to_enum unless block_given?
				
				self.tcp_endpoint.each do |endpoint|
					yield self.class.new(@url, endpoint, **@options)
				end
			end
			
			# @returns [Array] A key suitable for identifying this endpoint in a hash.
			def key
				[@url, @options]
			end
			
			# @returns [Boolean] Whether two endpoints are equal.
			def eql? other
				self.key.eql? other.key
			end
			
			# @returns [Integer] The hash code for this endpoint.
			def hash
				self.key.hash
			end
			
			protected
			
			# @returns [Array] The identity of the protocol used to create connections.
			def protocol_identity
				protocol = self.protocol
				
				if protocol.respond_to?(:protocol)
					# Configured protocols delegate to an underlying protocol, and some expose their own configuration:
					[protocol.class, protocol.protocol, protocol.respond_to?(:options) ? protocol.options : nil]
				else
					[protocol]
				end
			end
			
			# @returns [Array] The identity of the TLS material and negotiation used to create connections.
			def tls_connection_identity
				return freeze_identity unless secure?
				
				[
					ssl_context_identity,
					tls_configuration_identity,
					alpn_identity,
					ssl_verify_mode,
				].freeze
			end
			
			def freeze_identity
				[:insecure].freeze
			end
			
			def alpn_identity
				protocols = self.alpn_protocols
				protocols&.map{|name| name.to_s.dup.freeze}&.freeze
			end
			
			def tls_configuration_identity
				if configuration = self.tls_configuration
					[
						trust_store_identity(configuration.trust_store),
						certificate_chain_identity(configuration.certificate_chain),
						digest_identity(configuration.private_key),
						configuration.verification,
					].freeze
				end
			end
			
			def trust_store_identity(trust_store)
				if trust_store
					[
						trust_store.certificates.map{|certificate| digest_identity(certificate)},
						trust_store.system_certificates?,
					].freeze
				end
			end
			
			def ssl_context_identity
				context = @options[:ssl_context]
				
				if context
					[
						context.verify_mode,
						context.verify_hostname,
						context.alpn_protocols&.map{|name| name.to_s.dup.freeze}&.freeze,
						certificate_chain_identity(context.extra_chain_cert),
						digest_identity(context.cert),
						digest_identity(context.key),
						cert_store_identity(context.cert_store),
					].freeze
				else
					[:default, self.ssl_verify_mode].freeze
				end
			end
			
			def cert_store_identity(cert_store)
				# An `OpenSSL::X509::Store` does not expose its certificates for enumeration, and its `inspect` includes verification state which changes as handshakes complete. Use the store's stable object identity instead: replacing the store is observed, while a store shared by several approved configurations remains a shared reference.
				cert_store ? [cert_store.class, cert_store.object_id] : nil
			end
			
			def certificate_chain_identity(chain)
				chain&.map{|certificate| digest_identity(certificate)}&.freeze
			end
			
			def digest_identity(material)
				case material
				when nil
					nil
				when String
					Digest::SHA256.hexdigest(material)
				else
					if material.respond_to?(:to_der)
						Digest::SHA256.hexdigest(material.to_der)
					else
						Digest::SHA256.hexdigest(material.to_s)
					end
				end
			end
			
			def tcp_options
				options = @options.dup
				
				options.delete(:scheme)
				options.delete(:port)
				options.delete(:hostname)
				options.delete(:ssl_context)
				options.delete(:tls_configuration)
				options.delete(:alpn_protocols)
				options.delete(:protocol)
				
				return options
			end
			
			def tcp_endpoint
				::IO::Endpoint.tcp(self.hostname, port, **tcp_options)
			end
		end
	end
end

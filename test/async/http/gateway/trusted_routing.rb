# frozen_string_literal: true

require "async/barrier"
require "async/http"
require "async/http/client"
require "async/http/mock/endpoint"
require "async/http/protocol/request"
require "protocol/http"
require "set"
require "socket"

require "sus/fixtures/async/reactor_context"

module TrustedRoutingRegression
	SERVICE_AUTHORITIES = {
		"alpha.internal" => "alpha",
		"beta.internal" => "beta",
	}.freeze

	def self.request(request_id, service, headers: nil)
		authority = service == :alpha ? "alpha.internal" : "beta.internal"

		::Protocol::HTTP::Request[
			"GET", "/jobs/#{request_id}", headers, nil,
			scheme: "http", authority: authority
		]
	end

	class TrustedSource
		attr_reader :key, :ip_address, :port, :address, :connection_id, :peer_id

		def initialize(request)
			@address = request.remote_address
			@peer = request.peer
			@connection = request.connection
			@connection_id = @connection&.object_id
			@peer_id = @peer&.object_id
			@ip_address = @address&.ip_address if @address&.ip?
			@port = @address.ip_port if @address&.ip?
			@key = compute_key
		end

		def audit
			{
				key: @key,
				ip_address: @ip_address,
				port: @port,
				address: @address&.inspect,
				connection_id: @connection_id,
				peer_id: @peer_id,
			}
		end

		private

		def compute_key
			if @address&.ip?
				"ip:#{@address.ip_address}"
			elsif @address && @address.afamily == Socket::AF_UNIX
				"local:unix"
			else
				"connection:#{@connection_id}"
			end
		end
	end

	class ApprovalPolicy
		def initialize(approved = [])
			@approved = approved.to_set
		end

		def allow?(source_key, service)
			@approved.include?([source_key, service])
		end

		def approve(source_key, service)
			@approved << [source_key, service]
		end
	end

	class IsolatedService
		attr_reader :name, :calls

		def initialize(name)
			@name = name
			@calls = []
			@endpoint = ::Async::HTTP::Mock::Endpoint.new(
				::Async::HTTP::Protocol::HTTP2, "http", "#{name}.internal"
			)
		end

		def start
			@server = Async do
				@endpoint.run { |request| handle(request) }
			end
			@client = ::Async::HTTP::Client.new(
				@endpoint,
				protocol: ::Async::HTTP::Protocol::HTTP2,
				authority: "#{@name}.internal",
				retries: 0
			)

			self
		end

		def call(request)
			@client.call(request)
		end

		def request_ids
			@calls.map { |call| call[:request_id] }
		end

		def close
			@client&.close
			@server&.stop
		end

		private

		def handle(request)
			request_id = File.basename(request.path)
			@calls << {request_id: request_id, path: request.path}

			::Protocol::HTTP::Response[
				200,
				{"content-type" => "text/plain"},
				["handled #{@name}"]
			]
		end
	end

	class Gateway
		def initialize(policy:, events:, services:)
			@policy = policy
			@events = events
			@services = services
		end

		def call(request)
			source = TrustedSource.new(request)
			service = SERVICE_AUTHORITIES[request.authority]
			request_id = File.basename(request.path)

			if service.nil?
				record("unknown_route", request_id, service, source)
				return ::Protocol::HTTP::Response[404, {}, ["unknown service"]]
			end

			unless @policy.allow?(source.key, service)
				record("deny", request_id, service, source)
				return ::Protocol::HTTP::Response[403, {}, ["service not approved for source"]]
			end

			record("allow", request_id, service, source)
			backend_request = ::Protocol::HTTP::Request[
				request.method,
				request.path,
				nil,
				nil,
				scheme: "http",
				authority: "#{service}.internal"
			]
			@services.fetch(service).call(backend_request)
		end

		private

		def record(decision, request_id, service, source)
			@events << {
				decision: decision,
				request_id: request_id,
				service: service,
				source: source.audit,
			}
		end
	end

	class Harness
		attr_reader :endpoint, :client, :policy, :events, :services

		def initialize(source_key = "local:unix")
			@source_key = source_key
			@policy = ApprovalPolicy.new([[source_key, "alpha"]])
			@events = []
			@services = SERVICE_AUTHORITIES.values.uniq.to_h do |name|
				[name, IsolatedService.new(name)]
			end
			@gateway = Gateway.new(policy: @policy, events: @events, services: @services)
		end

		def start_mock
			start_services
			@endpoint = ::Async::HTTP::Mock::Endpoint.new(
				::Async::HTTP::Protocol::HTTP2, "http", "gateway.local"
			)
			@server = Async do
				@endpoint.run { |request| @gateway.call(request) }
			end
			@client = make_client

			self
		end

		def rebuild_client
			@client&.close
			@client = make_client
		end

		def request_ids(service)
			@services.fetch(service).request_ids
		end

		def close
			@client&.close
			@server&.stop
			@services.each_value(&:close)
		end

		protected

		def start_services
			@services.each_value(&:start)
		end

		def make_client
			::Async::HTTP::Client.new(
				@endpoint,
				protocol: ::Async::HTTP::Protocol::HTTP2,
				authority: "gateway.local",
				retries: 0
			)
		end
	end

	class LoopbackHarness < Harness
		def initialize
			super("ip:127.0.0.1")
		end

		def start
			start_services
			@endpoint = ::Async::HTTP::Endpoint.parse(
				"http://127.0.0.1:0",
				protocol: ::Async::HTTP::Protocol::HTTP2
			)
			@bound_endpoint = @endpoint.bound
			@server = ::Async::HTTP::Server.new(@gateway, @bound_endpoint)
			@server_task = @server.run
			@client = make_client

			self
		end

		def close
			::Async::Task.current.with_timeout(1) do
				@client&.close
				@server_task&.stop
				@server_task&.wait_all
			end
		ensure
			@bound_endpoint&.close
			@services.each_value(&:close)
		end

		private

		def make_client
			client_endpoint = @bound_endpoint.local_address_endpoint(timeout: @endpoint.timeout)

			::Async::HTTP::Client.new(
				client_endpoint,
				protocol: ::Async::HTTP::Protocol::HTTP2,
				authority: "gateway.local",
				retries: 0
			)
		end
	end
end

describe "trusted connection routing" do
	include Sus::Fixtures::Async::ReactorContext

	let(:harness) { TrustedRoutingRegression::Harness.new.start_mock }

	after do
		@harness&.close
	end

	it "judges both multiplexed requests from the shared connection's trusted source" do
		gateway_harness = harness
		results = {}
		barrier = Async::Barrier.new

		barrier.async do
			response = gateway_harness.client.call(
				TrustedRoutingRegression.request("req-alpha", :alpha)
			)
			results["req-alpha"] = {
				status: response.status,
				body: response.read,
				connection_id: response.connection.object_id,
			}
		end

		barrier.async do
			response = gateway_harness.client.call(
				TrustedRoutingRegression.request("req-beta-pending", :beta)
			)
			results["req-beta-pending"] = {
				status: response.status,
				body: response.read,
				connection_id: response.connection.object_id,
			}
		end

		barrier.wait

		expect(results["req-alpha"][:status]).to be == 200
		expect(results["req-alpha"][:body]).to be == "handled alpha"
		expect(results["req-beta-pending"][:status]).to be == 403
		expect(results["req-alpha"][:connection_id]).to be == results["req-beta-pending"][:connection_id]

		observed = gateway_harness.events.to_h { |event| [event[:request_id], event] }
		alpha_event = observed.fetch("req-alpha")
		beta_event = observed.fetch("req-beta-pending")

		expect(alpha_event[:decision]).to be == "allow"
		expect(alpha_event[:service]).to be == "alpha"
		expect(beta_event[:decision]).to be == "deny"
		expect(beta_event[:service]).to be == "beta"

		alpha_source = alpha_event[:source]
		beta_source = beta_event[:source]

		expect(alpha_source[:key]).to be == "local:unix"
		expect(beta_source[:key]).to be == "local:unix"
		expect(alpha_source[:connection_id]).not.to be_nil
		expect(alpha_source[:connection_id]).to be == beta_source[:connection_id]
		expect(alpha_source[:peer_id]).to be == beta_source[:peer_id]
		expect(alpha_source[:address]).to be =~ /AF_UNIX/

		expect(gateway_harness.request_ids("alpha")).to be == ["req-alpha"]
		expect(gateway_harness.request_ids("beta")).to be == []
	end

	it "uses approval and the rebuilt connection for the second service" do
		first_response = harness.client.call(
			TrustedRoutingRegression.request("req-beta-pending", :beta)
		)

		expect(first_response.status).to be == 403
		expect(first_response.read).to be == "service not approved for source"
		first_client_connection_id = first_response.connection.object_id
		first_server_connection_id = harness.events.last[:source][:connection_id]
		expect(harness.request_ids("beta")).to be == []

		harness.policy.approve("local:unix", "beta")
		harness.rebuild_client

		second_response = harness.client.call(
			TrustedRoutingRegression.request("req-beta-approved", :beta)
		)

		expect(second_response.status).to be == 200
		expect(second_response.read).to be == "handled beta"
		expect(second_response.connection.object_id).not.to be == first_client_connection_id

		approved_event = harness.events.last
		expect(approved_event[:decision]).to be == "allow"
		expect(approved_event[:request_id]).to be == "req-beta-approved"
		expect(approved_event[:service]).to be == "beta"
		expect(approved_event[:source][:key]).to be == "local:unix"
		expect(approved_event[:source][:connection_id]).not.to be == first_server_connection_id

		expect(harness.request_ids("beta")).to be == ["req-beta-approved"]
	end

	it "uses the kernel-provided loopback address across a rebuilt TCP connection" do
		loopback = TrustedRoutingRegression::LoopbackHarness.new

		begin
			loopback.start
		rescue Errno::EPERM, Errno::EACCES => error
			loopback.close
			skip("loopback binding is unavailable: #{error.class}")
		end

		begin
			alpha_response = loopback.client.call(
				TrustedRoutingRegression.request("loop-alpha", :alpha)
			)
			beta_response = loopback.client.call(
				TrustedRoutingRegression.request("loop-beta-pending", :beta)
			)

			expect(alpha_response.status).to be == 200
			expect(alpha_response.read).to be == "handled alpha"
			expect(beta_response.status).to be == 403
			expect(alpha_response.connection.object_id).to be == beta_response.connection.object_id

			first_source = loopback.events.first[:source]
			expect(first_source[:key]).to be == "ip:127.0.0.1"
			expect(first_source[:ip_address]).to be == "127.0.0.1"
			expect(first_source[:port]).to be_a(Integer)
			expect(first_source[:port]).to be > 0
			expect(loopback.events.last[:source][:connection_id]).to be == first_source[:connection_id]
			expect(loopback.request_ids("alpha")).to be == ["loop-alpha"]
			expect(loopback.request_ids("beta")).to be == []

			loopback.policy.approve("ip:127.0.0.1", "beta")
			loopback.rebuild_client

			approved_response = loopback.client.call(
				TrustedRoutingRegression.request("loop-beta-approved", :beta)
			)

			expect(approved_response.status).to be == 200
			expect(approved_response.read).to be == "handled beta"
			expect(approved_response.connection.object_id).not.to be == alpha_response.connection.object_id
			expect(loopback.events.last[:source][:connection_id]).not.to be == first_source[:connection_id]
			expect(loopback.request_ids("beta")).to be == ["loop-beta-approved"]
		ensure
			alpha_response&.close
			beta_response&.close
			approved_response&.close
			loopback.close
		end
	end

	it "ignores routing hints carried by ordinary request headers" do
		headers = {
			"x-forwarded-for" => "203.0.113.7",
			"x-real-ip" => "203.0.113.8",
			"forwarded" => "for=203.0.113.9",
		}

		response = harness.client.call(
			TrustedRoutingRegression.request("req-spoofed", :alpha, headers: headers)
		)

		expect(response.status).to be == 200
		expect(response.read).to be == "handled alpha"
		event = harness.events.first
		source = event[:source]

		expect(source[:key]).to be == "local:unix"
		expect(source[:address]).to be =~ /AF_UNIX/
		expect(source[:address]).not.to be =~ /203\.0\.113/
		expect(harness.request_ids("alpha")).to be == ["req-spoofed"]
	end

	it "gives free-standing synthetic requests no settable trusted source" do
		request = ::Async::HTTP::Protocol::Request["GET", "/jobs/standalone"]
		request.headers["x-forwarded-for"] = "203.0.113.10"

		expect(request.connection).to be_nil
		expect(request.peer).to be_nil
		expect(request.remote_address).to be_nil
		expect(request.respond_to?(:remote_address=)).to be == false
	end
end

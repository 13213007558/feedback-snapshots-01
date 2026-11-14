require 'ipaddr'
require 'socket'

require 'net/ssh/errors'
require 'net/ssh/loggable'
require 'net/ssh/service/forward/policy'

module Net
  module SSH
    module Service
      # This class implements various port forwarding services for use by
      # Net::SSH clients. The Forward class should never need to be instantiated
      # directly; instead, it should be accessed via the singleton instance
      # returned by Connection::Session#forward:
      #
      #   ssh.forward.local(1234, "www.capify.org", 80)
      #
      # == Destination policy
      #
      # A destination policy restricts which forwarding destinations may be
      # used, for each direction separately. Set a callable with #policy=, or
      # pass :forward_policy to Net::SSH.start:
      #
      #   ssh.forward.policy = lambda do |request|
      #     allowed = [["db.internal", 5432], ["cache.internal", 6379]]
      #     allowed.include?([request.host, request.port]) ? [request.host, request.port] : nil
      #   end
      #
      # The callable receives a Forward::Request and returns a Forward::Permit,
      # an Array of [host, port, ips], a Hash, or nil/false to refuse. It is
      # called for:
      #
      # * :local - binding a local listener (#local, #local_socket). The server
      #   resolves and connects the destination, so Request#target_resolution is
      #   :server and no addresses are resolved here. The policy can restrict the
      #   name and port only; it must not claim to have pinned the final IP.
      # * :remote - requesting a remote listener (#remote). The client connects
      #   the destination for every channel the server opens, so it is resolved
      #   once, before tcpip-forward is sent, and the permit carries the
      #   addresses that may be connected. A later DNS change can't redirect it.
      # * :server - a channel the server opens (forwarded-tcpip). The policy sees
      #   the listener and originator the server claims and the destination it
      #   will connect, and can refuse the channel, which is answered with
      #   CHANNEL_OPEN_FAILURE before any address is resolved or connected.
      #
      # A cancelled forward revokes its permit: a channel the server opens after
      # #cancel_remote, or a connection accepted after #cancel_local, is refused
      # and never reaches the connection path. With no policy, forwarding is
      # unrestricted, exactly as before this interface existed.
      #
      # == Name resolution boundaries
      #
      # Request#target_resolution says which end resolves the destination:
      #
      # * :server for local forwarding. The client sends the name to the server
      #   and the server resolves and connects it, so the client never sees the
      #   address. The policy limits the name and port; approving one address
      #   literal is still only a request to the server. There is no claim that
      #   the final IP was restricted.
      # * :client for remote forwarding and server-opened channels. The client
      #   resolves the destination once, when the forward is approved, and then
      #   connects only the resolved addresses (the Permit's #ips), so a later
      #   DNS answer can't reach a different host. Resolution is a snapshot at
      #   approval time, not a property enforced for every future answer.
      #
      # The listener address is resolved by the side that binds it. A remote
      # listener's bind address (and a server-opened channel's connected
      # address and originator) are reported by the server and are not verified
      # by the client; they are context for the policy, not claims it can
      # enforce. Request#listener_resolution names that side.
      class Forward
        include Loggable

        # The underlying connection service instance that the port-forwarding
        # services employ.
        attr_reader :session

        # The callable used to resolve host names for the client. It receives
        # the host and port and returns the addresses to connect to, as
        # Addrinfo objects or strings; the default is Socket.getaddrinfo.
        attr_writer :resolver

        # The callable used to open the TCP connection for remote and
        # server-opened channels. It receives the host or IP and the port and
        # returns a socket; the default is TCPSocket.new.
        attr_writer :connector

        # A simple class for representing a requested remote forwarded port.
        Remote = Struct.new(:host, :port, :grant) # :nodoc:

        # A local forwarding registration. +host+ and +port+ are the destination
        # the server will connect to for each accepted client.
        LocalForward = Struct.new(:socket, :host, :port, :grant) # :nodoc:

        # The policy callable set with #policy=. It is called with a
        # Service::Forward::Request (see policy.rb) and must return a
        # Service::Forward::Permit, an Array of [host, port] or [host, port,
        # ip], or nil/false to refuse. The default nil policy permits
        # everything, preserving the behaviour of earlier releases.
        attr_reader :policy

        # The verified identity used for policy decisions, as
        # [session_id, user], or nil to derive it from the session. The session
        # id is the SSH session id from the key exchange, and the user the one
        # that was authenticated. Callers that know them (e.g. through a
        # ControlMaster, whose transport hides both) can set them here.
        attr_accessor :policy_identity

        # Sets the destination policy callable; see #policy.
        def policy=(callable)
          unless callable.nil? || callable.respond_to?(:call)
            raise ArgumentError, "forwarding policy must respond to call or be nil, got #{callable.class}"
          end

          @policy = callable
        end

        # Instantiates a new Forward service instance atop the given connection
        # service session. This will register new channel open handlers to handle
        # the specialized channels that the SSH port forwarding protocols employ.
        def initialize(session)
          @session = session
          self.logger = session.logger
          @remote_forwarded_ports = {}
          @local_forwarded_ports = {}
          @agent_forwarded = false
          @local_forwarded_sockets = {}
          @policy = nil
          @policy_identity = nil
          @resolver = nil
          @connector = nil
          @pending_remote_grants = {}

          session.on_open_channel('forwarded-tcpip', &method(:forwarded_tcpip))
          session.on_open_channel('auth-agent', &method(:auth_agent_channel))
          session.on_open_channel('auth-agent@openssh.com', &method(:auth_agent_channel))
        end

        # Starts listening for connections on the local host, and forwards them
        # to the specified remote host/port via the SSH connection. This method
        # accepts either three or four arguments. When four arguments are given,
        # they are:
        #
        # * the local address to bind to
        # * the local port to listen on
        # * the remote host to forward connections to
        # * the port on the remote host to connect to
        #
        # If three arguments are given, it is as if the local bind address is
        # "127.0.0.1", and the rest are applied as above.
        #
        # To request an ephemeral port on the local server, provide 0 (zero) for
        # the local port number. In all cases, this method will return the port
        # that has been assigned.
        #
        #   ssh.forward.local(1234, "www.capify.org", 80)
        #   assigned_port = ssh.forward.local("0.0.0.0", 0, "www.capify.org", 80)
        def local(*args)
          if args.length < 3 || args.length > 4
            raise ArgumentError, "expected 3 or 4 parameters, got #{args.length}"
          end

          local_port_type = :long
          unix_server = nil
          local_port = nil
          bind_address = "127.0.0.1"

          if defined?(UNIXServer) and args.first.class == UNIXServer
            local_port_type = :string
            unix_server = args.shift
            bind_address = unix_server.path
          else
            bind_address = args.shift if args.first.is_a?(String) && args.first =~ /\D/
            local_port = args.shift.to_i
          end

          remote_host = args.shift
          remote_port = args.shift.to_i

          # Authorize the destination before anything is bound, and keep the
          # decision with the registration so a cancelled forward can't be used
          # by a connection that was already accepted.
          grant = authorize_local(remote_host, remote_port, bind_address)

          # A UNIXServer passed by the caller is used as is; a TCP listener is
          # only created now that the destination is authorized.
          socket = unix_server || TCPServer.new(bind_address, local_port)

          local_port = socket.addr[1] if local_port == 0 # ephemeral port was requested

          @local_forwarded_ports[[local_port, bind_address]] = LocalForward.new(socket, remote_host, remote_port, grant)

          session.listen_to(socket) do |server|
            client = server.accept
            debug { "received connection on #{socket}" }

            begin
              reauthorize_local(grant)
            rescue NotPermitted => e
              debug { "refusing connection on #{socket}: #{e.message}" }
              client.close
              next
            end

            channel = session.open_channel("direct-tcpip", :string, remote_host, :long,
                                           remote_port, :string, bind_address, local_port_type, local_port) do |achannel|
              achannel.info { "direct channel established" }
            end

            prepare_client(client, channel, :local)

            channel.on_open_failed do |ch, code, description|
              channel.error { "could not establish direct channel: #{description} (#{code})" }
              session.stop_listening_to(channel[:socket])
              channel[:socket].close
            end
          end

          local_port
        end

        # Terminates an active local forwarded port.
        #
        #   ssh.forward.cancel_local(1234)
        #   ssh.forward.cancel_local(1234, "0.0.0.0")
        def cancel_local(port, bind_address = "127.0.0.1")
          registration = @local_forwarded_ports.delete([port, bind_address])
          return unless registration

          registration.grant.revoke!
          socket = registration.socket
          socket.shutdown rescue nil
          socket.close rescue nil
          session.stop_listening_to(socket)
        end

        # Returns a list of all active locally forwarded ports. The returned value
        # is an array of arrays, where each element is a two-element tuple
        # consisting of the local port and bind address corresponding to the
        # forwarding port.
        def active_locals
          @local_forwarded_ports.keys
        end

        # Starts listening for connections on the local host, and forwards them
        # to the specified remote socket via the SSH connection. This will
        # (re)create the local socket file. The remote server needs to have the
        # socket file already available.
        #
        #   ssh.forward.local_socket('/tmp/local.sock', '/tmp/remote.sock')
        def local_socket(local_socket_path, remote_socket_path)
          # A streamlocal destination is a path, not a host and port; the
          # server resolves and opens it. Authorize it before creating the local
          # socket so a refused path leaves nothing behind.
          grant = authorize_local(remote_socket_path, nil, local_socket_path, channel_type: "direct-streamlocal@openssh.com")

          File.delete(local_socket_path) if File.exist?(local_socket_path)
          socket = Socket.unix_server_socket(local_socket_path)

          @local_forwarded_sockets[local_socket_path] = LocalForward.new(socket, remote_socket_path, nil, grant)

          session.listen_to(socket) do |server|
            client = server.accept[0]
            debug { "received connection on #{socket}" }

            begin
              reauthorize_local(grant)
            rescue NotPermitted => e
              debug { "refusing connection on #{socket}: #{e.message}" }
              client.close
              next
            end

            channel = session.open_channel("direct-streamlocal@openssh.com",
                                           :string, remote_socket_path,
                                           :string, nil,
                                           :long, 0) do |achannel|
              achannel.info { "direct channel established" }
            end

            prepare_client(client, channel, :local)

            channel.on_open_failed do |ch, code, description|
              channel.error { "could not establish direct channel: #{description} (#{code})" }
              session.stop_listening_to(channel[:socket])
              channel[:socket].close
            end
          end

          local_socket_path
        end

        # Terminates an active local forwarded socket.
        #
        #   ssh.forward.cancel_local_socket('/tmp/foo.sock')
        def cancel_local_socket(local_socket_path)
          registration = @local_forwarded_sockets.delete(local_socket_path)
          return unless registration

          registration.grant.revoke!
          socket = registration.socket
          socket.shutdown rescue nil
          socket.close rescue nil
          session.stop_listening_to(socket)
        end

        # Returns a list of all active locally forwarded sockets. The returned value
        # is an array of Unix domain socket file paths.
        def active_local_sockets
          @local_forwarded_sockets.keys
        end

        # Requests that all connections on the given remote-port be forwarded via
        # the local host to the given port/host. The last argument describes the
        # bind address on the remote host, and defaults to 127.0.0.1.
        #
        # This method will return immediately, but the port will not actually be
        # forwarded immediately. If the remote server is not able to begin the
        # listener for this request, an exception will be raised asynchronously.
        #
        # To request an ephemeral port on the remote server, provide 0 (zero) for
        # the port number. The assigned port will show up in the # #active_remotes
        # list.
        #
        # remote_host is interpreted by the server per RFC 4254, which has these
        # special values:
        #
        # - "" means that connections are to be accepted on all protocol
        #   families supported by the SSH implementation.
        # - "0.0.0.0" means to listen on all IPv4 addresses.
        # - "::" means to listen on all IPv6 addresses.
        # - "localhost" means to listen on all protocol families supported by
        #   the SSH implementation on loopback addresses only ([RFC3330] and
        #   [RFC3513]).
        # - "127.0.0.1" and "::1" indicate listening on the loopback
        #   interfaces for IPv4 and IPv6, respectively.
        #
        # You may pass a block that will be called when the the port forward
        # request receives a response.  This block will be passed the remote_port
        # that was actually bound to, or nil if the binding failed.  If the block
        # returns :no_exception, the "failed binding" exception will not be thrown.
        #
        # If you want to block until the port is active, you could do something
        # like this:
        #
        #   got_remote_port = nil
        #   remote(port, host, remote_port, remote_host) do |actual_remote_port|
        #     got_remote_port = actual_remote_port || :error
        #     :no_exception # will yield the exception on my own thread
        #   end
        #   session.loop { !got_remote_port }
        #   if got_remote_port == :error
        #     raise Net::SSH::Exception, "remote forwarding request failed"
        #   end
        #
        def remote(port, host, remote_port, remote_host = "127.0.0.1")
          # Refuse before asking the server to listen: the server binds the
          # listener, but the client connects host:port for every channel the
          # server opens later, so the decision is made here.
          grant = authorize_remote(host, port, remote_host, remote_port)
          @pending_remote_grants[[remote_port, remote_host]] = grant

          session.send_global_request("tcpip-forward", :string, remote_host, :long, remote_port) do |success, response|
            @pending_remote_grants.delete([remote_port, remote_host])
            if success
              remote_port = response.read_long if remote_port == 0
              debug { "remote forward from remote #{remote_host}:#{remote_port} to #{host}:#{port} established" }
              # A cancel that arrived while the request was in flight revoked the
              # grant; don't register a listener the permit no longer covers.
              unless grant.active?
                debug { "remote forward on #{remote_host}:#{remote_port} was cancelled while being established" }
                next
              end

              @remote_forwarded_ports[[remote_port, remote_host]] = Remote.new(host, port, grant)
              yield remote_port, remote_host if block_given?
            else
              instruction = if block_given?
                              yield :error
                            end
              unless instruction == :no_exception
                error { "remote forwarding request failed" }
                raise Net::SSH::Exception, "remote forwarding request failed"
              end
            end
          end
        end

        # an alias, for token backwards compatibility with the 1.x API
        alias :remote_to :remote

        # Requests that a remote forwarded port be cancelled. The remote forwarded
        # port on the remote host, bound to the given address on the remote host,
        # will be terminated, but not immediately. This method returns immediately
        # after queueing the request to be sent to the server. If for some reason
        # the port cannot be cancelled, an exception will be raised (asynchronously).
        #
        # If you want to know when the connection has been cancelled, it will no
        # longer be present in the #active_remotes list. If you want to block until
        # the port is no longer active, you could do something like this:
        #
        #   ssh.forward.cancel_remote(1234, "0.0.0.0")
        #   ssh.loop { ssh.forward.active_remotes.include?([1234, "0.0.0.0"]) }
        def cancel_remote(port, host = "127.0.0.1")
          # Revoke first, while the request is in flight: a forwarded-tcpip
          # channel that the server opened for the listener must not be served
          # by the permit of the forward being cancelled. The policy is not
          # consulted again for a cancelled listener.
          @remote_forwarded_ports[[port, host]]&.grant&.revoke!
          @pending_remote_grants.delete([port, host])&.revoke!

          session.send_global_request("cancel-tcpip-forward", :string, host, :long, port) do |success, response|
            if success
              @remote_forwarded_ports.delete([port, host])
            else
              # The server still forwards, so honor its permit again rather than
              # leaving the listener unusable over a failed cancel.
              @remote_forwarded_ports[[port, host]]&.grant&.restore!
              raise Net::SSH::Exception, "could not cancel remote forward request on #{host}:#{port}"
            end
          end
        end

        # Returns all active forwarded remote ports. The returned value is an
        # array of two-element tuples, where the first element is the port on the
        # remote host and the second is the bind address.
        def active_remotes
          @remote_forwarded_ports.keys
        end

        # Returns all active remote forwarded ports and where they forward to. The
        # returned value is a hash from [<forwarding port on the local host>, <local forwarding address>]
        # to [<port on the remote host>, <remote bind address>].
        def active_remote_destinations
          @remote_forwarded_ports.each_with_object({}) do |(listener, destination), result|
            result[[destination.port, destination.host]] = listener
          end
        end

        # Enables SSH agent forwarding on the given channel. The forwarded agent
        # will remain active even after the channel closes--the channel is only
        # used as the transport for enabling the forwarded connection. You should
        # never need to call this directly--it is called automatically the first
        # time a session channel is opened, when the connection was created with
        # :forward_agent set to true:
        #
        #    Net::SSH.start("remote.host", "me", :forward_agent => true) do |ssh|
        #      ssh.open_channel do |ch|
        #        # agent will be automatically forwarded by this point
        #      end
        #      ssh.loop
        #    end
        def agent(channel)
          return if @agent_forwarded

          @agent_forwarded = true

          channel.send_channel_request("auth-agent-req@openssh.com") do |achannel, success|
            if success
              debug { "authentication agent forwarding is active" }
            else
              achannel.send_channel_request("auth-agent-req") do |a2channel, success2|
                if success2
                  debug { "authentication agent forwarding is active" }
                else
                  error { "could not establish forwarding of authentication agent" }
                end
              end
            end
          end
        end

        private

        # The verified identity of the SSH session, if it can be observed. The
        # session id comes from the transport's key exchange and the user from
        # the options the connection authenticated with. Through a
        # ControlMaster the master owns both, so they stay nil rather than
        # being guessed from the requested user or the proxy user; a policy
        # that needs them there can be given them with #policy_identity=.
        def session_identity
          return policy_identity if policy_identity

          session_id = observable_session_id
          [session_id, session_id && session.options[:user]]
        end

        def observable_session_id
          transport = session.transport
          return nil unless transport.respond_to?(:algorithms)

          transport.algorithms.session_id
        rescue NotSupportedOverControlMaster
          nil
        end

        def policy_request(direction, host, port, options = {})
          session_id, user = session_identity
          Request.new(direction: direction, host: host, port: port, session_id: session_id, user: user, **options)
        end

        # Runs the destination policy. Returns a Permit that captures the
        # decision's host, port and (when the client resolves the name) the
        # addresses it may connect to. With no policy every destination is
        # permitted, as before this interface existed.
        def authorize(request)
          return Permit.new(request) if @policy.nil?

          decision = @policy.call(request)
          return nil if decision.nil? || decision == false

          permit =
            case decision
            when Permit
              decision
            when Array
              host, port, *ips = decision
              Permit.new(request, host: host, port: port, ips: ips.empty? ? request.resolved_ips : ips)
            when Hash
              Permit.new(request,
                         host: decision.fetch(:host, request.host),
                         port: decision.fetch(:port, request.port),
                         ips: decision.fetch(:ips, request.resolved_ips))
            else
              raise ArgumentError, "forwarding policy returned #{decision.inspect}; " \
                                   "expected a Forward::Permit, an Array, a Hash, nil or false"
            end

          validate_permit!(permit, request)

          # Once the client has resolved a destination, a permit may narrow the
          # addresses it uses, but not drop the pin and connect by name later.
          if request.resolved_ips && permit.ips.empty?
            permit = Permit.new(request, host: permit.host, port: permit.port, ips: request.resolved_ips)
          end

          permit
        end

        # A permit is only good for the request it was decided for: same
        # direction, destination, session id and user, and only for addresses
        # among those resolved for that request. The policy approves or refuses
        # a request; it can't redirect it to a destination it wasn't asked about.
        def validate_permit!(permit, request)
          decided = permit.request
          unless decided.is_a?(Request) &&
                 decided.direction == request.direction &&
                 decided.host == request.host &&
                 decided.port == request.port &&
                 decided.session_id == request.session_id &&
                 decided.user == request.user
            raise ArgumentError, "forwarding policy returned a permit for a different request " \
                                 "(#{decided.inspect} for #{request.inspect})"
          end

          unless permit.host == request.host && permit.port == request.port
            raise ArgumentError, "forwarding policy changed #{request.host}:#{request.port} " \
                                 "to #{permit.host}:#{permit.port}; return nil to refuse instead"
          end

          if request.local? && !permit.ips.empty?
            raise ArgumentError, "a local forward is resolved and connected by the server, so " \
                                 "#{permit.ips.inspect} can't be enforced; don't return addresses for it"
          end

          if request.resolved_ips && !(permit.ips - request.resolved_ips).empty?
            raise ArgumentError, "forwarding policy approved #{permit.ips.inspect} for #{request.host}:#{request.port}, " \
                                 "but only #{request.resolved_ips.inspect} was resolved for it"
          end

          permit
        end

        # Authorizes a local forward. The client only ever hands the name to
        # the server, which resolves and connects it (direct-tcpip), so no
        # addresses are resolved here and a policy can't claim to have pinned
        # the final IP.
        def authorize_local(host, port, listen_host, channel_type: "direct-tcpip")
          request = policy_request(:local, host, port,
                                   listen_host: listen_host, channel_type: channel_type)
          permit = authorize(request)
          raise NotPermitted, "local forwarding to #{host}:#{port} is not permitted" unless permit

          Grant.new(permit)
        end

        # Checks the permit of a local listener when a connection is accepted.
        # The policy runs when the listener is created, not per connection: a
        # later policy change isn't re-evaluated, but a cancelled forward's
        # revoked permit is refused here in case a connection was already
        # accepted before the listener was removed.
        def reauthorize_local(grant)
          return grant if grant.active?

          raise NotPermitted, "local forward was cancelled"
        end

        # Authorizes a remote forward when it is requested. The client connects
        # host:port for every channel the server opens, so resolve the name now
        # and bind the permit to the result: a later DNS change can't redirect
        # the forward. +port+ is the requested listener port.
        def authorize_remote(host, port, listen_host, listen_port)
          ips = @policy ? resolve_for_client(host, port) : nil
          request = policy_request(:remote, host, port, resolved_ips: ips,
                                   listen_host: listen_host, listen_port: listen_port,
                                   channel_type: "tcpip-forward")
          permit = authorize(request)
          raise NotPermitted, "remote forwarding to #{host}:#{port} is not permitted" unless permit

          Grant.new(permit)
        end

        # Authorizes a channel the server opened for a remote forward. It is a
        # separate direction because the server chooses when it arrives and
        # what it claims as the listener and originator; the client still
        # connects the forward's destination. A cancelled forward refuses the
        # channel before the policy runs or a socket is opened.
        def authorize_server_channel(remote, connected_host, connected_port, originator_host, originator_port)
          raise NotPermitted, "remote forward on #{connected_host}:#{connected_port} was cancelled" unless remote.grant.active?

          # Reuse the addresses pinned when the forward was approved, so the
          # decision for this channel can't be redirected by a changed record.
          # If the policy was only set after the forward was registered, resolve
          # now so this channel is still pinned to the address it connects.
          ips = remote.grant.permit.ips
          ips = resolve_for_client(remote.host, remote.port) if ips.empty? && @policy
          request = policy_request(:server, remote.host, remote.port, resolved_ips: (@policy ? ips : nil),
                                   listen_host: connected_host, listen_port: connected_port,
                                   originator_host: originator_host, originator_port: originator_port,
                                   channel_type: "forwarded-tcpip")
          permit = authorize(request)
          raise NotPermitted, "server-opened channel to #{remote.host}:#{remote.port} is not permitted" unless permit

          permit
        end

        # Resolves a destination for the client side and returns the addresses
        # that the connection may use. An address literal is used as is.
        def resolve_for_client(host, port)
          return [host.to_s] if ip_address?(host)

          resolver.call(host, port).map(&:to_s).uniq
        rescue SocketError, SystemCallError
          raise NotPermitted, "could not resolve #{host}:#{port} for forwarding"
        end

        def ip_address?(host)
          IPAddr.new(host.to_s)
          true
        rescue IPAddr::InvalidAddressError
          false
        end

        def resolver
          @resolver ||= lambda do |host, port|
            Addrinfo.getaddrinfo(host, port, nil, :STREAM).map(&:ip_address).uniq
          end
        end

        # Opens the connection to an authorized destination. When the permit
        # pins addresses, connect to one of them directly so that a name that
        # now resolves elsewhere can't be reached.
        def connect_destination(host, port, permit)
          ips = permit ? permit.ips : []
          return connector.call(host, port) if ips.empty?

          last_error = nil
          ips.each do |ip|
            return connector.call(ip, port)
          rescue SystemCallError => e
            last_error = e
          end
          raise last_error
        end

        def connector
          @connector ||= ->(host, port) { TCPSocket.new(host, port) }
        end

        # Perform setup operations that are common to all forwarded channels.
        # +client+ is a socket, +channel+ is the channel that was just created,
        # and +type+ is an arbitrary string describing the type of the channel.
        def prepare_client(client, channel, type)
          client.extend(Net::SSH::BufferedIo)
          client.extend(Net::SSH::ForwardedBufferedIo)
          client.logger = logger

          session.listen_to(client)
          channel[:socket] = client

          # Grant window only for data the local end has accepted, so a slow
          # reader stalls the remote sender instead of filling our memory.
          channel.grant_window_on_consume!
          client.on_sent { |bytes| channel.consumed(bytes) }

          channel.on_data do |ch, data|
            debug { "data:#{data.length} on #{type} forwarded channel" }
            ch[:socket].enqueue(data)
          end

          channel.on_eof do |ch|
            debug { "eof #{type} on #{type} forwarded channel" }
            ch[:socket].shutdown_write_when_drained
          end

          channel.on_close do |ch|
            debug { "closing #{type} forwarded channel" }
            session.close_when_drained(ch[:socket])
          end

          channel.on_process do |ch|
            socket = ch[:socket]
            if socket.closed?
              ch.info { "#{type} forwarded connection closed" }
              session.stop_listening_to(socket)
              ch.close
            elsif ch.eof?
              # Like OpenSSH's chan_shutdown_read: data already read still goes out before CHANNEL_EOF, the rest is dropped.
              ch.output.append(socket.read_available) if socket.available > 0
              session.pause_reading(socket)
            else
              if socket.available > 0
                data = socket.read_available(8192)
                ch.debug { "read #{data.length} bytes from client, sending over #{type} forwarded connection" }
                ch.send_data(data)
              end

              # Like OpenSSH's channel_pre_open, only read more once the remote
              # window can take what is already queued; writes to the socket keep
              # flowing. ch.output is still unsent here because Channel#process
              # runs this block before enqueue_pending_output.
              if ch.output.length + socket.available < ch.remote_window_size.to_i
                session.resume_reading(socket)
              else
                session.pause_reading(socket)
              end
            end
          end
        end

        # not a real socket, so use a simpler behaviour
        def prepare_simple_client(client, channel, type)
          channel[:socket] = client

          channel.on_data do |ch, data|
            ch.debug { "data:#{data.length} on #{type} forwarded channel" }
            ch[:socket].send(data)
          end

          channel.on_process do |ch|
            next if ch.eof?

            data = ch[:socket].read(8192)
            if data
              ch.debug { "read #{data.length} bytes from client, sending over #{type} forwarded connection" }
              ch.send_data(data)
            end
          end
        end

        # The callback used when a new "forwarded-tcpip" channel is requested
        # by the server.  This will open a new socket to the host/port specified
        # when the forwarded connection was first requested.
        def forwarded_tcpip(session, channel, packet)
          connected_address  = packet.read_string
          connected_port     = packet.read_long
          originator_address = packet.read_string
          originator_port    = packet.read_long

          debug { "REMOTE 0: #{connected_port} #{connected_address} #{originator_address} #{originator_port}" }
          remote = @remote_forwarded_ports[[connected_port, connected_address]]
          if remote.nil?
            raise Net::SSH::ChannelOpenFailed.new(1, "unknown request from remote forwarded connection on #{connected_address}:#{connected_port}")
          end

          # Authorize the channel the server opened against the forward it
          # belongs to. A cancelled forward's grant is revoked, so a packet
          # that arrives after cancel_remote is refused before a policy runs or
          # a destination is resolved and connected.
          permit = authorize_server_channel(remote, connected_address, connected_port,
                                            originator_address, originator_port)

          debug { "REMOTE: #{remote.host} #{remote.port}" }
          client = connect_destination(remote.host, remote.port, permit)
          info { "connected #{connected_address}:#{connected_port} originator #{originator_address}:#{originator_port}" }

          prepare_client(client, channel, :remote)
        rescue NotPermitted => err
          debug { err.message }
          raise Net::SSH::ChannelOpenFailed.new(1, err.message)
        rescue SocketError, SystemCallError => err
          raise Net::SSH::ChannelOpenFailed.new(2, "could not connect to remote host (#{remote.host}:#{remote.port}): #{err.message}")
        end

        # The callback used when an auth-agent channel is requested by the server.
        def auth_agent_channel(session, channel, packet)
          # Like OpenSSH, only relay the local agent when forwarding was requested (GHSA-qpg5-fx6p-8cq3).
          unless session.options[:forward_agent] || @agent_forwarded
            error { "server tried agent forwarding, which was not requested; refusing" }
            raise Net::SSH::ChannelOpenFailed.new(1, "agent forwarding was not requested")
          end

          info { "opening auth-agent channel" }
          channel[:invisible] = true

          begin
            agent = Authentication::Agent.connect(logger, session.options[:agent_socket_factory], session.options[:identity_agent])
            if (agent.socket.is_a? ::IO)
              prepare_client(agent.socket, channel, :agent)
            else
              prepare_simple_client(agent.socket, channel, :agent)
            end
          rescue Exception => e
            error { "attempted to connect to agent but failed: #{e.class.name} (#{e.message})" }
            raise Net::SSH::ChannelOpenFailed.new(2, "could not connect to authentication agent")
          end
        end
      end
    end
  end
end

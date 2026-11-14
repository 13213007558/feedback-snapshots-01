require 'socket'

require 'net/ssh/errors'

module Net
  module SSH
    module Service
      class Forward
        # Raised when forwarding is not permitted by the destination policy set
        # with Forward#policy=.
        class NotPermitted < Net::SSH::Exception; end

        # The context given to the destination policy. It describes what is
        # being authorized:
        #
        # * direction - :local for a listener on the client that forwards
        #   through the server (direct-tcpip or direct-streamlocal), :remote for
        #   a listener requested on the server (tcpip-forward), or :server for
        #   a channel the server opens towards the client (forwarded-tcpip).
        # * host, port - the destination that will be connected to, not the
        #   address the listener binds to. For :server it is the destination of
        #   the remote forward the channel belongs to.
        # * session_id - the SSH session id established by the key exchange, or
        #   nil when it can't be observed (e.g. through a ControlMaster proxy,
        #   where the master owns the transport and authentication).
        # * user - the user that was authenticated on this connection, or nil
        #   when that can't be observed.
        # * listen_host, listen_port - the local listener for :local, the
        #   requested remote listener for :remote, and the address the server
        #   says it accepted the connection on for :server.
        # * originator_host, originator_port - the peer that connected to the
        #   listener, for :server channels.
        # * channel_type - the SSH channel type, e.g. "direct-tcpip".
        # * resolved_ips - the addresses the client will connect to, when the
        #   client resolves the destination (:remote and :server), or nil when
        #   the server resolves it (:local). A policy that approves :local can
        #   restrict the destination name and port only; it must not treat the
        #   name as having been resolved to a final IP.
        #
        # The host name resolution owner differs by direction; see
        # #target_resolution and #listener_resolution.
        Request = Struct.new(
          :direction, :host, :port, :resolved_ips, :session_id, :user,
          :listen_host, :listen_port, :originator_host, :originator_port, :channel_type,
          keyword_init: true
        ) do
          def initialize(direction:, host:, port:, resolved_ips: nil, session_id: nil, user: nil,
                         listen_host: nil, listen_port: nil, originator_host: nil, originator_port: nil,
                         channel_type: nil)
            super(
              direction: direction.to_sym, host: host, port: port && port.to_i,
              resolved_ips: resolved_ips && Array(resolved_ips).map(&:to_s).freeze,
              session_id: session_id, user: user,
              listen_host: listen_host, listen_port: listen_port && listen_port.to_i,
              originator_host: originator_host, originator_port: originator_port && originator_port.to_i,
              channel_type: channel_type
            )
            freeze
          end

          def local?
            direction == :local
          end

          def remote?
            direction == :remote
          end

          def server?
            direction == :server
          end

          # Which end resolves the destination. For a local forward the server
          # connects to host:port, so it resolves the name. For remote and
          # server-opened channels the client connects, so it resolves it.
          def target_resolution
            local? ? :server : :client
          end

          # Which end resolves the listener address. The client binds local
          # listeners; the server binds listeners requested with tcpip-forward
          # and reports the address it accepted on.
          def listener_resolution
            local? ? :client : :server
          end

          def inspect
            "#<#{self.class} #{direction} #{host}:#{port} ip=#{resolved_ips.inspect}>"
          end
        end

        # An approved forwarding destination. It is created for one request and
        # is only honored while the forwarding registration that owns it is
        # active. +ips+ are the addresses the client will connect to when the
        # client resolves the destination (see Request#target_resolution); they
        # are empty when the server resolves it.
        class Permit
          attr_reader :request, :host, :port, :ips

          def initialize(request, host: request.host, port: request.port, ips: request.resolved_ips)
            @request = request
            @host = host
            @port = port && port.to_i
            @ips = (ips || []).map(&:to_s).freeze
            freeze
          end

          def direction
            request.direction
          end

          def session_id
            request.session_id
          end

          def user
            request.user
          end

          def resolved_ip?
            !ips.empty?
          end

          def inspect
            "#<#{self.class} #{direction} #{host}:#{port} ip=#{ips.inspect}>"
          end
        end

        # Internal bookkeeping that makes a Permit revocable. Revoking it when
        # a forward is cancelled stops channels that the server opens later
        # from using the old approval.
        class Grant # :nodoc:
          attr_reader :permit

          def initialize(permit)
            @permit = permit
            @active = true
          end

          def active?
            @active
          end

          def revoke!
            @active = false
          end

          def restore!
            @active = true
          end

        end
      end
    end
  end
end

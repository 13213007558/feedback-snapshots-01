require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/loggable'

require 'net/ssh/transport/server_version'
require 'socket'
require 'rubygems'

require 'net/ssh/authentication/pageant' if Gem.win_platform? && RUBY_PLATFORM != "java"

module Net
  module SSH
    module Authentication
      # Class for representing agent-specific errors.
      class AgentError < Net::SSH::Exception; end

      # An exception for indicating that the SSH agent is not available.
      class AgentNotAvailable < AgentError; end

      # Raised when the agent closes the connection before replying.
      class AgentClosedConnection < AgentError; end

      # Raised when an agent reply violates the protocol framing (oversized
      # frames or fields, truncated fields, or structurally corrupted blobs).
      # The connection is poisoned before this is raised, as its stream can no
      # longer be kept in sync with the agent's message boundaries.
      class AgentProtocolError < AgentError; end

      # This class implements a simple client for the ssh-agent protocol. It
      # does not implement any specific protocol, but instead copies the
      # behavior of the ssh-agent functions in the OpenSSH library (3.8).
      #
      # This means that although it behaves like a SSH1 client, it also has
      # some SSH2 functionality (like signing data).
      class Agent
        include Loggable

        # A simple module for extending keys, to allow comments to be specified
        # for them.
        module Comment
          attr_accessor :comment
        end

        SSH2_AGENT_REQUEST_VERSION       = 1
        SSH2_AGENT_REQUEST_IDENTITIES    = 11
        SSH2_AGENT_IDENTITIES_ANSWER     = 12
        SSH2_AGENT_SIGN_REQUEST          = 13
        SSH2_AGENT_SIGN_RESPONSE         = 14
        SSH2_AGENT_ADD_IDENTITY          = 17
        SSH2_AGENT_REMOVE_IDENTITY       = 18
        SSH2_AGENT_REMOVE_ALL_IDENTITIES = 19
        SSH2_AGENT_LOCK                  = 22
        SSH2_AGENT_UNLOCK                = 23
        SSH2_AGENT_ADD_ID_CONSTRAINED    = 25
        SSH2_AGENT_FAILURE               = 30
        SSH2_AGENT_VERSION_RESPONSE      = 103

        SSH_COM_AGENT2_FAILURE = 102

        SSH_AGENT_REQUEST_RSA_IDENTITIES = 1
        SSH_AGENT_RSA_IDENTITIES_ANSWER1 = 2
        SSH_AGENT_RSA_IDENTITIES_ANSWER2 = 5
        SSH_AGENT_FAILURE                = 5
        SSH_AGENT_SUCCESS                = 6

        SSH_AGENT_CONSTRAIN_LIFETIME = 1
        SSH_AGENT_CONSTRAIN_CONFIRM  = 2

        SSH_AGENT_RSA_SHA2_256 = 0x02
        SSH_AGENT_RSA_SHA2_512 = 0x04

        # Upper bounds for data received over the agent socket. The agent is
        # treated as untrusted input: these keep a malicious or broken agent
        # from making the client allocate unbounded amounts of memory.
        #
        # Maximum size of a single agent message, matching OpenSSH's
        # AGENT_MAX_MSGLEN (the 4-byte length prefix is not included).
        MAX_PACKET_LENGTH = 256 * 1024
        # Maximum number of identities a single IDENTITIES_ANSWER may claim.
        MAX_IDENTITIES = 1024
        # Maximum size of any single length-prefixed field (key blob, comment
        # or signature).
        MAX_FIELD_LENGTH = 64 * 1024

        # The underlying socket being used to communicate with the SSH agent.
        attr_reader :socket

        # Instantiates a new agent object, connects to a running SSH agent,
        # negotiates the agent protocol version, and returns the agent object.
        def self.connect(logger = nil, agent_socket_factory = nil, identity_agent = nil)
          agent = new(logger)
          agent.connect!(agent_socket_factory, identity_agent)
          agent.negotiate!
          agent
        end

        # Creates a new Agent object, using the optional logger instance to
        # report status.
        def initialize(logger = nil)
          self.logger = logger
          @closed = false
        end

        # Connect to the agent process using the socket factory and socket name
        # given by the attribute writers. If the agent on the other end of the
        # socket reports that it is an SSH2-compatible agent, this will fail
        # (it only supports the ssh-agent distributed by OpenSSH).
        def connect!(agent_socket_factory = nil, identity_agent = nil)
          @agent_socket_factory = agent_socket_factory
          @identity_agent = identity_agent
          open_agent_socket!
        end

        def open_agent_socket!
          @closed = false
          debug { "connecting to ssh-agent" }
          @socket =
            if @agent_socket_factory
              @agent_socket_factory.call
            elsif @identity_agent
              unix_socket_class.open(File.expand_path(@identity_agent))
            elsif ENV['SSH_AUTH_SOCK'] && unix_socket_class
              unix_socket_class.open(File.expand_path(ENV['SSH_AUTH_SOCK']))
            elsif Gem.win_platform? && RUBY_ENGINE != "jruby"
              Pageant::Socket.open
            else
              raise AgentNotAvailable, "Agent not configured"
            end
        rescue StandardError => e
          error { "could not connect to ssh-agent: #{e.message}" }
          raise AgentNotAvailable, $!.message
        end
        private :open_agent_socket!

        # Attempts to negotiate the SSH agent protocol version. Raises an error
        # if the version could not be negotiated successfully.
        def negotiate!
          # determine what type of agent we're communicating with
          type, body = send_and_wait(SSH2_AGENT_REQUEST_VERSION, :string, Transport::ServerVersion::PROTO_VERSION)

          raise AgentNotAvailable, "SSH2 agents are not yet supported" if type == SSH2_AGENT_VERSION_RESPONSE

          if type == SSH2_AGENT_FAILURE
            debug { "Unexpected response type==#{type}, this will be ignored" }
          elsif type != SSH_AGENT_RSA_IDENTITIES_ANSWER1 && type != SSH_AGENT_RSA_IDENTITIES_ANSWER2
            raise AgentNotAvailable, "unknown response from agent: #{type}, #{body.to_s.inspect}"
          end
        rescue AgentClosedConnection
          # Agents built on ssh-agent-lib <= 0.6.0 (e.g. older Proton Pass) drop the connection on
          # this legacy request but handle the rest of the protocol (#1008).
          debug { "ssh-agent closed the connection on the version request; assuming a modern agent and reconnecting" }
          open_agent_socket!
        end

        # Return an array of all identities (public keys) known to the agent.
        # Each key returned is augmented with a +comment+ property which is set
        # to the comment returned by the agent for that key.
        def identities
          type, body = send_and_wait(SSH2_AGENT_REQUEST_IDENTITIES)
          raise AgentError, "could not get identity count" if agent_failed(type)
          raise AgentError, "bad authentication reply: #{type}" if type != SSH2_AGENT_IDENTITIES_ANSWER

          count = read_bounded_long(body, MAX_IDENTITIES, "identity count")
          identities = []
          count.times do
            key_str = read_agent_string(body, "key blob")
            comment_str = read_agent_string(body, "comment")
            begin
              key = Buffer.new(key_str).read_key
              if key.nil?
                error { "ignoring invalid key: #{safe_for_log(comment_str)}" }
                next
              end
              key.extend(Comment)
              key.comment = comment_str
              identities.push key
            rescue Net::SSH::UnsupportedKeyType, NotImplementedError => e
              # The key type is known to be unsupported, but its blob was
              # length-delimited and consumed cleanly, so the framing is still
              # intact and the remaining identities can be parsed.
              error { "ignoring unimplemented key:#{e.message} #{safe_for_log(comment_str)}" }
            rescue StandardError => e
              # A key type we claim to support but whose blob is structurally
              # corrupt cannot be trusted; poison the connection rather than
              # risk parsing the next bytes out of sync.
              poison_connection!("corrupt key blob: #{e.class} (#{e.message})")
            end
          end

          return identities
        end

        # Closes this socket. This agent reference is no longer able to
        # query the agent.
        def close
          @closed = true
          @socket.close
        end

        # Whether this agent reference can no longer be used. A connection is
        # closed explicitly or poisoned after a framing violation leaves its
        # byte stream out of sync with the agent's message boundaries.
        def closed?
          @closed == true
        end

        # Using the agent and the given public key, sign the given data. The
        # signature is returned in SSH2 format.
        def sign(key, data, flags = 0)
          type, reply = send_and_wait(SSH2_AGENT_SIGN_REQUEST, :string, Buffer.from(:key, key), :string, data, :long, flags)

          raise AgentError, "agent could not sign data with requested identity" if agent_failed(type)
          raise AgentError, "bad authentication response #{type}" if type != SSH2_AGENT_SIGN_RESPONSE

          return read_agent_string(reply, "signature")
        end

        # Adds the private key with comment to the agent.
        # If lifetime is given, the key will automatically be removed after lifetime
        # seconds.
        # If confirm is true, confirmation will be required for each agent signing
        # operation.
        def add_identity(priv_key, comment, lifetime: nil, confirm: false)
          constraints = Buffer.new
          if lifetime
            constraints.write_byte(SSH_AGENT_CONSTRAIN_LIFETIME)
            constraints.write_long(lifetime)
          end
          constraints.write_byte(SSH_AGENT_CONSTRAIN_CONFIRM) if confirm

          req_type = constraints.empty? ? SSH2_AGENT_ADD_IDENTITY : SSH2_AGENT_ADD_ID_CONSTRAINED
          type, = send_and_wait(req_type, :string, priv_key.ssh_type, :raw, blob_for_add(priv_key),
                                :string, comment, :raw, constraints)
          raise AgentError, "could not add identity to agent" if type != SSH_AGENT_SUCCESS
        end

        # Removes key from the agent.
        def remove_identity(key)
          type, = send_and_wait(SSH2_AGENT_REMOVE_IDENTITY, :string, key.to_blob)
          raise AgentError, "could not remove identity from agent" if type != SSH_AGENT_SUCCESS
        end

        # Removes all identities from the agent.
        def remove_all_identities
          type, = send_and_wait(SSH2_AGENT_REMOVE_ALL_IDENTITIES)
          raise AgentError, "could not remove all identity from agent" if type != SSH_AGENT_SUCCESS
        end

        # lock the ssh agent with password
        def lock(password)
          type, = send_and_wait(SSH2_AGENT_LOCK, :string, password)
          raise AgentError, "could not lock agent" if type != SSH_AGENT_SUCCESS
        end

        # unlock the ssh agent with password
        def unlock(password)
          type, = send_and_wait(SSH2_AGENT_UNLOCK, :string, password)
          raise AgentError, "could not unlock agent" if type != SSH_AGENT_SUCCESS
        end

        private

        def unix_socket_class
          defined?(UNIXSocket) && UNIXSocket
        end

        # Send a new packet of the given type, with the associated data.
        def send_packet(type, *args)
          buffer = Buffer.from(*args)
          data = [buffer.length + 1, type.to_i, buffer.to_s].pack("NCA*")
          debug { "sending agent request #{type} len #{buffer.length}" }
          write_full(data)
        end

        # Read the next packet from the agent. This will return a two-part
        # tuple consisting of the packet type, and the packet's body (which
        # is returned as a Net::SSH::Buffer).
        def read_packet
          header = read_full(4)
          length = Net::SSH::Buffer.new(header).read_long
          if length < 1 || length > MAX_PACKET_LENGTH
            poison_connection!("agent packet length #{length} exceeds the #{MAX_PACKET_LENGTH}-byte limit")
          end

          body = read_full(length)
          buffer = Net::SSH::Buffer.new(body)
          type = buffer.read_byte
          debug { "received agent packet #{type} len #{length - 1}" }
          return type, buffer
        end

        # Send the given packet and return the subsequent reply from the agent.
        # (See #send_packet and #read_packet).
        def send_and_wait(type, *args)
          if closed?
            raise AgentClosedConnection, "agent connection is closed; the previous reply violated the protocol framing"
          end
          send_packet(type, *args)
          read_packet
        rescue Errno::ECONNRESET, Errno::EPIPE => e
          # Linux reports an agent that closes with our request unread as a reset, not EOF.
          poison_connection!("agent closed the connection (#{e.class})", AgentClosedConnection)
        end

        # Reads exactly +length+ bytes, retrying on short reads. A truncated
        # frame (the agent reaches EOF before the whole message arrived) means
        # the stream has no usable boundary, so the connection is poisoned.
        def read_full(length)
          data = +""
          until data.bytesize == length
            chunk = @socket.read(length - data.bytesize)
            raise AgentClosedConnection, "agent closed the connection" if chunk.nil? || chunk.empty?
            data << chunk
          end
          data
        rescue AgentClosedConnection => e
          poison_connection!(e.message, AgentClosedConnection)
        end

        # Writes the whole message, retrying when the socket accepts only part
        # of it. A short or failed write leaves the request half-sent, so the
        # connection cannot be reused.
        def write_full(data)
          written = 0
          while written < data.bytesize
            count = @socket.send(data.byteslice(written, data.bytesize - written), 0)
            if count.nil? || count <= 0
              poison_connection!("agent accepted no more data while writing request")
            end
            written += count
          end
        end

        # Reads a length-prefixed field, enforcing the field size limit and
        # requiring the declared bytes to be fully present inside the reply.
        # Any violation means the message's internal framing is corrupt.
        def read_agent_string(buffer, field_name)
          length = buffer.read_long
          if length.nil?
            poison_connection!("truncated #{field_name} length")
          elsif length > MAX_FIELD_LENGTH
            poison_connection!("#{field_name} length #{length} exceeds the #{MAX_FIELD_LENGTH}-byte limit")
          elsif length > buffer.available
            poison_connection!("truncated #{field_name}: #{length} bytes declared but #{buffer.available} available")
          end
          buffer.read(length)
        end

        # Like Buffer#read_long, but rejects values outside the permitted
        # range so that a hostile count cannot drive unbounded allocation or
        # iteration.
        def read_bounded_long(buffer, maximum, field_name)
          value = buffer.read_long
          if value.nil?
            poison_connection!("truncated #{field_name}")
          elsif value < 0 || value > maximum
            poison_connection!("#{field_name} #{value} exceeds the limit of #{maximum}")
          end
          value
        end

        # Marks the connection unusable and closes the socket before raising,
        # so callers never keep reading bytes whose message boundaries are no
        # longer known.
        def poison_connection!(message, exception_class = AgentProtocolError)
          @closed = true
          begin
            @socket.close unless @socket.nil?
          rescue StandardError
            # Closing is best effort; the protocol error is what matters.
          end
          raise exception_class, message
        end

        # Escapes control characters (including newlines) in untrusted agent
        # text before it is written to a log, so a malicious comment cannot
        # forge additional log lines.
        def safe_for_log(text)
          text.to_s.each_char.map do |char|
            if char.ord < 0x20 || char.ord == 0x7F
              "\\x%02X" % char.ord
            else
              char
            end
          end.join
        end

        # Returns +true+ if the parameter indicates a "failure" response from
        # the agent, and +false+ otherwise.
        def agent_failed(type)
          type == SSH_AGENT_FAILURE ||
            type == SSH2_AGENT_FAILURE ||
            type == SSH_COM_AGENT2_FAILURE
        end

        def blob_for_add(priv_key)
          # Ideally we'd have something like `to_private_blob` on the various key types, but the
          # nuances with encoding (e.g. `n` and `e` are reversed for RSA keys) make this impractical.
          case priv_key.ssh_type
          when /^ssh-dss$/
            Net::SSH::Buffer.from(:bignum, priv_key.p, :bignum, priv_key.q, :bignum, priv_key.g,
                                  :bignum, priv_key.pub_key, :bignum, priv_key.priv_key).to_s
          when /^ssh-dss-cert-v01@openssh\.com$/
            Net::SSH::Buffer.from(:string, priv_key.to_blob, :bignum, priv_key.key.priv_key).to_s
          when /^ecdsa\-sha2\-(\w*)$/
            curve_name = OpenSSL::PKey::EC::CurveNameAliasInv[priv_key.group.curve_name]
            Net::SSH::Buffer.from(:string, curve_name, :mstring, priv_key.public_key.to_bn.to_s(2),
                                  :bignum, priv_key.private_key).to_s
          when /^ecdsa\-sha2\-(\w*)-cert-v01@openssh\.com$/
            Net::SSH::Buffer.from(:string, priv_key.to_blob, :bignum, priv_key.key.private_key).to_s
          when /^ssh-ed25519$/
            Net::SSH::Buffer.from(:string, priv_key.public_key_bytes,
                                  :string, priv_key.private_key_bytes_for_agent).to_s
          when /^ssh-ed25519-cert-v01@openssh\.com$/
            # Unlike the other certificate types, the public key is included after the certifiate.
            Net::SSH::Buffer.from(:string, priv_key.to_blob,
                                  :string, priv_key.key.public_key_bytes,
                                  :string, priv_key.key.private_key_bytes_for_agent).to_s
          when /^ssh-rsa$/
            # `n` and `e` are reversed compared to the ordering in `OpenSSL::PKey::RSA#to_blob`.
            Net::SSH::Buffer.from(:bignum, priv_key.n, :bignum, priv_key.e, :bignum, priv_key.d,
                                  :bignum, priv_key.iqmp, :bignum, priv_key.p, :bignum, priv_key.q).to_s
          when /^ssh-rsa-cert-v01@openssh\.com$/
            Net::SSH::Buffer.from(:string, priv_key.to_blob, :bignum, priv_key.key.d,
                                  :bignum, priv_key.key.iqmp, :bignum, priv_key.key.p,
                                  :bignum, priv_key.key.q).to_s
          end
        end
      end
    end
  end
end

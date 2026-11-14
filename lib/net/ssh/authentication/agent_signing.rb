require 'net/ssh/errors'

module Net
  module SSH
    module Authentication
      # The verified target of an ssh-agent signing decision: the host this
      # connection was verified against, the host key that proved it, and the
      # SSH session identity those belong to.
      #
      # This is a snapshot. A new instance is built for every signature
      # request, so a rekey or a retried authentication can never present a
      # previous target as if it still applied.
      class AgentSigningTarget
        # The host as given to Net::SSH.start.
        attr_reader :host

        # The port of the connection.
        attr_reader :port

        # The host key that was verified for the current key exchange.
        attr_reader :host_key

        # The fingerprint of #host_key, in the format selected by the
        # :fingerprint_hash option (SHA256 unless configured otherwise).
        attr_reader :host_key_fingerprint

        # The SSH session id, from the initial key exchange.
        attr_reader :session_id

        # Counts the completed key exchanges on the connection, so a decision
        # can tell a rekey from the exchange it saw before.
        attr_reader :key_exchange

        def initialize(host:, port:, host_key:, host_key_fingerprint:, session_id:, key_exchange:)
          @host = host
          @port = port
          @host_key = host_key
          @host_key_fingerprint = host_key_fingerprint
          @session_id = session_id
          @key_exchange = key_exchange
          freeze
        end

        # The algorithm of the verified host key, e.g. "ssh-ed25519".
        def host_key_type
          host_key.ssh_type
        end
      end

      # The context passed to a :agent_signing_authorization hook.
      #
      # It deliberately contains only public material: which verified target
      # and session the signature is for, the public key the agent signs with,
      # the identity offered to the server, why the signature is needed, and
      # the signature algorithm. It does not contain the private key, the data
      # being signed, or the signature returned by the agent.
      class AgentSigningContext
        # The AgentSigningTarget with the verified host, host key and session.
        attr_reader :target

        # The public key the agent was asked to sign with.
        attr_reader :public_key

        # The identity that was offered to the server. It equals #public_key,
        # except for a certificate, where it is the certificate the agent's key
        # backs.
        attr_reader :identity

        # The fingerprint of #public_key, in the format selected by the
        # :fingerprint_hash option.
        attr_reader :public_key_fingerprint

        # The fingerprint of #identity, in the format selected by the
        # :fingerprint_hash option.
        attr_reader :identity_fingerprint

        # Why net-ssh is signing: :publickey or :hostbased, so a hook can
        # refuse signatures requested for anything else.
        attr_reader :purpose

        # The signature algorithm requested from the agent, e.g.
        # "rsa-sha2-512", or nil when the key type decides.
        attr_reader :signature_algorithm

        def initialize(target:, public_key:, public_key_fingerprint:, purpose:, signature_algorithm: nil,
                       identity: nil, identity_fingerprint: nil)
          @target = target
          @public_key = public_key
          @identity = identity || public_key
          @public_key_fingerprint = public_key_fingerprint
          @identity_fingerprint = identity_fingerprint
          @purpose = purpose
          @signature_algorithm = signature_algorithm
          freeze
        end

        # The host as given to Net::SSH.start.
        def host
          target.host
        end

        # The port of the connection.
        def port
          target.port
        end

        # The host key that was verified for the current key exchange.
        def host_key
          target.host_key
        end

        # The fingerprint of the verified host key.
        def host_key_fingerprint
          target.host_key_fingerprint
        end

        # The algorithm of the verified host key.
        def host_key_type
          target.host_key_type
        end

        # The SSH session id.
        def session_id
          target.session_id
        end

        # The key exchange generation the verified target belongs to.
        def key_exchange
          target.key_exchange
        end

        # A plain Hash of the context, for logging or audit records. It holds
        # no private key and no signing material.
        def to_h
          {
            host: host,
            port: port,
            host_key: host_key_type,
            host_key_fingerprint: host_key_fingerprint,
            session_id: session_id,
            key_exchange: key_exchange,
            public_key: public_key.ssh_type,
            public_key_fingerprint: public_key_fingerprint,
            identity: identity.ssh_type,
            identity_fingerprint: identity_fingerprint,
            purpose: purpose,
            signature_algorithm: signature_algorithm
          }
        end
      end

      # Raised when the ssh-agent was not allowed to sign an authentication
      # request: the connection's host key has not been verified, the
      # :agent_signing_authorization hook declined (or raised), or the verified
      # target changed between the decision and the agent call. Authentication
      # methods treat it as a refused key and may try another one.
      class AgentSigningDenied < Net::SSH::Exception; end
    end
  end
end

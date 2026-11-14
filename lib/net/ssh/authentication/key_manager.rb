require 'net/ssh/errors'
require 'net/ssh/key_factory'
require 'net/ssh/loggable'
require 'net/ssh/authentication/agent'
require 'net/ssh/authentication/agent_signing'

module Net
  module SSH
    module Authentication
      # A trivial exception class used to report errors in the key manager.
      class KeyManagerError < Net::SSH::Exception; end

      # This class encapsulates all operations done by clients on a user's
      # private keys. In practice, the client should never need a reference
      # to a private key; instead, they grab a list of "identities" (public
      # keys) that are available from the KeyManager, and then use
      # the KeyManager to do various private key operations using those
      # identities.
      #
      # The KeyManager also uses the Agent class to encapsulate the
      # ssh-agent. Thus, from a client's perspective it is completely
      # hidden whether an identity comes from the ssh-agent or from a file
      # on disk.
      class KeyManager
        include Loggable

        # The list of user key files that will be examined
        attr_reader :key_files

        # The list of user key data that will be examined
        attr_reader :key_data

        # The list of user key certificate files that will be examined
        attr_reader :keycert_files

        # The list of user key certificate data that will be examined
        attr_reader :keycert_data

        # The map of loaded identities
        attr_reader :known_identities

        # The map of options that were passed to the key-manager
        attr_reader :options

        # The transport session whose verified host key and session id are
        # presented to the :agent_signing_authorization hook. It is optional so
        # that a KeyManager used on its own keeps working; without it the hook
        # is never satisfied and agent signing is refused.
        attr_reader :transport

        # The callable given as :agent_signing_authorization, or nil. See
        # Net::SSH.start for its contract.
        attr_reader :agent_signing_authorization

        # Create a new KeyManager. By default, the manager will
        # use the ssh-agent if it is running and the `:use_agent` option
        # is not false.
        def initialize(logger, options = {}, transport = nil)
          self.logger = logger
          @key_files = []
          @key_data = []
          @keycert_files = []
          @keycert_data = []
          @use_agent = options[:use_agent] != false
          @known_identities = {}
          @agent = nil
          @options = options
          @transport = transport
          @agent_signing_authorization = options[:agent_signing_authorization]
          validate_signing_authorization!
        end

        # Clear all knowledge of any loaded user keys. This also clears the list
        # of default identity files that are to be loaded, thus making it
        # appropriate to use if a client wishes to NOT use the default identity
        # files.
        def clear!
          key_files.clear
          key_data.clear
          keycert_data.clear
          known_identities.clear
          self
        end

        # Add the given key_file to the list of key files that will be used.
        def add(key_file)
          key_files.push(File.expand_path(key_file)).uniq!
          self
        rescue ArgumentError
          self
        end

        # Add the given keycert_file to the list of keycert files that will be used.
        def add_keycert(keycert_file)
          keycert_files.push(File.expand_path(keycert_file)).uniq!
          self
        rescue ArgumentError
          self
        end

        # Add the given keycert_data to the list of keycerts that will be used.
        def add_keycert_data(keycert_data_)
          keycert_data.push(keycert_data_).uniq!
          self
        end

        # Add the given key_file to the list of keys that will be used.
        def add_key_data(key_data_)
          key_data.push(key_data_).uniq!
          self
        end

        # This is used as a hint to the KeyManager indicating that the agent
        # connection is no longer needed. Any other open resources may be closed
        # at this time.
        #
        # Calling this does NOT indicate that the KeyManager will no longer
        # be used. Identities may still be requested and operations done on
        # loaded identities, in which case, the agent will be automatically
        # reconnected. This method simply allows the client connection to be
        # closed when it will not be used in the immediate future.
        def finish
          @agent.close if @agent
          @agent = nil
        end

        # Iterates over all available identities (public keys) known to this
        # manager. As it finds one, it will then yield it to the caller.
        # The origin of the identities may be from files on disk or from an
        # ssh-agent. Note that identities from an ssh-agent are always listed
        # first in the array, with other identities coming after.
        #
        # If key manager was created with :keys_only option, any identity
        # from ssh-agent will be ignored unless it present in key_files or
        # key_data.
        def each_identity
          prepared_identities = prepare_identities_from_files + prepare_identities_from_data

          user_identities = load_identities(prepared_identities, false, true)

          agent_identities.each do |key|
            corresponding_user_identity = user_identities.detect { |identity|
              identity[:public_key] && identity[:public_key].to_blob == key.to_blob
            }
            # By identity: EC::Point#== raises TypeError when compared with other key types.
            user_identities.reject! { |identity| identity.equal?(corresponding_user_identity) }

            if !options[:keys_only] || corresponding_user_identity
              known_identities[key] = { from: :agent, identity: key }
              yield key
            end
          end

          user_identities = load_identities(user_identities, !options[:non_interactive], false)

          user_identities.each do |identity|
            key = identity.delete(:public_key)
            known_identities[key] = identity
            yield key
          end

          known_identity_blobs = known_identities.keys.map(&:to_blob)

          keycerts.each do |keycert|
            next if known_identity_blobs.include?(keycert.to_blob)

            (_, corresponding_identity) = known_identities.detect { |public_key, _|
              public_key.to_pem == keycert.to_pem
            }

            if corresponding_identity
              known_identities[keycert] = corresponding_identity
              yield keycert
            end
          end

          self
        end

        # Sign the given data, using the corresponding private key of the given
        # identity. If the identity was originally obtained from an ssh-agent,
        # then the ssh-agent will be used to sign the data, otherwise the
        # private key for the identity will be loaded from disk (if it hasn't
        # been loaded already) and will then be used to sign the data.
        #
        # An identity held by the ssh-agent is only signed with when the
        # connection's host key has been verified and the
        # :agent_signing_authorization hook (if any) allows it for this target,
        # key and +purpose+; otherwise AgentSigningDenied is raised. Keys loaded
        # from disk are not affected.
        #
        # Regardless of the identity's origin or who does the signing, this
        # will always return the signature in an SSH2-specified "signature
        # blob" format.
        def sign(identity, data, sig_alg = nil, purpose: :publickey)
          info = known_identities[identity] or raise KeyManagerError, "the given identity is unknown to the key manager"

          if info[:from] == :pubkey_file_only
            raise KeyManagerError, "the given identity is a public key only and cannot be used for signing without an agent"
          end

          if info[:key].nil? && (info[:from] == :file || info[:from] == :pubkey_file)
            begin
              info[:key] = KeyFactory.load_private_key(info[:file], options[:passphrase], !options[:non_interactive], options[:password_prompt])
            rescue OpenSSL::OpenSSLError, Exception => e
              raise KeyManagerError, "the given identity is known, but the private key could not be loaded: #{e.class} (#{e.message})"
            end
          end

          if info[:key]
            if sig_alg.nil?
              signed = info[:key].ssh_do_sign(data.to_s)
              sig_alg = identity.ssh_signature_type
            else
              signed = info[:key].ssh_do_sign(data.to_s, sig_alg)
            end
            return Net::SSH::Buffer.from(:string, sig_alg,
                                         :mstring, signed).to_s
          end

          if info[:from] == :agent
            raise KeyManagerError, "the agent is no longer available" unless agent

            target = authorize_agent_signature!(info[:identity], sig_alg, purpose, identity: identity)
            # Re-check right before asking the agent: a rekey or a new
            # authentication attempt may have moved the connection on while
            # the hook was deciding.
            assert_signing_target_current!(target, purpose)

            case sig_alg
            when "rsa-sha2-512"
              return agent.sign(info[:identity], data.to_s, Net::SSH::Authentication::Agent::SSH_AGENT_RSA_SHA2_512)
            when "rsa-sha2-256"
              return agent.sign(info[:identity], data.to_s, Net::SSH::Authentication::Agent::SSH_AGENT_RSA_SHA2_256)
            else
              return agent.sign(info[:identity], data.to_s)
            end
          end

          raise KeyManagerError, "[BUG] can't determine identity origin (#{info.inspect})"
        end

        # Identifies whether the ssh-agent will be used or not.
        def use_agent?
          @use_agent
        end

        # Toggles whether the ssh-agent will be used or not. If true, an
        # attempt will be made to use the ssh-agent. If false, any existing
        # connection to an agent is closed and the agent will not be used.
        def use_agent=(use_agent)
          finish if !use_agent
          @use_agent = use_agent
        end

        # Returns an Agent instance to use for communicating with an SSH
        # agent process. Returns nil if use of an SSH agent has been disabled,
        # or if the agent is otherwise not available.
        def agent
          return unless use_agent?

          @agent ||= Agent.connect(logger, options[:agent_socket_factory], options[:identity_agent])
        rescue AgentNotAvailable
          @use_agent = false
          nil
        end

        def no_keys?
          key_files.empty? && key_data.empty?
        end

        private

        def validate_signing_authorization!
          authorization = @agent_signing_authorization
          return if authorization.nil? || authorization.respond_to?(:call)

          raise ArgumentError,
                ":agent_signing_authorization must respond to call or be nil, got #{authorization.class}"
        end

        # Builds the context of a signing decision from the connection's
        # currently verified target and asks the hook. Raises
        # AgentSigningDenied unless the host key for the current key exchange
        # has been verified and the hook, if one is set, returns true. Returns
        # the target the decision was made for.
        #
        # The target is read from the transport for every signature, so a retry
        # after a rekey sees the new exchange (or is refused until the new host
        # key verifies) instead of a cached one.
        def authorize_agent_signature!(public_key, sig_alg, purpose, identity: public_key)
          target = verified_signing_target
          raise AgentSigningDenied, "the host key has not been verified, so the agent may not sign" if target.nil?

          return target unless agent_signing_authorization

          context = AgentSigningContext.new(
            target: target, public_key: public_key,
            public_key_fingerprint: key_fingerprint(public_key),
            identity: identity, identity_fingerprint: key_fingerprint(identity),
            purpose: purpose, signature_algorithm: sig_alg
          )
          allowed = begin
            agent_signing_authorization.call(context)
          rescue AgentSigningDenied
            raise
          rescue StandardError => e
            error { "agent signing authorization raised #{e.class}: #{e.message}" }
            false
          end

          unless allowed
            debug { "agent signing refused by :agent_signing_authorization (#{context.to_h.inspect})" }
            raise AgentSigningDenied,
                  "the agent may not sign #{purpose} authentication for #{context.host} (#{context.public_key_fingerprint}), " \
                  "the :agent_signing_authorization hook refused it"
          end

          debug { "agent signing allowed for #{purpose} authentication (#{context.to_h.inspect})" }
          target
        end

        # The fingerprint shown to the hook, in the configured format.
        def key_fingerprint(key)
          key.fingerprint(options[:fingerprint_hash] || 'SHA256')
        rescue StandardError
          nil
        end

        # Confirms that a decision still applies to the connection right before
        # the agent is asked, so a rekey or a concurrent retry in between the
        # hook's decision and the agent call can't reuse the earlier target.
        def assert_signing_target_current!(target, purpose)
          current = verified_signing_target
          denied = lambda do |reason|
            debug { "agent signing refused after the decision: #{reason}" }
            raise AgentSigningDenied,
                  "the agent may not sign #{purpose} authentication for #{target.host}, the signing target " \
                  "changed after the :agent_signing_authorization hook allowed it (#{reason})"
          end

          denied.call("the host key is no longer verified") if current.nil?
          denied.call("the connection moved to another key exchange") if current.key_exchange != target.key_exchange
          denied.call("the verified host key changed") unless current.host_key.to_blob == target.host_key.to_blob
        end

        # Returns an AgentSigningTarget for the transport's current key
        # exchange, or nil when the host key of that exchange has not been
        # verified (yet).
        def verified_signing_target
          return nil unless transport && transport.respond_to?(:verified_host_key)

          host_key = transport.verified_host_key
          return nil if host_key.nil?

          AgentSigningTarget.new(
            host: transport.host,
            port: transport.port,
            host_key: host_key,
            host_key_fingerprint: transport.verified_host_key_fingerprint,
            session_id: transport_session_id,
            key_exchange: transport.key_exchange_sequence
          )
        end

        # The SSH session id, as generated by the initial key exchange. A
        # transport that cannot provide one (or hasn't completed the exchange)
        # yields nil, and the hook is told so rather than being given a made-up
        # value.
        def transport_session_id
          transport.algorithms.session_id if transport.respond_to?(:algorithms) && transport.algorithms
        rescue StandardError
          nil
        end

        # Like OpenSSH's pubkey_prepare, an agent that fails to list its keys is
        # dropped for the session so that key files are still tried.
        def agent_identities
          return [] unless agent

          agent.identities
        rescue AgentError => e
          error { "could not get identities from agent: #{e.class} (#{e.message})" }
          self.use_agent = false
          []
        end

        # Load keycerts from files and data.
        def keycerts
          keycert_files.map { |keycert_file| KeyFactory.load_public_key(keycert_file) } +
            keycert_data.map { |data| KeyFactory.load_data_public_key(data) }
        end

        # Prepares identities from user key_files for loading, preserving their order and sources.
        def prepare_identities_from_files
          key_files.map do |file|
            if readable_file?(file)
              identity = { privkey_file: file }
              cert_file = file + "-cert.pub"
              public_key_file = file + ".pub"
              if file.end_with?(".pub")
                identity[:load_from] = :pubkey_file_only
                identity[:pubkey_file] = file
                identity.delete(:privkey_file)
              elsif readable_file?(cert_file)
                identity[:load_from] = :pubkey_file
                identity[:pubkey_file] = cert_file
              elsif readable_file?(public_key_file)
                identity[:load_from] = :pubkey_file
                identity[:pubkey_file] = public_key_file
              else
                identity[:load_from] = :privkey_file
              end
              identity
            end
          end.compact
        end

        def readable_file?(path)
          File.file?(path) && File.readable?(path)
        end

        # Prepared identities from user key_data, preserving their order and sources.
        def prepare_identities_from_data
          key_data.map do |data|
            { load_from: :data, data: data }
          end
        end

        # Load prepared identities. Private key decryption errors ignored if ignore_decryption_errors
        def load_identities(identities, ask_passphrase, ignore_decryption_errors)
          identities.map do |identity|
            case identity[:load_from]
            when :pubkey_file
              key = KeyFactory.load_public_key(identity[:pubkey_file])
              { public_key: key, from: :pubkey_file, file: identity[:privkey_file] }
            when :pubkey_file_only
              key = KeyFactory.load_public_key(identity[:pubkey_file])
              { public_key: key, from: :pubkey_file_only, file: identity[:privkey_file] }
            when :privkey_file
              private_key = KeyFactory.load_private_key(
                identity[:privkey_file], options[:passphrase], ask_passphrase, options[:password_prompt]
              )
              key = private_key.send(:public_key)
              { public_key: key, from: :file, file: identity[:privkey_file], key: private_key }
            when :data
              private_key = KeyFactory.load_data_private_key(
                identity[:data], options[:passphrase], ask_passphrase, "<key in memory>", options[:password_prompt]
              )
              key = private_key.send(:public_key)
              { public_key: key, from: :key_data, data: identity[:data], key: private_key }
            else
              identity
            end
          rescue OpenSSL::PKey::RSAError, OpenSSL::PKey::DSAError, OpenSSL::PKey::ECError, OpenSSL::PKey::PKeyError, ArgumentError => e
            if ignore_decryption_errors
              identity
            else
              process_identity_loading_error(identity, e)
              nil
            end
          rescue Exception => e
            process_identity_loading_error(identity, e)
            nil
          end.compact
        end

        def process_identity_loading_error(identity, e)
          case identity[:load_from]
          when :pubkey_file, :pubkey_file_only
            error { "could not load public key file `#{identity[:pubkey_file]}': #{e.class} (#{e.message})" }
          when :privkey_file
            error { "could not load private key file `#{identity[:privkey_file]}': #{e.class} (#{e.message})" }
          else
            raise e
          end
        end
      end
    end
  end
end

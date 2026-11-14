require 'net/ssh/errors'
require 'net/ssh/loggable'

module Net
  module SSH
    module Multiplex
      # Decides whether reusing an OpenSSH ControlMaster can satisfy the
      # security requirements of a Net::SSH.start call. Key exchange, host key
      # verification and authentication already happened on the master, so the
      # options that steer them cannot be enforced by a proxied session: they
      # only hold if the master was started with matching settings.
      #
      # Options fall into three groups:
      #
      # * Layer-guaranteed. They only shape the multiplexed channel layer
      #   (:send_env, :set_env, :properties, :timeout, :preopen_channels ...)
      #   or are explicitly neutralized over a master (:keepalive,
      #   :forward_agent, :rekey_*), so they stay effective without trusting
      #   the master's configuration.
      # * Master-owned. They steer the connection the master established
      #   (Multiplex::MASTER_OWNED_OPTIONS): the host key verifier and known
      #   hosts, algorithm restrictions (:encryption, :hmac, :kex, :host_key,
      #   :pubkey_algorithms ...) and every authentication identity (:keys,
      #   :key_data, :password, :passphrase, :auth_methods, :use_agent ...).
      #   A proxied session cannot tell whether the master honors them.
      # * Unverifiable target. The ControlPath contains no host, port and user
      #   token (%C, or all of %h/%n + %p + %r), so a matching socket path
      #   proves nothing about which host and identity the master serves.
      #
      # The policy chosen with :control_master_policy says what to do with the
      # last two groups: :allow logs and reuses, :direct falls back to a fresh
      # direct connection, :strict raises ControlMasterSecurityError before a
      # channel is opened or a remote command is sent.
      class SecurityPolicy
        include Loggable

        POLICIES = %i[allow strict direct].freeze

        # Options Net::SSH itself neutralizes over a master (the master owns
        # the behavior). They are reported through session_options, not here.
        NEUTRALIZED_OPTIONS = %i[keepalive forward_agent].freeze

        # ControlPath tokens that bind the socket to a connection target. %C
        # alone binds host, port, user and the ProxyJump hop; otherwise each
        # dimension must be named explicitly. %n (the host as given) and %h
        # (after HostName) both identify the host.
        PORT_TOKEN = 'p'
        USER_TOKEN = 'r'

        # The raw ControlPath, before ~/${ENV}/% expansion, is what carries the
        # tokens; a literal %% never produces one.
        def self.target_bound?(control_path)
          template = control_path.to_s.gsub('%%', '')
          tokens = template.scan(/%(.)/).flatten
          return true if tokens.include?('C')

          tokens.include?(PORT_TOKEN) && tokens.include?(USER_TOKEN) &&
            (tokens.include?('h') || tokens.include?('n'))
        end

        def initialize(options, explicit:, logger: nil)
          @options = options
          @explicit = explicit
          self.logger = logger
        end

        # The master-owned option names the caller actually passed to
        # Net::SSH.start. Options coming from ssh_config or
        # Net::SSH.default_configuration are not conflicts: only an explicit
        # caller requirement can be silently ignored.
        def master_owned_conflicts
          @master_owned_conflicts ||= (@explicit & MASTER_OWNED_OPTIONS) - NEUTRALIZED_OPTIONS
        end

        def target_verifiable?
          @target_verifiable ||= self.class.target_bound?(@options[:control_path])
        end

        # Human-readable reasons the caller's requirements can't be checked on
        # a proxied session, empty when reuse is safe without trusting the
        # master's configuration.
        def violations
          violations = []
          unless master_owned_conflicts.empty?
            violations << "explicit option(s) #{master_owned_conflicts.join(', ')} are owned by the ControlMaster: " \
                         "host key verification, algorithm and authentication settings can't be checked on a proxied session"
          end
          unless target_verifiable?
            violations << "ControlPath #{@options[:control_path].inspect} has no %C or %h/%n, %p and %r tokens: " \
                         'a matching socket path does not prove which host, port and user the master is connected to'
          end
          violations
        end

        # Applies the configured policy after a usable master was found.
        # Returns :reuse to run the session through the master, or :direct to
        # open a fresh direct connection instead. Raises
        # ControlMasterSecurityError under :strict.
        def decide
          problems = violations
          return :reuse if problems.empty?

          case @options[:control_master_policy]
          when :strict
            raise ControlMasterSecurityError,
                  "refusing to reuse the ControlMaster at #{@options[:control_path].inspect}: #{problems.join('; ')}"
          when :direct
            lwarn { "control_master: bypassing the ControlMaster and connecting directly: #{problems.join('; ')}" }
            :direct
          else
            info { "control_master: reusing despite requirements only the ControlMaster's own configuration can guarantee: #{problems.join('; ')}" }
            :reuse
          end
        end
      end
    end
  end
end

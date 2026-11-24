# frozen_string_literal: true

module Net
  class HTTP
    # An immutable network path selected for one HTTP request invocation.
    #
    # The route is resolved once for a request and retained across retries.
    # Approval is checked whenever a connection is opened or an existing
    # keep-alive connection is reused, so changing configuration for a new
    # request cannot redirect an older request's retry.
    class NetworkPath
      DIRECT = :direct
      PROXY = :proxy

      attr_reader :kind, :target_address, :target_port
      attr_reader :proxy_address, :proxy_port, :proxy_user
      attr_reader :proxy_use_ssl

      def initialize(kind:, target_address:, target_port:, use_ssl:,
                     proxy_address: nil, proxy_port: nil,
                     proxy_user: nil, proxy_pass: nil,
                     proxy_use_ssl: nil)
        @kind = kind.to_sym
        @target_address = target_address
        @target_port = target_port
        @use_ssl = use_ssl
        @proxy_address = proxy_address
        @proxy_port = proxy_port
        @proxy_user = proxy_user
        @proxy_pass = proxy_pass
        @proxy_use_ssl = proxy_use_ssl
        freeze
      end

      def self.direct(target_address:, target_port:, use_ssl:)
        new(
          kind: DIRECT,
          target_address: target_address,
          target_port: target_port,
          use_ssl: use_ssl
        )
      end

      def self.proxy(target_address:, target_port:, use_ssl:,
                     proxy_address:, proxy_port:, proxy_user: nil,
                     proxy_pass: nil, proxy_use_ssl: nil)
        new(
          kind: PROXY,
          target_address: target_address,
          target_port: target_port,
          use_ssl: use_ssl,
          proxy_address: proxy_address,
          proxy_port: proxy_port,
          proxy_user: proxy_user,
          proxy_pass: proxy_pass,
          proxy_use_ssl: proxy_use_ssl
        )
      end

      def direct?
        kind == DIRECT
      end

      def proxy?
        kind == PROXY
      end

      def use_ssl?
        @use_ssl
      end

      def proxy_pass
        @proxy_pass
      end

      # Returns the host to which the TCP connection is opened.
      def connection_address
        proxy? ? proxy_address : target_address
      end

      # Returns the port to which the TCP connection is opened.
      def connection_port
        proxy? ? proxy_port : target_port
      end

      def key
        [
          kind, target_address, target_port, use_ssl?,
          proxy_address, proxy_port, proxy_use_ssl
        ]
      end

      def ==(other)
        other.is_a?(NetworkPath) && key == other.key
      end
      alias eql? ==

      def hash
        key.hash
      end

      def approval_kind
        direct? ? 'direct' : 'proxy'
      end

      def to_s
        target = +"#{target_address}:#{target_port}"
        if direct?
          "direct network path to #{target}"
        else
          "proxy network path to #{target} via #{proxy_address}:#{proxy_port}"
        end
      end
      alias inspect to_s
    end

    # Raised when the selected network path does not have the required
    # direct-connection or proxy-connection approval.
    class MissingNetworkApproval < Net::ProtocolError
      attr_reader :approval_kind, :network_path

      def initialize(network_path, approval_kind = network_path.approval_kind)
        @network_path = network_path
        @approval_kind = approval_kind.to_sym
        super(
          "missing #{@approval_kind} network approval for #{network_path}"
        )
      end
    end

    NetworkPathApprovalError = MissingNetworkApproval

    # Separate approval policy for direct and proxied network paths.
    #
    # Each approval may be true/false, a callable, or an object responding to
    # direct_approved?/proxy_approved? (and the allowed?/permitted? aliases).
    class NetworkPathPolicy
      METHOD_NAMES = {
        direct: %i[direct_approved? approve_direct? direct_allowed? direct_permitted?],
        proxy: %i[proxy_approved? approve_proxy? proxy_allowed? proxy_permitted?]
      }.freeze

      def initialize(approvals = nil, direct: nil, proxy: nil, **options)
        approvals ||= options[:approvals]
        direct_approval = direct.nil? ? approvals : direct
        proxy_approval = proxy.nil? ? approvals : proxy
        @direct_check = coerce_check(direct_approval, :direct)
        @proxy_check = coerce_check(proxy_approval, :proxy)
      end

      def authorize!(network_path)
        check = network_path.direct? ? @direct_check : @proxy_check
        approved = check.call(network_path)
        raise MissingNetworkApproval.new(network_path) unless approved

        network_path
      end

      private

      def coerce_check(value, kind)
        return ->(_path) { false } if value.nil?
        return ->(_path) { value } if value == true || value == false
        return value if value.respond_to?(:call)

        method_name = METHOD_NAMES.fetch(kind).find do |name|
          value.respond_to?(name)
        end
        if method_name
          lambda do |path|
            if value.method(method_name).arity == 0
              value.public_send(method_name)
            else
              value.public_send(method_name, path)
            end
          end
        else
          raise ArgumentError,
                "network approval must respond to #{METHOD_NAMES[kind].join(', ')} " \
                "or be callable"
        end
      end
    end

    NetworkPathApproval = NetworkPathPolicy
  end
end

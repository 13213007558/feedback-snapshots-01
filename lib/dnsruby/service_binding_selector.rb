require 'base64'

module Dnsruby
  # Builds a connection plan from an already-authenticated Service Binding
  # answer chain (RFC 9460 section 3).
  #
  # The selector is offline and policy-driven: it never sends a query and it
  # never resolves A or AAAA records. Its inputs are the SVCB/HTTPS resource
  # records a caller has already validated (for example with DNSSEC) and the
  # caller's own capabilities -- the ALPN protocols it speaks, the SvcParamKeys
  # it understands, and whether an Encrypted ClientHello (RFC 9848) is required.
  # Its output is a ServiceBindingSelector::Selection that orders the usable
  # endpoints and explains why every other candidate was rejected.
  #
  # Security properties the selector preserves:
  #
  # * AliasMode (SvcPriority 0) only redirects the name whose A/AAAA records are
  #   looked up. It never changes the origin, so every plan keeps the original
  #   service name for SNI and TLS certificate validation. An ipv4hint/ipv6hint
  #   is likewise only a set of connection addresses, never an identity: the
  #   caller still authenticates the original service name (RFC 9460 sections
  #   2.4.2, 9.1 and 9.4).
  # * A candidate carrying a mandatory key the caller does not understand is
  #   incompatible and is skipped, not parsed on a best-effort basis (RFC 9460
  #   section 8).
  # * When the caller requires ECH, no candidate without an ech SvcParam is
  #   usable, and an empty result forbids falling back to a plaintext A/AAAA
  #   connection rather than silently downgrading.
  class ServiceBindingSelector
    # Numeric SvcParamKeys the selector reasons about directly (RFC 9460
    # section 7, plus ech from RFC 9848).
    MANDATORY_KEY      = 0
    ALPN_KEY           = 1
    NO_DEFAULT_ALPN    = 2
    PORT_KEY           = 3
    IPV4HINT_KEY       = 4
    ECH_KEY            = 5
    IPV6HINT_KEY       = 6

    # SvcParamKeys automatically mandatory for the HTTPS mapping when present
    # (RFC 9460 section 9), alongside whatever the mandatory key names.
    HTTPS_AUTO_MANDATORY = [PORT_KEY, NO_DEFAULT_ALPN].freeze

    # RFC 9460 section 3 step 3: AliasMode chains are bounded. Five redirects
    # is the value the SVCB resolution guidance gives clients as a workable
    # limit; reaching it fails SVCB resolution instead of looping forever.
    MAX_ALIAS_REDIRECTS = 5

    # The HTTPS mapping's default ALPN set (RFC 9460 section 9): HTTP/1.1.
    HTTPS_DEFAULT_ALPN = ['http/1.1'].freeze

    # Rejection reasons, stable for callers that branch on them.
    module Reason
      # The mandatory SvcParam (or an automatically-mandatory HTTPS key) names
      # a SvcParamKey this caller does not support.
      UNSUPPORTED_MANDATORY = :unsupported_mandatory

      # No ALPN identifier offered by the endpoint is one the caller supports.
      NO_ALPN_MATCH = :no_alpn_match

      # The caller requires ECH but this ServiceMode RR carries no ech param.
      ECH_REQUIRED = :ech_required
    end

    # Human-readable explanations for Reason, kept next to the symbols so error
    # reporting cannot drift from the conditions that set them.
    REASON_TEXT = {
      Reason::UNSUPPORTED_MANDATORY =>
        'mandatory SvcParamKey is not supported by this client',
      Reason::NO_ALPN_MATCH =>
        'none of the endpoint ALPN identifiers are supported by this client',
      Reason::ECH_REQUIRED =>
        'client requires Encrypted ClientHello but the record offers no ech SvcParam',
    }.freeze

    # One endpoint the selector could not use and why.
    class Rejection
      # The ServiceMode RR::SVCB (or RR::HTTPS) that was rejected.
      attr_reader :record

      # A Reason symbol describing the first rule the record failed.
      attr_reader :reason

      # For UNSUPPORTED_MANDATORY, the numeric SvcParamKeys the caller lacks;
      # nil for the other reasons.
      attr_reader :unsupported_keys

      def initialize(record, reason, unsupported_keys = nil)
        @record = record
        @reason = reason
        @unsupported_keys = unsupported_keys
      end

      # The explanation from REASON_TEXT, with the unsupported key names
      # appended where relevant.
      def message
        text = REASON_TEXT.fetch(reason)
        return text if unsupported_keys.nil? || unsupported_keys.empty?

        "#{text}: #{unsupported_keys.map { |key| RR::SVCB::KEY_NUM_TO_NAME[key] || "key#{key}" }.join(', ')}"
      end
    end

    # A usable endpoint in the order the caller should attempt it.
    class ConnectionPlan
      # The ServiceMode RR the plan was derived from.
      attr_reader :record

      # The name whose A/AAAA records give the connection addresses. This is
      # the effective TargetName (RFC 9460 section 2.5.2), never the origin.
      attr_reader :target_name

      # The origin name to send in SNI and validate the TLS certificate for.
      # AliasMode redirects and address hints do not change this.
      attr_reader :server_name

      # The TCP/UDP port to connect to (the port SvcParam or the default).
      attr_reader :port

      # ALPN identifiers in the caller's preference order that both the
      # endpoint and the caller support.
      attr_reader :alpn

      # Base64 Encrypted ClientHello configuration from the ech SvcParam, or
      # nil when the endpoint offers none.
      attr_reader :ech

      # IPv4 connection addresses decoded from ipv4hint (possibly empty).
      attr_reader :ipv4_hints

      # IPv6 connection addresses decoded from ipv6hint (possibly empty).
      attr_reader :ipv6_hints

      def initialize(record, target_name, server_name, port, alpn, ech, ipv4_hints, ipv6_hints)
        @record = record
        @target_name = target_name
        @server_name = server_name
        @port = port
        @alpn = alpn
        @ech = ech
        @ipv4_hints = ipv4_hints
        @ipv6_hints = ipv6_hints
      end

      # True when the plan carries Encrypted ClientHello configuration.
      def ech?
        !@ech.nil?
      end
    end

    # The result of evaluating an answer chain for one caller.
    class Selection
      # One of:
      #
      # :usable:: at least one compatible ServiceMode candidate produced a plan.
      # :no_compatible_candidate:: every ServiceMode RR was rejected.
      # :downgrade_forbidden:: the caller requires ECH and no ECH-capable plan
      #   exists, so a bare A/AAAA connection must not be attempted.
      # :alias_unavailable:: an AliasMode TargetName of "." says the service
      #   does not exist (RFC 9460 section 2.5.1).
      # :alias_loop:: the AliasMode chain revisits a name.
      # :alias_limit:: the chain exceeded MAX_ALIAS_REDIRECTS.
      # :missing_alias_target:: an AliasMode RR names a target with no records
      #   in the supplied answer chain.
      # :no_records:: the answer chain held no SVCB/HTTPS records.
      attr_reader :status

      # ConnectionPlan objects in attempt order (ascending SvcPriority).
      attr_reader :plans

      # Rejection objects for every ServiceMode candidate that was skipped.
      attr_reader :rejections

      # The TargetNames visited through AliasMode redirects, in order.
      attr_reader :alias_path

      def initialize(status, plans, rejections, alias_path)
        @status = status
        @plans = plans
        @rejections = rejections
        @alias_path = alias_path
      end

      def usable?
        status == :usable
      end

      # True when no plan exists and the caller's policy forbids connecting
      # without an ECH-capable SVCB record.
      def downgrade_forbidden?
        status == :downgrade_forbidden
      end

      # True when ordinary (non-SVCB) A/AAAA connection establishment remains a
      # legal fallback. A required ECH handshake removes that fallback.
      def fallback_allowed?
        plans.empty? && !downgrade_forbidden?
      end
    end

    # Builds a selector for one caller.
    #
    # +alpn+:: the ALPN identifiers the caller supports, in preference order.
    # +supported_keys+:: numeric SvcParamKeys the caller understands. Defaults
    #   to every key dnsruby knows; unknown keys are not understood.
    # +require_ech+:: when true, only ech-bearing candidates are usable and a
    #   bare A/AAAA fallback is forbidden on an empty result.
    # +default_port+:: the authority endpoint's port, used when a record omits
    #   the port SvcParam.
    # +default_alpn+:: ALPN identifiers implied when a record lacks the alpn
    #   SvcParam, unless it carries no-default-alpn. Defaults to the HTTPS
    #   mapping's set.
    def initialize(alpn:, supported_keys: nil, require_ech: false,
                   default_port: 443, default_alpn: HTTPS_DEFAULT_ALPN)
      @alpn = alpn.map(&:to_s).freeze
      @supported_keys = (supported_keys || RR::SVCB::KEY_NAME_TO_NUM.values.dup).freeze
      @require_ech = require_ech
      @default_port = default_port
      @default_alpn = default_alpn.map(&:to_s).freeze
    end

    # Evaluates an answer chain.
    #
    # +chain+ is an ordered list of RR groups, one per owner name in resolution
    # order: the queried service name first, then each AliasMode target. A
    # group is an Array of RR objects (an RRset or a Message section's SVCB
    # records). A flat Array of records is treated as a single group.
    def select(chain)
      groups = normalize(chain)
      return Selection.new(:no_records, [], [], []) if groups.empty?

      visited = []
      alias_path = []
      candidates = nil
      origin = nil
      service_owner = nil

      groups.each do |group|
        records = group.select { |rr| rr.is_a?(RR::SVCB) }
        next if records.empty?

        owner = records.first.name
        if visited.any? { |name| same_name?(name, owner) }
          return Selection.new(:alias_loop, [], [], alias_path)
        end
        visited << owner
        origin ||= owner
        service_owner = owner

        aliases = records.select { |rr| rr.priority.zero? }
        services = records.reject { |rr| rr.priority.zero? }

        if aliases.any?
          # RFC 9460 section 2.4.2: an AliasMode RRset SHOULD hold one RR; if
          # several are present pick one. Its SvcParams are ignored.
          target = aliases.first.target
          if root_name?(target)
            return Selection.new(:alias_unavailable, [], [], alias_path)
          end
          alias_path << target
          if alias_path.length > MAX_ALIAS_REDIRECTS
            return Selection.new(:alias_limit, [], [], alias_path)
          end
          next
        end

        candidates = services
        break
      end

      return Selection.new(:missing_alias_target, [], [], alias_path) if candidates.nil?

      plans = []
      rejections = []
      candidates.each do |record|
        evaluate(record, origin, service_owner, plans, rejections)
      end
      # RFC 9460 section 3 step 4: ascending SvcPriority. Equal-priority RRs
      # may be tried in any order, so keep the chain's order deterministically.
      plans = plans.sort_by.with_index { |plan, index| [plan.record.priority, index] }

      status =
        if plans.any?
          :usable
        elsif @require_ech
          :downgrade_forbidden
        else
          :no_compatible_candidate
        end
      Selection.new(status, plans, rejections, alias_path)
    end

    private

    # A flat Array of RRs is one group; an Array of Arrays is the chain. Each
    # group is copied so callers' arrays are never reordered.
    def normalize(chain)
      return [] if chain.nil?

      groups =
        if chain.is_a?(Array) && chain.all? { |entry| entry.is_a?(Array) }
          chain
        else
          [Array(chain)]
        end
      groups.map { |group| Array(group) }.reject(&:empty?)
    end

    def evaluate(record, origin, service_owner, plans, rejections)
      unsupported = mandatory_keys(record).reject { |key| @supported_keys.include?(key) }
      if unsupported.any?
        rejections << Rejection.new(record, Reason::UNSUPPORTED_MANDATORY, unsupported)
        return
      end

      offered = alpn_set(record)
      matched = @alpn.select { |protocol| offered.include?(protocol) }
      if matched.empty?
        rejections << Rejection.new(record, Reason::NO_ALPN_MATCH)
        return
      end

      if @require_ech && !record.params.key?(ECH_KEY)
        rejections << Rejection.new(record, Reason::ECH_REQUIRED)
        return
      end

      # RFC 9460 section 2.5.2: a TargetName of "." means this record's owner
      # is the effective target for address resolution. The origin is retained
      # separately: SNI and TLS certificate validation never follow the alias
      # or the hints (sections 2.4, 9.1 and 9.4).
      target = root_name?(record.target) ? service_owner : record.target
      plans << ConnectionPlan.new(
        record,
        target,
        origin,
        record.params.key?(PORT_KEY) ? unpack_port(record.params[PORT_KEY]) : @default_port,
        matched,
        record.params.key?(ECH_KEY) ? Base64.strict_encode64(record.params[ECH_KEY]) : nil,
        unpack_addresses(record, IPV4HINT_KEY, IPv4, 4),
        unpack_addresses(record, IPV6HINT_KEY, IPv6, 16)
      )
    end

    # The keys the caller must understand to use this RR: the mandatory list,
    # plus the HTTPS mapping's automatically-mandatory keys when present.
    def mandatory_keys(record)
      keys = record.params.key?(MANDATORY_KEY) ? record.params[MANDATORY_KEY].unpack('n*') : []
      if record.is_a?(RR::HTTPS)
        keys += HTTPS_AUTO_MANDATORY.select { |key| record.params.key?(key) }
      end
      keys.uniq.sort
    end

    # RFC 9460 section 7.1: the offered set starts with the alpn SvcParam; a
    # record with no alpn param offers the mapping's default set instead,
    # unless no-default-alpn suppresses that default.
    def alpn_set(record)
      if record.params.key?(ALPN_KEY)
        unpack_length_prefixed(record.params[ALPN_KEY])
      elsif record.params.key?(NO_DEFAULT_ALPN)
        []
      else
        @default_alpn.dup
      end
    end

    def unpack_length_prefixed(bytes)
      items = []
      index = 0
      while index < bytes.bytesize
        length = bytes.getbyte(index)
        items << bytes.byteslice(index + 1, length)
        index += 1 + length
      end
      items
    end

    def unpack_port(bytes)
      bytes.unpack1('n')
    end

    def unpack_addresses(record, key, ip_class, width)
      bytes = record.params[key]
      return [] if bytes.nil?

      (bytes.bytesize / width).times.map do |offset|
        ip_class.new(bytes.byteslice(offset * width, width)).to_s
      end
    end

    def root_name?(name)
      name.to_a.empty?
    end

    def same_name?(first, second)
      first.canonical == second.canonical
    end
  end
end

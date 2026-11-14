# frozen_string_literal: true
module SecureHeaders
  module DynamicConfig
    def initialize(hash)
      @config = {}

      from_hash(hash)
    end

    def initialize_copy(hash)
      @config = hash.to_h
    end

    def update_directive(directive, value)
      @config[directive] = value
    end

    def directive_value(directive)
      # No need to check attrs, as we only assign valid keys
      @config[directive]
    end

    def merge(new_hash)
      new_config = self.dup
      new_config.send(:from_hash, new_hash)
      new_config
    end

    def merge!(new_hash)
      from_hash(new_hash)
    end

    def append(new_hash)
      from_hash(ContentSecurityPolicy.combine_policies(self.to_h, new_hash))
    end

    def to_h
      @config.dup
    end

    def dup
      self.class.new(self.to_h)
    end

    def opt_out?
      false
    end

    def ==(o)
      self.class == o.class && self.to_h == o.to_h
    end

    alias_method :[], :directive_value
    alias_method :[]=, :update_directive

    private
    def from_hash(hash)
      hash.each_pair do |k, v|
        next if v.nil?

        if self.class.attrs.include?(k)
          write_attribute(k, v)
        else
          raise ContentSecurityPolicyConfigError, "Unknown config directive: #{k}=#{v}"
        end
      end
    end

    def write_attribute(attr, value)
      value = value.dup if PolicyManagement::DIRECTIVE_VALUE_TYPES[attr] == :source_list
      if value.nil?
        @config.delete(attr)
      else
        @config[attr] = value
      end
    end
  end

  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicyConfig
    HEADER_NAME = "content-security-policy".freeze

    ATTRS = Set.new(PolicyManagement::ALL_DIRECTIVES + PolicyManagement::META_CONFIGS + PolicyManagement::NONCES)
    def self.attrs
      ATTRS
    end

    include DynamicConfig

    # based on what was suggested in https://github.com/rails/rails/pull/24961/files
    DEFAULT = {
      default_src: %w('self' https:),
      font_src: %w('self' https: data:),
      img_src: %w('self' https: data:),
      object_src: %w('none'),
      script_src: %w(https:),
      style_src: %w('self' https: 'unsafe-inline')
    }

    def report_only?
      false
    end

    def make_report_only
      ContentSecurityPolicyReportOnlyConfig.new(self.to_h)
    end
  end

  class ContentSecurityPolicyReportOnlyConfig < ContentSecurityPolicyConfig
    HEADER_NAME = "content-security-policy-report-only".freeze

    def report_only?
      true
    end

    def make_report_only
      self
    end
  end

  # Public: pairs one enforced Content-Security-Policy with its optional
  # report-only counterpart. A pair represents a single, independent policy:
  # the browser enforces the policy under the
  # `content-security-policy` header and (when present) only reports violations
  # of the policy under `content-security-policy-report-only`.
  #
  # Multiple entries are emitted as separate header values rather than having
  # their source lists concatenated. Browsers intersect every delivered CSP, so
  # keeping policies independent can only tighten, never widen, the effective
  # restriction.
  class CspPolicyEntry
    ENFORCED_HEADER_NAME = ContentSecurityPolicyConfig::HEADER_NAME
    REPORT_ONLY_HEADER_NAME = ContentSecurityPolicyReportOnlyConfig::HEADER_NAME

    attr_reader :enforced, :report_only

    def initialize(enforced, report_only = OPT_OUT)
      self.enforced = enforced
      self.report_only = report_only
    end

    def report_only=(config)
      @report_only =
        case config
        when OPT_OUT, nil
          OPT_OUT
        when ContentSecurityPolicyReportOnlyConfig
          config
        when ContentSecurityPolicyConfig
          config.make_report_only
        when Hash
          ContentSecurityPolicyReportOnlyConfig.new(config)
        else
          raise ArgumentError, "Must provide a CSP config, a config hash, or OPT_OUT"
        end
    end

    def enforced=(config)
      @enforced =
        case config
        when OPT_OUT
          OPT_OUT
        when ContentSecurityPolicyConfig
          config
        when Hash
          ContentSecurityPolicyConfig.new(config)
        else
          raise ArgumentError, "Must provide either an existing CSP config or a CSP config hash"
        end
    end

    def opt_out?
      enforced.opt_out? && report_only.opt_out?
    end

    def to_h
      { enforced: enforced, report_only: report_only }
    end

    def dup
      self.class.new(
        enforced.opt_out? ? OPT_OUT : enforced.dup,
        report_only.opt_out? ? OPT_OUT : report_only.dup
      )
    end

    def ==(other)
      other.is_a?(CspPolicyEntry) &&
        enforced == other.enforced &&
        report_only == other.report_only
    end

    # Returns [header_name, value] for the requested mode, or nil when opted out.
    def header(mode)
      config = mode == :report_only ? report_only : enforced
      return if config.nil? || config == OPT_OUT

      header = ContentSecurityPolicy.new(config)
      [header.name, header.value]
    end
  end
end

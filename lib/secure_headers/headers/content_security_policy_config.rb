# frozen_string_literal: true
module SecureHeaders
  module DynamicConfig
    def initialize(hash)
      @config = {}
      @header_cache = nil
      @mutation_listeners = []

      from_hash(hash)
    end

    def initialize_copy(hash)
      @config = hash.to_h
      @header_cache = nil
      @mutation_listeners = []
    end

    # Register a block invoked whenever this config is mutated in place. Used
    # by the owning Configuration to invalidate its memoized header hash when
    # callers modify a CSP directly (e.g. config.csp.merge!(...)).
    def on_mutation(&block)
      @mutation_listeners << block
    end

    def clear_header_cache!
      @header_cache = nil unless frozen?
    end

    # Memoize the rendered header value per config object. Any mutation goes
    # through update_directive/merge!/append, which clears the cache, so the
    # rendered header always matches the current directives. Frozen registered
    # configs cannot store the memo, so they render directly.
    def cached_header_value
      return yield if frozen?
      @header_cache ||= yield
    end

    def update_directive(directive, value)
      clear_header_cache!
      notify_mutation!
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
      clear_header_cache!
      notify_mutation!
      from_hash(new_hash)
    end

    def append(new_hash)
      clear_header_cache!
      notify_mutation!
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

    # Freeze the internal directive store in addition to the object itself so
    # that a registered CSP cannot be mutated through its nested arrays.
    def freeze_registered_config!
      Ownership.deep_freeze(@config)
      freeze
    end

    # A CSP is only fully immutable when both the wrapper and its internal
    # directive store (including source-list arrays) are frozen.
    def deep_frozen?
      frozen? && Ownership.deep_frozen?(@config)
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

    def notify_mutation!
      @mutation_listeners.each(&:call)
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
end

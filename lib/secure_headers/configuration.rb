# frozen_string_literal: true
require "yaml"

module SecureHeaders
  class Configuration
    DEFAULT_CONFIG = :default
    NOOP_OVERRIDE = "secure_headers_noop_override"
    class AlreadyConfiguredError < StandardError; end
    class NotYetConfiguredError < StandardError; end
    class IllegalPolicyModificationError < StandardError; end
    class << self
      # Public: Disable secure_headers entirely. When disabled, no headers will be set.
      #
      # Note: This must be called before Configuration.default. Calling it after
      # Configuration.default has been set will raise an AlreadyConfiguredError.
      #
      # Returns nothing
      # Raises AlreadyConfiguredError if Configuration.default has already been called
      def disable!
        if defined?(@default_config)
          raise AlreadyConfiguredError, "Configuration already set, cannot disable"
        end

        @disabled = true
        @noop_config = create_noop_config.freeze

        # Ensure the built-in NOOP override is available even if `default` has never been called
        @overrides ||= {}
        unless @overrides.key?(NOOP_OVERRIDE)
          @overrides[NOOP_OVERRIDE] = method(:create_noop_config_block)
        end
      end

      # Public: Check if secure_headers is disabled
      #
      # Returns boolean
      def disabled?
        defined?(@disabled) && @disabled
      end

      # Public: Set the global default configuration.
      #
      # Optionally supply a block to override the defaults set by this library.
      #
      # Returns the newly created config.
      # Raises AlreadyConfiguredError if Configuration.disable! has already been called
      def default(&block)
        if disabled?
          raise AlreadyConfiguredError, "Configuration has been disabled, cannot set default"
        end

        if defined?(@default_config)
          raise AlreadyConfiguredError, "Policy already configured"
        end

        # Define a built-in override that clears all configuration options and
        # results in no security headers being set.
        override(NOOP_OVERRIDE, &method(:create_noop_config_block))

        new_config = new(&block).freeze
        new_config.validate_config!
        @default_config = new_config
      end
      alias_method :configure, :default

      # Public: create a named configuration that overrides the default config.
      #
      # name - use an identifier for the override config.
      # base - override another existing config, or override the default config
      # if no value is supplied.
      #
      # Returns: the newly created config
      def override(name, &block)
        @overrides ||= {}
        raise "Provide a configuration block" unless block_given?
        if named_append_or_override_exists?(name)
          raise AlreadyConfiguredError, "Configuration already exists"
        end
        @overrides[name] = block
      end

      def overrides(name)
        @overrides ||= {}
        @overrides[name]
      end

      def named_appends(name)
        @appends ||= {}
        @appends[name]
      end

      def named_append(name, &block)
        @appends ||= {}
        raise "Provide a configuration block" unless block_given?
        if named_append_or_override_exists?(name)
          raise AlreadyConfiguredError, "Configuration already exists"
        end
        @appends[name] = block
      end

      def dup
        default_config.dup
      end

      private

      def named_append_or_override_exists?(name)
        (defined?(@appends) && @appends.key?(name)) ||
          (defined?(@overrides) && @overrides.key?(name))
      end

      # Public: perform a basic deep dup. The shallow copy provided by dup/clone
      # can lead to modifying parent objects.
      def deep_copy(config)
        return unless config
        result = {}
        config.each_pair do |key, value|
          result[key] =
            case value
            when Array
              value.dup
            else
              value
            end
        end
        result
      end

      # Private: Returns the internal default configuration. This should only
      # ever be called by internal callers (or tests) that know the semantics
      # of ensuring that the default config is never mutated and is dup(ed)
      # before it is used in a request.
      def default_config
        return @noop_config if disabled?
        unless defined?(@default_config)
          raise NotYetConfiguredError, "Default policy not yet configured"
        end
        @default_config
      end

      # Private: convenience method purely DRY things up. The value may not be a
      # hash (e.g. OPT_OUT, nil)
      def deep_copy_if_hash(value)
        if value.is_a?(Hash)
          deep_copy(value)
        else
          value
        end
      end

      # Private: Creates a NOOP configuration that opts out of all headers
      def create_noop_config
        new(&method(:create_noop_config_block))
      end

      # Private: Block for creating NOOP configuration
      # Used by both create_noop_config and the NOOP_OVERRIDE mechanism
      def create_noop_config_block(config)
        CONFIG_ATTRIBUTES.each do |attr|
          config.instance_variable_set("@#{attr}", OPT_OUT)
        end
      end
    end

    CONFIG_ATTRIBUTES_TO_HEADER_CLASSES = {
      hsts: StrictTransportSecurity,
      x_frame_options: XFrameOptions,
      x_content_type_options: XContentTypeOptions,
      x_xss_protection: XXssProtection,
      x_download_options: XDownloadOptions,
      x_permitted_cross_domain_policies: XPermittedCrossDomainPolicies,
      referrer_policy: ReferrerPolicy,
      clear_site_data: ClearSiteData,
      expect_certificate_transparency: ExpectCertificateTransparency,
      csp: ContentSecurityPolicy,
      csp_report_only: ContentSecurityPolicy,
      cookies: Cookie,
      reporting_endpoints: ReportingEndpoints,
    }.freeze

    CONFIG_ATTRIBUTES = CONFIG_ATTRIBUTES_TO_HEADER_CLASSES.keys.freeze

    # The list of attributes that must respond to a `validate_config!` method
    VALIDATABLE_ATTRIBUTES = CONFIG_ATTRIBUTES

    # CSP is produced as potentially multi-valued headers (one value per
    # independent policy) and is handled separately from scalar headers.
    CSP_ATTRIBUTES = [:csp, :csp_report_only].freeze

    # The list of attributes that must respond to a `make_header` method
    HEADERABLE_ATTRIBUTES = (CONFIG_ATTRIBUTES - [:cookies]).freeze

    # Scalar, single-valued headers. The CSP pair is generated on its own so
    # that multiple independent policies survive as separate header values.
    SCALAR_HEADERABLE_ATTRIBUTES = (HEADERABLE_ATTRIBUTES - CSP_ATTRIBUTES).freeze

    # The primary policy always answers to this name. The legacy single-policy
    # `csp` / `csp_report_only` configuration maps onto this entry.
    DEFAULT_CSP_POLICY_NAME = :default
    # Built-in selectors that describe which mode of a policy to modify. Any
    # other symbol is interpreted as the name of an additional CSP policy.
    CSP_MODE_TARGETS = [:both, :enforced, :report_only].freeze

    attr_writer(*(CONFIG_ATTRIBUTES_TO_HEADER_CLASSES.reject { |key| [:csp, :csp_report_only].include?(key) }.keys))

    attr_reader(*(CONFIG_ATTRIBUTES_TO_HEADER_CLASSES.keys))

    @script_hashes = nil
    @style_hashes = nil

    HASH_CONFIG_FILE = ENV["secure_headers_generated_hashes_file"] || "config/secure_headers_generated_hashes.yml"
    if File.exist?(HASH_CONFIG_FILE)
      config = YAML.safe_load(File.open(HASH_CONFIG_FILE))
      @script_hashes = config["scripts"]
      @style_hashes = config["styles"]
    end

    def initialize(&block)
      @cookies = self.class.send(:deep_copy_if_hash, Cookie::COOKIE_DEFAULTS)
      @clear_site_data = nil
      @csp = nil
      @csp_report_only = nil
      @csp_policies = {}
      @hsts = nil
      @x_content_type_options = nil
      @x_download_options = nil
      @x_frame_options = nil
      @x_permitted_cross_domain_policies = nil
      @x_xss_protection = nil
      @expect_certificate_transparency = nil
      @reporting_endpoints = nil

      self.referrer_policy = OPT_OUT
      self.csp = ContentSecurityPolicyConfig.new(ContentSecurityPolicyConfig::DEFAULT)
      self.csp_report_only = OPT_OUT

      instance_eval(&block) if block_given?
    end

    # Public: copy everything
    #
    # Returns a deep-dup'd copy of this configuration.
    def dup
      copy = self.class.new
      copy.cookies = self.class.send(:deep_copy_if_hash, @cookies)
      copy.csp = @csp.dup if @csp
      copy.csp_report_only = @csp_report_only.dup if @csp_report_only
      copy.instance_variable_set(:@csp_policies, duplicate_csp_policies)
      copy.x_content_type_options = @x_content_type_options
      copy.hsts = @hsts
      copy.x_frame_options = @x_frame_options
      copy.x_xss_protection = @x_xss_protection
      copy.x_download_options = @x_download_options
      copy.x_permitted_cross_domain_policies = @x_permitted_cross_domain_policies
      copy.clear_site_data = @clear_site_data
      copy.expect_certificate_transparency = @expect_certificate_transparency
      copy.referrer_policy = @referrer_policy
      copy.reporting_endpoints = self.class.send(:deep_copy_if_hash, @reporting_endpoints)
      copy
    end

    # Public: register an additional, independently enforced CSP.
    #
    # name - a symbol uniquely identifying this policy. `:default`, `:both`,
    #        `:enforced` and `:report_only` are reserved.
    # block - receives a CspPolicyEntry so the enforced and report-only
    #         configs can be configured together.
    #
    # Returns the configured CspPolicyEntry.
    def csp_policy(name, &block)
      name = name.to_sym
      if name == DEFAULT_CSP_POLICY_NAME || CSP_MODE_TARGETS.include?(name)
        raise ArgumentError, ":#{name} is reserved and cannot name an additional CSP policy"
      end

      default_config = ContentSecurityPolicyConfig.new(ContentSecurityPolicyConfig::DEFAULT)
      entry = (@csp_policies[name] ||= CspPolicyEntry.new(default_config))
      block.call(entry) if block_given?
      entry
    end

    def csp_policies
      @csp_policies.dup
    end

    def csp_policy_named(name)
      @csp_policies[name.to_sym]
    end

    # Public: every independent CSP entry, starting with the primary policy and
    # followed by the additionally registered policies in registration order.
    def csp_entries
      entries = [[DEFAULT_CSP_POLICY_NAME, primary_csp_entry]]
      @csp_policies.each { |name, entry| entries << [name, entry] }
      entries
    end

    # Public: the concrete CSP config objects for one mode across every
    # independent policy, in the same order the headers are emitted.
    def all_csp_configs(mode)
      csp_entries.map { |_name, entry| mode == :report_only ? entry.report_only : entry.enforced }
    end

    # Public: Apply a named override to the current config
    #
    # Returns self
    def override(name = nil, &block)
      if override = self.class.overrides(name)
        instance_eval(&override)
      else
        raise ArgumentError.new("no override by the name of #{name} has been configured")
      end
      self
    end

    def generate_headers
      headers = {}
      SCALAR_HEADERABLE_ATTRIBUTES.each do |attr|
        klass = CONFIG_ATTRIBUTES_TO_HEADER_CLASSES[attr]
        header_name, value = klass.make_header(instance_variable_get("@#{attr}"))
        if header_name && value
          headers[header_name] = value
        end
      end
      append_csp_headers(headers)
      headers
    end

    # Builds the CSP headers for every independent policy. Each policy keeps its
    # own enforced and report-only value. When more than one value targets the
    # same header name, the values are returned as an array (Rack's multi-value
    # representation) instead of being joined into one widened policy.
    #
    # Returns a hash whose CSP values are either a String (single policy) or an
    # Array of Strings (multiple independent policies).
    def csp_header_hash
      headers = Hash.new { |hash, key| hash[key] = [] }
      csp_entries.each do |_name, entry|
        [[:enforced, CspPolicyEntry::ENFORCED_HEADER_NAME],
         [:report_only, CspPolicyEntry::REPORT_ONLY_HEADER_NAME]].each do |mode, header_name|
          pair = entry.header(mode)
          headers[header_name] << pair.last if pair
        end
      end

      headers.each_with_object({}) do |(header_name, values), result|
        result[header_name] = values.length == 1 ? values.first : values
      end
    end

    def opt_out(header)
      send("#{header}=", OPT_OUT)
    end

    def update_x_frame_options(value)
      @x_frame_options = value
    end

    # Public: validates all configurations values.
    #
    # Raises various configuration errors if any invalid config is detected.
    #
    # Returns nothing
    def validate_config!
      VALIDATABLE_ATTRIBUTES.each do |attr|
        klass = CONFIG_ATTRIBUTES_TO_HEADER_CLASSES[attr]
        klass.validate_config!(instance_variable_get("@#{attr}"))
      end

      @csp_policies.each do |name, entry|
        validate_csp_entry!(name, entry)
      end
    end

    def secure_cookies=(secure_cookies)
      raise ArgumentError, "#{Kernel.caller.first}: `#secure_cookies=` is no longer supported. Please use `#cookies=` to configure secure cookies instead."
    end

    def csp=(new_csp)
      case new_csp
      when OPT_OUT
        @csp = new_csp
      when ContentSecurityPolicyConfig
        @csp = new_csp
      when Hash
        @csp = ContentSecurityPolicyConfig.new(new_csp)
      else
        raise ArgumentError, "Must provide either an existing CSP config or a CSP config hash"
      end
    end

    # Configures the content-security-policy-report-only header. `new_csp` cannot
    # contain `report_only: false` or an error will be raised.
    #
    # NOTE: if csp has not been configured/has the default value when
    # configuring csp_report_only, the code will assume you mean to only use
    # report-only mode and you will be opted-out of enforce mode.
    def csp_report_only=(new_csp)
      case new_csp
      when OPT_OUT
        @csp_report_only = new_csp
      when ContentSecurityPolicyReportOnlyConfig
        @csp_report_only = new_csp.dup
      when ContentSecurityPolicyConfig
        @csp_report_only = new_csp.make_report_only
      when Hash
        @csp_report_only = ContentSecurityPolicyReportOnlyConfig.new(new_csp)
      else
        raise ArgumentError, "Must provide either an existing CSP config or a CSP config hash"
      end
    end

    private

    # The primary policy entry backed by the legacy `csp` / `csp_report_only`
    # attributes so that the single-policy interface stays unchanged.
    def primary_csp_entry
      CspPolicyEntry.new(
        @csp.respond_to?(:opt_out?) && @csp.opt_out? ? OPT_OUT : @csp,
        @csp_report_only.respond_to?(:opt_out?) && @csp_report_only.opt_out? ? OPT_OUT : @csp_report_only
      )
    end

    def duplicate_csp_policies
      @csp_policies.each_with_object({}) do |(name, entry), result|
        result[name] = entry.dup
      end
    end

    def validate_csp_entry!(name, entry)
      unless entry.enforced.opt_out?
        ContentSecurityPolicy.validate_config!(entry.enforced)
      end
      unless entry.report_only.opt_out?
        ContentSecurityPolicy.validate_config!(entry.report_only)
      end
    rescue ContentSecurityPolicyConfigError => error
      raise ContentSecurityPolicyConfigError, "CSP policy :#{name} is invalid: #{error.message}"
    end

    # Merges the (potentially multi-valued) CSP headers into the scalar header
    # hash produced for the other headers.
    def append_csp_headers(headers)
      csp_header_hash.each do |header_name, value|
        headers[header_name] = value
      end
    end
  end
end

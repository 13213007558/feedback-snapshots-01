# frozen_string_literal: true
require "secure_headers/hash_helper"
require "secure_headers/headers/cookie"
require "secure_headers/headers/content_security_policy"
require "secure_headers/headers/x_frame_options"
require "secure_headers/headers/strict_transport_security"
require "secure_headers/headers/x_xss_protection"
require "secure_headers/headers/x_content_type_options"
require "secure_headers/headers/x_download_options"
require "secure_headers/headers/x_permitted_cross_domain_policies"
require "secure_headers/headers/referrer_policy"
require "secure_headers/headers/clear_site_data"
require "secure_headers/headers/expect_certificate_transparency"
require "secure_headers/headers/reporting_endpoints"
require "secure_headers/middleware"
require "secure_headers/railtie"
require "secure_headers/view_helper"
require "singleton"
require "securerandom"
require "secure_headers/configuration"

# Provide SecureHeaders::OPT_OUT as a config value to disable a given header
module SecureHeaders
  class NoOpHeaderConfig
    include Singleton

    def boom(*args)
      raise "Illegal State: attempted to modify NoOpHeaderConfig. Create a new config instead."
    end

    def to_h
      {}
    end

    def dup
      self.class.instance
    end

    def opt_out?
      true
    end

    alias_method :[], :boom
    alias_method :[]=, :boom
    alias_method :keys, :boom
  end

  OPT_OUT = NoOpHeaderConfig.instance
  SECURE_HEADERS_CONFIG = "secure_headers_request_config".freeze
  NONCE_KEY = "secure_headers_content_security_policy_nonce".freeze
  HTTPS = "https".freeze
  CSP = ContentSecurityPolicy

  class << self
    # Public: override a given set of directives for the current request. If a
    # value already exists for a given directive, it will be overridden.
    #
    # If CSP was previously OPT_OUT, a new blank policy is used.
    #
    # additions - a hash containing directives. e.g.
    #    script_src: %w(another-host.com)
    # target - which policy/mode to modify. Accepts:
    #    :both, :enforced, :report_only (applied to the primary policy), or the
    #    name of an additional policy registered with `config.csp_policy`. A
    #    two-element array [policy_name, mode] targets one mode of a named
    #    policy. Defaults to :both when both modes of a policy are configured.
    def override_content_security_policy_directives(request, additions, target = nil)
      config, policy_name, mode = resolve_csp_target(request, target)

      each_targeted_csp(config, policy_name, mode) do |csp|
        csp = blank_csp_for(csp) if csp.opt_out?
        csp.merge!(additions)
        csp
      end

      override_secure_headers_request_config(request, config)
    end

    # Public: appends source values to the current configuration. If no value
    # is set for a given directive, the value will be merged with the default-src
    # value. If a value exists for the given directive, the values will be combined.
    #
    # additions - a hash containing directives. e.g.
    #    script_src: %w(another-host.com)
    # target - see #override_content_security_policy_directives. Appending never
    # creates a new policy: an opted-out target is left untouched so that calls
    # cannot silently introduce additional enforced constraints.
    def append_content_security_policy_directives(request, additions, target = nil)
      config, policy_name, mode = resolve_csp_target(request, target)

      each_targeted_csp(config, policy_name, mode) do |csp|
        csp.append(additions) unless csp.opt_out?
        csp
      end

      override_secure_headers_request_config(request, config)
    end

    def use_content_security_policy_named_append(request, name, target = nil)
      additions = SecureHeaders::Configuration.named_appends(name).call(request)
      append_content_security_policy_directives(request, additions, target)
    end

    # Public: override X-Frame-Options settings for this request.
    #
    # value - deny, sameorigin, or allowall
    #
    # Returns the current config
    def override_x_frame_options(request, value)
      config = config_for(request)
      config.update_x_frame_options(value)
      override_secure_headers_request_config(request, config)
    end

    # Public: opts out of setting a given header by creating a temporary config
    # and setting the given headers config to OPT_OUT.
    def opt_out_of_header(request, header_key)
      config = config_for(request)
      config.opt_out(header_key)
      override_secure_headers_request_config(request, config)
    end

    # Public: opts out of setting all headers by telling secure_headers to use
    # the NOOP configuration.
    def opt_out_of_all_protection(request)
      use_secure_headers_override(request, Configuration::NOOP_OVERRIDE)
    end

    # Public: Builds the hash of headers that should be applied base on the
    # request.
    #
    # StrictTransportSecurity is not applied to http requests.
    # upgrade_insecure_requests is not applied to http requests.
    # See #config_for to determine which config is used for a given request.
    #
    # Returns a hash of header names => header values. The value
    # returned is meant to be merged into the header value from `@app.call(env)`
    # in Rack middleware.
    def header_hash_for(request)
      prevent_dup = true
      config = config_for(request, prevent_dup)
      config.validate_config!
      headers = config.generate_headers

      if request.scheme != HTTPS
        headers.delete(StrictTransportSecurity::HEADER_NAME)

        # Remove upgrade_insecure_requests from CSP headers for HTTP requests
        # as it doesn't make sense to upgrade requests when the page itself is served over HTTP
        remove_upgrade_insecure_requests_from_csp!(headers, config.all_csp_configs(:enforced))
        remove_upgrade_insecure_requests_from_csp!(headers, config.all_csp_configs(:report_only))
      end
      headers
    end

    # Public: specify which named override will be used for this request.
    # Raises an argument error if no named override exists.
    #
    # name - the name of the previously configured override.
    def use_secure_headers_override(request, name)
      config = config_for(request)
      config.override(name)
      override_secure_headers_request_config(request, config)
    end

    # Public: gets or creates a nonce for CSP.
    #
    # The nonce will be added to script_src of the targeted policy only. Pass a
    # policy name (or [name, mode]) to scope it to an additional policy; when
    # omitted it applies to the primary policy exactly as before.
    #
    # Returns the nonce
    def content_security_policy_script_nonce(request, target = nil)
      content_security_policy_nonce(request, ContentSecurityPolicy::SCRIPT_SRC, target)
    end

    # Public: gets or creates a nonce for CSP.
    #
    # The nonce will be added to style_src of the targeted policy only.
    #
    # Returns the nonce
    def content_security_policy_style_nonce(request, target = nil)
      content_security_policy_nonce(request, ContentSecurityPolicy::STYLE_SRC, target)
    end

    # Public: Retrieves the config for a given header type:
    #
    # Checks to see if there is an override for this request, then
    # Checks to see if a named override is used for this request, then
    # Falls back to the global config
    def config_for(request, prevent_dup = false)
      config = request.env[SECURE_HEADERS_CONFIG] ||
        Configuration.send(:default_config)


      # Global configs are frozen, per-request configs are not. When we're not
      # making modifications to the config, prevent_dup ensures we don't dup
      # the object unnecessarily. It's not necessarily frozen to begin with.
      if config.frozen? && !prevent_dup
        config.dup
      else
        config
      end
    end

    private
    TARGETS = [:both, :enforced, :report_only]
    def raise_on_unknown_target(target)
      unless TARGETS.include?(target)
        raise "Unrecognized target: #{target}. Must be [:both, :enforced, :report_only]"
      end
    end

    # Resolves a public target argument into [config, policy_name, mode].
    #
    # policy_name - :default for the primary policy, or the name of a policy
    #               registered through Configuration#csp_policy.
    # mode - :both, :enforced, or :report_only.
    def resolve_csp_target(request, target)
      config = config_for(request)

      case target
      when nil
        [config, Configuration::DEFAULT_CSP_POLICY_NAME, guess_target(config)]
      when Array
        policy_name, mode = target
        mode ||= :enforced
        validate_named_policy!(config, policy_name)
        raise_on_unknown_target(mode)
        [config, policy_name.to_sym, mode]
      when *Configuration::CSP_MODE_TARGETS
        [config, Configuration::DEFAULT_CSP_POLICY_NAME, target]
      when Symbol, String
        policy_name = target.to_sym
        validate_named_policy!(config, policy_name)
        # A bare policy name addresses that policy's enforced constraints; use
        # [:name, :report_only] or [:name, :both] to touch its other modes.
        [config, policy_name, :enforced]
      else
        raise ArgumentError, "Unrecognized CSP target: #{target.inspect}"
      end
    end

    def validate_named_policy!(config, name)
      return if name.to_sym == Configuration::DEFAULT_CSP_POLICY_NAME
      unless config.csp_policy_named(name)
        raise ArgumentError, "no additional CSP policy named :#{name} has been configured"
      end
    end

    # Builds a blank config of the same kind as `csp`, preserving whether the
    # target is enforced or report-only.
    def blank_csp_for(csp)
      if csp.respond_to?(:report_only?) && csp.report_only?
        ContentSecurityPolicyReportOnlyConfig.new({})
      else
        ContentSecurityPolicyConfig.new({})
      end
    end

    # Yields each concrete CSP config object selected by the resolved target.
    # The block may return the (possibly new) config object; for the primary
    # policy the result is written back through its setter so OPT_OUT handling
    # keeps working exactly as the single-policy interface expects.
    def each_targeted_csp(config, policy_name, mode)
      if policy_name == Configuration::DEFAULT_CSP_POLICY_NAME
        if [:both, :enforced].include?(mode)
          config.csp = yield(config.csp)
        end
        if [:both, :report_only].include?(mode)
          config.csp_report_only = yield(config.csp_report_only)
        end
      else
        entry = config.csp_policy_named(policy_name)
        if [:both, :enforced].include?(mode)
          entry.enforced = yield(entry.enforced)
        end
        if [:both, :report_only].include?(mode)
          entry.report_only = yield(entry.report_only)
        end
      end
    end

    def guess_target(config)
      if !config.csp.opt_out? && !config.csp_report_only.opt_out?
        :both
      elsif !config.csp.opt_out?
        :enforced
      elsif !config.csp_report_only.opt_out?
        :report_only
      else
        :both
      end
    end

    # Private: gets or creates a nonce for CSP.
    #
    # The nonce is added only to the policy selected by `target`. It is never
    # copied into another independent policy, so requesting a nonce for one
    # policy cannot relax the constraints enforced by the other policy.
    #
    # Returns the nonce
    def content_security_policy_nonce(request, script_or_style, target = nil)
      nonce_key = script_or_style == ContentSecurityPolicy::SCRIPT_SRC ? :script_nonce : :style_nonce
      request.env[NONCE_KEY] ||= SecureRandom.base64(32).chomp
      append_content_security_policy_directives(request, { nonce_key => request.env[NONCE_KEY] }, target)
      request.env[NONCE_KEY]
    end

    # Private: convenience method for specifying which configuration object should
    # be used for this request.
    #
    # Returns the config.
    def override_secure_headers_request_config(request, config)
      request.env[SECURE_HEADERS_CONFIG] = config
    end

    # Private: removes upgrade_insecure_requests directive from a CSP config
    # if it's present, and updates the headers hash with the modified CSP.
    #
    # Handles both single-valued (String) and multi-valued (Array) CSP headers,
    # rewriting every independent policy without merging them together.
    #
    # headers - the headers hash to update
    # csp_configs - the CSP configs backing the header
    #
    # Returns nothing (modifies headers in place)
    def remove_upgrade_insecure_requests_from_csp!(headers, csp_configs)
      header_name = nil
      values = Array(csp_configs).map do |csp_config|
        next if csp_config.opt_out?
        next unless csp_config.directive_value(ContentSecurityPolicy::UPGRADE_INSECURE_REQUESTS)

        modified_config = csp_config.dup
        modified_config.update_directive(ContentSecurityPolicy::UPGRADE_INSECURE_REQUESTS, false)
        name, value = ContentSecurityPolicy.make_header(modified_config)
        header_name = name
        value
      end.compact

      return if values.empty?

      headers[header_name] = values.length == 1 ? values.first : values
    end
  end

  # These methods are mixed into controllers and delegate to the class method
  # with the same name.
  def use_secure_headers_override(name)
    SecureHeaders.use_secure_headers_override(request, name)
  end

  def content_security_policy_script_nonce
    SecureHeaders.content_security_policy_script_nonce(request)
  end

  def content_security_policy_style_nonce
    SecureHeaders.content_security_policy_style_nonce(request)
  end

  def opt_out_of_header(header_key)
    SecureHeaders.opt_out_of_header(request, header_key)
  end

  def append_content_security_policy_directives(additions)
    SecureHeaders.append_content_security_policy_directives(request, additions)
  end

  def override_content_security_policy_directives(additions)
    SecureHeaders.override_content_security_policy_directives(request, additions)
  end

  def override_x_frame_options(value)
    SecureHeaders.override_x_frame_options(request, value)
  end

  def use_content_security_policy_named_append(name)
    SecureHeaders.use_content_security_policy_named_append(request, name)
  end
end

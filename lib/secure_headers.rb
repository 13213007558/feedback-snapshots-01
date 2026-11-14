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
  SECURE_HEADERS_CSP_VIOLATIONS = "secure_headers_csp_validation_violations".freeze
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
    def override_content_security_policy_directives(request, additions, target = nil, options = {})
      config, target = config_and_target(request, target)

      candidates = []
      candidates << [additions, CspValidation::ENFORCED_POLICY] if [:both, :enforced].include?(target)
      candidates << [additions, CspValidation::REPORT_ONLY_POLICY] if [:both, :report_only].include?(target)
      preflight_csp_changes!(request, candidates, :request_override, options[:validation_mode])

      if [:both, :enforced].include?(target)
        if config.csp.opt_out?
          config.csp = ContentSecurityPolicyConfig.new({})
        end

        config.csp.merge!(additions)
      end

      if [:both, :report_only].include?(target)
        if config.csp_report_only.opt_out?
          config.csp_report_only = ContentSecurityPolicyReportOnlyConfig.new({})
        end

        config.csp_report_only.merge!(additions)
      end

      override_secure_headers_request_config(request, config)
    end

    # Public: appends source values to the current configuration. If no value
    # is set for a given directive, the value will be merged with the default-src
    # value. If a value exists for the given directive, the values will be combined.
    #
    # additions - a hash containing directives. e.g.
    #    script_src: %w(another-host.com)
    def append_content_security_policy_directives(request, additions, target = nil, options = {})
      config, target = config_and_target(request, target)

      candidates = []
      if [:both, :enforced].include?(target) && !config.csp.opt_out?
        candidates << [combined_csp_hash(config.csp, additions), CspValidation::ENFORCED_POLICY]
      end
      if [:both, :report_only].include?(target) && !config.csp_report_only.opt_out?
        candidates << [combined_csp_hash(config.csp_report_only, additions), CspValidation::REPORT_ONLY_POLICY]
      end
      preflight_csp_changes!(request, candidates, :request_append, options[:validation_mode])

      if [:both, :enforced].include?(target) && !config.csp.opt_out?
        config.csp.append(additions)
      end

      if [:both, :report_only].include?(target) && !config.csp_report_only.opt_out?
        config.csp_report_only.append(additions)
      end

      override_secure_headers_request_config(request, config)
    end

    def use_content_security_policy_named_append(request, name, options = {})
      additions = SecureHeaders::Configuration.named_appends(name).call(request)
      append_content_security_policy_directives(request, additions, nil, options)
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
      record_csp_violations!(request, config)
      headers = config.generate_headers

      if request.scheme != HTTPS
        headers.delete(StrictTransportSecurity::HEADER_NAME)

        # Remove upgrade_insecure_requests from CSP headers for HTTP requests
        # as it doesn't make sense to upgrade requests when the page itself is served over HTTP
        remove_upgrade_insecure_requests_from_csp!(headers, config.csp)
        remove_upgrade_insecure_requests_from_csp!(headers, config.csp_report_only)
      end
      headers
    end

    # Public: specify which named override will be used for this request.
    # Raises an argument error if no named override exists. In strict CSP
    # validation mode, raises CspValidationError before the override is applied
    # when it would inject directives, leaving the default policy untouched.
    #
    # name - the name of the previously configured override.
    def use_secure_headers_override(request, name, options = {})
      config = config_for(request)
      if CspValidation.resolve_mode(options[:validation_mode]) == CspValidation::STRICT_MODE
        candidate = config.dup
        candidate.override(name)
        violations = candidate.csp_violations(source: :named_override)
        raise CspValidation.strict_violation_error(violations) unless violations.empty?
      end
      config.override(name)
      override_secure_headers_request_config(request, config)
    end

    # Public: gets or creates a nonce for CSP.
    #
    # The nonce will be added to script_src
    #
    # Returns the nonce
    def content_security_policy_script_nonce(request)
      content_security_policy_nonce(request, ContentSecurityPolicy::SCRIPT_SRC)
    end

    # Public: gets or creates a nonce for CSP.
    #
    # The nonce will be added to style_src
    #
    # Returns the nonce
    def content_security_policy_style_nonce(request)
      content_security_policy_nonce(request, ContentSecurityPolicy::STYLE_SRC)
    end

    # Public: returns the structured, redacted CSP directive-injection
    # violations observed for this request across the enforced and report-only
    # policies. The order is deterministic so identical policies always produce
    # identical results.
    def content_security_policy_violations(request)
      request.env[SECURE_HEADERS_CSP_VIOLATIONS] || []
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

    def config_and_target(request, target)
      config = config_for(request)
      target ||= guess_target(config)
      raise_on_unknown_target(target)
      [config, target]
    end

    # Private: validates every policy a pending mutation touches before any of
    # them is changed. In :strict mode all violations are collected up front
    # (so a :both change reports both enforced and report-only locations) and
    # a single CspValidationError is raised, leaving the existing policies
    # completely intact. In :observe mode the redacted violations are stashed
    # on the request and the legacy scrub-and-warn renderer keeps producing the
    # same output as before.
    def preflight_csp_changes!(request, candidates, source, explicit_mode)
      mode = CspValidation.resolve_mode(explicit_mode)
      violations = candidates.flat_map do |candidate_hash, policy_kind|
        CspValidation.violations_for(candidate_hash, policy_kind: policy_kind, source: source)
      end
      return if violations.empty?

      if mode == CspValidation::STRICT_MODE
        raise CspValidation.strict_violation_error(violations)
      end

      stash_csp_violations!(request, violations)
    end

    # Private: mirrors PolicyManagement.combine_policies without mutating either
    # input, so an append can be validated against its resulting policy before
    # any value is written.
    def combined_csp_hash(current_config, additions)
      ContentSecurityPolicy.combine_policies(current_config.to_h, additions)
    end

    # Private: records observed violations at header-generation time, covering
    # policies that were invalid before the request started (default config or
    # a named override). Strict mode never reaches here; it raises on build.
    def record_csp_violations!(request, config)
      return if CspValidation.resolve_mode(nil) == CspValidation::STRICT_MODE
      violations = config.csp_violations(source: :header_generation)
      stash_csp_violations!(request, violations) unless violations.empty?
    end

    def stash_csp_violations!(request, violations)
      existing = request.env[SECURE_HEADERS_CSP_VIOLATIONS] || []
      # A physical location is identified by policy, directive, token and
      # offsets - not by :source - so the same offending value seen both when a
      # request mutates the policy and again when the header is rendered is
      # reported exactly once. The first observed source is retained.
      location_key = ->(violation) do
        [
          violation[:policy],
          violation[:directive],
          violation[:token_index],
          violation[:char_offsets],
        ]
      end
      known_locations = existing.map { |violation| location_key.call(violation) }
      combined = existing + violations.reject { |violation| known_locations.include?(location_key.call(violation)) }
      request.env[SECURE_HEADERS_CSP_VIOLATIONS] = combined.uniq.sort_by do |violation|
        [
          CspValidation::POLICY_ORDER.fetch(violation[:policy], 99),
          violation[:source].to_s,
          violation[:directive].to_s,
          violation[:token_index].nil? ? -1 : violation[:token_index],
          violation[:char_offsets].first || 0,
        ]
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
    # Returns the nonce
    def content_security_policy_nonce(request, script_or_style)
      request.env[NONCE_KEY] ||= SecureRandom.base64(32).chomp
      nonce_key = script_or_style == ContentSecurityPolicy::SCRIPT_SRC ? :script_nonce : :style_nonce
      append_content_security_policy_directives(request, nonce_key => request.env[NONCE_KEY])
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
    # headers - the headers hash to update
    # csp_config - the CSP config to check and potentially modify
    #
    # Returns nothing (modifies headers in place)
    def remove_upgrade_insecure_requests_from_csp!(headers, csp_config)
      return if csp_config.opt_out?
      return unless csp_config.directive_value(ContentSecurityPolicy::UPGRADE_INSECURE_REQUESTS)

      modified_config = csp_config.dup
      modified_config.update_directive(ContentSecurityPolicy::UPGRADE_INSECURE_REQUESTS, false)
      header_name, value = ContentSecurityPolicy.make_header(modified_config)
      headers[header_name] = value if header_name && value
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

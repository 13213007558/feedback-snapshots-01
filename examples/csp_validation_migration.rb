# frozen_string_literal: true

# End-to-end walkthrough for migrating CSP directive-injection handling from
# the legacy "replace with a space + warn" behavior to strict rejection.
#
# Run it with:
#
#   bundle exec ruby examples/csp_validation_migration.rb
#
# The script uses its own in-memory request objects (no Rails needed) and
# prints the observable result of every phase so it can be copy/pasted into an
# incident runbook.
require "uri"
require "rack"
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "secure_headers"

module CspValidationMigrationExample
  module_function

  def fresh_request
    Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
  end

  def reset!
    SecureHeaders::Configuration.csp_validation_mode = :observe
    SecureHeaders::Configuration.remove_instance_variable(:@default_config) if
      SecureHeaders::Configuration.instance_variable_defined?(:@default_config)
    SecureHeaders::Configuration.remove_instance_variable(:@overrides) if
      SecureHeaders::Configuration.instance_variable_defined?(:@overrides)
    SecureHeaders::Configuration.remove_instance_variable(:@appends) if
      SecureHeaders::Configuration.instance_variable_defined?(:@appends)
  end

  def banner(title)
    puts "\n" + ("=" * 72)
    puts title
    puts ("=" * 72)
  end

  # A production-shaped policy: one directive is fed a value that contains an
  # injection byte (";"). The value also contains a nonce and an absolute
  # tenant URL, both of which must stay out of the reported data.
  CLEAN_DEFAULT = {
    default_src: %w('self'),
    script_src: %w('self'),
    style_src: %w('self'),
  }.freeze

  INJECTED_VALUE = "https://tenant-42.example.com/assets/app.js; script-src 'unsafe-inline' *".freeze

  NONCE_VALUE = "rotation-secret-1234567890".freeze

  # Phase 1 ---------------------------------------------------------------
  def observe_phase
    banner "PHASE 1 - OBSERVE (default). Existing output is unchanged."
    reset!
    SecureHeaders::Configuration.default do |config|
      config.csp = CLEAN_DEFAULT.dup
    end

    request = fresh_request
    SecureHeaders.append_content_security_policy_directives(
      request,
      { script_src: [INJECTED_VALUE], style_src: ["'nonce-#{NONCE_VALUE}'\nevil"] }
    )

    headers = SecureHeaders.header_hash_for(request)
    puts "Header still rendered with the legacy space replacement:"
    puts "  #{headers['content-security-policy']}"

    puts "\nStructured violations (nonce and tenant host are redacted):"
    SecureHeaders.content_security_policy_violations(request).each do |violation|
      puts "  - policy=#{violation[:policy]} directive=#{violation[:directive]} " \
           "token_index=#{violation[:token_index].inspect} " \
           "offsets=#{violation[:char_offsets].inspect} " \
           "bytes=#{violation[:offending_bytes].inspect}"
      puts "    redacted_value=#{violation[:redacted_value].inspect}"
    end
  end

  # Phase 2 ---------------------------------------------------------------
  def remediate_phase
    banner "PHASE 2 - REMEDIATE. Remove the injection bytes at the caller."
    reset!
    SecureHeaders::Configuration.default do |config|
      config.csp = CLEAN_DEFAULT.dup
    end

    # The fix lives at the source of the value: split on the injection bytes,
    # keep the legitimate source expression the caller actually intended, and
    # drop the smuggled directive fragment instead of letting it through.
    safe_sources = INJECTED_VALUE.split(/[\n\r;]/).map(&:strip).reject(&:empty?)
    intended_source = safe_sources.first
    smuggled_fragment = safe_sources.last

    request = fresh_request
    SecureHeaders.append_content_security_policy_directives(request, script_src: [intended_source])
    SecureHeaders.header_hash_for(request)

    puts "Discarded smuggled fragment: #{smuggled_fragment.inspect}"
    puts "Kept intended source:        #{intended_source.inspect}"
    puts "Violations after remediation: #{SecureHeaders.content_security_policy_violations(request).inspect}"
    puts "Header:"
    puts "  #{SecureHeaders.header_hash_for(fresh_request)['content-security-policy']}"
  end

  # Phase 3 ---------------------------------------------------------------
  def strict_enable_phase
    banner "PHASE 3 - ENFORCE STRICT. Invalid changes are rejected wholesale."
    reset!
    SecureHeaders::Configuration.csp_validation_mode = :strict
    SecureHeaders::Configuration.default do |config|
      config.csp = CLEAN_DEFAULT.dup
    end

    request = fresh_request
    begin
      SecureHeaders.append_content_security_policy_directives(
        request,
        script_src: [INJECTED_VALUE]
      )
      puts "UNEXPECTED: the invalid append was accepted"
    rescue SecureHeaders::CspValidation::CspValidationError => error
      puts "Rejected with #{error.class}: #{error.message}"
      error.violations.each do |violation|
        puts "  - policy=#{violation[:policy]} directive=#{violation[:directive]} " \
             "offsets=#{violation[:char_offsets].inspect}"
      end
    end

    puts "\nNo per-request config was stored, so the next request gets the clean default:"
    puts "  request override present? #{request.env.key?(SecureHeaders::SECURE_HEADERS_CONFIG)}"
    puts "  #{SecureHeaders.header_hash_for(fresh_request)['content-security-policy']}"
  end

  # Phase 4 ---------------------------------------------------------------
  def rollback_phase
    banner "PHASE 4 - FAILURE ROLLBACK. Flip the global switch back to observe."
    reset!
    SecureHeaders::Configuration.csp_validation_mode = :strict
    SecureHeaders::Configuration.default do |config|
      config.csp = CLEAN_DEFAULT.dup
    end

    request = fresh_request
    begin
      SecureHeaders.append_content_security_policy_directives(
        request,
        script_src: [INJECTED_VALUE]
      )
    rescue SecureHeaders::CspValidation::CspValidationError
      puts "Strict mode blocked the rollout candidate; rolling the switch back."
    end

    # The rollback is a single, reversible configuration assignment; no data
    # migration or code change is required.
    SecureHeaders::Configuration.csp_validation_mode = :observe
    retry_request = fresh_request
    SecureHeaders.append_content_security_policy_directives(
      retry_request,
      script_src: [INJECTED_VALUE]
    )
    puts "Observe mode restored service; header renders again:"
    puts "  #{SecureHeaders.header_hash_for(retry_request)['content-security-policy']}"
    puts "Violations remain available for follow-up:"
    puts "  #{SecureHeaders.content_security_policy_violations(retry_request).map { |v| v[:directive] }.inspect}"
  end

  # Parity check ----------------------------------------------------------
  def parity_phase
    banner "PARITY - unchanged, valid configs generate byte-identical headers."
    reset!
    configs = [
      nil,
      { default_src: %w('self'), script_src: %w('self') },
      { default_src: %w(https:), img_src: %w(https: data: 'self'), report_uri: %w(/csp), sandbox: true },
    ]

    configs.each do |config|
      observe = SecureHeaders::ContentSecurityPolicy.new(config, validation_mode: :observe).value
      strict = SecureHeaders::ContentSecurityPolicy.new(config, validation_mode: :strict).value
      status = observe == strict ? "IDENTICAL" : "MISMATCH"
      puts "  [#{status}] #{observe}"
    end
  end
end

CspValidationMigrationExample.observe_phase
CspValidationMigrationExample.remediate_phase
CspValidationMigrationExample.strict_enable_phase
CspValidationMigrationExample.rollback_phase
CspValidationMigrationExample.parity_phase

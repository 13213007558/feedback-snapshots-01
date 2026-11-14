# frozen_string_literal: true
# Demonstrates the configuration ownership model in secure_headers:
#
#   * registered configs (default + named overrides) are deep-frozen snapshots
#   * per-request configs are independent writable copies
#   * caller-owned nested objects (CSP arrays, cookie only/except, reporting
#     endpoints) are copied at registration and at request modification
#   * OPT_OUT keeps its singleton identity and is never frozen
#   * memoized headers are invalidated by legitimate request modifications
#
# Run with: bundle exec ruby examples/ownership_isolation_demo.rb
require "secure_headers"
require "rack"
require "cgi/cookie"

module Demo
  def self.reset!
    config = SecureHeaders::Configuration
    config.remove_instance_variable(:@default_config) if config.instance_variable_defined?(:@default_config)
    config.remove_instance_variable(:@overrides) if config.instance_variable_defined?(:@overrides)
    config.remove_instance_variable(:@appends) if config.instance_variable_defined?(:@appends)
    config.remove_instance_variable(:@disabled) if config.instance_variable_defined?(:@disabled)
    config.remove_instance_variable(:@noop_config) if config.instance_variable_defined?(:@noop_config)
  end

  # Count how many objects (hashes, arrays, CSP config wrappers) are reachable
  # from a configuration so the copy scope can be compared across versions.
  def self.object_graph_size(value, seen = {})
    return 0 if value.nil? || value.equal?(SecureHeaders::OPT_OUT)
    return seen[value.object_id] if seen.key?(value.object_id)
    seen[value.object_id] = 0

    size = 1
    case value
    when Hash
      value.each { |key, nested| size += object_graph_size(key, seen) + object_graph_size(nested, seen) }
    when Array
      value.each { |element| size += object_graph_size(element, seen) }
    when SecureHeaders::ContentSecurityPolicyConfig
      size += object_graph_size(value.to_h, seen)
    when SecureHeaders::Configuration
      SecureHeaders::Configuration::CONFIG_ATTRIBUTES.each do |attr|
        size += object_graph_size(value.instance_variable_get("@#{attr}"), seen)
      end
    end
    seen[value.object_id] = size
    size
  end

  def self.section(title)
    puts
    puts "=" * 78
    puts title
    puts "=" * 78
  end
end

Demo.reset!

# One public array feeds both the default CSP and a named override; one cookie
# condition hash and one endpoints hash are reused as well.
shared_script_src = %w(shared.cdn)
shared_cookie_only = %w(_session)
shared_endpoints = { "csp-endpoint" => "https://reports.example.com/collect" }

SecureHeaders::Configuration.default do |config|
  config.csp = {
    default_src: %w('self'),
    script_src: shared_script_src,
    style_src: %w('self'),
  }
  config.cookies = {
    httponly: { only: shared_cookie_only },
    secure: true,
    samesite: { lax: { except: %w(_guest) } },
  }
  config.reporting_endpoints = shared_endpoints
end

SecureHeaders::Configuration.override(:api) do |config|
  config.csp.merge!(script_src: shared_script_src + %w(api.partner.com))
  config.reporting_endpoints = shared_endpoints.merge("api-endpoint" => "https://reports.example.com/api")
end

default_config = SecureHeaders::Configuration.send(:default_config)

Demo.section("1. Registered objects are immutable; caller objects stay writable")
puts "default config deep frozen?            #{SecureHeaders::Ownership.deep_frozen?(default_config)}"
puts "default CSP deep frozen?               #{SecureHeaders::Ownership.deep_frozen?(default_config.csp)}"
puts "default cookies deep frozen?           #{SecureHeaders::Ownership.deep_frozen?(default_config.cookies)}"
puts "default endpoints deep frozen?         #{SecureHeaders::Ownership.deep_frozen?(default_config.reporting_endpoints)}"

shared_script_src << "attacker.example"
shared_cookie_only << "hijacked-cookie"
shared_endpoints["csp-endpoint"] = "https://attacker.example/steal"
puts "caller objects mutated after registration (writable: #{shared_script_src.frozen? == false})"
puts "registered script_src:                 #{default_config.csp.directive_value(:script_src).inspect}"
puts "registered cookie only:                #{default_config.cookies[:httponly][:only].inspect}"
puts "registered endpoint:                   #{default_config.reporting_endpoints.inspect}"

begin
  default_config.csp.update_directive(:script_src, %w(no))
rescue FrozenError
  puts "mutating the registered CSP raises:    FrozenError"
end

Demo.section("2. OPT_OUT identity is preserved")
Demo.reset!
SecureHeaders::Configuration.default do |config|
  config.csp = SecureHeaders::OPT_OUT
  config.cookies = SecureHeaders::OPT_OUT
  config.reporting_endpoints = SecureHeaders::OPT_OUT
end
optout_default = SecureHeaders::Configuration.send(:default_config)
puts "registered csp.equal?(OPT_OUT):        #{optout_default.csp.equal?(SecureHeaders::OPT_OUT)}"
puts "dup csp.equal?(OPT_OUT):               #{optout_default.dup.csp.equal?(SecureHeaders::OPT_OUT)}"
puts "OPT_OUT frozen?                        #{SecureHeaders::OPT_OUT.frozen?}"

Demo.reset!
SecureHeaders::Configuration.default do |config|
  config.csp = { default_src: %w('self'), script_src: %w('self') }
  config.cookies = { secure: true, httponly: true, samesite: { lax: true } }
  config.reporting_endpoints = { "csp-endpoint" => "https://reports.example.com/collect" }
end
default_config = SecureHeaders::Configuration.send(:default_config)

Demo.section("3. Two interleaved requests reuse nested config but stay isolated")
request_one = Rack::Request.new({})
request_two = Rack::Request.new({})

# Request 1 starts a modification, then request 2 modifies before request 1 finishes.
SecureHeaders.append_content_security_policy_directives(request_one, script_src: %w(one.example))
SecureHeaders.override_content_security_policy_directives(request_two, img_src: %w(two-img.example))
SecureHeaders.append_content_security_policy_directives(request_one, img_src: %w(one-img.example))

config_one = request_one.env[SecureHeaders::SECURE_HEADERS_CONFIG]
config_two = request_two.env[SecureHeaders::SECURE_HEADERS_CONFIG]
puts "request config objects distinct?       #{!config_one.equal?(config_two)}"
puts "request 1 CSP distinct from default?   #{!config_one.csp.equal?(default_config.csp)}"
puts "request 2 CSP distinct from default?   #{!config_two.csp.equal?(default_config.csp)}"
puts "request 1 cookies distinct?            #{!config_one.cookies.equal?(default_config.cookies)}"
puts "request 1 writable?                    #{!config_one.frozen?}"
puts "request 2 writable?                    #{!config_two.frozen?}"

headers_one = SecureHeaders.header_hash_for(request_one)
headers_two = SecureHeaders.header_hash_for(request_two)
puts "req 1 CSP: #{headers_one["content-security-policy"]}"
puts "req 2 CSP: #{headers_two["content-security-policy"]}"
puts "default CSP after both requests:       #{default_config.csp.to_h.inspect}"
puts "default cookies after both requests:   #{default_config.cookies.inspect}"

Demo.section("4. Header cache invalidates on legitimate request modifications")
cached_before = config_one.instance_variable_get(:@generated_headers_cache)
puts "header hash memoized on first read?    #{!cached_before.nil?}"
SecureHeaders.override_x_frame_options(request_one, "DENY")
puts "memo cleared after writer call?        #{config_one.instance_variable_get(:@generated_headers_cache).nil?}"
config_one.csp.merge!(connect_src: %w(widget.example))
puts "memo cleared after direct CSP merge!?  #{config_one.instance_variable_get(:@generated_headers_cache).nil?}"
fresh_headers = SecureHeaders.header_hash_for(request_one)
puts "regenerated header reflects changes?   #{fresh_headers["x-frame-options"] == "DENY" && fresh_headers["content-security-policy"].include?("widget.example")}"

Demo.section("5. Copy scope: what is duplicated vs shared")
full_tree = Demo.object_graph_size(default_config)
request_copy = SecureHeaders::Configuration.dup
copied_tree = Demo.object_graph_size(request_copy)
puts "objects reachable from registered config:            #{full_tree}"
puts "objects rebuilt by a per-request dup:                #{copied_tree}"
puts
SecureHeaders::Configuration::CONFIG_ATTRIBUTES.each do |attr|
  source = default_config.instance_variable_get("@#{attr}")
  target = request_copy.instance_variable_get("@#{attr}")
  kind =
    if source.equal?(SecureHeaders::OPT_OUT)
      "OPT_OUT singleton (identity shared, never copied)"
    elsif source.nil? || source.is_a?(String) || [true, false].include?(source)
      "immutable scalar (shared safely)"
    else
      "deep copied, distinct object (#{source.equal?(target) == false})"
    end
  puts "  %-22<attr>s %<kind>s" % { attr: attr, kind: kind }
end
puts
puts "Before this change a per-request dup rebuilt ~12 shell/hash objects but"
puts "aliased the nested cookie conditions, endpoint hashes and source arrays."
puts "The extra copies below are exactly those previously-shared mutable objects;"
puts "the whole tree is only copied once, when a request first modifies the"
puts "config - generate_headers itself never duplicates the tree:"
puts "  * unmodified request: 0 copies, reads the frozen registered config"
puts "  * modified request:   1 deep dup of the mutable nested trees"
puts "  * repeated reads:     memoized header hash, no rebuild"
puts
puts "An unmodified request copies nothing: it reads the frozen registered"
puts "config directly (#{SecureHeaders.header_hash_for(Rack::Request.new({})).size} headers generated without a per-request config object)."

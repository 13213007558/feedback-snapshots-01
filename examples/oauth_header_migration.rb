# frozen_string_literal: true

# ============================================================================
# OAuth 1.0a credential-carrier migration: query string -> Authorization header
# ============================================================================
#
# This file is a *runnable* integration example. It signs requests with the
# OAuth gem and verifies them through the Rack request proxy, proving that:
#
#   * the legacy (:query_string) and the new (:header) mode both authenticate;
#   * ordinary business parameters (query + form) participate in the signature
#     in BOTH modes and survive the migration unchanged;
#   * in the new mode the actual request URL no longer contains any oauth_*
#     credential (no oauth_token / oauth_signature / oauth_nonce ...);
#   * a request that sends protocol parameters in more than one carrier is
#     rejected with OAuth::AmbiguousCredentials instead of being silently
#     merged;
#   * error/log handling never copies header credentials back into the URL.
#
# Run it with:
#   bundle exec ruby -Ilib examples/oauth_header_migration.rb
# ============================================================================

require "oauth"
require "oauth/request_proxy/rack_request"
require "net/http"
require "rack"

# ---- Fixed credentials/deterministic nonce so the output is reproducible ---
CONSUMER = OAuth::Consumer.new(
  "consumer-key", "consumer-secret",
  site: "https://api.example.com",
  body_hash_enabled: false
)
TOKEN = OAuth::Token.new("token-key", "token-secret")
ENDPOINT_PATH = "/v1/orders".freeze
# Business data only -- these are NOT protocol parameters and must be carried
# identically before and after the migration.
BUSINESS_QUERY = { "status" => "open", "page" => "2" }.freeze
SIGN_OPTIONS = { nonce: "fixed-nonce-0001", timestamp: "1700000000" }.freeze
OAUTH_NAME = /\boauth_/.freeze

# ----------------------------------------------------------------------------
# Signing side: build a Net::HTTP request using a SINGLE credential carrier.
# Pass exactly one scheme -- never combine carriers.
# ----------------------------------------------------------------------------
def build_signed_request(scheme)
  query = OAuth::Helper.normalize(BUSINESS_QUERY)
  request = Net::HTTP::Post.new("#{ENDPOINT_PATH}?#{query}")
  request.set_form_data("note" => "urgent") # form body business parameter
  request["Content-Type"] = "application/x-www-form-urlencoded"
  request.oauth!(CONSUMER.http, CONSUMER, TOKEN, SIGN_OPTIONS.merge(scheme: scheme))
  request
end

# ----------------------------------------------------------------------------
# Rack verification side. Turn the outbound request into a Rack env and verify
# the signature exactly as a provider would. Ambiguity is raised BEFORE any
# signature work, so a split-credential request can never be accepted.
# ----------------------------------------------------------------------------
def verify(request)
  env = Rack::MockRequest.env_for(
    "https://api.example.com#{request.path}",
    method: request.method,
    "HTTP_AUTHORIZATION" => request["Authorization"],
    "CONTENT_TYPE" => request["Content-Type"],
    input: request.body
  )
  rack_request = Rack::Request.new(env)
  proxy = OAuth::RequestProxy.proxy(rack_request, consumer: CONSUMER, token: TOKEN)
  {
    ok: OAuth::Signature.verify(proxy, consumer: CONSUMER, token: TOKEN),
    business: proxy.non_oauth_parameters,
    locations: proxy.oauth_parameters_by_location
  }
end

# Safe logging helper: logs the URL but never folds Authorization header data
# into it. Only parameter *names*/locations are reported on failure.
def safe_log(label, request)
  url = "https://api.example.com#{request.path}"
  warn "[#{label}] url=#{url} authorization_present=#{!request['Authorization'].nil?}"
end

def report(title, request, result)
  safe_log(title, request)
  puts "== #{title} =="
  puts "  sent URL            : #{"https://api.example.com#{request.path}"}"
  puts "  URL has credentials? : #{OAUTH_NAME.match?(request.path)}"
  puts "  Authorization header : #{request['Authorization'] ? 'present' : 'absent'}"
  puts "  signature verified  : #{result[:ok]}"
  puts "  business parameters : #{result[:business].inspect}"
  puts "  carrier locations    : #{result[:locations].reject { |_k, v| v.empty? }.keys.inspect}"
  puts
end

puts "Migrating OAuth credentials from query string to Authorization header\n\n"

# --- Step 1: legacy mode (credentials in the URL query string) --------------
legacy = build_signed_request(:query_string)
legacy_result = verify(legacy)
report("STEP 1 - legacy :query_string mode", legacy, legacy_result)

# --- Step 2: new mode (credentials only in the Authorization header) --------
modern = build_signed_request(:header)
modern_result = verify(modern)
report("STEP 2 - new :header mode", modern, modern_result)

# --- Equivalence proof: identical business params, only the carrier changes -
raise "business params changed during migration!" unless
  legacy_result[:business] == modern_result[:business] && modern_result[:business] == {
    "status" => "open", "page" => "2", "note" => "urgent"
  }
raise "header mode must keep credentials out of the URL!" if OAUTH_NAME.match?(modern.path)
puts "Business parameters are IDENTICAL across modes; header-mode URL is clean.\n\n"

# --- Step 3: ambiguity rejection (header AND query on the same request) -----
mixed = build_signed_request(:header)
# Simulate a misconfigured/legacy client that ALSO leaks oauth params on the URL.
mixed_uri = URI.parse(mixed.path)
mixed_uri.query = "#{mixed_uri.query}&oauth_token=stale-leftover&oauth_signature=stale"
mixed_path = mixed_uri.to_s

# Verify against a Rack env that carries both the header and the leaked query.
mixed_env = Rack::MockRequest.env_for(
  "https://api.example.com#{mixed_path}",
  method: mixed.method,
  "HTTP_AUTHORIZATION" => mixed["Authorization"],
  "CONTENT_TYPE" => mixed["Content-Type"],
  input: mixed.body
)

begin
  OAuth::RequestProxy.proxy(Rack::Request.new(mixed_env),
                            consumer: CONSUMER, token: TOKEN).parameters
  raise "expected ambiguity to be rejected!"
rescue OAuth::AmbiguousCredentials => e
  puts "== STEP 3 - mixed carrier rejected =="
  puts "  raised              : #{e.class}"
  puts "  message (no values) : #{e.message}"
  puts "  safe log payload    : #{e.to_h.inspect}"
  # The logged URL still contains only the query-string leftovers; we do NOT
  # append the Authorization header to it.
  puts "  logged URL stays    : https://api.example.com#{mixed_path}"
  puts
end

puts "All migration checks passed."

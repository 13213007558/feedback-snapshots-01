# frozen_string_literal: true

# Example initializer for bounded-state login throttling.
#
# Preconditions:
# - Set Rack::Attack.bounded_throttle_hash_key to the same secret in every
#   process (for example from an environment variable or Rails credentials).
# - HTTP_X_TENANT_ID must be set by a trusted edge, not by the client.
# - Rack::Request.ip_filter must be configured for your proxy topology if you
#   rely on req.ip.

Rack::Attack.bounded_throttle_hash_key = ENV.fetch('RACK_ATTACK_HASH_KEY')

Rack::Attack.bounded_throttle(
  'login/account',
  strategy: :gate,
  limit: 5,
  period: 60,
  budgets: {
    global: {
      limit: 5_000,
      buckets: 1
    },
    tenant: {
      limit: 500,
      buckets: 256,
      discriminator: ->(req) { req.get_header('HTTP_X_TENANT_ID') }
    },
    ip: {
      limit: 30,
      buckets: 1_024,
      prefix: 24,
      discriminator: ->(req) { req.ip }
    }
  }
) do |req|
  next unless req.post? && req.path == '/login'

  req.params['email'].to_s.downcase.strip
end

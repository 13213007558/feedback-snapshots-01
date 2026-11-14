# frozen_string_literal: true
require_relative 'harness'

# Token that is NOT YET VALID (nbf in the future), no exp. Demonstrates that the
# two APIs' BUILT-IN DEFAULTS disagree, which is why the harness aligns policy.
future = Time.now.to_i + 3600
token = JWT.encode({ 'nbf' => future }, DiffFuzz::GOOD_SECRET, 'HS256')

# Legacy defaults (configuration.decode): verify_expiration AND verify_not_before true.
begin
  JWT.decode(token, DiffFuzz::GOOD_SECRET, true, { algorithm: 'HS256' })
  puts 'legacy DEFAULT nbf: ACCEPT (unexpected)'
rescue JWT::Error => e
  puts "legacy DEFAULT nbf: REJECT #{e.class}(#{e.message})"
end

# New API default verify_claims! -> only :exp. nbf is NOT checked by default.
et = JWT::EncodedToken.new(token)
begin
  et.verify_signature!(algorithm: 'HS256', key: DiffFuzz::GOOD_SECRET)
  et.verify_claims!                       # default: exp only
  puts "new    DEFAULT nbf: ACCEPT payload=#{et.payload.inspect}"
rescue JWT::Error => e
  puts "new    DEFAULT nbf: REJECT #{e.class}(#{e.message})"
end

# After explicit alignment (both check exp + nbf), they agree.
et2 = JWT::EncodedToken.new(token)
et2.verify_signature!(algorithm: 'HS256', key: DiffFuzz::GOOD_SECRET)
begin
  et2.verify_claims!(:exp, :nbf)
  puts 'new    ALIGNED nbf: ACCEPT (unexpected)'
rescue JWT::Error => e
  puts "new    ALIGNED nbf: REJECT #{e.class}(#{e.message})  -> now matches legacy"
end

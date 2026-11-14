# frozen_string_literal: true
require_relative 'harness'
require_relative 'corpus'

# Use the library's own supported detached-payload flow (RFC 7515 Appendix F).
src = JWT::Token.new(payload: { 'a' => 1, 'nbf' => 0 })
src.detach_payload!
src.sign!(algorithm: 'HS256', key: DiffFuzz::GOOD_SECRET)
compact       = src.jwt                    # header..signature  (empty payload seg)
detached_pseg = src.encoded_payload        # the payload to re-attach out-of-band

puts "compact (#{compact.count('.') + 1} segments, empty payload): #{compact.inspect}"
puts "detached payload segment           : #{detached_pseg.inspect}"
puts

et = JWT::EncodedToken.new(compact)
et.encoded_payload = detached_pseg
begin
  et.verify_signature!(algorithm: 'HS256', key: DiffFuzz::GOOD_SECRET)
  et.verify_claims!(:exp, :nbf)
  puts "NEW API accepted detached token; trusted payload=#{et.payload.inspect}"
rescue JWT::Error => e
  puts "NEW API rejected: #{e.class}: #{e.message}"
end
puts

opts = { algorithm: 'HS256', verify_expiration: true, verify_not_before: true,
         verify_iss: false, verify_iat: false, verify_jti: false,
         verify_aud: false, verify_sub: false, required_claims: [] }
begin
  JWT.decode(compact, DiffFuzz::GOOD_SECRET, true, opts)
  puts 'LEGACY accepted (unexpected)'
rescue JWT::Error => e
  puts "LEGACY rejects the same compact token: #{e.class}: #{e.message}"
end

# Sanity: a normal (non-detached) token of the same content verifies on both.
normal = JWT::Token.new(payload: { 'a' => 1, 'nbf' => 0 }).tap { |t| t.sign!(algorithm: 'HS256', key: DiffFuzz::GOOD_SECRET) }.jwt
l, n = DiffFuzz.compare(normal)
puts
puts "normal token -> legacy=#{l.verdict} new=#{n.verdict} (both accept expected)"

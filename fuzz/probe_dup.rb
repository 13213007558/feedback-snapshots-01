# frozen_string_literal: true
require_relative 'harness'
require_relative 'corpus'

# A token whose header carries a DUPLICATE alg but whose signature is valid for
# the surviving (last) value, HS256. Ruby's JSON.parse keeps the last member.
dup_raw = '{"alg":"none","alg":"HS256"}'
hseg = DiffFuzz.b64u(dup_raw)
pseg = DiffFuzz.b64u('{"a":1,"nbf":0}')
sig = OpenSSL::HMAC.digest('SHA256', DiffFuzz::GOOD_SECRET, "#{hseg}.#{pseg}")
token = "#{hseg}.#{pseg}.#{DiffFuzz.b64u(sig)}"
puts "parsed header (last-wins): #{JWT::JSON.parse(DiffFuzz.b64u_dec(hseg)).inspect}"
l, n = DiffFuzz.compare(token)
puts "dup-alg valid-sig -> legacy=#{l.verdict}(#{l.error_class}) new=#{n.verdict}(#{n.error_class})"

# Finder arity contract: legacy supports 1- or 2-arity (header, payload);
# new API always yields the EncodedToken (single object).
puts
puts '--- key-finder arity contract ---'
valid = DiffFuzz::Corpus.valid_token
begin
  JWT.decode(valid, nil, true, { algorithm: 'HS256' }) { |header, payload|
    puts "legacy 2-arity finder called: header=#{header.class} payload=#{payload.class}"
    DiffFuzz::GOOD_SECRET
  }
  puts 'legacy accepted via 2-arity finder'
rescue StandardError => e
  puts "legacy 2-arity: #{e.class}: #{e.message}"
end
begin
  et = JWT::EncodedToken.new(valid)
  et.verify_signature!(algorithm: 'HS256', key_finder: ->(tok) { puts "new 1-arg finder called with: #{tok.class}"; DiffFuzz::GOOD_SECRET })
  puts 'new accepted via 1-arg finder'
rescue StandardError => e
  puts "new finder: #{e.class}: #{e.message}"
end

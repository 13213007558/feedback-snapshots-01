# frozen_string_literal: true

# Complementary self-test: deliberately RELAX the legacy segment-count check
# (drop the "not enough" rejection, keep only "too many") so it matches the new
# API's weaker rule. A well-formed two-segment token (header.payload, a legal
# unsigned-JWS shape) must then traverse the same code path on both sides and
# stop at signature verification, whereas the real legacy API rejects it first.
# In-process patch only; the installed library is never modified.
require_relative 'harness'
require_relative 'corpus'
require_relative 'run_diff'

runner = DiffFuzz::Runner.new
h = DiffFuzz.b64u('{"alg":"HS256"}')
pseg = DiffFuzz.b64u('{"a":1,"nbf":0}')
two_segment = "#{h}.#{pseg}"

l_real, n_real = DiffFuzz.compare(two_segment, use_finder: true)
real_diff = runner.divergent?(l_real, n_real)
puts "real library   : legacy=#{l_real.verdict}(finder=#{l_real.finder_called}) " \
     "new=#{n_real.verdict}(finder=#{n_real.finder_called}) divergent=#{real_diff}"

JWT::Decode.class_eval do
  # Relaxed mutant: tolerate short tokens, reject only "too many" (new-API rule).
  def validate_segment_count!
    raise JWT::MalformedTokenError, 'Too many segments' if token.jwt.count('.') > 2
  end
end

l_mut, n_mut = DiffFuzz.compare(two_segment, use_finder: true)
mut_diff = runner.divergent?(l_mut, n_mut)
puts "relaxed mutant : legacy=#{l_mut.verdict}(finder=#{l_mut.finder_called}) " \
     "new=#{n_mut.verdict}(finder=#{n_mut.finder_called}) divergent=#{mut_diff}"
puts "               legacy error=#{l_mut.error_class}(#{l_mut.error_message.inspect})"
puts
if real_diff && !mut_diff
  puts 'PASS: relaxing the legacy segment-count gate removed the difference.'
  puts 'Weak-mutant evidence: the oracle detects segment-count logic, not noise.'
  exit 0
else
  puts 'FAIL: relaxed mutant did not behave as predicted.'
  exit 1
end

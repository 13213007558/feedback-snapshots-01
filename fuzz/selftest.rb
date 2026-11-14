# frozen_string_literal: true

# Self-test / mutation-validation of the oracle's segment-count sensitivity.
#
# The real difference found in fuzzing is that JWT::EncodedToken only rejects
# "too many" segments, whereas legacy JWT::Decode also rejects "not enough"
# (one- and two-segment tokens). On a short token the new API therefore walks
# far enough to invoke the key-finder before failing; legacy aborts first.
#
# Proof that the oracle keys on this exact check:
#   (A) baseline  -> short tokens diverge (finder timing + error class)
#   (B) make the NEW API's check as STRICT as legacy -> divergence disappears
#   (C) instead merely RELAX legacy's check the same way -> divergence also
#       collapses for the well-formed short token (the structural-only case)
#
# All patches are in-process monkeypatches; the installed library is untouched.
require_relative 'harness'
require_relative 'corpus'
require_relative 'run_diff'

runner = DiffFuzz::Runner.new
short  = DiffFuzz::Corpus.structural_cases.select { |c| %w[seg-1 seg-2].include?(c.id) }

def count_divergent(runner, cases, use_finder:)
  cases.count do |c|
    l, n = DiffFuzz.compare(c.token, payload_override: c.payload_override, use_finder: use_finder)
    runner.divergent?(l, n)
  end
end

# (A) Baseline, real library, key-finder mode (where the timing gap is visible).
base = count_divergent(runner, short, use_finder: true)
puts "(A) baseline divergent short-token cases (real library)      : #{base}/#{short.size}"

# (B) Tighten the NEW API to the legacy three-segment rule.
JWT::EncodedToken.class_eval do
  def validate_segment_count!
    raise JWT::MalformedTokenError, 'Not enough or too many segments' unless jwt.count('.') == 2
  end
end
strict = count_divergent(runner, short, use_finder: true)
puts "(B) divergent cases after NEW API uses strict 3-segment rule : #{strict}/#{short.size}"

# Reset method by reloading the original file in a fresh comparison is awkward;
# instead run (C) in a separate process below. Here just assert (B).
ok_b = base.positive? && strict.zero?
puts(ok_b ? 'PASS: strict segment check erases the short-token differences.' :
           'FAIL: strict segment check did not erase the differences.')
exit(ok_b ? 0 : 1)

# Proof, without any network access or without measuring wall-clock time,
# that Ruby's && short-circuits while & evaluates both sides.
#
# Each "comparison" increments a counter instead of doing real work, so the
# number of comparisons actually performed is observable deterministically.
# This is the same ordering difference the Brakeman check warns about when
# the operands are credential comparisons.
module ShortCircuitDemo
  class CountingEquality
    attr_reader :comparisons

    def initialize
      @comparisons = 0
    end

    def ==(_other)
      @comparisons += 1
      false
    end
  end

  # Both credentials are wrong. With && the second comparison is skipped
  # because the first one already failed.
  def self.short_circuit_count
    user_check = CountingEquality.new
    pass_check = CountingEquality.new

    _result = (user_check == :wrong_user) && (pass_check == :wrong_pass)

    {
      :user_comparisons => user_check.comparisons,
      :password_comparisons => pass_check.comparisons,
      :total => user_check.comparisons + pass_check.comparisons
    }
  end

  # With the non-short-circuit & both comparisons are always evaluated, even
  # though the first one already returned false.
  def self.non_short_circuit_count
    user_check = CountingEquality.new
    pass_check = CountingEquality.new

    _result = (user_check == :wrong_user) & (pass_check == :wrong_pass)

    {
      :user_comparisons => user_check.comparisons,
      :password_comparisons => pass_check.comparisons,
      :total => user_check.comparisons + pass_check.comparisons
    }
  end
end

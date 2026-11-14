# frozen_string_literal: false

module REXML
  class XPath
    # Base class for exceptions raised when an XPath evaluation is stopped
    # before it has produced a result.
    #
    # Rescuing either {BudgetExceeded} or {Cancelled} is normally enough;
    # both are subclasses of this class, so rescuing it catches either.
    class Aborted < StandardError
    end

    # Raised when an evaluation consumes more work units than its {Budget}
    # allows.
    class BudgetExceeded < Aborted
      # The number of work units consumed when the evaluation was stopped.
      attr_reader :used

      # The work-unit limit that was exceeded.
      attr_reader :limit

      def initialize(used, limit, message = nil)
        @used = used
        @limit = limit
        super(message || "XPath work budget exceeded (#{used} > #{limit})")
      end
    end

    # Raised when an evaluation is stopped through a cancellation token or
    # through {Budget#cancel!}.
    class Cancelled < Aborted
    end

    # A cancel flag that may be shared between the thread running an XPath
    # evaluation and the thread that decides the evaluation should stop.
    #
    #   cancellation = REXML::XPath::Cancellation.new
    #   thread = Thread.new do
    #     REXML::XPath.match(document, "//item", nil, {},
    #                        cancellation: cancellation)
    #   end
    #   cancellation.cancel!
    #
    # The flag is sticky: an evaluation that starts after {#cancel!} is
    # cancelled as soon as it checks the token.  Call {#reset!} before reusing
    # the token for a fresh evaluation.
    class Cancellation
      def initialize
        @cancelled = false
      end

      # Asks any evaluation using this token to stop at its next checkpoint.
      def cancel!
        @cancelled = true
        self
      end
      alias cancel cancel!

      def cancelled?
        @cancelled
      end
      alias cancelled cancelled?

      # Clears the flag so that the token can be used for another evaluation.
      def reset!
        @cancelled = false
        self
      end
    end

    # An optional work budget for one XPath evaluation.
    #
    # A budget is counted in implementation-defined work units.  One unit is
    # roughly one visited node, one predicate evaluation, one node pair
    # compared, or one function call, so a short expression that repeatedly
    # scans a large document still consumes work proportional to the scan.
    # The number of nodes returned is not what bounds the budget.
    #
    # The limit is per evaluation: {XPath.match}, {XPath.first} and
    # {XPath.each} reset the counter and any cancellation state at the start
    # of each evaluation, and clear the evaluation's transient caches at the
    # end even when it was aborted.  A budget object can therefore be reused
    # after an abort.  A budget object must not be shared by evaluations
    # running at the same time.
    #
    #   budget = REXML::XPath::Budget.new(10_000)
    #   begin
    #     REXML::XPath.match(document, "//item[contains(., 'x')]",
    #                        nil, {}, budget: budget)
    #   rescue REXML::XPath::BudgetExceeded
    #     # The query was stopped; budget.used tells how far it got.
    #   end
    #
    # A budget without a limit is useful as a pure cancellation handle:
    #
    #   budget = REXML::XPath::Budget.new
    #   budget.cancel! # from another thread, while an evaluation is running
    class Budget
      # The maximum number of work units, or +nil+ for no limit.
      attr_reader :limit

      # The number of work units consumed since the current evaluation began.
      attr_reader :used

      # An optional cancellation token checked in addition to {#cancel!}.
      attr_accessor :cancellation

      def initialize(limit = nil, cancellation: nil)
        @used = 0
        @cancelled = false
        @cancellation = cancellation
        @limit = nil
        self.limit = limit unless limit.nil?
      end

      # Changes the work-unit limit.  +nil+ removes the limit.  The counter
      # is not reset; start a new evaluation or call {#reset!} for that.
      def limit=(value)
        unless value.nil? || (value.is_a?(Numeric) && value >= 0)
          raise ArgumentError,
                "budget limit must be a non-negative number or nil: " +
                "<#{value.inspect}>"
        end
        @limit = value
      end

      # Resets the consumed counter and checks whether this evaluation may
      # start.  Called by REXML::XPathParser at the beginning of each
      # evaluation; it is also safe to call by hand.
      def begin_evaluation!
        @used = 0
        check!
      end

      # Adds +units+ to the consumed counter and checks the limit and the
      # cancellation state.  Raises {BudgetExceeded} or {Cancelled} when the
      # evaluation must stop.
      def consume(units = 1)
        @used += units
        check!
      end
      alias charge consume

      # Checks the cancellation state and the limit without consuming
      # anything.
      def check!
        if cancelled?
          raise Cancelled, "XPath evaluation cancelled"
        end
        if !@limit.nil? && @used > @limit
          raise BudgetExceeded.new(@used, @limit)
        end
        self
      end

      # Asks the evaluation using this budget to stop.  Safe to call from
      # another thread.
      def cancel!
        @cancelled = true
        self
      end
      alias cancel cancel!

      def cancelled?
        return true if @cancelled
        return false if @cancellation.nil?
        token = @cancellation
        if token.respond_to?(:cancelled?)
          token.cancelled?
        elsif token.respond_to?(:cancelled)
          token.cancelled
        elsif token.respond_to?(:call)
          !!token.call
        else
          false
        end
      end
      alias cancelled cancelled?

      # Clears the consumed counter and the local cancel flag.  A cancellation
      # token supplied through +cancellation+ is not reset; reset it
      # separately if it is to be reused.
      def reset!
        @used = 0
        @cancelled = false
        self
      end

      # How many work units are left, or +Float::INFINITY+ for an unlimited
      # budget.
      def remaining
        return Float::INFINITY if @limit.nil?
        remainder = @limit - @used
        remainder.negative? ? 0 : remainder
      end

      def unlimited?
        @limit.nil?
      end

      def exhausted?
        !@limit.nil? && @used > @limit
      end
    end
  end
end

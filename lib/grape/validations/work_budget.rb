# frozen_string_literal: true

module Grape
  module Validations
    # Meters the work an endpoint spends validating one request.
    #
    # The same shape of request can cost wildly different amounts depending on
    # how many Array elements a params block repeats, how many +given+ scopes
    # each element makes the validators evaluate, and how many failures are
    # collected and rendered. A request that is small in bytes can therefore
    # ask for an unbounded amount of CPU. This budget turns that work into a
    # per-request allowance and stops the request once it is used up.
    #
    # It is request-local (fiber-local, like ParamScopeTracker) and only
    # allocated when a limit is configured. With no limit, every charge is a
    # no-op.
    class WorkBudget
      FIBER_KEY = :grape_validation_work_budget

      class << self
        # Runs the block with a meter for the request, restoring whatever meter
        # was current before. A nil +limit+ turns metering off, unless an
        # enclosing endpoint already opened one for this request: endpoints
        # reached through +mount+ then spend from the same allowance rather
        # than starting a fresh one.
        def track(limit)
          previous = Fiber[FIBER_KEY]
          Fiber[FIBER_KEY] = previous || (limit && new(limit))
          yield
        ensure
          Fiber[FIBER_KEY] = previous
        end

        def current
          Fiber[FIBER_KEY]
        end

        # Charges the current request, if one is being metered. The common case
        # -- no budget configured -- stays a single lookup.
        def charge(units = 1)
          budget = Fiber[FIBER_KEY]
          budget&.charge(units)
        end

        # Charges one unit per entry in the params tree +value+ roots. Walking
        # it here, iteratively, is what keeps a batch that is small as a Hash
        # but large once normalized from being free. The walk stops as soon as
        # the count alone would overrun the allowance, so a payload too large to
        # be validated is not walked to the end first.
        def charge_params(value)
          budget = Fiber[FIBER_KEY]
          budget&.charge(tree_size(value, budget))
        end

        private

        def tree_size(value, budget)
          units = 0
          pending = [value]
          until pending.empty?
            node = pending.pop
            next unless node.is_a?(Hash) || node.is_a?(Array)

            children = node.is_a?(Hash) ? node.each_value : node
            children.each do |child|
              units += 1
              budget.check(units)
              pending << child
            end
          end
          units
        end
      end

      attr_reader :limit, :spent

      def initialize(limit)
        raise ArgumentError, 'validation work budget must be a non-negative Integer' unless limit.is_a?(Integer) && limit >= 0

        @limit = limit
        @spent = 0
      end

      def charge(units = 1)
        @spent += units
        raise Exceptions::ValidationBudgetExceeded.new(limit:, spent:) if @spent > @limit
      end

      # Whether +units+ more, on top of what has been spent, would overrun the
      # allowance. Lets a caller that accumulates before charging stop partway.
      def check(units)
        return if @spent + units <= @limit

        raise Exceptions::ValidationBudgetExceeded.new(limit:, spent: @spent + units)
      end
    end
  end
end

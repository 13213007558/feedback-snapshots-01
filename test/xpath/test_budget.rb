# frozen_string_literal: false

require "rexml/document"
require "rexml/xpath"

module REXMLTests
  class TestXPathBudget < Test::Unit::TestCase
    include REXML

    def build_document(count)
      items = count.times.collect do |i|
        "<item id='#{i}'><name>name#{i}</name><value>#{i}</value></item>"
      end
      Document.new("<root>#{items.join}</root>")
    end

    # A query whose result is small but whose work is quadratic in the number
    # of elements: a predicate that counts every element again for every
    # candidate element.
    QUADRATIC_QUERY = "//*[count(//*) > 0]"

    def test_option_aliases
      doc = build_document(10)
      expected = XPath.match(doc, "//item")

      [
        {budget: 1_000_000},
        {work_budget: 1_000_000},
        {limit: 1_000_000},
        {budget_limit: 1_000_000},
        {max_work: 1_000_000},
        {work_limit: 1_000_000},
      ].each do |options|
        assert_equal(expected,
                     XPath.match(doc, "//item", nil, {}, options),
                     options.inspect)
      end

      # Keywords land in the namespaces slot when the call has no explicit
      # nil there.
      assert_equal(expected, XPath.match(doc, "//item", budget: 1_000_000))
      assert_equal(expected, XPath.match(doc, "//item", limit: 1_000_000))
    end

    def test_default_unchanged
      doc = build_document(20)
      expected = XPath.match(doc, "//item[@id='3']/name")
      assert_equal(expected, XPath.match(doc, "//item[@id='3']/name"))
    end

    def test_sufficient_budget_same_result
      doc = build_document(50)
      xpath = "//item[value > 40]/name"
      expected = XPath.match(doc, xpath)

      unlimited = XPath::Budget.new
      actual = XPath.match(doc, xpath, nil, {}, budget: unlimited)

      assert_equal(expected, actual)
      assert_nil(unlimited.limit)
      assert_operator(unlimited.used, :>, 0)
    end

    def test_numeric_budget_and_result_unchanged
      doc = build_document(10)
      expected = XPath.match(doc, "//item")
      assert_equal(expected,
                   XPath.match(doc, "//item", nil, {}, budget: 1_000_000))
      assert_equal(expected,
                   XPath.match(doc, "//item", nil, {}, limit: 1_000_000))
    end

    def test_budget_exceeded
      doc = build_document(40)
      budget = XPath::Budget.new(200)

      error = assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, QUADRATIC_QUERY, nil, {}, budget: budget)
      end

      assert_operator(error.used, :>, error.limit)
      assert_equal(200, error.limit)
      assert_operator(budget.used, :>, 200)
      assert_true(budget.exhausted?)
      assert_equal(0, budget.remaining)
      assert_kind_of(XPath::Aborted, error)
    end

    def test_first_and_each_accept_budget
      doc = build_document(40)

      assert_raise(XPath::BudgetExceeded) do
        XPath.first(doc, QUADRATIC_QUERY, nil, {}, budget: 100)
      end

      assert_raise(XPath::BudgetExceeded) do
        XPath.each(doc, QUADRATIC_QUERY, nil, {}, budget: 100) {|node|}
      end
    end

    def test_abort_is_timely
      doc = build_document(500)
      budget = XPath::Budget.new(500)

      started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, QUADRATIC_QUERY, nil, {}, budget: budget)
      end
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at

      # Without the budget this query does millions of units of work.
      assert_operator(elapsed, :<, 2.0)
      assert_operator(budget.used, :<, 5_000)
      assert_equal(1, XPath.match(doc, "//item[@id='42']").size)
    end

    def test_work_scales_with_document_not_result
      # The result of QUADRATIC_QUERY is one node per element, but the work
      # done to find it grows quadratically because each candidate counts all
      # elements again.  A budget has to follow the work, not the result.
      small = build_document(60)
      large = build_document(120)

      small_budget = XPath::Budget.new
      large_budget = XPath::Budget.new
      XPath.match(small, QUADRATIC_QUERY, nil, {}, budget: small_budget)
      XPath.match(large, QUADRATIC_QUERY, nil, {}, budget: large_budget)

      assert_operator(large_budget.used, :>, small_budget.used * 3)
    end

    def test_predicate_work_is_charged
      doc = build_document(200)
      budget = XPath::Budget.new(50)

      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, "//item[name = 'name199']", nil, {}, budget: budget)
      end
    end

    def test_node_set_comparison_work_is_charged
      doc = build_document(200)
      budget = XPath::Budget.new(50)

      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, "//item[name = //item/name]", nil, {}, budget: budget)
      end
    end

    def test_descendant_traversal_function_work_is_charged
      doc = build_document(400)
      budget = XPath::Budget.new(50)

      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, "//item[string(.) = 'never']", nil, {}, budget: budget)
      end
    end

    def test_axis_traversal_work_is_charged
      doc = build_document(200)
      budget = XPath::Budget.new(50)

      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, "//item/preceding::*", nil, {}, budget: budget)
      end
    end

    def test_cancellation_token
      # XPath.each materialises the whole node set before yielding, so the
      # token is checked during the evaluation, not between the yielded nodes.
      # A token that flips after a number of checks stands in for another
      # thread doing so.
      doc = build_document(150)
      token = Class.new do
        attr_reader :checks

        def initialize(after)
          @after = after
          @checks = 0
        end

        def cancelled?
          @checks += 1
          @checks > @after
        end
      end.new(100)

      error = assert_raise(XPath::Cancelled) do
        XPath.each(doc, QUADRATIC_QUERY, nil, {}, cancellation: token) {|node|}
      end
      assert_kind_of(XPath::Aborted, error)
      assert_operator(token.checks, :>, 100)
    end

    def test_cancellation_from_another_thread
      doc = build_document(250)
      token = XPath::Cancellation.new

      thread = Thread.new do
        begin
          XPath.match(doc, QUADRATIC_QUERY, nil, {}, cancellation: token)
          :completed
        rescue XPath::Cancelled
          :cancelled
        end
      end
      sleep(0.02)
      token.cancel!

      assert_equal(:cancelled, thread.value)
    end

    def test_cancelled_before_start
      doc = build_document(10)
      token = XPath::Cancellation.new
      token.cancel!

      assert_raise(XPath::Cancelled) do
        XPath.match(doc, "//item", nil, {}, cancellation: token)
      end
    end

    def test_budget_cancel
      doc = build_document(250)
      budget = XPath::Budget.new

      thread = Thread.new do
        begin
          XPath.match(doc, QUADRATIC_QUERY, nil, {}, budget: budget)
          :completed
        rescue XPath::Cancelled
          :cancelled
        end
      end
      sleep(0.02)
      budget.cancel!

      assert_equal(:cancelled, thread.value)
    end

    def test_next_query_after_abort_with_same_parser
      doc = build_document(80)
      parser = XPathParser.new
      parser.budget = 100

      assert_raise(XPath::BudgetExceeded) do
        parser.parse(QUADRATIC_QUERY, doc)
      end

      # The aborted evaluation must not leave a half-built node index, a
      # function context or a used-up counter behind.
      parser.budget = 10_000_000
      expected = XPathParser.new.parse("//item[@id='7']/name", doc)
      actual = parser.parse("//item[@id='7']/name", doc)
      assert_equal(expected.map(&:text), actual.map(&:text))
      assert_equal(["name7"], actual.map(&:text))
    end

    def test_next_query_after_abort_without_budget
      doc = build_document(80)
      budget = XPath::Budget.new(50)

      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, QUADRATIC_QUERY, nil, {}, budget: budget)
      end

      assert_equal(["name7"],
                   XPath.match(doc, "//item[@id='7']/name").map(&:text))
      assert_equal(1, XPath.match(doc, "//item[@id='7']/name").size)
      assert_equal(80, XPath.match(doc, "//item").size)
    end

    def test_same_budget_can_be_reused_after_abort
      doc = build_document(80)
      budget = XPath::Budget.new(50)

      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, QUADRATIC_QUERY, nil, {}, budget: budget)
      end

      # The limit is per evaluation; the counter is reset, not carried over.
      budget.limit = 10_000_000
      assert_equal(80, XPath.match(doc, "//item", nil, {}, budget: budget).size)
      assert_operator(budget.used, :>, 0)
      assert_operator(budget.used, :<, 10_000_000)
    end

    def test_position_context_does_not_leak_after_abort
      doc = build_document(30)
      parser = XPathParser.new
      parser.budget = 5

      assert_raise(XPath::BudgetExceeded) do
        parser.parse("//item[last()]", doc)
      end

      parser.budget = 1_000_000
      assert_equal(["name29"],
                   parser.parse("//item[last()]/name", doc).map(&:text))
    end

    def test_repeated_pre_start_cancellation_does_not_corrupt_parser
      doc = build_document(5)
      token = XPath::Cancellation.new
      token.cancel!
      parser = XPathParser.new(cancellation: token)

      5.times do
        assert_raise(XPath::Cancelled) do
          parser.parse("//item", doc)
        end
      end

      token.reset!
      assert_equal(5, parser.parse("//item", doc).size)
    end

    def test_budget_is_per_evaluation_on_parser
      doc = build_document(40)
      parser = XPathParser.new(budget: 200)

      3.times do
        assert_raise(XPath::BudgetExceeded) do
          parser.parse(QUADRATIC_QUERY, doc)
        end
      end

      parser.budget = 10_000_000
      assert_equal(40, parser.parse("//item", doc).size)
    end

    def test_node_set_union_work_is_charged
      doc = build_document(300)
      budget = XPath::Budget.new(50)

      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, "//item | //item/name", nil, {}, budget: budget)
      end
    end

    def test_sort_work_is_charged
      doc = build_document(400)
      budget = XPath::Budget.new(50)

      # Every match has to be put into document order, which walks to the
      # root for each node; that work counts even though the result set is
      # bounded by the query itself.
      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, "//item/ancestor-or-self::*", nil, {}, budget: budget)
      end
    end

    def test_budget_object_interface
      budget = XPath::Budget.new(10)
      assert_equal(10, budget.limit)
      assert_equal(0, budget.used)
      assert_equal(10, budget.remaining)
      assert_false(budget.unlimited?)

      budget.consume(4)
      assert_equal(4, budget.used)
      assert_equal(6, budget.remaining)
      assert_false(budget.exhausted?)

      assert_raise(XPath::BudgetExceeded) { budget.consume(7) }
      assert_true(budget.exhausted?)

      budget.reset!
      assert_equal(0, budget.used)
      assert_false(budget.cancelled?)

      budget.cancel!
      assert_true(budget.cancelled?)
      assert_raise(XPath::Cancelled) { budget.check! }

      unlimited = XPath::Budget.new
      assert_true(unlimited.unlimited?)
      assert_equal(Float::INFINITY, unlimited.remaining)
    end

    def test_invalid_budget
      doc = build_document(3)
      assert_raise(ArgumentError) { XPath::Budget.new(-1) }
      assert_raise(ArgumentError) { XPath.match(doc, "//item", nil, {}, budget: Object.new) }
      assert_raise(ArgumentError) { XPath::Budget.new(1).limit = "lots" }
    end

    def test_zero_limit
      doc = build_document(5)
      budget = XPath::Budget.new(0)

      # Nothing at all may be evaluated without consuming a unit first, so a
      # zero budget stops the query as soon as it starts.
      assert_raise(XPath::BudgetExceeded) do
        XPath.match(doc, "//item", nil, {}, budget: budget)
      end
      assert_equal(1, budget.used)
    end

    def test_budget_via_parser_options
      doc = build_document(10)
      parser = XPathParser.new(budget: 1_000_000)
      assert_equal(10, parser.parse("//item", doc).size)
      assert_operator(parser.budget.used, :>, 0)
      assert_same(parser.budget, parser.budget)
      assert_nil(parser.cancellation)

      token = XPath::Cancellation.new
      parser.cancellation = token
      assert_same(token, parser.cancellation)
      token.cancel!
      parser.budget.limit = 1_000_000
      assert_raise(XPath::Cancelled) { parser.parse("//item", doc) }
    end

    def test_no_budget_by_default
      doc = build_document(10)
      assert_nil(XPathParser.new.budget)
      assert_equal(10, XPath.match(doc, "//item").size)
    end
  end
end

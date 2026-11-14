# frozen_string_literal: false
require_relative 'functions'
require_relative 'xpath_budget'
require_relative 'xpath_parser'

module REXML
  # Wrapper class.  Use this class to access the XPath functions.
  class XPath
    # A base Hash object, supposing to be used when initializing a
    # default empty namespaces set, but is currently unused.
    # TODO: either set the namespaces=EMPTY_HASH, or deprecate this.
    EMPTY_HASH = {}

    # Finds and returns the first node that matches the supplied xpath.
    # element::
    #   The context element
    # path::
    #   The xpath to search for.  If not supplied or nil, returns the first
    #   node matching '*'.
    # namespaces::
    #   If supplied, a Hash which defines a namespace mapping.
    # variables::
    #   If supplied, a Hash which maps $variables in the query
    #   to values. This can be used to avoid XPath injection attacks
    #   or to automatically handle escaping string values.
    #
    #  XPath.first( node )
    #  XPath.first( doc, "//b"} )
    #  XPath.first( node, "a/x:b", { "x"=>"http://doofus" } )
    #  XPath.first( node, '/book/publisher/text()=$publisher', {}, {"publisher"=>"O'Reilly"})
    #
    # A work budget and a cancellation token may be given as options:
    #
    #  XPath.first( doc, "//b", nil, {}, budget: 10_000 )
    #  XPath.first( doc, "//b", nil, {}, budget: REXML::XPath::Budget.new(10_000) )
    #  XPath.first( doc, "//b", nil, {}, cancellation: token )
    def XPath::first(element, path=nil, namespaces=nil, variables={}, options={})
      raise "The namespaces argument, if supplied, must be a hash object." unless namespaces.nil? or namespaces.kind_of?(Hash)
      raise "The variables argument, if supplied, must be a hash object." unless variables.kind_of?(Hash)
      match(element, path, namespaces, variables, options).flatten[0]
    end

    # Iterates over nodes that match the given path, calling the supplied
    # block with the match.
    # element::
    #   The context element
    # path::
    #   The xpath to search for.  If not supplied or nil, defaults to '*'
    # namespaces::
    #   If supplied, a Hash which defines a namespace mapping
    # variables::
    #   If supplied, a Hash which maps $variables in the query
    #   to values. This can be used to avoid XPath injection attacks
    #   or to automatically handle escaping string values.
    #
    #  XPath.each( node ) { |el| ... }
    #  XPath.each( node, '/*[@attr='v']' ) { |el| ... }
    #  XPath.each( node, 'ancestor::x' ) { |el| ... }
    #  XPath.each( node, '/book/publisher/text()=$publisher', {}, {"publisher"=>"O'Reilly"}) \
    #    {|el| ... }
    #
    # See XPath.first for the optional +budget+ and +cancellation+ options.
    def XPath::each(element, path=nil, namespaces=nil, variables={}, options={}, &block)
      raise "The namespaces argument, if supplied, must be a hash object." unless namespaces.nil? or namespaces.kind_of?(Hash)
      raise "The variables argument, if supplied, must be a hash object." unless variables.kind_of?(Hash)
      match(element, path, namespaces, variables, options).each( &block )
    end

    # Names of options that control the work budget.  They are accepted in
    # the trailing options Hash, and also in the namespaces or variables Hash
    # when that is where Ruby put them because the call used keywords, as in
    # XPath.match(doc, "//b", budget: 10_000).
    BUDGET_OPTION_KEYS = [
      :budget,
      :cancellation,
      :cancel,
      :limit,
      :max_work,
      :work_limit,
      :work_budget,
      :budget_limit,
    ].freeze

    # Returns an array of nodes matching a given XPath.
    #
    # The following options are accepted in addition to the options that
    # REXML::XPathParser understands:
    #
    # budget::
    #   A REXML::XPath::Budget, or a numeric work-unit limit.  The
    #   evaluation is stopped with REXML::XPath::BudgetExceeded when it
    #   consumes more work units than the limit.  A budget is reset at the
    #   beginning of each evaluation, so the same object may be reused.
    # cancellation::
    #   A REXML::XPath::Cancellation (or any object responding to
    #   +cancelled?+) that stops the evaluation with
    #   REXML::XPath::Cancelled when cancelled.
    # cancel::
    #   An alias for +cancellation+; a callable is also accepted.
    # limit:, max_work:, work_limit:, budget_limit::
    #   Numeric aliases for the +budget+ limit.  work_budget: is an alias for
    #   +budget+.
    def XPath::match(element, path=nil, namespaces=nil, variables={}, options={})
      raise "The namespaces argument, if supplied, must be a hash object." unless namespaces.nil? or namespaces.kind_of?(Hash)
      raise "The variables argument, if supplied, must be a hash object." unless variables.kind_of?(Hash)

      namespaces = namespaces.dup if namespaces
      variables = variables.dup
      options = options.dup

      budget = nil
      cancellation = nil
      limit = nil
      # Options normally arrive in the trailing Hash.  A call written with
      # keywords puts them in the namespaces slot or the variables slot
      # instead, so look there too; any other key there stays a namespace
      # prefix or a variable.
      shared_budget_key_in_namespaces = false
      [options, namespaces, variables].each do |source|
        next unless source.kind_of?(Hash)
        source.keys.each do |key|
          next unless BUDGET_OPTION_KEYS.include?(key)
          value = source.delete(key)
          case key
          when :budget, :work_budget
            budget = value if budget.nil?
          when :cancellation, :cancel
            cancellation = value if cancellation.nil?
          else
            limit = value if limit.nil?
          end
          if source.equal?(namespaces)
            shared_budget_key_in_namespaces = true
          end
        end
      end
      # If the namespaces slot only carried budget options, no namespace
      # mapping was really supplied; keep the default context lookup.
      if shared_budget_key_in_namespaces && namespaces.empty?
        namespaces = nil
      end

      if budget.is_a?(Numeric)
        budget = Budget.new(budget)
      elsif !budget.nil? && !budget.respond_to?(:consume)
        raise ArgumentError,
              "budget must be a REXML::XPath::Budget or a number: " +
              "<#{budget.inspect}>"
      end
      if !limit.nil? && budget.nil?
        budget = Budget.new(limit)
      end
      budget = Budget.new(nil, cancellation: cancellation) if budget.nil? && cancellation
      if budget && cancellation
        budget.cancellation = cancellation
      end
      options[:budget] = budget unless budget.nil?

      parser = XPathParser.new(**options)
      parser.namespaces = namespaces
      parser.variables = variables
      path = "*" unless path
      parser.parse(path,element)
    end

    def XPath::extract_budget_option(options, key)
      return nil unless options.kind_of?(Hash) && options.key?(key)
      options.delete(key)
    end
    private_class_method :extract_budget_option
  end
end

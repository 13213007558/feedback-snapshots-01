# frozen_string_literal: true

module Loofah
  #
  #  A RuntimeError raised when Loofah could not find an appropriate scrubber.
  #
  class ScrubberNotFound < RuntimeError; end

  #
  #  A Scrubber wraps up a block (or method) that is run on an HTML node (element):
  #
  #    # change all <span> tags to <div> tags
  #    span2div = Loofah::Scrubber.new do |node|
  #      node.name = "div" if node.name == "span"
  #    end
  #
  #  Alternatively, this scrubber could have been implemented as:
  #
  #    class Span2Div < Loofah::Scrubber
  #      def scrub(node)
  #        node.name = "div" if node.name == "span"
  #      end
  #    end
  #    span2div = Span2Div.new
  #
  #  This can then be run on a document:
  #
  #    Loofah.html5_fragment("<span>foo</span><p>bar</p>").scrub!(span2div).to_s
  #    # => "<div>foo</div><p>bar</p>"
  #
  #  Scrubbers can be run on a document in either a top-down traversal (the
  #  default) or bottom-up. Top-down scrubbers can optionally return
  #  Scrubber::STOP to terminate the traversal of a subtree.
  #
  #  Traversal uses an explicit stack and a per-traversal work budget, so the depth of the
  #  document does not consume Ruby's call stack. The budget bounds both node visits and,
  #  optionally, tree depth; when either limit is exceeded, {BudgetExceeded} is raised and the
  #  caller never receives a partially-scrubbed document as if it were a successful result.
  #
  #    budgeted = Loofah::Scrubber.new(max_nodes: 100_000, max_depth: 1_000) do |node|
  #      # ...
  #    end
  #
  class Scrubber
    # Raised when a traversal exceeds its work budget.
    #
    # The document may have been partially modified when this is raised. Callers must treat the
    # scrub as failed rather than using the document's current contents as sanitized output.
    class BudgetExceeded < RuntimeError
      # :max_nodes or :max_depth
      attr_reader :limit_name

      # The configured limit that was exceeded.
      attr_reader :limit

      # The number of nodes visited, including the visit that exceeded the limit.
      attr_reader :nodes

      # The depth of the node that exceeded the limit. A traversal root has depth 0.
      attr_reader :depth

      def initialize(limit_name, limit, nodes, depth)
        @limit_name = limit_name
        @limit = limit
        @nodes = nodes
        @depth = depth
        message = if limit_name == :max_depth
          "scrubber work budget exceeded: node depth #{depth} is greater than max_depth #{limit} " \
            "after visiting #{nodes} nodes"
        else
          "scrubber work budget exceeded: visited more than max_nodes #{limit} nodes"
        end
        super(message)
      end
    end

    # The default maximum number of nodes a single scrub operation may visit.
    DEFAULT_MAX_NODES = 1_000_000

    # Tracks the work performed by one traversal, or by one +scrub!+ call over several roots.
    #
    # A node is charged when its traversal frame is entered. Because every visited node has
    # exactly one frame, this counts every scrubber callback and also bounds the traversal's
    # memory use when a scrubber dynamically creates new children.
    class Budget
      # The maximum number of node visits, or nil for no node limit.
      attr_reader :max_nodes

      # The maximum node depth, or nil for no depth limit. A traversal root has depth 0.
      attr_reader :max_depth

      # The number of nodes visited so far.
      attr_reader :nodes

      def self.validate_limits!(max_nodes, max_depth)
        unless max_nodes.nil? || (max_nodes.is_a?(Integer) && max_nodes >= 0)
          raise ArgumentError, "max_nodes must be a non-negative Integer or nil"
        end

        unless max_depth.nil? || (max_depth.is_a?(Integer) && max_depth >= 0)
          raise ArgumentError, "max_depth must be a non-negative Integer or nil"
        end
      end

      def initialize(max_nodes: Scrubber::DEFAULT_MAX_NODES, max_depth: nil)
        self.class.validate_limits!(max_nodes, max_depth)

        @max_nodes = max_nodes
        @max_depth = max_depth
        @nodes = 0
      end

      # Charge one node visit at +depth+, raising {BudgetExceeded} if a limit is exceeded.
      def consume(depth)
        @nodes += 1

        if !max_nodes.nil? && @nodes > max_nodes
          raise BudgetExceeded.new(:max_nodes, max_nodes, @nodes, depth)
        end

        if !max_depth.nil? && depth > max_depth
          raise BudgetExceeded.new(:max_depth, max_depth, @nodes, depth)
        end

        self
      end
    end

    # Top-down Scrubbers may return CONTINUE to indicate that the subtree should be traversed.
    CONTINUE = Object.new.freeze

    # Top-down Scrubbers may return STOP to indicate that the subtree should not be traversed.
    STOP = Object.new.freeze

    # When a scrubber is initialized, the :direction may be specified
    # as :top_down (the default) or :bottom_up.
    attr_reader :direction

    # The maximum number of nodes this scrubber may visit in one scrub operation.
    def max_nodes
      @budget_limits_configured ? @max_nodes : DEFAULT_MAX_NODES
    end

    # The maximum node depth this scrubber may visit in one scrub operation, or nil for no limit.
    def max_depth
      @budget_limits_configured ? @max_depth : nil
    end

    # When a scrubber is initialized, the optional block is saved as
    # :block. Note that, if no block is passed, then the +scrub+
    # method is assumed to have been implemented.
    attr_reader :block

    #
    #  Options may include
    #    :direction => :top_down (the default)
    #  or
    #    :direction => :bottom_up
    #
    #  and the work budget limits
    #    :max_nodes => 1_000_000 (the default)
    #  or
    #    :max_nodes => nil (unlimited)
    #  and
    #    :max_depth => nil (the default, no depth limit)
    #
    #  For top_down traversals, if the block returns
    #  Loofah::Scrubber::STOP, then the traversal will be terminated
    #  for the current node's subtree.
    #
    #  Alternatively, a Scrubber may inherit from Loofah::Scrubber,
    #  and implement +scrub+, which is slightly faster than using a
    #  block.
    #
    def initialize(options = {}, &block)
      direction = options[:direction] || :top_down
      unless [:top_down, :bottom_up].include?(direction)
        raise ArgumentError, "direction #{direction} must be one of :top_down or :bottom_up"
      end

      @direction = direction
      @block = block

      configure_budget(options)
    end

    #
    #  Set the work limits used by one scrub operation. Subclasses that implement their own
    #  +initialize+ can call this to accept the same +:max_nodes+ and +:max_depth+ options as
    #  Loofah::Scrubber.
    #
    def configure_budget(options) # :nodoc:
      max_nodes = options.fetch(:max_nodes, DEFAULT_MAX_NODES)
      max_depth = options[:max_depth]
      Budget.validate_limits!(max_nodes, max_depth)

      @max_nodes = max_nodes
      @max_depth = max_depth
      @budget_limits_configured = true
      self
    end

    #
    #  Calling +traverse+ will cause the document to be traversed by
    #  either the lambda passed to the initializer or the +scrub+
    #  method, in the direction specified at +new+ time.
    #
    def traverse(node)
      traverse_with_budget(node, new_budget)
    end

    #
    #  Traverse +node+ using +budget+, which may be shared across several roots so that one
    #  +scrub!+ call has one overall budget. Raises {BudgetExceeded} when the budget runs out.
    #
    def traverse_with_budget(node, budget) # :nodoc:
      if direction == :bottom_up
        traverse_bottom_up(node, budget)
      else
        traverse_top_down(node, budget)
      end

      self
    end

    #
    #  Build a fresh work budget from this scrubber's limits. Called once per +scrub!+ operation.
    #
    def new_budget # :nodoc:
      if @budget_limits_configured
        Budget.new(max_nodes: @max_nodes, max_depth: @max_depth)
      else
        # A subclass may implement its own +initialize+ without calling +super+.
        Budget.new
      end
    end

    #
    #  When +new+ is not passed a block, the class may implement
    #  +scrub+, which will be called for each document node.
    #
    def scrub(node)
      raise ScrubberNotFound, "No scrub method has been defined on #{self.class}"
    end

    #
    # If the attribute is not set, add it
    # If the attribute is set, don't overwrite the existing value
    #
    def append_attribute(node, attribute, value)
      current_value = node.get_attribute(attribute) || ""
      current_values = current_value.split(/\s+/)
      updated_value = current_values | [value]
      node.set_attribute(attribute, updated_value.join(" "))
    end

    private

    def html5lib_sanitize(node)
      case node.type
      when Nokogiri::XML::Node::ELEMENT_NODE
        if HTML5::Scrub.allowed_element?(node.name)
          HTML5::Scrub.scrub_attributes(node)
          return Scrubber::CONTINUE
        end
      when Nokogiri::XML::Node::TEXT_NODE, Nokogiri::XML::Node::CDATA_SECTION_NODE
        if HTML5::Scrub.cdata_needs_escaping?(node)
          node.before(HTML5::Scrub.cdata_escape(node))
          return Scrubber::STOP
        end
        return Scrubber::CONTINUE
      end
      Scrubber::STOP
    end

    #
    # An explicit frame replaces a Ruby call frame. Each frame captures its children at the
    # moment the recursive implementation evaluated `node.children`, so tree mutations affect
    # the pending nodes in exactly the same order as before:
    #
    # * top-down evaluates `node.children` after the scrubber returns and before descending;
    # * bottom-up evaluates `node.children` on entry and scrubs the node after its children.
    #
    # Children are held in a live Nokogiri NodeSet, not flattened. A node removed by a sibling
    # stays reachable from the snapshot and is still visited, as it was before.
    #
    TOP_DOWN_FRAME = Struct.new(:node, :depth, :children, :length, :index)
    BOTTOM_UP_FRAME = Struct.new(:node, :depth, :children, :length, :index, :scrubbed)

    def scrub_node(node)
      block ? block.call(node) : scrub(node)
    end

    def traverse_top_down(root, budget)
      budget.consume(0)
      stack = [TOP_DOWN_FRAME.new(root, 0, nil, 0, 0)]

      until stack.empty?
        frame = stack.last

        if frame.children.nil?
          if scrub_node(frame.node) == STOP
            stack.pop
            next
          end

          frame.children = frame.node.children
          frame.length = frame.children.length
          frame.index = 0
          next
        end

        if frame.index >= frame.length
          stack.pop
          next
        end

        child = frame.children[frame.index]
        frame.index += 1
        budget.consume(frame.depth + 1)
        stack.push(TOP_DOWN_FRAME.new(child, frame.depth + 1, nil, 0, 0))
      end
    end

    def traverse_bottom_up(root, budget)
      budget.consume(0)
      stack = [BOTTOM_UP_FRAME.new(root, 0, root.children, root.children.length, 0, false)]

      until stack.empty?
        frame = stack.last

        if frame.index < frame.length
          child = frame.children[frame.index]
          frame.index += 1
          budget.consume(frame.depth + 1)
          children = child.children
          stack.push(BOTTOM_UP_FRAME.new(child, frame.depth + 1, children, children.length, 0, false))
          next
        end

        unless frame.scrubbed
          frame.scrubbed = true
          scrub_node(frame.node)
        end

        stack.pop
      end
    end
  end
end

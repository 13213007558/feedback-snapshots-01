# frozen_string_literal: false

require_relative "xpath"

module REXML
  # Raised when an XPath expression uses a capability that would let a rule
  # author observe nodes outside the tenant subtree handed to
  # RestrictedXPath.
  #
  # The expression is rejected before it is evaluated, so no part of it runs
  # against the surrounding document.  RestrictedXPath never silently drops
  # the offending step and returns a narrowed result: an expression that asks
  # for something outside the subtree always fails loudly instead of producing
  # an answer that looks like an authorization decision.
  class XPathBoundaryError < ParseException
  end

  # Evaluates rule-author supplied XPath expressions against a single tenant
  # subtree, with a hard boundary around that subtree.
  #
  # A regular REXML::XPath query runs against the whole document and can walk
  # from the supplied context node to anywhere else (a parent axis, an
  # absolute path, or a node variable can all reach a neighbouring tenant).
  # RestrictedXPath closes those routes:
  #
  # - the context node is treated as the only observable root;
  # - the parsed expression is statically checked and rejected if it names a
  #   capability that crosses the boundary (see FORBIDDEN_TOKENS);
  # - the evaluated node-set is checked again at runtime, so a result can only
  #   ever contain the tenant root or one of its descendants.
  #
  # Everything needed for ordinary in-subtree rules still works: child and
  # descendant paths, predicates with position(), functions, attribute and
  # namespace-prefixed node tests, and the arithmetic, boolean and string
  # XPath operators.
  class RestrictedXPath
    # Path tokens that never leave the subtree and are therefore accepted.
    ALLOWED_TOKENS = [
      # Forward, downward or self-only navigation rooted at the context node.
      :child, :attribute, :self,
      :descendant, :descendant_or_self,
      # Node tests: name, wildcard, node(), text(), comment(),
      # processing-instruction(), namespace-prefixed names.
      :qname, :any, :node, :text, :comment, :processing_instruction,
      # Predicates and grouping.
      :predicate, :group,
      # Literals and value expressions.
      :literal,
      # Comparison / boolean / arithmetic / unary operators.
      :eq, :neq, :lt, :lteq, :gt, :gteq,
      :and, :or, :not, :neg,
      :div, :mod, :mult, :plus, :minus,
      # Function calls; the function name is checked separately.
      :function,
    ].freeze

    # Expressions naming one of these tokens can observe nodes outside the
    # subtree, so they are rejected.  Each maps to the reason surfaced in the
    # XPathBoundaryError message.
    FORBIDDEN_TOKENS = {
      :document =>
        "absolute paths ('/' and '//') reset the context to the document root",
      :parent =>
        "the parent axis ('..' and 'parent::') climbs out of the subtree",
      :ancestor =>
        "the ancestor axis climbs out of the subtree",
      :ancestor_or_self =>
        "the ancestor-or-self axis climbs out of the subtree",
      :preceding =>
        "the preceding axis reaches nodes outside the subtree",
      :preceding_sibling =>
        "the preceding-sibling axis reaches sibling tenants",
      :following =>
        "the following axis reaches nodes outside the subtree",
      :following_sibling =>
        "the following-sibling axis reaches sibling tenants",
      :namespace =>
        "the namespace axis exposes in-scope namespaces inherited from ancestors",
      :union =>
        "the union operator ('|') combines independently evaluated paths",
      :variable =>
        "node variables ('$name') can carry nodes from outside the subtree",
    }.freeze

    # Functions that are safe inside the boundary.  Every XPath function REXML
    # implements is listed here except +lang+, which walks up the ancestor
    # chain reading +xml:lang+ and therefore observes nodes above the tenant.
    ALLOWED_FUNCTIONS = %w[
      boolean
      ceiling
      concat
      contains
      count
      false
      floor
      id
      last
      local-name
      name
      namespace-uri
      normalize-space
      not
      number
      position
      round
      starts-with
      string
      string-length
      substring
      substring-after
      substring-before
      sum
      translate
      true
    ].freeze

    # Validates a parsed XPath expression, raising XPathBoundaryError if it
    # uses any capability that could observe a node outside the subtree.
    #
    # This walks the same nested-array AST produced by
    # REXML::Parsers::XPathParser, so predicates, grouped sub-expressions,
    # function arguments and operator operands are all inspected.
    def self.validate!(path_stack)
      each_token(path_stack) do |token|
        next unless token.is_a?(Symbol)

        if FORBIDDEN_TOKENS.key?(token)
          raise XPathBoundaryError.new(
            "Restricted XPath rejected :#{token}: #{FORBIDDEN_TOKENS[token]}"
          )
        end

        unless ALLOWED_TOKENS.include?(token)
          raise XPathBoundaryError.new(
            "Restricted XPath rejected unsupported token :#{token}"
          )
        end
      end

      validate_functions!(path_stack)
    end

    # Recursively yields every leaf of the (possibly nested) AST.
    def self.each_token(node, &block)
      case node
      when Array
        node.each { |child| each_token(child, &block) }
      else
        yield node
      end
    end
    private_class_method :each_token

    # Function nodes are [:function, name, [args]].  The name and every
    # argument expression are checked; +lang+ is the one built-in function
    # whose own implementation escapes the subtree.
    def self.validate_functions!(node)
      case node
      when Array
        if node[0] == :function
          name = node[1].to_s
          unless ALLOWED_FUNCTIONS.include?(name)
            raise XPathBoundaryError.new(
              "Restricted XPath rejected function '#{name}()': " \
              "it can observe nodes outside the subtree"
            )
          end
        end
        node.each { |child| validate_functions!(child) }
      end
    end
    private_class_method :validate_functions!

    # The single node that defines the boundary: it and its descendants.
    attr_reader :root

    # Builds a restricted entry point for one tenant subtree.
    #
    # root::
    #   The element (or other node) handed to the rule author.  It becomes the
    #   only observable root.
    # namespaces::
    #   Optional Hash mapping prefixes to namespace URIs, exactly as accepted
    #   by REXML::XPath.  Namespace-prefixed queries stay available.
    def initialize(root, namespaces = nil)
      unless root.is_a?(REXML::Node)
        raise TypeError, "root must be a REXML::Node"
      end

      @root = root
      @namespaces = namespaces
    end

    # Returns every node matching +path+ inside the subtree, in document
    # order.  Raises XPathBoundaryError if +path+ crosses the boundary.
    def match(path = "*")
      evaluate(path)
    end

    # Returns the first node matching +path+ inside the subtree, or nil.
    def first(path = "*")
      match(path).first
    end

    # Yields each node matching +path+ inside the subtree.  Returns an
    # Enumerator when no block is given.
    def each(path = "*", &block)
      return to_enum(__method__, path) unless block

      match(path).each(&block)
    end

    private

    def evaluate(path)
      grammar = REXML::Parsers::XPathParser.new
      ast = grammar.parse(path.nil? ? "*" : path)
      self.class.validate!(ast)

      # No variables hash is ever supplied, so even if a future grammar change
      # let a :variable token through it resolves to an empty string rather
      # than a caller-provided node.
      engine = REXML::XPathParser.new
      engine.namespaces = @namespaces
      result = engine.match(ast, @root)

      enforce_boundary(result)
    end

    # Defence in depth: independently confirm every returned node is the root
    # or one of its descendants.  A non-node scalar result (boolean, number or
    # string from a comparison) is returned untouched.
    def enforce_boundary(nodes)
      nodes.each do |node|
        next unless node.is_a?(REXML::Node)
        unless within_subtree?(node)
          raise XPathBoundaryError.new(
            "Restricted XPath produced a node outside the subtree; " \
            "the expression was not allowed to do this"
          )
        end
      end
      nodes
    end

    def within_subtree?(node)
      current = node
      while current
        return true if current.equal?(@root)

        # An attribute hangs off its element via #element rather than #parent.
        current = current.is_a?(REXML::Attribute) ? current.element : current.parent
      end
      false
    end
  end
end

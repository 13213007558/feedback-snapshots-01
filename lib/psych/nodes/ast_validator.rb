# frozen_string_literal: true
require_relative '../exception'

module Psych
  module Nodes
    # An ASTValidator verifies that a hand-built or plugin-modified YAML AST
    # still satisfies the structural invariants that a parser-produced tree is
    # guaranteed to have.  Psych's visitors (Psych::Visitors::ToRuby and
    # Psych::Visitors::Emitter) assume those invariants hold; feeding them a
    # malformed tree otherwise causes low level errors such as +NoMethodError+,
    # +RuntimeError+ or +SystemStackError+, and can drive object construction
    # hooks with attacker chosen state.
    #
    # The walk is iterative, so a tree that loops back on itself through its
    # real +children+ links is reported as Psych::InvalidAST instead of
    # overflowing the stack.  Psych::Nodes::Alias nodes are terminal and only
    # name an anchor; they never create object identity sharing, so aliases that
    # conform to YAML semantics are accepted rather than mistaken for cycles.
    #
    # The checks performed are:
    #
    # * every node is one of the known Psych::Nodes kinds with well-formed
    #   attributes,
    # * the parent/child relationship rules documented in Psych::Nodes,
    # * a legal root (Stream, Document, or a single content node),
    # * every Mapping has an even number of children (complete key/value
    #   pairs),
    # * terminal nodes (Scalar, Alias) carry no children,
    # * no node object is reachable twice, which covers both real children
    #   cycles and cross-document node reuse,
    # * every Alias names a non-empty anchor defined inside the same document.
    class ASTValidator
      # Nodes that may legally appear below a Sequence or a Mapping.
      CONTENT_KINDS = [Mapping, Sequence, Scalar, Alias].freeze

      # Nodes that may be handed in as the entry point.  A bare Alias can never
      # be a document root (there is no preceding anchor to resolve it against).
      ROOT_KINDS = [Stream, Document, Mapping, Sequence, Scalar].freeze

      # Validate +root+, returning it unchanged when it is well formed and
      # raising Psych::InvalidAST otherwise.
      def self.validate! root
        new.validate!(root)
      end

      # Return +true+ when +root+ passes validation without raising.
      def self.valid? root
        validate!(root)
        true
      rescue Psych::InvalidAST
        false
      end

      def validate! root
        unless root.is_a?(Psych::Nodes::Node) &&
               ROOT_KINDS.any? { |kind| root.is_a?(kind) }
          raise Psych::InvalidAST,
                "expected a Psych::Nodes root (Stream, Document, Mapping, " \
                "Sequence or Scalar), got #{root.class}"
        end

        @seen = {}.compare_by_identity
        @documents = {}
        @next_document_id = 0

        implicit_document = root.is_a?(Psych::Nodes::Node) &&
                             !root.stream? && !root.document?
        root_document = implicit_document ? new_document : nil

        stack = [[root, nil, root_document]]
        until stack.empty?
          node, parent_kind, document_id = stack.pop
          visit(node, parent_kind, document_id, stack)
        end

        verify_alias_targets
        root
      end

      private

      def new_document
        id = @next_document_id
        @next_document_id += 1
        @documents[id] = { anchors: {}.compare_by_identity, anchor_names: {}, aliases: [] }
        id
      end

      def visit node, parent_kind, document_id, stack
        unless node.is_a?(Psych::Nodes::Node)
          raise Psych::InvalidAST,
                "child must be a Psych::Nodes::Node, got #{node.inspect}"
        end

        if @seen.key?(node)
          raise Psych::InvalidAST,
                "#{node.class} node is reachable more than once: real " \
                "children cycles and cross-document node reuse are not " \
                "permitted (use an Alias node to share an anchored value)"
        end
        @seen[node] = true

        case node
        when Stream   then visit_stream(node, parent_kind, stack)
        when Document then visit_document(node, parent_kind, stack)
        when Sequence then visit_sequence(node, parent_kind, document_id, stack)
        when Mapping  then visit_mapping(node, parent_kind, document_id, stack)
        when Scalar   then visit_scalar(node, parent_kind, document_id)
        when Alias    then visit_alias(node, parent_kind, document_id)
        else
          raise Psych::InvalidAST, "unknown node kind #{node.class}"
        end      end

      def visit_stream node, parent_kind, stack
        unless parent_kind.nil?
          raise Psych::InvalidAST, "Stream may only be the root node"
        end

        if node.children.empty?
          raise Psych::InvalidAST, "Stream must contain at least one Document"
        end

        node.children.reverse_each do |child|
          unless child.is_a?(Document)
            raise Psych::InvalidAST,
                  "Stream children must be Document nodes, got #{child.class}"
          end
          stack << [child, :stream, nil]
        end
      end

      def visit_document node, parent_kind, stack
        unless parent_kind.nil? || parent_kind == :stream
          raise Psych::InvalidAST,
                "Document may only be the root or a child of Stream"
        end

        unless node.children.length == 1
          raise Psych::InvalidAST,
                "Document must have exactly one root node, got " \
                "#{node.children.length}"
        end

        child = node.children.first
        unless child.is_a?(Mapping) || child.is_a?(Sequence) || child.is_a?(Scalar)
          raise Psych::InvalidAST,
                "Document root must be a Mapping, Sequence or Scalar, " \
                "got #{child.class}"
        end

        document_id = new_document
        stack << [child, :document, document_id]
      end

      def visit_sequence node, parent_kind, document_id, stack
        check_content_parent(node, parent_kind)
        record_anchor(node, document_id)
        push_content_children(node, document_id, stack)
      end

      def visit_mapping node, parent_kind, document_id, stack
        check_content_parent(node, parent_kind)
        record_anchor(node, document_id)

        if node.children.length.odd?
          raise Psych::InvalidAST,
                "Mapping has #{node.children.length} children: mappings need " \
                "an even number so every key has a value"
        end

        push_content_children(node, document_id, stack)
      end

      def visit_scalar node, parent_kind, document_id
        check_content_parent(node, parent_kind)
        unless node.value.is_a?(String)
          raise Psych::InvalidAST,
                "Scalar value must be a String, got #{node.value.class}"
        end
        ensure_terminal(node)
        record_anchor(node, document_id)
      end

      def visit_alias node, parent_kind, document_id
        unless parent_kind == :sequence || parent_kind == :mapping
          raise Psych::InvalidAST,
                "Alias may only appear inside a Sequence or Mapping"
        end
        ensure_terminal(node)
        unless node.anchor.is_a?(String) && !node.anchor.empty?
          raise Psych::InvalidAST, "Alias must name a non-empty anchor"
        end

        if document_id.nil?
          raise Psych::InvalidAST, "Alias appears outside of a document"
        end
        @documents.fetch(document_id)[:aliases] << node.anchor
      end

      # Scalar and Alias do not initialize their inherited +@children+ array,
      # so the reader returns nil for a pristine terminal node.  Either way a
      # terminal node must expose no children.
      def ensure_terminal node
        children = node.children
        return if children.nil? || children.empty?

        raise Psych::InvalidAST,
              "#{node.class} is terminal and cannot have children"
      end

      def check_content_parent node, parent_kind
        return if parent_kind.nil? ||
                  %i[document sequence mapping].include?(parent_kind)

        raise Psych::InvalidAST,
              "#{node.class} cannot be a child in this position"
      end

      def push_content_children node, document_id, stack
        kind = node.mapping? ? :mapping : :sequence
        node.children.reverse_each do |child|
          unless CONTENT_KINDS.any? { |allowed| child.is_a?(allowed) }
            raise Psych::InvalidAST,
                  "#{node.class} children must be Mapping, Sequence, Scalar " \
                  "or Alias, got #{child.class}"
          end
          stack << [child, kind, document_id]
        end
      end

      def record_anchor node, document_id
        anchor = node.anchor
        return if anchor.nil?

        unless anchor.is_a?(String) && !anchor.empty?
          raise Psych::InvalidAST, "anchor must be a non-empty String"
        end
        return if document_id.nil?

        record = @documents.fetch(document_id)
        record[:anchors][node] = true
        record[:anchor_names][anchor] = true
      end

      def verify_alias_targets
        @documents.each_value do |record|
          record[:aliases].each do |anchor|
            unless record[:anchor_names].key?(anchor)
              raise Psych::InvalidAST,
                    "Alias references anchor #{anchor.inspect} that is not " \
                    "defined in the same document"
            end
          end
        end
      end
    end
  end
end

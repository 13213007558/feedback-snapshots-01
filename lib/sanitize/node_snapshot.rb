# frozen_string_literal: true

class Sanitize
  # Captures the state of the DOM tree containing a node so it can be restored
  # if sanitization raises an exception.
  #
  # The snapshot is only used on the failure path. On success nothing is
  # restored, so the sanitized tree is committed in place exactly as before.
  #
  # Transformers have unrestricted access to the tree, so they can move,
  # replace, detach, or merge nodes in ways Nokogiri can't always undo. This
  # class restores the captured structure and content by reusing every node
  # that's still usable and recreating any node whose underlying Nokogiri node
  # was destroyed. See the `Sanitize#node!` documentation for the guarantees
  # this provides to callers.
  #
  # @api private
  class NodeSnapshot
    ELEMENT_NODE = Nokogiri::XML::Node::ELEMENT_NODE
    TEXT_NODE = Nokogiri::XML::Node::TEXT_NODE
    COMMENT_NODE = Nokogiri::XML::Node::COMMENT_NODE
    CDATA_SECTION_NODE = Nokogiri::XML::Node::CDATA_SECTION_NODE
    PI_NODE = Nokogiri::XML::Node::PI_NODE
    DTD_NODE = Nokogiri::XML::Node::DTD_NODE
    DOCUMENT_NODE = Nokogiri::XML::Node::DOCUMENT_NODE
    HTML_DOCUMENT_NODE = Nokogiri::XML::Node::HTML_DOCUMENT_NODE

    DOCUMENT_NODES = [DOCUMENT_NODE, HTML_DOCUMENT_NODE].freeze
    CONTENT_NODES = [TEXT_NODE, COMMENT_NODE, CDATA_SECTION_NODE, PI_NODE].freeze

    XMLNS_NS = "http://www.w3.org/2000/xmlns/"

    # State captured for a single node.
    #
    # @api private
    Entry = Struct.new(
      :node,
      :type,
      :parent,
      :name,
      :namespace,
      :attributes,
      :content,
      :children,
      keyword_init: true
    )

    # @param node [Nokogiri::XML::Node] the node being sanitized
    def initialize(node)
      # Transformers can reach the whole document through `node.document` and
      # can move nodes into or out of the sanitized subtree, so the snapshot
      # covers the topmost tree rather than just the node passed in.
      @root = topmost(node)
      @document = @root.document
      @entries = []
      @entries_by_object_id = {}
      @doctype = nil

      capture(@root)
    end

    # Restores the captured tree.
    def restore
      # Do this first: merging is only detectable while the captured wrappers
      # still share their underlying nodes, and replacing stale wrappers would
      # obscure it.
      replace_merged_text_nodes

      replace_destroyed_nodes(current_tree_ids)
      restore_structure
      restore_intrinsics
      restore_doctype
      restore_root_position
    end

    private

    # Returns the highest node in the tree that contains _node_. The document
    # is included when _node_ belongs to one.
    def topmost(node)
      top = node

      while top.respond_to?(:parent) && top.parent
        top = top.parent
      end

      top
    end

    def capture(node)
      entry = Entry.new(
        node: node,
        type: node.type,
        parent: (node.parent if node.respond_to?(:parent)),
        name: nil,
        namespace: nil,
        attributes: nil,
        content: nil,
        children: node.children.to_a.reject { |child| child.type == DTD_NODE }
      )

      case node.type
      when ELEMENT_NODE
        entry.name = node.name
        entry.namespace = node.namespace
        entry.attributes = capture_attributes(node)
      when PI_NODE
        entry.name = node.name
        entry.content = node.content
      when *CONTENT_NODES
        entry.content = node.content
      when DTD_NODE
        @doctype = [node.name, node.external_id, node.system_id]
      end

      if DOCUMENT_NODES.include?(node.type)
        @doctype ||= doctype_info(node)
      end

      @entries << entry
      @entries_by_object_id[node.object_id] = entry
      entry.children.each { |child| capture(child) }
    end

    def capture_attributes(node)
      node.attribute_nodes.map do |attr|
        [attr.name, attr.value, attr.namespace&.href, attr.namespace&.prefix]
      end
    end

    def doctype_info(document)
      dtd = document.internal_subset
      dtd && [dtd.name, dtd.external_id, dtd.system_id]
    end

    # Returns the object ids of the Ruby wrappers currently in the tree.
    def current_tree_ids
      ids = Set.new

      walk = lambda do |node|
        ids << node.object_id
        node.children.each { |child| walk.call(child) }
      end

      walk.call(@root)
      ids
    end

    # Nokogiri may destroy a node's underlying representation when a node is
    # merged with a text sibling or adopted into another document. When that
    # happens, the captured wrapper becomes a stale view of a node that's no
    # longer in the tree. Detect those wrappers and replace them with fresh
    # nodes built from the captured state. Wrappers that are merely detached
    # are still usable and are kept.
    def replace_destroyed_nodes(tree_ids)
      @entries.each do |entry|
        next if entry.node.equal?(@root)
        next if DOCUMENT_NODES.include?(entry.type)
        next if usable?(entry, tree_ids)

        replace_entry_node(entry)
      end
    end

    # Nokogiri merges adjacent text nodes when one is inserted next to another.
    # The merge keeps one wrapper and destroys the others' underlying nodes, so
    # every wrapper involved is either the merged node itself or a stale view of
    # it. Rather than leave a stale wrapper pointing at the node that replaced
    # it (where a write would silently corrupt a neighboring node), detach the
    # merged node and rebuild each original text node from its captured content.
    def replace_merged_text_nodes
      @entries
        .select { |entry| entry.type == TEXT_NODE && entry.node.respond_to?(:pointer_id) }
        .group_by { |entry| entry.node.pointer_id }
        .each_value do |entries|
          next if entries.length < 2

          merged = entries.first.node
          merged.unlink if merged.respond_to?(:parent) && merged.parent

          replacements = entries.to_h do |entry|
            [entry.node.object_id, Nokogiri::XML::Text.new(entry.content, @document)]
          end

          entries.each { |entry| entry.node = replacements.fetch(entry.node.object_id) }

          # Point the captured child lists of any parent in the group at the
          # replacements. The captured wrappers are distinct even though their
          # pointer ids are shared, so matching by object id is unambiguous.
          @entries.each do |parent_entry|
            parent_entry.children = parent_entry.children.map do |child|
              replacements.fetch(child.object_id, child)
            end
          end
        end
    end

    def usable?(entry, tree_ids)
      # A wrapper that's present in the tree is usable as-is.
      return true if tree_ids.include?(entry.node.object_id)

      # A wrapper whose node was adopted into another document was rewrapped by
      # Nokogiri and can't be reused.
      return false unless entry.node.document.equal?(@document)

      # Nokogiri leaves a stale wrapper's `parent` pointing at its former
      # parent even after replacing the underlying node, but that parent's
      # child list contains the replacement instead. A genuinely detached node
      # either has no parent or its parent still contains its exact wrapper.
      node = entry.node
      return true unless node.respond_to?(:parent)

      parent = node.parent
      return true if parent.nil?

      parent.children.any? { |child| child.equal?(node) }
    end

    def replace_entry_node(entry, replacement = build_replacement(entry))
      previous = entry.node
      entry.node = replacement

      parent_entry = @entries_by_object_id[entry.parent&.object_id]
      return unless parent_entry

      parent_entry.children = parent_entry.children.map do |child|
        child.equal?(previous) ? replacement : child
      end
    end

    def build_replacement(entry)
      case entry.type
      when TEXT_NODE
        Nokogiri::XML::Text.new(entry.content, @document)
      when COMMENT_NODE
        Nokogiri::XML::Comment.new(@document, entry.content)
      when CDATA_SECTION_NODE
        Nokogiri::XML::CDATA.new(@document, entry.content)
      when PI_NODE
        Nokogiri::XML::ProcessingInstruction.new(@document, entry.name, entry.content)
      when ELEMENT_NODE
        element = @document.create_element(entry.name)
        assign_namespace(element, entry.namespace)
        element
      else
        entry.node
      end
    end

    def assign_namespace(element, namespace)
      return if namespace.nil? || namespace.href.nil?

      current = element.namespace
      return if current && current.href == namespace.href && current.prefix == namespace.prefix

      element.namespace = element.add_namespace_definition(namespace.href, namespace.prefix)
    rescue ArgumentError, TypeError
      nil
    end

    def restore_structure
      @entries.each do |entry|
        next if entry.type == DTD_NODE

        restore_children(entry)
      end
    end

    def restore_children(entry)
      node = entry.node
      saved = entry.children
      actual = children_of(node)

      return if same_children?(actual, saved)

      saved.each_with_index do |child, index|
        actual = children_of(node)

        next if actual[index]&.equal?(child)

        if index < actual.length
          insert_before(actual[index], child)
        else
          append_child(node, child)
        end
      end

      (children_of(node)[saved.length..] || []).each(&:unlink)
    end

    def children_of(node)
      children = node.children.to_a
      DOCUMENT_NODES.include?(node.type) ? children.reject { |child| child.type == DTD_NODE } : children
    end

    def same_children?(actual, saved)
      actual.length == saved.length &&
        actual.each_with_index.all? { |child, index| child.equal?(saved[index]) }
    end

    def insert_before(anchor, node)
      anchor.add_previous_sibling(node)
    end

    def append_child(parent, node)
      parent.add_child(node)
    end

    def restore_intrinsics
      @entries.each do |entry|
        node = entry.node

        case entry.type
        when ELEMENT_NODE
          restore_element(node, entry)
        when *CONTENT_NODES
          node.content = entry.content unless node.content == entry.content
        end
      end
    end

    def restore_element(node, entry)
      node.name = entry.name unless node.name == entry.name

      restore_namespace(node, entry.namespace)
      restore_attributes(node, entry.attributes)
    end

    def restore_namespace(node, namespace)
      current = node.namespace

      return if same_namespace?(current, namespace)

      if namespace.nil?
        node.namespace = nil
        return
      end

      begin
        node.namespace = namespace
      rescue ArgumentError
        assign_namespace(node, namespace)
      end
    end

    def same_namespace?(a, b)
      if a.nil? || b.nil?
        a.nil? && b.nil?
      else
        a.href == b.href && a.prefix == b.prefix
      end
    end

    def restore_attributes(node, saved)
      current = node.attribute_nodes.to_a

      if same_attribute_structure?(current, saved)
        current.each_with_index do |attr, index|
          value = saved[index][1]
          attr.value = value unless attr.value == value
        end

        return
      end

      current.each(&:unlink)

      deferred = []

      saved.each do |name, value, namespace_href, namespace_prefix|
        key = attribute_key(name, namespace_href, namespace_prefix)

        begin
          node[key] = value
        rescue ArgumentError
          # The namespace prefix may be declared by an attribute that hasn't
          # been restored yet. Retry after all other attributes are in place.
          deferred << [key, value]
        end
      end

      deferred.each do |key, value|
        begin
          node[key] = value
        rescue ArgumentError
          # Give up on the namespace prefix and restore at least the value.
          node[key.split(":").last] = value
        end
      end
    end

    # Returns true if _current_ and _saved_ describe the same attributes in the
    # same order. Values aren't compared, since they can be updated in place.
    def same_attribute_structure?(current, saved)
      return false unless current.length == saved.length

      current.each_with_index.all? do |attr, index|
        name, _value, namespace_href, namespace_prefix = saved[index]

        attr.name == name &&
          attr.namespace&.href == namespace_href &&
          (attr.namespace&.prefix || nil) == (namespace_prefix || nil)
      end
    end

    def attribute_key(name, namespace_href, namespace_prefix)
      if namespace_href == XMLNS_NS
        name == "xmlns" ? "xmlns" : "xmlns:#{name}"
      elsif namespace_prefix
        "#{namespace_prefix}:#{name}"
      else
        name
      end
    end

    def restore_doctype
      return unless DOCUMENT_NODES.include?(@root.type)

      document = @root
      current = document.internal_subset

      if @doctype.nil?
        current&.unlink
        return
      end

      name, external_id, system_id = @doctype

      return if current &&
        current.name == name &&
        current.external_id == external_id &&
        current.system_id == system_id

      current&.unlink
      document.create_internal_subset(name, external_id, system_id)
    end

    # The snapshot root is always parentless. If a transformer attached it
    # somewhere during the failed attempt, detach it again.
    def restore_root_position
      return unless @root.respond_to?(:parent) && @root.parent

      @root.unlink
    end
  end
end

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
  class Scrubber
    # Top-down Scrubbers may return CONTINUE to indicate that the subtree should be traversed.
    CONTINUE = Object.new.freeze

    # Top-down Scrubbers may return STOP to indicate that the subtree should not be traversed.
    STOP = Object.new.freeze

    # Returned by the html5lib sanitizer when it replaced the node (for example, by escaping
    # unsafe CDATA content). The calling sanitizer must stop without recording a second change.
    REPLACED = Object.new.freeze # :nodoc:

    # When a scrubber is initialized, the :direction may be specified
    # as :top_down (the default) or :bottom_up.
    attr_reader :direction

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
    end

    #
    #  Calling +traverse+ will cause the document to be traversed by
    #  either the lambda passed to the initializer or the +scrub+
    #  method, in the direction specified at +new+ time.
    #
    #  If an +evidence+ recorder is given, it is told about every change this scrubber makes. The
    #  built-in scrubbers report explicit reasons. Custom block scrubbers are compared against a
    #  snapshot taken around each call, so their changes are attributed to the scratch call that
    #  made them and never to the parser.
    #
    def traverse(node, evidence: nil)
      return traverse_without_evidence(node) unless evidence

      @evidence = evidence
      evidence.note_scrub_document(node.document)
      evidence.with_step(self) do
        direction == :bottom_up ? traverse_conditionally_bottom_up(node) : traverse_conditionally_top_down(node)
      end
    ensure
      @evidence = nil
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

    def traverse_without_evidence(node)
      direction == :bottom_up ? traverse_conditionally_bottom_up(node) : traverse_conditionally_top_down(node)
    end

    def html5lib_sanitize(node)
      case node.type
      when Nokogiri::XML::Node::ELEMENT_NODE
        if HTML5::Scrub.allowed_element?(node.name)
          HTML5::Scrub.scrub_attributes(node, evidence: @evidence)
          return Scrubber::CONTINUE
        end
      when Nokogiri::XML::Node::TEXT_NODE, Nokogiri::XML::Node::CDATA_SECTION_NODE
        if HTML5::Scrub.cdata_needs_escaping?(node)
          escaped = HTML5::Scrub.cdata_escape(node)
          record_rewrite(node, reason: :unsafe_cdata_escaped, replacement_nodes: [escaped],
            details: { replacement: escaped.cdata? ? :cdata : :text })
          node.before(escaped)
          return Scrubber::REPLACED
        end
        return Scrubber::CONTINUE
      end
      Scrubber::STOP
    end

    def traverse_conditionally_top_down(node)
      if block
        return if call_with_evidence(node) { |inner| block.call(inner) } == STOP
      elsif scrub_with_evidence(node) == STOP
        return
      end
      node.children.each { |j| traverse_conditionally_top_down(j) }
    end

    def traverse_conditionally_bottom_up(node)
      node.children.each { |j| traverse_conditionally_bottom_up(j) }
      if block
        call_with_evidence(node) { |inner| block.call(inner) }
      else
        scrub_with_evidence(node)
      end
    end

    # -- evidence helpers ---------------------------------------------------

    def scrub_with_evidence(node)
      return scrub(node) unless @evidence
      return scrub(node) if explicit_evidence?

      snapshot = evidence_snapshot(node)
      result = scrub(node)
      evidence_compare(node, snapshot, :custom_scrubber)
      result
    end

    def call_with_evidence(node)
      return yield(node) unless @evidence
      return yield(node) if explicit_evidence?

      snapshot = evidence_snapshot(node)
      result = yield(node)
      evidence_compare(node, snapshot, :custom_scrubber)
      result
    end

    def explicit_evidence?
      defined?(Loofah::Scrubbers::MAP) && Loofah::Scrubbers::MAP.value?(self.class)
    end

    def record_removal(node, reason:, path: nil, parent: nil, details: {})
      return unless @evidence

      @evidence.record_removal(
        node: node,
        reason: reason,
        path: path || @evidence.path_for(node),
        parent: parent,
        details: details,
      )
    end

    def record_unwrap(node, reason:, retained_nodes:, path: nil, parent: nil, details: {})
      return unless @evidence

      retained_nodes = retained_nodes.select { |child| attached?(child) }

      @evidence.record_unwrap(
        node: node,
        reason: reason,
        retained_nodes: retained_nodes,
        path: path || @evidence.path_for(node),
        parent: parent,
        details: details.merge(unwrapped_replacement_child: true),
      )
    end

    def record_rewrite(node, reason:, target: nil, path: nil, replacement_nodes: [], details: {})
      return unless @evidence

      @evidence.record_rewrite(
        node: node,
        reason: reason,
        target: target,
        path: path || @evidence.path_for(node),
        replacement_nodes: replacement_nodes,
        details: details,
      )
    end

    def record_attribute_change(node, attribute_name, value, reason)
      return unless @evidence

      before = node[attribute_name]
      after = append_attribute_value(before, value)
      return if before == after

      record_attribute_rewrite(node, attribute_name, reason: reason, before_value: before, after_value: after)
    end

    def append_attribute_value(current_value, value)
      current_values = (current_value || "").split(/\s+/)
      (current_values | [value]).join(" ")
    end

    def evidence_path(node)
      @evidence&.path_for(node)
    end

    def record_attribute_removal(node, attribute, reason:, before_value: nil, details: {})
      return unless @evidence

      @evidence.record_attribute_removal(
        node: node,
        attribute: attribute,
        reason: reason,
        before_value: before_value,
        details: details,
      )
    end

    def record_attribute_rewrite(node, attribute, reason:, before_value: nil, after_value: nil,
      target: :attribute, details: {})
      return unless @evidence

      @evidence.record_attribute_rewrite(
        node: node,
        attribute: attribute,
        reason: reason,
        before_value: before_value,
        after_value: after_value,
        target: target,
        details: details,
      )
    end

    def evidence_snapshot(node)
      entries = []
      stack = [node]
      until stack.empty?
        current = stack.pop
        attributes = if current.element?
          current.attribute_nodes.map do |attribute|
            [HTML5::Scrub.prefixed_attribute_name(attribute), attribute.value]
          end
        end
        entries << {
          node: current,
          path: @evidence.path_for(current),
          attached: attached?(current),
          parent: current.parent,
          name: current.name,
          attributes: attributes,
          content: (current.text.dup if current.text? || current.cdata? || current.comment?),
        }
        stack.concat(current.children.to_a) if current.element?
      end
      entries
    end

    def evidence_compare(root, snapshot, reason)
      recorded = {}.compare_by_identity
      snapshot.each do |before|
        node = before[:node]
        next unless before[:attached]

        if attached?(node)
          evidence_compare_attached(before, reason, recorded)
        else
          ancestor_recorded = false
          ancestor = before[:parent]
          while ancestor
            if recorded[ancestor]
              ancestor_recorded = true
              break
            end
            ancestor = ancestor.respond_to?(:parent) ? ancestor.parent : nil
          end
          if ancestor_recorded
            recorded[node] = true
          else
            evidence_record_detached(before, reason)
            recorded[node] = true
          end
        end
      end
    end

    def evidence_compare_attached(before, reason, recorded)
      node = before[:node]
      if node.element?
        current = node.attribute_nodes.to_h { |attribute| [HTML5::Scrub.prefixed_attribute_name(attribute), attribute] }
        (before[:attributes] || []).each do |name, old_value|
          attribute = current[name]
          if attribute.nil?
            record_attribute_removal(node, name, reason: reason)
          elsif attribute.value != old_value
            record_attribute_rewrite(node, name, reason: reason,
              before_value: old_value, after_value: attribute.value)
          end
        end
        (current.keys - (before[:attributes] || []).map(&:first)).each do |name|
          record_attribute_rewrite(node, name, reason: reason, after_value: current[name].value,
            details: { added: true })
        end
        if before[:name] != node.name
          record_rewrite(node, reason: reason, target: :element, path: before[:path],
            details: {
              from_tag: @evidence.safe_label(before[:name]),
              to_tag: @evidence.safe_label(node.name),
            })
        end
      elsif before[:content] && before[:content] != node.text
        record_rewrite(node, reason: reason, target: evidence_target(node), path: before[:path])
      end
      if before[:parent] && !node.document? && !before[:parent].equal?(node.parent)
        @evidence.record_move(node: node, reason: :node_moved, previous_path: before[:path])
      end
      recorded[node] = true
    end

    def evidence_record_detached(before, reason)
      node = before[:node]
      retained = node.children.select { |child| attached?(child) } if node.element?
      if retained && !retained.empty?
        record_unwrap(node, reason: reason, retained_nodes: retained, path: before[:path])
      else
        record_removal(node, reason: reason, path: before[:path])
      end
    end

    def evidence_target(node)
      case node.type
      when Nokogiri::XML::Node::TEXT_NODE then :text
      when Nokogiri::XML::Node::COMMENT_NODE then :comment
      when Nokogiri::XML::Node::CDATA_SECTION_NODE then :cdata
      else :node
      end
    end

    def attached?(node)
      current = node
      while current
        return true if current.document? || current.type == Nokogiri::XML::Node::DOCUMENT_FRAG_NODE

        current = current.parent
      end
      false
    end
  end
end

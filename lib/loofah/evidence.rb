# frozen_string_literal: true

require "digest"
require "json"

module Loofah
  #
  #  Optional, opt-in records of what a scrubber changed and why.
  #
  #  A Recorder is passed to <tt>scrub!</tt>:
  #
  #    recorder = Loofah::Evidence::Recorder.new
  #    doc = Loofah.html5_fragment(unsafe_html)
  #    doc.scrub!(:prune, evidence: recorder)
  #    recorder.entries # => [#<Loofah::Evidence::Entry ...>, ...]
  #
  #  Every entry identifies the scrubber step that produced it, the structural location of the
  #  affected node, a symbolic reason, and (when a node survives) a stable node id. Node ids are
  #  assigned in traversal order, so replaying the same input with the same scrubbers produces the
  #  same ids and entries.
  #
  #  The default recorder keeps only summaries and structural information. Attribute values, text
  #  content, comments, CSS declarations, and URLs are not copied into the record. Pass
  #  <tt>include_values: true</tt> only when the record is kept in a trusted, local debugging
  #  context: even then values of sensitive-looking attributes and URL query strings are redacted.
  #
  #  Parser diagnostics are kept in a separate <tt>parser_notices</tt> list. A parser can repair
  #  malformed markup before any scrubber runs (for example, by implying end tags or inserting a
  #  <tt>tbody</tt> element). Those repairs are never reported as scrubber actions. If evidence is
  #  requested while parsing (for example,
  #  <tt>Loofah.html5_fragment(input, evidence: recorder)</tt>), diagnostics are collected into
  #  that separate list. Scrubbing an already-parsed document leaves the list empty and records
  #  that diagnostics were not collected.
  #
  module Evidence
    SCHEMA = "loofah.evidence.v1"

    # Number of parser diagnostics collected when evidence is requested while parsing.
    DEFAULT_MAX_PARSER_NOTICES = 100

    # Actions that a scrubber can apply to a node or an attribute.
    ACTIONS = [
      :removed,           # a node and its subtree, or a single attribute, was removed
      :unwrapped,         # a node was removed but its children were kept in its place
      :rewritten,         # a node's content or shape was replaced
      :moved,             # a node was re-parented and remains in the tree
      :attribute_removed,
      :attribute_rewritten,
      :diagnostic,        # a parser report, never a scrubber action
    ].freeze

    # Targets of a change.
    TARGETS = [:element, :attribute, :style, :text, :comment, :cdata, :parser, :node].freeze

    # When a change cannot be attributed to a concrete parent node (for example, the document
    # fragment itself), the parent is reported as this sentinel instead of a node id.
    ROOT = :root

    # Attribute names whose values are never included, even when values are opted in.
    SENSITIVE_ATTRIBUTE = /\A(?:password|passwd|pwd|secret|token|api[-_]?key|apikey|auth|authorization|session|cookie|csrf|xsrf|otp|pin|value)\z/i

    # Attributes whose values are URLs, and therefore need query-string redaction when values are
    # opted in.
    URL_ATTRIBUTE = /\A(?:href|src|action|formaction|poster|cite|background|longdesc|manifest|ping|xlink:href)\z/i

    # A scrubber-reported change, or a parser diagnostic when actor is :parser.
    class Entry
      attr_reader :id, :step, :scrubber, :actor, :action, :reason, :target,
        :path, :line, :column, :node, :parent, :attribute,
        :retained_nodes, :replacement_nodes, :summary, :details

      def initialize(id:, step:, scrubber:, actor:, action:, reason:, target:, path: nil,
        line: nil, column: nil, node: nil, parent: nil, attribute: nil,
        retained_nodes: [], replacement_nodes: [], summary: nil, details: {})
        @id = id
        @step = step
        @scrubber = scrubber
        @actor = actor
        @action = action
        @reason = reason
        @target = target
        @path = path
        @line = line
        @column = column
        @node = node
        @parent = parent
        @attribute = attribute
        @retained_nodes = retained_nodes.freeze
        @replacement_nodes = replacement_nodes.freeze
        @summary = summary
        @details = details.freeze
        freeze
      end

      def parser?
        actor == :parser
      end

      def to_h
        {
          id: id,
          step: step,
          scrubber: scrubber,
          actor: actor,
          action: action,
          reason: reason,
          target: target,
          path: path,
          line: line,
          column: column,
          node: node,
          parent: parent,
          attribute: attribute,
          retained_nodes: retained_nodes,
          replacement_nodes: replacement_nodes,
          summary: summary,
          details: details,
        }.reject { |_key, value| value.nil? || value == [] || value == {} }
      end
    end

    class << self
      # Returns the recorder for an evidence option, or nil when evidence is off.
      def resolve(evidence)
        return nil if evidence.nil?
        return evidence if evidence.is_a?(Recorder)

        raise ArgumentError, "not a Loofah::Evidence::Recorder: #{evidence.inspect}"
      end

      # Records the parser's own diagnostics separately from scrubber changes.
      def capture_parser_diagnostics(recorder, parsed)
        return unless recorder

        if parsed.respond_to?(:errors) || (parsed.respond_to?(:document) && parsed.document.respond_to?(:errors))
          recorder.capture_parser_diagnostics(parsed)
        else
          recorder.parser_diagnostics_unavailable!
        end
      end
    end

    #
    #  Collects the evidence for one or more scrub operations.
    #
    class Recorder
      attr_reader :entries, :parser_notices, :steps, :input_metadata
      attr_reader :include_values, :capture_parser, :max_parser_notices

      def initialize(include_values: false, capture_parser: true, max_parser_notices: 100)
        @entries = []
        @parser_notices = []
        @steps = []
        @nodes = []
        @node_ids = {}.compare_by_identity
        @input_metadata = nil
        @include_values = !!include_values
        @capture_parser = !!capture_parser
        @max_parser_notices = Integer(max_parser_notices)
        @parser_notices_truncated = false
        @parser_capture = :not_requested
        @next_entry = 0
        @next_node = 0
        @step = 0
        @step_depth = 0
      end

      # Records metadata about the source input without retaining the input itself.
      # Only String inputs can be digested; an IO has already been consumed by the parser.
      def note_input(input, format:, collector: nil)
        @parser_capture = :capable if collector && capture_parser
        return unless input.is_a?(String)

        @input_metadata ||= {
          format: format.to_sym,
          bytesize: input.bytesize,
          digest: "sha256:#{Digest::SHA256.hexdigest(input)}",
        }
      end

      # Records that scrubbing started on an already-parsed document. Such a document was parsed
      # without a recorder unless a recorder supplied it during parsing, so diagnostics were not
      # collected and parser repairs are explicitly out of scope for this record.
      def note_scrub_document(document)
        @scrubbed_documents ||= {}.compare_by_identity
        return if @scrubbed_documents[document]

        @scrubbed_documents[document] = true
        @parser_capture = :not_collected if @parser_capture == :not_requested
      end

      # Marks this recorder as attached to a parser without a diagnostics interface.
      def parser_diagnostics_unavailable!
        @parser_capture = :unavailable unless @parser_capture == :capable
      end

      # Whether diagnostics could be and were collected: :collected, :not_collected (the document
      # was parsed without an evidence recorder), :disabled (the recorder opted out), or
      # :unavailable (the parser has no diagnostics interface).
      def parser_diagnostics_status
        @parser_capture == :capable ? :collected : @parser_capture
      end

      # Starts a numbered scrubber step. Returns the step number. The step is also opened when a
      # change is recorded before any traversal started (for example, a direct call to the HTML5
      # attribute scrubber).
      def begin_step(scrubber)
        @step += 1
        @steps << { index: @step, scrubber: scrubber_label(scrubber), entries: 0 }
        @step
      end

      # Runs the block as one scrubber step. Nested calls (for example, a fragment traversal that
      # invokes +traverse+ once per top-level child) share the step started by the outermost call.
      def with_step(scrubber)
        if @step_depth.zero?
          begin_step(scrubber)
        end
        @step_depth += 1
        begin
          yield
        ensure
          @step_depth -= 1
        end
      end

      # Returns the index of the current step, or zero before any step has started.
      attr_reader :step

      # Returns a stable id for a node, assigning one on first use. Ids depend only on the
      # order in which nodes are encountered, not on object identity across runs. Once a node is
      # detached, its current path is no longer meaningful, so `nodes` reports its first path
      # instead.
      def node_id(node, path: nil)
        return nil unless node

        @node_ids[node] ||= begin
          @next_node += 1
          id = format("n-%04d", @next_node)
          @nodes << {
            id: id,
            node: node,
            first_path: path || path_for(node),
            first_step: @step,
          }
          id
        end
      end

      # Returns the Node registered for an id, or nil if the id is unknown.
      def node(id)
        @nodes.find { |entry| entry[:id] == id }&.fetch(:node)
      end

      # Returns the stable id previously assigned to a node, without assigning a new one.
      def id_for(node)
        @node_ids[node]
      end
      alias_method :node_id_for, :id_for

      # Returns a conservative label for an element or attribute name, for use in summaries.
      def safe_label(name, fallback: "node")
        safe_name(name, fallback: fallback)
      end

      # Returns the structural path for a node, rooted at its document or document fragment.
      #
      # Element segments are ns:name[index], and sibling indexes count only siblings of the same
      # kind. Detached nodes have no path.
      def path_for(node)
        return nil unless node
        return "/" if root_node?(node)

        segments = []
        current = node
        while current && !root_node?(current)
          parent = current.parent
          return nil unless parent

          segments << segment_for(current)
          current = parent
        end
        "/#{segments.reverse.join("/")}"
      end

      # Returns every node referenced by the record, in the order ids were assigned.
      #
      # Each hash contains the stable id, the current structural path (nil once detached), the
      # node kind, whether the node is still attached to the scrubbed tree, and the first path at
      # which the node was observed.
      def nodes
        @nodes.filter_map do |entry|
          node = entry[:node]
          retained = attached?(node)

          {
            id: entry[:id],
            path: retained ? path_for(node) : nil,
            retained: retained,
            target: target_for(node),
            tag: node.element? ? safe_name(node.name) : nil,
            first_path: entry[:first_path],
            first_step: entry[:first_step],
          }.reject { |_key, value| value.nil? }
        rescue StandardError
          nil
        end
      end

      # Returns the nodes that are still attached after all recorded operations, in the same form
      # as `nodes` but without the `retained` flag (which is true for every item).
      def final_nodes
        nodes.select { |entry| entry[:retained] }.map do |entry|
          entry.reject { |key, _value| key == :retained }
        end
      end

      # Captures parse diagnostics from a parsed document or document fragment. Diagnostics for
      # the same document are recorded at most once per recorder. Returns the number recorded.
      #
      # Parsing must have been configured to collect diagnostics (for HTML5, pass
      # <tt>max_errors:</tt>); otherwise the list is empty even for malformed input. Repairs the
      # parser made silently are therefore never presented as scrubber actions and are only
      # visible when the parser itself was asked to report them.
      def capture_parser_diagnostics(source)
        unless capture_parser
          @parser_capture = :disabled if @parser_capture == :not_requested
          return 0
        end
        return 0 unless source

        @parser_capture = :capable
        document = source.respond_to?(:document) ? source.document : nil
        identity = document || source
        @diagnosed_documents ||= {}.compare_by_identity
        return 0 if @diagnosed_documents[identity]

        @diagnosed_documents[identity] = true
        errors = if source.respond_to?(:errors)
          source.errors
        elsif document&.respond_to?(:errors)
          document.errors
        else
          []
        end
        record_parser_errors(errors)
      rescue StandardError
        0
      end

      # Records a parser diagnostic. The raw message is never stored because Nokogiri includes
      # the offending source line in it; only the stable diagnostic code and position are kept.
      def record_parser_error(error)
        return unless capture_parser

        if parser_notices.length >= max_parser_notices
          @parser_notices_truncated = true
          return
        end

        code = safe_diagnostic_code(error)
        line = positive_integer(error.line)
        column = positive_integer(error.column)
        level = positive_integer(error.level)
        summary = "parser reported diagnostic #{code}"
        summary += " at line #{line}" if line
        summary += " column #{column}" if line && column

        add_entry(
          actor: :parser,
          action: :diagnostic,
          reason: :parser_diagnostic,
          target: :parser,
          line: line,
          column: column,
          summary: summary,
          details: { code: code, level: level }.reject { |_key, value| value.nil? },
        )
      end

      def record_parser_errors(errors)
        Array(errors).each { |error| record_parser_error(error) }
      end

      # A node was removed with its subtree.
      def record_removal(node:, reason:, parent: nil, path: nil, details: {})
        parent = parent_or_root(node.parent) if parent.nil?
        details = details.merge(subtree_summary(node))
        add_node_entry(
          node: node,
          parent: parent,
          path: path,
          action: :removed,
          reason: reason,
          target: target_for(node),
          details: details,
        )
      end

      # A node was removed but its children were moved into its place.
      def record_unwrap(node:, reason:, retained_nodes:, parent: nil, path: nil, details: {})
        parent = parent_or_root(node.parent) if parent.nil?
        retained_ids = retained_nodes.map { |child| node_id(child) }
        details = details.merge(
          retained_node_count: retained_nodes.length,
          retained_element_count: retained_nodes.count(&:element?),
          retained_text_count: retained_nodes.count(&:text?),
        )
        add_node_entry(
          node: node,
          parent: parent,
          path: path,
          action: :unwrapped,
          reason: reason,
          target: target_for(node),
          retained_nodes: retained_ids,
          details: details,
        )
      end

      # A node's content or shape was replaced.
      def record_rewrite(node:, reason:, target: nil, path: nil, replacement_nodes: [], details: {})
        replacement_ids = replacement_nodes.map { |replacement| node_id(replacement) }
        add_node_entry(
          node: node,
          parent: parent_or_root(node.parent),
          path: path,
          action: :rewritten,
          reason: reason,
          target: target || target_for(node),
          replacement_nodes: replacement_ids,
          details: details,
        )
      end

      # An attribute was removed from a surviving element.
      def record_attribute_removal(node:, attribute:, reason:, before_value: nil, details: {})
        add_attribute_entry(
          node: node,
          attribute: attribute,
          action: :attribute_removed,
          reason: reason,
          before_value: before_value,
          details: details,
        )
      end

      # A node was moved to a different parent without being removed.
      def record_move(node:, reason:, previous_path:, details: {})
        add_node_entry(
          node: node,
          parent: parent_or_root(node.parent),
          path: previous_path,
          action: :moved,
          reason: reason,
          target: target_for(node),
          details: details,
        )
      end

      # An attribute value was changed on a surviving element.
      def record_attribute_rewrite(node:, attribute:, reason:, before_value: nil,
        after_value: nil, target: :attribute, details: {})
        add_attribute_entry(
          node: node,
          attribute: attribute,
          action: :attribute_rewritten,
          reason: reason,
          before_value: before_value,
          after_value: after_value,
          target: target,
          details: details,
        )
      end

      # Returns a stable digest of the record, suitable for comparing two runs over the same
      # input. Runtime node ids and object ids are not included.
      def fingerprint
        canonical = {
          schema: SCHEMA,
          loofah_version: Loofah::VERSION,
          input: input_metadata,
          steps: steps,
          entries: entries.map(&:to_h),
          parser_notices: parser_notices.map(&:to_h),
          nodes: nodes,
        }
        "sha256:#{Digest::SHA256.hexdigest(JSON.generate(canonical))}"
      end

      def to_h
        {
          schema: SCHEMA,
          loofah_version: Loofah::VERSION,
          redaction: include_values ? :opt_in_values : :summary,
          input: input_metadata,
          parser_diagnostics: parser_diagnostics_status,
          parser_notices_truncated: @parser_notices_truncated,
          steps: steps,
          entries: entries.map(&:to_h),
          parser_notices: parser_notices.map(&:to_h),
          nodes: nodes,
          final_nodes: final_nodes,
          fingerprint: fingerprint,
        }.reject { |_key, value| value.nil? }
      end

      def as_json(*)
        to_h
      end

      def to_json(*args)
        JSON.generate(to_h, *args)
      end

      private

      def add_node_entry(node:, parent:, path:, action:, reason:, target:, retained_nodes: [],
        replacement_nodes: [], details: {})
        path ||= path_for(node)
        add_entry(
          actor: :scrubber,
          action: action,
          reason: reason,
          target: target,
          path: path,
          line: positive_integer(node.line),
          column: safe_column(node),
          node: node_id(node, path: path),
          parent: parent == ROOT || parent.nil? ? nil : node_id(parent),
          retained_nodes: retained_nodes,
          replacement_nodes: replacement_nodes,
          summary: summarize(action: action, reason: reason, node: node, target: target),
          details: details,
        )
      end

      def add_attribute_entry(node:, attribute:, action:, reason:, before_value: nil,
        after_value: nil, target: :attribute, details: {})
        attribute_name = safe_name(attribute)
        details = details.dup
        if include_values
          before_value = present_value(before_value, attribute_name)
          after_value = present_value(after_value, attribute_name)
          details[:before] = before_value unless before_value.nil?
          details[:after] = after_value unless after_value.nil?
        end

        add_entry(
          actor: :scrubber,
          action: action,
          reason: reason,
          target: target,
          path: "#{path_for(node)}/@#{attribute_name}",
          line: positive_integer(node.line),
          column: safe_column(node),
          node: node_id(node),
          attribute: attribute_name,
          summary: summarize(
            action: action,
            reason: reason,
            node: node,
            attribute: attribute_name,
            target: target,
          ),
          details: details,
        )
      end

      def add_entry(**attributes)
        begin_step(:unattributed) if @steps.empty? && attributes[:actor] != :parser
        @next_entry += 1
        entry = Entry.new(id: format("ev-%04d", @next_entry), step: @step, scrubber: current_scrubber, **attributes)
        if entry.parser?
          parser_notices << entry
        else
          entries << entry
          steps.last[:entries] += 1 if steps.last
        end
        entry
      end

      def current_scrubber
        steps.last&.fetch(:scrubber) || "none"
      end

      def scrubber_label(scrubber)
        return scrubber.to_s if scrubber.is_a?(Symbol)
        return "custom block" if scrubber.is_a?(Scrubber) && scrubber.block

        name = scrubber.class.name
        name && !name.empty? ? name : "custom scrubber"
      end

      def segment_for(node)
        name = case node.type
        when Nokogiri::XML::Node::ELEMENT_NODE
          prefix = node.namespace&.prefix
          safe_name(prefix ? "#{prefix}:#{node.name}" : node.name)
        when Nokogiri::XML::Node::TEXT_NODE
          "text()"
        when Nokogiri::XML::Node::COMMENT_NODE
          "comment()"
        when Nokogiri::XML::Node::CDATA_SECTION_NODE
          "cdata()"
        else
          safe_name(node.node_name, fallback: "node()")
        end
        "#{name}[#{sibling_index(node)}]"
      end

      def sibling_index(node)
        index = 1
        sibling = node.previous_sibling
        while sibling
          index += 1 if same_segment_kind?(sibling, node)
          sibling = sibling.previous_sibling
        end
        index
      end

      def same_segment_kind?(left, right)
        return false unless left.type == right.type
        return left.name == right.name if left.element?

        true
      end

      def root_node?(node)
        node.document? || node.type == Nokogiri::XML::Node::DOCUMENT_FRAG_NODE
      end

      def parent_or_root(node)
        return ROOT if node.nil? || root_node?(node)

        node
      end

      def attached?(node)
        current = node
        while current
          return true if root_node?(current)

          current = current.parent
        end
        false
      end

      def target_for(node)
        case node.type
        when Nokogiri::XML::Node::ELEMENT_NODE then :element
        when Nokogiri::XML::Node::TEXT_NODE then :text
        when Nokogiri::XML::Node::COMMENT_NODE then :comment
        when Nokogiri::XML::Node::CDATA_SECTION_NODE then :cdata
        else :node
        end
      end

      def subtree_summary(node)
        nodes = 0
        elements = 0
        text_bytes = 0
        comments = 0
        stack = [node]
        until stack.empty?
          current = stack.pop
          nodes += 1
          elements += 1 if current.element?
          comments += 1 if current.comment?
          text_bytes += current.text.bytesize if current.text? || current.cdata?
          stack.concat(current.children.to_a) if current.element?
        end
        {
          subtree_nodes: nodes,
          subtree_elements: elements,
          subtree_text_bytes: text_bytes,
          subtree_comments: comments,
        }
      end

      def safe_name(name, fallback: "node")
        name = name.to_s
        return name if name.match?(/\A[A-Za-z][A-Za-z0-9._:-]{0,63}\z/)

        fallback
      end

      def positive_integer(value)
        number = value.to_i
        number.positive? ? number : nil
      rescue StandardError
        nil
      end

      def safe_column(node)
        column = positive_integer(node.column) if node.respond_to?(:column)
        column
      rescue StandardError
        nil
      end

      def safe_diagnostic_code(error)
        if error.respond_to?(:str1) && error.str1
          safe_name(error.str1, fallback: "diagnostic")
        elsif error.respond_to?(:code)
          "libxml2 code #{error.code.to_i}"
        else
          "diagnostic"
        end
      rescue StandardError
        "diagnostic"
      end

      def present_value(value, attribute_name)
        return nil if value.nil?
        return "[REDACTED]" if attribute_name.match?(SENSITIVE_ATTRIBUTE)

        string = value.to_s
        if attribute_name.match?(URL_ATTRIBUTE) || attribute_name == "style"
          string = redact_urls_in(string)
        end
        truncate(string)
      end

      # Removes userinfo and query/fragment data from every URL-like token in the string, so a
      # CSS declaration that embeds a URL is redacted as well. The scheme and host remain, which
      # is enough to explain a decision without retaining a credential or a query string.
      def redact_urls_in(value)
        string = value.gsub(%r{\b([a-z][a-z0-9+.-]*://)[^\s/@]*@}i, "\\1[REDACTED]@")
        string = string.gsub(/(\?)[^\s"'#;)]*/) { "#{::Regexp.last_match(1)}[REDACTED]" }
        string.gsub(/(#)[^\s"');]*/) { "#{::Regexp.last_match(1)}[REDACTED]" }
      end

      def truncate(value, limit = 200)
        string = value.to_s
        string = string.scrub unless string.valid_encoding?
        return string if string.bytesize <= limit

        "#{string.byteslice(0, limit)}...[truncated]"
      end

      def summarize(action:, reason:, node: nil, target: nil, attribute: nil, visible_attribute: nil)
        tag = node&.element? ? "<#{safe_name(node.name)}>" : nil
        case action
        when :removed
          "removed #{tag || target || "node"} (#{reason_text(reason)})"
        when :unwrapped
          "unwrapped #{tag || "node"}, kept its children (#{reason_text(reason)})"
        when :rewritten
          "rewrote #{tag || target || "node"} (#{reason_text(reason)})"
        when :moved
          "moved #{tag || target || "node"} (#{reason_text(reason)})"
        when :attribute_removed
          "removed attribute #{attribute || safe_name(visible_attribute)} from #{tag || "element"} (#{reason_text(reason)})"
        when :attribute_rewritten
          kind = target == :style ? "style attribute" : "attribute #{attribute || safe_name(visible_attribute)}"
          "rewrote #{kind} on #{tag || "element"} (#{reason_text(reason)})"
        when :diagnostic
          "parser diagnostic (#{reason_text(reason)})"
        else
          "#{action} #{tag || target || "node"} (#{reason_text(reason)})"
        end
      end

      def reason_text(reason)
        reason.to_s.tr("_", " ")
      end
    end
  end
end

# frozen_string_literal: true

require_relative 'nodes/node'
require_relative 'exception'

module Psych
  # = Psych::Redactor
  #
  # Emits a redacted copy of a YAML document while preserving the graph
  # semantics of the parsed Psych AST (anchors, aliases, merge keys and
  # cycles).
  #
  # The caller declares sensitive *paths*.  When a value reachable through
  # one of those paths is shared with another location - through an alias, a
  # YAML merge key (<tt><<</tt>) or a cycle - every syntactic and effective
  # occurrence of that value is hidden as well, so the sensitive value can no
  # longer be reconstructed from the emitted copy.
  #
  # The parsed tree handed in by the caller is never mutated: redaction runs
  # against a new, cycle-safe copy and the original nodes stay usable.
  #
  #   result = Psych::Redactor.redact(yaml, paths: [["db", "password"]])
  #   puts result.yaml
  #   result.additional_paths.each { |entry| puts entry }
  class Redactor
    # Path segment that targets a mapping *key* instead of the value paired
    # with it.  Appended to the value's path, e.g.
    # <tt>["headers", "X-Api-Key", Psych::Redactor::KEY]</tt> redacts that
    # key while leaving its value in place.
    KEY = :"__redact_key__"

    # Default replacement rendered in place of a hidden scalar or key.
    DEFAULT_REPLACEMENT = "[REDACTED]"

    MERGE_KEY = "<<"
    private_constant :MERGE_KEY

    # One redaction recorded in RedactionResult#hidden_paths.
    #
    # +path+::   path segments from the document root to the hidden node
    # +reason+:: +:requested+, +:alias+, +:merge+, +:cycle+, +:shared_key+
    #            or +:contained+
    # +role+::   +:value+ or +:key+
    Entry = Struct.new(:path, :reason, :role, keyword_init: true) do
      def to_s
        "#{Redactor.format_path(path)} [#{role}/#{reason}]"
      end
    end

    # Outcome of a redaction run.
    #
    # +yaml+::          redacted YAML string, safe to emit
    # +tree+::          new Psych::Nodes::Document/Stream behind +yaml+
    # +requested+::     normalized paths supplied by the caller
    # +hidden_paths+::  Entry list, starting with the requested paths and
    #                   followed by the additional paths hidden because they
    #                   shared a sensitive value
    class RedactionResult
      attr_reader :yaml, :tree, :requested, :hidden_paths

      def initialize(yaml, tree, requested, hidden_paths)
        @yaml = yaml
        @tree = tree
        @requested = requested
        @hidden_paths = hidden_paths
      end

      # Entries hidden in addition to the requested paths: aliases, merge
      # contributions, cycle back edges, shared keys and descendants of
      # redacted containers.
      def additional_paths
        @hidden_paths.reject { |entry| entry.reason == :requested }
      end
    end

    # Raised when a requested sensitive path cannot be resolved.  Redaction
    # fails closed instead of silently skipping the path.
    class PathNotFound < Psych::Exception
    end

    # Shortcut for Redactor.new(replacement: ...).redact(...).
    def self.redact(yaml_or_tree, paths:, replacement: DEFAULT_REPLACEMENT)
      new(replacement: replacement).redact(yaml_or_tree, paths: paths)
    end

    def initialize(replacement: DEFAULT_REPLACEMENT)
      @replacement = replacement
    end

    # Redacts +yaml_or_tree+ (a YAML String, Psych::Nodes::Document or
    # Psych::Nodes::Stream) according to +paths+ and returns a
    # RedactionResult.  The input tree is never modified.
    def redact(yaml_or_tree, paths:)
      original = parse(yaml_or_tree)
      requested = paths.map { |path| normalize_path(path) }

      @anchors = build_anchor_map(original)
      @sensitive = {}.compare_by_identity
      requested.each { |path| mark_requested_path(original, path) }

      hidden_paths = enumerate(original, requested)
      redacted_tree = copy(original)

      RedactionResult.new(emit(redacted_tree), redacted_tree, requested, hidden_paths)
    end

    # A standalone Document cannot emit itself (the emitter only opens a
    # stream on a Stream node), so wrap single-document output for emission.
    def emit(tree)
      target = tree.is_a?(Nodes::Stream) ? tree : Nodes::Stream.new.tap { |stream| stream.children << tree }
      target.yaml
    end

    # Human-readable rendering of a path, e.g. <tt>$.prod.<<.password</tt> or
    # <tt>$.servers[0].host</tt>.
    def self.format_path(path)
      rendered = +"$"
      path.each do |segment|
        if segment.equal?(KEY)
          rendered << ".<key>"
        elsif segment.is_a?(Integer)
          rendered << "[#{segment}]"
        else
          rendered << ".#{segment}"
        end
      end
      rendered
    end

    private

    def parse(yaml_or_tree)
      case yaml_or_tree
      when Nodes::Document, Nodes::Stream
        yaml_or_tree
      when String
        parsed = Psych.parse(yaml_or_tree)
        if parsed == false
          raise ArgumentError, "cannot redact an empty YAML document: no nodes to traverse"
        end
        parsed
      else
        raise ArgumentError,
          "expected a YAML String, Psych::Nodes::Document or Psych::Nodes::Stream, got #{yaml_or_tree.class}"
      end
    end

    def normalize_path(path)
      valid = path.is_a?(Array) && path.all? do |segment|
        segment.is_a?(String) || segment.is_a?(Integer) || segment.equal?(KEY)
      end
      raise ArgumentError, "paths must be Arrays of String/Integer segments, got #{path.inspect}" unless valid

      path.dup
    end

    # Index of anchor name -> defining node, built from the AST graph.
    def build_anchor_map(root)
      map = {}
      visit = lambda do |node|
        if node.respond_to?(:anchor) && node.anchor && !node.is_a?(Nodes::Alias)
          map[node.anchor] = node
        end
        children = node.respond_to?(:children) ? node.children : nil
        children&.each { |child| visit.call(child) }
      end
      visit.call(root)
      map
    end

    def dereference(node)
      node.is_a?(Nodes::Alias) ? @anchors.fetch(node.anchor) : node
    end

    # --- requested path resolution ---------------------------------------

    def documents_of(root)
      root.is_a?(Nodes::Stream) ? root.children : [root]
    end

    # Applies one requested path to every document in which it resolves.  A
    # path must resolve in at least one document or redaction fails closed.
    def mark_requested_path(root, path)
      matched = false
      documents_of(root).each do |document|
        node = resolve_in_document(document, path)
        next if node.nil?

        matched = true
        mark_sensitive(node)
      end
      raise PathNotFound, "sensitive path not found: #{self.class.format_path(path)}" unless matched
    end

    def resolve_in_document(document, path)
      node = document_root(document)
      path.each_with_index do |segment, index|
        node =
          if segment.equal?(KEY)
            key_node_for(document_root(document), path[0...index])
          else
            descend(node, segment)
          end
        return nil if node.nil?
      end
      node
    end

    def document_root(document)
      document.children.first
    end

    # Returns the key node paired with the value located at +value_path+.
    def key_node_for(document, value_path)
      return nil if value_path.empty?

      mapping = dereference(follow_path(document, value_path[0...-1]))
      value = dereference(follow_path(document, value_path))
      return nil unless mapping.is_a?(Nodes::Mapping)

      mapping.children.each_slice(2) do |key, paired_value|
        return key if dereference(paired_value).equal?(value)
      end
      nil
    end

    def follow_path(document, path)
      path.reduce(document) { |node, segment| descend(node, segment) }
    end

    def descend(node, segment)
      target = dereference(node)
      case target
      when Nodes::Mapping
        target.children.each_slice(2) do |key, value|
          next if merge_key?(key)
          named = dereference(key)
          return value if named.is_a?(Nodes::Scalar) && named.value == segment
        end
        nil
      when Nodes::Sequence
        segment.is_a?(Integer) ? target.children[segment] : nil
      else
        nil
      end
    end

    # --- sensitivity marking ---------------------------------------------

    # Marks +node+ and every node reachable underneath it as sensitive, by
    # object identity.  Aliases of a marked node are therefore covered with
    # no extra work.
    def mark_sensitive(node)
      stack = [dereference(node)]
      until stack.empty?
        current = stack.pop
        next if @sensitive.key?(current)

        @sensitive[current] = true
        case current
        when Nodes::Mapping
          current.children.each { |child| stack << dereference(child) }
        when Nodes::Sequence
          current.children.each { |child| stack << dereference(child) }
        end
      end
    end

    def sensitive?(node)
      @sensitive.key?(dereference(node))
    end

    # --- occurrence enumeration / reporting ------------------------------

    def enumerate(root, requested)
      requested_set = requested.each_with_object({}) { |path, set| set[path] = true }
      entries = []
      on_stack = {}.compare_by_identity

      documents_of(root).each do |document|
        walk(document, [], :value, false, on_stack, requested_set, entries)
      end
      entries
    end

    def walk(node, path, role, cyclic, on_stack, requested_set, entries)
      target = dereference(node)

      if sensitive?(node)
        entries << Entry.new(
          path: path.dup,
          reason: classify(node, path, role, cyclic, requested_set),
          role: role
        )
      end

      return if node.is_a?(Nodes::Alias) && cyclic
      return if on_stack.key?(target)

      case target
      when Nodes::Mapping, Nodes::Sequence
        on_stack[target] = true
        entered = true
        if target.is_a?(Nodes::Mapping)
          walk_mapping(target, path, on_stack, requested_set, entries)
        else
          target.children.each_with_index do |child, index|
            child_cyclic = child.is_a?(Nodes::Alias) && on_stack.key?(dereference(child))
            walk(child, path + [index], :value, child_cyclic, on_stack, requested_set, entries)
          end
        end
      when Nodes::Document, Nodes::Stream
        target.children.each { |child| walk(child, path, :value, false, on_stack, requested_set, entries) }
      end
    ensure
      on_stack.delete(target) if entered
    end

    def classify(node, path, role, cyclic, requested_set)
      if role == :value && requested_set.key?(path)
        :requested
      elsif role == :key && requested_set.key?(path + [KEY])
        :requested
      elsif role == :key
        :shared_key
      elsif path.length >= 2 && path[-2] == MERGE_KEY
        :merge
      elsif cyclic
        :cycle
      elsif node.is_a?(Nodes::Alias)
        :alias
      else
        :contained
      end
    end

    def walk_mapping(mapping, path, on_stack, requested_set, entries)
      explicit_names = {}
      merges = []

      mapping.children.each_slice(2) do |key, value|
        if merge_key?(key)
          merges << value
        else
          named = dereference(key)
          name = named.is_a?(Nodes::Scalar) ? named.value : named.object_id.to_s
          child_path = path + [name]
          explicit_names[name] = true
          key_cyclic = key.is_a?(Nodes::Alias) && on_stack.key?(dereference(key))
          value_cyclic = value.is_a?(Nodes::Alias) && on_stack.key?(dereference(value))
          walk(key, child_path, :key, key_cyclic, on_stack, requested_set, entries)
          walk(value, child_path, :value, value_cyclic, on_stack, requested_set, entries)
        end
      end

      merges.each do |merge_value|
        each_merge_pair(dereference(merge_value)) do |merged_key, merged_value|
          named = dereference(merged_key)
          next unless named.is_a?(Nodes::Scalar)
          next if explicit_names.key?(named.value) # explicit pair overrides merge

          merged_path = path + [MERGE_KEY, named.value]
          walk(merged_key, merged_path, :key, false, on_stack, requested_set, entries)
          walk(merged_value, merged_path, :value,
               merged_value.is_a?(Nodes::Alias) && on_stack.key?(dereference(merged_value)),
               on_stack, requested_set, entries)
        end
      end
    end

    # Yields [key_node, value_node] pairs contributed by a merge target,
    # expanding nested merges and merge sequences per the YAML 1.1 rules.
    def each_merge_pair(target, seen = {}.compare_by_identity, &block)
      target = dereference(target)
      return if seen.key?(target)
      seen[target] = true

      case target
      when Nodes::Mapping
        target.children.each_slice(2) do |key, value|
          if merge_key?(key)
            each_merge_pair(value, seen, &block)
          else
            yield(key, value)
          end
        end
      when Nodes::Sequence
        target.children.each { |child| each_merge_pair(child, seen, &block) }
      end
    end

    def merge_key?(node)
      named = dereference(node)
      named.is_a?(Nodes::Scalar) && named.value == MERGE_KEY && named.tag.nil?
    end

    # --- redacted copy ----------------------------------------------------

    def copy(root)
      memo = {}.compare_by_identity
      copy_node(root, memo)
    end

    def copy_node(node, memo)
      return memo[node] if memo.key?(node)

      if @sensitive.key?(node)
        replacement = Nodes::Scalar.new(
          @replacement, node.anchor, nil, false, true, Nodes::Scalar::DOUBLE_QUOTED
        )
        memo[node] = replacement
        return replacement
      end

      shell = clone_shell(node)
      memo[node] = shell
      populate(node, shell, memo)
      shell
    end

    def populate(node, copied, memo)
      case node
      when Nodes::Mapping
        node.children.each_slice(2) do |key, value|
          copied.children << copy_child(key, memo)
          copied.children << copy_child(value, memo)
        end
      when Nodes::Sequence, Nodes::Document, Nodes::Stream
        node.children.each { |child| copied.children << copy_child(child, memo) }
      end
    end

    # Aliases stay aliases; their anchor definition is materialized first so
    # emitted references (including those pointing at a redacted value) stay
    # valid, and cycles remain representable.
    def copy_child(node, memo)
      if node.is_a?(Nodes::Alias)
        target = @anchors.fetch(node.anchor)
        copy_node(target, memo) unless memo.key?(target)
        Nodes::Alias.new(node.anchor)
      else
        copy_node(node, memo)
      end
    end

    def clone_shell(node)
      case node
      when Nodes::Document
        Nodes::Document.new(node.version, node.tag_directives, node.implicit)
      when Nodes::Stream
        Nodes::Stream.new
      when Nodes::Mapping
        Nodes::Mapping.new(node.anchor, node.tag, node.implicit, node.style)
      when Nodes::Sequence
        Nodes::Sequence.new(node.anchor, node.tag, node.implicit, node.style)
      when Nodes::Scalar
        Nodes::Scalar.new(node.value, node.anchor, node.tag, node.plain, node.quoted, node.style)
      else
        raise ArgumentError, "unsupported AST node #{node.class}"
      end
    end
  end
end

# frozen_string_literal: true

require "set"
require "crass"

module Loofah
  module HTML5 # :nodoc:
    #
    #  Strict enforcement of local references inside inline SVG.
    #
    #  The attribute-level rules in Loofah::HTML5::Scrub only check the *shape* of a reference:
    #  +fill="url(#g)"+ and +<use href="#u">+ survive because they begin with a hash. They never
    #  verify that the referenced element exists in the same fragment, that it is unambiguous, or
    #  that its type matches the attribute pointing at it. A dangling reference is not inert: once
    #  the sanitized fragment is embedded in a host document, the browser resolves it there, so an id
    #  chosen by the author can hijack styling, clipping, or <use> shadow trees.
    #
    #  This module is a post-scrub pass over the *surviving* tree. A reference edge is kept only
    #  when all of these hold:
    #
    #    1. it is a bare same-fragment reference (+#id+) with no URL or query component;
    #    2. exactly one surviving element carries that id (duplicate ids are ambiguity);
    #    3. that element is an allowed target type for the attribute holding the reference;
    #    4. the target is terminal, carrying no local references itself, so references cannot be
    #       chained and cycles cannot form.
    #
    #  References are collected from +href+ / +xlink:href+ on SVG elements, from the SVG paint and
    #  filter presentation attributes, and from +url(#...)+ tokens in +style+ attributes.
    #
    module SvgLocalReferences
      SVG_NAMESPACE = "http://www.w3.org/2000/svg"

      # Attribute name (as matched by Scrub.prefixed_attribute_name) to the element types that may
      # be referenced through it. Names are compared case-insensitively so the rules are identical
      # for the HTML4 parser (which lowercases SVG tag names) and the HTML5 parser.
      REFERENCE_TARGET_TYPES = {
        "href" => %w[
          altGlyph animate animateColor animateMotion animateTransform circle cursor defs ellipse
          feImage filter g image line linearGradient marker mask mpath path pattern polygon
          polyline radialGradient rect set stop svg symbol text textPath tref tspan use
        ],
        "xlink:href" => %w[
          altGlyph animate animateColor animateMotion animateTransform circle cursor defs ellipse
          feImage filter g image line linearGradient marker mask mpath path pattern polygon
          polyline radialGradient rect set stop svg symbol text textPath tref tspan use
        ],
        "clip-path" => %w[clipPath],
        "filter" => %w[filter],
        "mask" => %w[mask],
        "marker" => %w[marker],
        "marker-end" => %w[marker],
        "marker-mid" => %w[marker],
        "marker-start" => %w[marker],
        "cursor" => %w[cursor],
        "fill" => %w[linearGradient radialGradient pattern solidColor],
        "stroke" => %w[linearGradient radialGradient pattern solidColor],
        # color-profile references an ICC profile element that Loofah does not allow, so no target
        # type is ever acceptable and a local reference in this attribute is always removed.
        "color-profile" => %w[],
      }.transform_values { |names| names.map(&:downcase).to_set.freeze }.freeze

      # CSS properties whose +url(#...)+ value references an SVG element, mapped to the target type
      # sets used for the presentation attributes of the same name.
      CSS_REFERENCE_PROPERTIES = %w[
        clip-path filter mask marker marker-end marker-mid marker-start cursor fill stroke
      ].each_with_object({}) { |name, map| map[name] = REFERENCE_TARGET_TYPES[name] }.freeze

      # Any other CSS property that survives the CSS scrubber (for example `background`) may still
      # carry a local url(); such an edge has no paint-specific target type, so it only needs the
      # referenced element to exist and be unambiguous and terminal.
      GENERIC_CSS_TARGET_TYPES = :any

      # Elements that only have an effect when referenced, and so can be pruned once nothing points
      # at their id anymore.
      REFERENCE_ONLY_ELEMENTS = %w[
        clipPath linearGradient radialGradient marker mask pattern solidColor symbol filter
      ].each_with_object(Set.new) { |name, set| set << name.downcase }.freeze

      # A hash followed by at least one non-space id character; a second hash or whitespace inside
      # the fragment makes it a non-local or malformed reference.
      LOCAL_REFERENCE = /\A#([^#\s]+)\z/

      class << self
        # Mutates +root+ (a Nokogiri node or fragment) so every local SVG reference resolves to a
        # unique, allowed, terminal target in the same tree. Returns the root.
        def scrub(root)
          # Invalidating one edge can make a previously non-terminal target terminal, and pruning a
          # dead target can invalidate another edge. Iterate until a pass changes nothing.
          loop do
            id_map = build_id_map(root)
            references = collect_references(root)
            referenced_ids = references.map { |reference| reference[:id] }.select(&:itself).to_set
            referencing_subtrees = build_referencing_subtrees(references)
            invalid = references.reject do |reference|
              valid_reference?(reference, id_map, referencing_subtrees)
            end

            invalid.each { |reference| invalidate_reference(reference) }
            pruned = prune_orphaned_targets(root, referenced_ids)

            return root if invalid.empty? && !pruned
          end
        end

        # Builds the reference graph of an already-sanitized tree. Each edge is a hash with the
        # referencing +node+, the +attribute+ holding it (or +style:<property>+), the referenced
        # +id+, and the resolved +target+ element (nil when it is missing or ambiguous).
        def reference_graph(root)
          id_map = build_id_map(root)
          collect_references(root).map do |reference|
            nodes = id_map[reference[:id]]
            reference.merge(target: nodes&.size == 1 ? nodes.first : nil)
          end
        end

        private

        # Maps every id in the surviving tree to its elements. An id with several entries is
        # ambiguous and can never be a valid target.
        def build_id_map(root)
          id_map = Hash.new { |hash, key| hash[key] = [] }
          root.traverse { |node| id_map[node["id"]] << node if node.element? && node["id"] }
          id_map
        end

        def collect_references(root)
          references = []
          root.traverse do |node|
            next unless node.element? && inside_svg?(node)

            collect_attribute_references(node, references)
            collect_style_references(node, references)
          end
          references
        end

        def collect_attribute_references(node, references)
          node.attribute_nodes.each do |attr_node|
            attr_name = Scrub.prefixed_attribute_name(attr_node)
            next unless REFERENCE_TARGET_TYPES.key?(attr_name)

            if href_attribute?(attr_name)
              references << { node: node, attribute: attr_name, id: href_local_id(attr_node.value) }
            else
              paint_url_ids(attr_node.value).each do |id|
                references << { node: node, attribute: attr_name, id: id }
              end
            end
          end
        end

        def collect_style_references(node, references)
          style = node.attribute("style")
          return unless style

          Crass.parse_properties(style.value).each do |property|
            next unless property[:node] == :property

            property_name = property[:name].downcase

            url_tokens(property).each do |token|
              id = local_id(token[:value])
              references << { node: node, attribute: "style:#{property_name}", id: id.nil? ? false : id }
            end
          end
        end

        def valid_reference?(reference, id_map, referencing_subtrees)
          targets = id_map[reference[:id]]
          return false unless targets&.size == 1

          target = targets.first
          return false unless target_allowed?(reference, target)
          return false if referencing_subtrees.include?(target)

          true
        end

        def target_allowed?(reference, target)
          target_types = if reference[:attribute].start_with?("style:")
            property = reference[:attribute].split(":", 2).last
            CSS_REFERENCE_PROPERTIES[property] || GENERIC_CSS_TARGET_TYPES
          else
            REFERENCE_TARGET_TYPES[reference[:attribute]]
          end
          return true if target_types == GENERIC_CSS_TARGET_TYPES

          target_types.include?(target.name.downcase)
        end

        # The set of every node that holds a reference, together with all of its ancestors. A target
        # appearing in this set is itself referencing (a chain/cycle) or contains a node that is, so
        # it is not terminal. Building it once keeps the per-edge check an O(1) set lookup.
        def build_referencing_subtrees(references)
          references.each_with_object(Set.new) do |reference, subtree|
            node = reference[:node]
            subtree.merge(node.ancestors)
            subtree << node
          end
        end

        def invalidate_reference(reference)
          if reference[:attribute].start_with?("style:")
            remove_style_reference(reference)
          else
            remove_attribute_reference(reference)
          end
        end

        def remove_attribute_reference(reference)
          node = reference[:node]
          attribute = reference[:attribute]
          attr_node = node.attribute_nodes.find do |candidate|
            Scrub.prefixed_attribute_name(candidate) == attribute
          end
          return unless attr_node

          if href_attribute?(attribute)
            attr_node.remove
          else
            attr_node.value = scrub_paint_value(attr_node.value, reference[:id])
            node.remove_attribute(attr_node.name) if attr_node.value !~ /[^[:space:]]/
          end
        end

        def remove_style_reference(reference)
          node = reference[:node]
          property = reference[:attribute].split(":", 2).last
          style = node.attribute("style")
          return unless style

          surviving = Crass.parse_properties(style.value).reject do |candidate|
            candidate[:node] == :semicolon ||
              (candidate[:node] == :property &&
                candidate[:name].downcase == property &&
                url_tokens(candidate).any? { |token| token_matches_edge?(token, reference[:id]) })
          end
          style.value = Crass::Parser.stringify(surviving)
          node.remove_attribute("style") if style.value.strip.empty?
        end

        # Rebuilds a paint/filter presentation attribute keeping every token except the url() that
        # the edge named, so a fallback such as `url(#g) red` degrades to `red`.
        def scrub_paint_value(value, edge_id)
          Crass::Parser.new(value).parse_component_values.filter_map do |node|
            node[:raw] unless node[:node] == :url && token_matches_edge?(node, edge_id)
          end.join.strip
        end

        # Matches the url() token an edge refers to: a concrete id, or (when the edge id is false)
        # any external/malformed url that did not parse as a local reference.
        def token_matches_edge?(token, edge_id)
          token_id = local_id(token[:value])
          if edge_id
            token_id == edge_id
          else
            token_id.nil?
          end
        end

        # Removes reference-only elements (gradients, clip paths, and so on) that no surviving edge
        # points at. They never render on their own, and leaving their id in the tree would let a
        # host document of the same id shadow or be confused with it. A <defs> wrapper is removed
        # once it is empty. Repeated by the caller's fixed-point loop so pruning cascades. Returns
        # true when at least one node was removed.
        def prune_orphaned_targets(root, referenced_ids)
          doomed = []
          root.traverse do |node|
            next unless node.element?

            name = node.name.downcase
            next unless REFERENCE_ONLY_ELEMENTS.include?(name) || name == "defs"
            next if node["id"] && referenced_ids.include?(node["id"])

            doomed << node if name == "defs" ? node.element_children.empty? : true
          end
          doomed.each(&:remove)
          !doomed.empty?
        end

        def inside_svg?(node)
          node.namespace&.href == SVG_NAMESPACE ||
            node.ancestors.any? { |ancestor| ancestor.name&.downcase == "svg" }
        end

        # Every url() token in a paint/filter attribute becomes an edge: a local #id yields its id,
        # while any external or malformed url() yields false so the strict pass removes it even when
        # invoked without the attribute-level scrubber having run first. filter_map would also drop
        # false, so the compact is explicit.
        def paint_url_ids(value)
          return [] unless value

          Crass::Parser.new(value).parse_component_values.map do |node|
            next nil unless node[:node] == :url

            id = local_id(node[:value])
            id.nil? ? false : id
          end.compact
        end

        # href / xlink:href hold the reference directly, not wrapped in url(). Returns the id for a
        # bare #id, false for a non-local or malformed value (which the strict pass must remove), or
        # nil when the attribute carries no reference at all.
        def href_local_id(value)
          return nil if value.nil? || value.strip.empty?

          stripped = value.strip
          return false unless stripped.start_with?("#")

          id = local_id(stripped)
          id.nil? ? false : id
        end

        def url_tokens(property)
          property[:children].select { |child| child[:node] == :url }
        end

        def local_id(value)
          return nil unless value

          match = LOCAL_REFERENCE.match(value.strip)
          match && match[1]
        end

        def href_attribute?(attribute)
          attribute == "href" || attribute == "xlink:href"
        end
      end
    end
  end
end

# frozen_string_literal: true

require "rexml/document"
require "rexml/parsers/pullparser"
require "rexml/parsers/sax2parser"

require_relative "oracle"

module REXMLTests
  module NamespaceSemantics
    # Each projection answers one question: for every element and
    # attribute in document order, what expanded name and value would an
    # authorizing consumer see?  The projection is allowed to use its
    # API's own namespace machinery; it is not allowed to fall back to a
    # different API or to compare serialized strings.
    module Projections
      module_function

      def records(api, xml)
        case api
        when :dom
          dom_records(xml)
        when :pull
          pull_records(xml)
        when :sax
          sax_records(xml)
        else
          raise ArgumentError, "unknown projection: #{api.inspect}"
        end
      end

      # DOM: ask the tree for the namespace of each node.  REXML keeps the
      # source prefix in #prefix and the resolved URI in #namespace; we
      # deliberately do not use #expanded_name, which is prefix-based.
      def dom_records(xml)
        document = REXML::Document.new(xml)
        records = []
        collect_dom(document.root, [], records)
        records
      end

      def collect_dom(element, path, records)
        records << Record.new(
          kind: :element,
          path: path,
          uri: Oracle.canonical_uri(element.namespace),
          local: element.name,
        )

        attributes = []
        element.attributes.each_attribute do |attribute|
          next if attribute.namespace_declaration?

          attributes << Record.new(
            kind: :attribute,
            path: path,
            uri: Oracle.canonical_uri(attribute.namespace),
            local: attribute.name,
            value: attribute.value,
          )
        end
        attributes.sort_by! { |record| [record.uri.to_s, record.local] }
        records.concat(attributes)

        element.elements.each_with_index do |child, index|
          collect_dom(child, [*path, index], records)
        end
      end

      # Pull: the pull parser exposes lexical events only.  An agent that
      # trusts it must maintain the binding stack itself; this projection
      # does exactly that from the values the event carries.
      def pull_records(xml)
        parser = REXML::Parsers::PullParser.new(xml)
        records = []
        scopes = [{ "xml" => XML_NAMESPACE }]
        open = []

        while parser.has_next?
          event = parser.pull
          case event.event_type
          when :start_element
            scope = Oracle.extended_scope(scopes.last, event[1])
            scopes.push(scope)
            path = open.empty? ? [] : [*open.last[:path], open.last[:next_child]]
            open.last[:next_child] += 1 unless open.empty?
            open.push({ path: path, next_child: 0 })

            uri, local = Oracle.expanded_element_name(event[0], scope)
            records << Record.new(kind: :element, path: path, uri: uri, local: local)

            attributes = event[1].flat_map do |name, raw_value|
              next [] if Oracle.declaration_name?(name)

              attribute_uri, attribute_local = Oracle.expanded_attribute_name(name, scope)
              [
                Record.new(
                  kind: :attribute,
                  path: path,
                  uri: attribute_uri,
                  local: attribute_local,
                  value: Oracle.normalize_value(raw_value),
                ),
              ]
            end
            attributes.sort_by! { |record| [record.uri.to_s, record.local] }
            records.concat(attributes)
          when :end_element
            scopes.pop
            open.pop
          end
        end

        records
      end

      # SAX: the parser hands us a URI and a local name directly, and a
      # consumer should use those.  Attribute expanded names are not in
      # the callback signature, so they are resolved from the
      # prefix-mapping events plus the declarations on the element.
      #
      # REXML's SAX callbacks deliver attribute values lexically (the
      # existing test_sax expectations are `&lt;`, not `<`), so the
      # projection decodes them exactly as a consumer must.  Using the
      # same decoder as Pull keeps the comparison honest: a divergence
      # then means the source text was rewritten, not merely passed
      # through encoded.
      def sax_records(xml)
        parser = REXML::Parsers::SAX2Parser.new(xml)
        records = []
        scopes = [{ "xml" => XML_NAMESPACE }]
        pending = nil
        open = []

        parser.listen(:start_prefix_mapping) do |prefix, uri|
          pending ||= scopes.last.dup
          apply_binding(pending, prefix, uri)
        end

        parser.listen(:start_element) do |uri, local, _qname, raw_attributes|
          if pending
            scopes.push(pending)
            pending = nil
          else
            scopes.push(scopes.last)
          end

          path = open.empty? ? [] : [*open.last[:path], open.last[:next_child]]
          open.last[:next_child] += 1 unless open.empty?
          open.push({ path: path, next_child: 0 })

          records << Record.new(
            kind: :element,
            path: path,
            uri: Oracle.canonical_uri(uri),
            local: local,
          )

          attributes = raw_attributes.flat_map do |name, raw_value|
            next [] if Oracle.declaration_name?(name)

            attribute_uri, attribute_local =
              Oracle.expanded_attribute_name(name, scopes.last)
            [
              Record.new(
                kind: :attribute,
                path: path,
                uri: attribute_uri,
                local: attribute_local,
                value: Oracle.normalize_value(raw_value),
              ),
            ]
          end
          attributes.sort_by! { |record| [record.uri.to_s, record.local] }
          records.concat(attributes)
        end

        parser.listen(:end_element) do |*|
          open.pop
          scopes.pop
        end

        parser.parse
        records
      end

      def apply_binding(scope, prefix, uri)
        key = prefix.nil? ? "" : prefix
        value = Oracle.normalize_value(uri.to_s)
        if value.empty?
          scope.delete(key)
        else
          scope[key] = value
        end
      end
    end
  end
end

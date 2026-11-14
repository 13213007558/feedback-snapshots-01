# frozen_string_literal: true

require "rexml/text"

module REXMLTests
  module NamespaceSemantics
    XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"

    # The only representation an authorizing consumer should depend on:
    # element/attribute identity by (namespace URI, local name) and value
    # after XML character-reference expansion.
    Record = Struct.new(:kind, :path, :uri, :local, :value, keyword_init: true) do
      def element?
        kind == :element
      end

      def attribute?
        kind == :attribute
      end

      def to_s
        if element?
          "element #{format_path} {#{uri}} #{local}".sub("{nil}", "{no-namespace}")
        else
          "attribute #{format_path} {#{uri}} #{local}=#{value.inspect}".sub("{nil}", "{no-namespace}")
        end
      end

      def format_path
        path.empty? ? "/" : "/#{path.join('/')}"
      end
    end

    module Oracle
      module_function

      # XML Namespaces 1.0: an unmapped default namespace and an empty
      # default namespace both mean "no namespace".  REXML surfaces those
      # as nil and "" depending on the API and the code path, so the
      # comparison collapses them here rather than at a convenient edge.
      def canonical_uri(uri)
        return nil if uri.nil?

        string = uri.to_s
        string.empty? ? nil : string
      end

      def split_qname(qname)
        prefix, separator, local = qname.partition(":")
        separator.empty? ? [nil, qname] : [prefix, local]
      end

      # Character references and predefined entities must be expanded
      # before an application sees the value.
      def normalize_value(raw)
        REXML::Text.unnormalize(raw)
      end

      def escape_attribute_value(value)
        value
          .gsub("&", "&#38;")
          .gsub("<", "&lt;")
          .gsub(">", "&gt;")
          .gsub('"', "&quot;")
      end

      def declaration_name?(name)
        name == "xmlns" || name.start_with?("xmlns:")
      end

      def declaration_key(name)
        name == "xmlns" ? "" : name.delete_prefix("xmlns:")
      end

      # In-scope bindings for one element: inherit, then apply this
      # element's declarations.  An empty URI removes a binding; that is
      # the only way to withdraw a default namespace in XML 1.0.
      def extended_scope(parent_scope, attributes)
        scope = parent_scope.dup
        attributes.each do |name, raw_value|
          next unless declaration_name?(name)

          key = declaration_key(name)
          value = normalize_value(raw_value)
          if value.empty?
            scope.delete(key)
          else
            scope[key] = value
          end
        end
        scope
      end

      def expanded_element_name(qname, scope)
        prefix, local = split_qname(qname)
        if prefix.nil?
          [canonical_uri(scope[""]), local]
        else
          [canonical_uri(scope[prefix]), local]
        end
      end

      def expanded_attribute_name(qname, scope)
        prefix, local = split_qname(qname)
        # The default namespace never applies to an unprefixed attribute.
        [prefix.nil? ? nil : canonical_uri(scope[prefix]), local]
      end

      # Records in document pre-order, attributes sorted by expanded name
      # so a projection's hash iteration order cannot affect comparison.
      def records(raw_element)
        records = []
        collect(raw_element, {"xml" => XML_NAMESPACE}, [], records)
        records
      end

      def collect(raw_element, parent_scope, path, records)
        scope = extended_scope(parent_scope, raw_element.attributes)
        uri, local = expanded_element_name(raw_element.qname, scope)
        records << Record.new(kind: :element, path: path, uri: uri, local: local)

        attribute_records = raw_element.ordinary_attributes.map do |name, raw_value|
          attribute_uri, attribute_local = expanded_attribute_name(name, scope)
          Record.new(
            kind: :attribute,
            path: path,
            uri: attribute_uri,
            local: attribute_local,
            value: normalize_value(raw_value),
          )
        end
        attribute_records.sort_by! { |record| [record.uri.to_s, record.local] }
        records.concat(attribute_records)

        raw_element.children.each_with_index do |child, index|
          collect(child, scope, [*path, index], records)
        end
      end
    end
  end
end

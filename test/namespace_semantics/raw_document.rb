# frozen_string_literal: true

require "rexml/parsers/baseparser"

module REXMLTests
  module NamespaceSemantics
    # A lexical tree: qnames and attribute values stay exactly as they
    # appeared in the source.  Namespace resolution happens later, in the
    # Oracle, so this layer is shared by every projection and is not
    # allowed to decide what a name means.
    class RawElement
      attr_reader :qname, :attributes, :children

      def initialize(qname:, attributes: [], children: [])
        @qname = qname
        @attributes = attributes
        @children = children
      end

      def namespace_declarations
        @attributes.select { |name, _| Oracle.declaration_name?(name) }
      end

      def ordinary_attributes
        @attributes.reject { |name, _| Oracle.declaration_name?(name) }
      end

      # Renders a canonical, single-line document.  Attribute values are
      # written back exactly as tokenized so replaying a failing case does
      # not silently re-encode the value that triggered the failure.
      def to_xml
        opening = +"<#{@qname}"
        @attributes.each { |name, value| opening << %( #{name}="#{value}") }
        return opening << "/>" if @children.empty?

        opening << ">" << @children.map(&:to_xml).join << "</#{@qname}>"
      end
    end

    class RawDocument
      attr_reader :root

      def self.parse(xml)
        parser = REXML::Parsers::BaseParser.new(xml)
        stack = []
        root = nil
        loop do
          event = parser.pull
          case event[0]
          when :start_element
            element = RawElement.new(qname: event[1], attributes: event[2].to_a)
            if stack.empty?
              root = element
            else
              stack.last.children << element
            end
            stack << element
          when :end_element
            stack.pop
          when :end_document
            break
          end
        end
        raise "empty document" if root.nil?

        new(root)
      end

      def initialize(root)
        @root = root
      end

      def to_xml
        @root.to_xml
      end
    end
  end
end

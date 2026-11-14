# frozen_string_literal: false

module REXML
  module Formatters
    # Canonical XML 1.1 (W3C Recommendation) formatter.
    #
    # Produces the canonical form of a whole document or of an element
    # subtree (a document subset), suitable for cryptographic digesting in
    # signature services.  The input tree is only read, never modified.
    #
    #   formatter = REXML::Formatters::C14N.new
    #   formatter.write(node, output)                 # without comments
    #
    #   formatter = REXML::Formatters::C14N.new(true)
    #   formatter.write(node, output)                 # with comments
    #
    # When +node+ is an Element, the subtree rooted at it is canonicalized
    # as a document subset: in-scope namespaces and xml:base, xml:lang,
    # xml:space and xml:id attributes are inherited from the ancestors of
    # the element, as required by Canonical XML 1.1.
    class C14N
      XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace"

      # with_comments::
      #   If true, comment nodes are included in the output
      #   (Canonical XML 1.1 with comments); otherwise they are omitted.
      def initialize(with_comments=false)
        @with_comments = with_comments
      end

      # Writes the canonical form of +node+ to +output+.
      #
      # node::
      #   A Document (canonicalized as a whole) or an Element (canonicalized
      #   as a subtree subset with ancestor context).  A bare Text, CData,
      #   Comment or Instruction node is canonicalized on its own.
      # output::
      #   A class implementing <TT>&lt;&lt;</TT>.
      def write(node, output)
        case node
        when Document
          write_document(node, output)
        when Element
          write_element_subset(node, output)
        when CData
          output << escape_text(node.to_s)
        when Text
          output << escape_text(node.value)
        when Comment
          write_comment(node, output) if @with_comments
        when Instruction
          write_instruction(node, output)
        else
          raise Exception.new("XML FORMATTING ERROR")
        end
      end

      protected

      def write_document(node, output)
        node.children.each do |child|
          case child
          when Element
            write_element_subset(child, output)
          when Comment
            write_comment(child, output) if @with_comments
          when Instruction
            write_instruction(child, output)
          end
        end
      end

      # Canonicalizes the subtree rooted at +apex+ as a document subset.
      # Descendants are walked with an explicit stack instead of recursion
      # so that a deeply nested document doesn't exhaust the machine stack.
      # A String on the stack is an end tag waiting to be written; an Array
      # is [element, rendered_namespaces, extra_attributes].
      def write_element_subset(apex, output)
        extra_attrs = inherited_xml_attributes(apex)
        stack = [[apex, {"" => ""}, extra_attrs]]
        until stack.empty?
          current = stack.pop
          case current
          when String
            output << current
          when Array
            element, rendered, extra = current
            in_scope = normalize_namespaces(element.namespaces)
            output << "<#{element.expanded_name}"
            write_namespace_declarations(element, in_scope, rendered, output)
            write_attributes(element, extra, output)
            children = canonical_children(element)
            child_context = child_rendered_namespaces(element, in_scope, rendered)
            if children.empty?
              output << "></#{element.expanded_name}>"
            else
              output << ">"
              stack << "</#{element.expanded_name}>"
              children.reverse_each do |child|
                if child.is_a?(Element)
                  stack << [child, child_context, {}]
                else
                  stack << child
                end
              end
            end
          when CData
            output << escape_text(current.to_s)
          when Text
            output << escape_text(current.value)
          when Comment
            write_comment(current, output) if @with_comments
          when Instruction
            write_instruction(current, output)
          end
        end
      end

      def write_comment(node, output)
        output << Comment::START
        output << node.to_s
        output << Comment::STOP
      end

      def write_instruction(node, output)
        output << Instruction::START
        output << node.target
        content = node.content
        if content and not content.empty?
          output << " "
          output << content
        end
        output << Instruction::STOP
      end

      private

      def canonical_children(element)
        element.children.select do |child|
          case child
          when Element, Text, CData, Instruction
            true
          when Comment
            @with_comments
          else
            false
          end
        end
      end

      # REXML reports the default namespace under the "xmlns" key; Canonical
      # XML treats it as the empty prefix.  Absent default means "".
      def normalize_namespaces(namespaces)
        result = {}
        namespaces.each do |prefix, uri|
          result[prefix == "xmlns" ? "" : prefix] = uri
        end
        result[""] = "" unless result.key?("")
        result
      end

      # The namespace context visible to the children of +element+: every
      # in-scope namespace has been rendered, except the default namespace
      # when +element+ does not visibly utilize it (i.e. its name is
      # prefixed); in that case the previously rendered default stays in
      # effect for the output.
      def child_rendered_namespaces(element, in_scope, rendered)
        return in_scope if element.prefix.empty?
        context = in_scope.dup
        context[""] = rendered[""] || ""
        context
      end

      # Renders the namespace nodes of +element+ that are not already
      # rendered by an output ancestor.  The default namespace node is part
      # of an element's namespace axis only when the element visibly
      # utilizes it, i.e. when the element name has no prefix.
      def write_namespace_declarations(element, in_scope, rendered, output)
        declarations = {}
        in_scope.each do |prefix, uri|
          next if prefix.empty? and not element.prefix.empty?
          next if rendered[prefix] == uri
          declarations[prefix] = uri
        end
        declarations.sort_by { |prefix, _| prefix }.each do |prefix, uri|
          if prefix.empty?
            output << " xmlns=\"#{escape_attribute(uri)}\""
          else
            output << " xmlns:#{prefix}=\"#{escape_attribute(uri)}\""
          end
        end
      end

      # Attributes are sorted lexicographically by namespace URI, then by
      # local name; attributes in no namespace (the empty URI) sort first.
      def write_attributes(element, extra_attrs, output)
        attributes = {}
        element.attributes.each_attribute do |attr|
          next if attr.namespace_declaration?
          attributes[attr.expanded_name] =
            [attribute_namespace(attr, element), attr.name, attr.value]
        end
        extra_attrs.each do |name, value|
          attributes[name] = [XML_NAMESPACE, name.split(":", 2)[1], value]
        end
        attributes.keys.sort_by { |name| attributes[name][0, 2] }.each do |name|
          output << " #{name}=\"#{escape_attribute(attributes[name][2])}\""
        end
      end

      def attribute_namespace(attr, element)
        prefix = attr.prefix
        return "" if prefix.empty?
        return XML_NAMESPACE if prefix == "xml"
        element.namespace(prefix) || ""
      end

      # Canonical XML 1.1 section 2.4: when a document subset is
      # canonicalized, the xml:lang, xml:space and xml:id attributes of the
      # nearest ancestor outside the subset are copied to the apex element,
      # and the xml:base attributes of the ancestors are joined with the
      # apex element's own xml:base.
      def inherited_xml_attributes(apex)
        ancestors = []
        node = apex.parent
        while node.is_a?(Element)
          ancestors.unshift(node)
          node = node.parent
        end
        return {} if ancestors.empty?

        inherited = {}
        ["xml:lang", "xml:space", "xml:id"].each do |name|
          next if apex.attributes[name]
          ancestors.reverse_each do |ancestor|
            value = ancestor.attributes[name]
            if value
              inherited[name] = value
              break
            end
          end
        end

        base = nil
        ancestors.each do |ancestor|
          value = ancestor.attributes["xml:base"]
          base = join_xml_base(base, value) if value
        end
        if base
          own = apex.attributes["xml:base"]
          base = join_xml_base(base, own) if own
          inherited["xml:base"] = base
        end
        inherited
      end

      # Resolves the relative URI reference +ref+ against +base+ following
      # RFC 3986, as required by the xml:base processing of Canonical
      # XML 1.1.
      def join_xml_base(base, ref)
        return ref if base.nil? or base.empty?
        return base if ref.nil? or ref.empty?
        return ref if ref =~ /\A[A-Za-z][A-Za-z0-9+.-]*:/
        if ref.start_with?("//")
          scheme = base[/\A[A-Za-z][A-Za-z0-9+.-]*:/]
          return scheme ? "#{scheme}#{ref}" : ref
        end
        match = base.match(/\A((?:[A-Za-z][A-Za-z0-9+.-]*:)?(?:\/\/[^\/?#]*)?)([^\?#]*)/)
        prefix, base_path = match[1], match[2]
        if ref.start_with?("/")
          merged = ref
        else
          merged = base_path.sub(/[^\/]*\z/, "") + ref
        end
        prefix + remove_dot_segments(merged)
      end

      # RFC 3986 section 5.2.4.
      def remove_dot_segments(path)
        input = path.dup
        output = +""
        until input.empty?
          if input.start_with?("../")
            input = input[3..]
          elsif input.start_with?("./")
            input = input[2..]
          elsif input.start_with?("/./")
            input = "/#{input[3..]}"
          elsif input == "/."
            input = "/"
          elsif input.start_with?("/../")
            input = "/#{input[4..]}"
            output = output.sub(/(\A|\/)[^\/]*\z/, "")
          elsif input == "/.."
            input = "/"
            output = output.sub(/(\A|\/)[^\/]*\z/, "")
          elsif input == "." or input == ".."
            input = ""
          elsif input.start_with?("/")
            index = input.index("/", 1) || input.length
            output << input[0...index]
            input = input[index..] || ""
          else
            index = input.index("/") || input.length
            output << input[0...index]
            input = input[index..] || ""
          end
        end
        output
      end

      TEXT_ESCAPE = {
        "&" => "&amp;",
        "<" => "&lt;",
        ">" => "&gt;",
        "\r" => "&#xD;",
      }
      ATTRIBUTE_ESCAPE = {
        "&" => "&amp;",
        "<" => "&lt;",
        '"' => "&quot;",
        "\t" => "&#x9;",
        "\n" => "&#xA;",
        "\r" => "&#xD;",
      }

      def escape_text(text)
        text.gsub(/[&<>\r]/, TEXT_ESCAPE)
      end

      def escape_attribute(text)
        text.gsub(/[&<"\t\n\r]/, ATTRIBUTE_ESCAPE)
      end
    end
  end
end

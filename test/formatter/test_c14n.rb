# frozen_string_literal: false

require "digest"

require_relative "../helper"

module REXMLTests
  class C14NFormatterTest < Test::Unit::TestCase
    def c14n(node, with_comments=false)
      output = +""
      REXML::Formatters::C14N.new(with_comments).write(node, output)
      output
    end

    def digest(node, with_comments=false)
      Digest::SHA256.hexdigest(c14n(node, with_comments))
    end

    class SpecificationExamples < self
      # Canonical XML 1.0, section 3.1: PIs, comments and doctype are
      # handled outside the root element.
      def test_document_with_pis_and_comments
        document = REXML::Document.new(<<-XML)
<?xml version="1.0"?>
<?xml-stylesheet   href="doc.xsl"
   type="text/xsl"   ?>
<!DOCTYPE doc SYSTEM "doc.dtd">
<doc>Hello, world!<!-- Comment 1 --></doc>
<?pi-without-data     ?>
<!-- Comment 2 -->
<!-- Comment 3 -->
        XML
        assert_equal(
          "<?xml-stylesheet href=\"doc.xsl\"\n" \
          "   type=\"text/xsl\"?>" \
          "<doc>Hello, world!</doc>" \
          "<?pi-without-data?>",
          c14n(document))
        assert_equal(
          "<?xml-stylesheet href=\"doc.xsl\"\n" \
          "   type=\"text/xsl\"?>" \
          "<doc>Hello, world!<!-- Comment 1 --></doc>" \
          "<?pi-without-data?>" \
          "<!-- Comment 2 --><!-- Comment 3 -->",
          c14n(document, true))
      end

      # Canonical XML 1.0, section 3.2: the default namespace is cancelled
      # with xmlns="" where an element visibly utilizes no namespace.
      def test_default_namespace_cancellation
        document = REXML::Document.new(<<-XML)
<doc xmlns="http://www.ietf.org" xmlns:w3c="http://www.w3.org">
   <e1>
      <e2 xmlns="">
         <e3 id="E3"/>
      </e2>
   </e1>
</doc>
        XML
        assert_equal(
          "<doc xmlns=\"http://www.ietf.org\" xmlns:w3c=\"http://www.w3.org\">\n" \
          "   <e1>\n" \
          "      <e2 xmlns=\"\">\n" \
          "         <e3 id=\"E3\"></e3>\n" \
          "      </e2>\n" \
          "   </e1>\n" \
          "</doc>",
          c14n(document))
      end

      # Canonical XML 1.0, section 3.3: namespace declarations are sorted
      # by prefix (default first), attributes by namespace URI then local
      # name; empty elements get explicit end tags.
      def test_namespace_and_attribute_ordering
        document = REXML::Document.new(
          "<e5 xmlns:b=\"http://www.ietf.org\"\n" \
          "    xmlns:a=\"http://www.w3.org\"\n" \
          "    xmlns=\"http://example.org\"\n" \
          "    a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I am\"/>")
        assert_equal(
          "<e5 xmlns=\"http://example.org\"" \
          " xmlns:a=\"http://www.w3.org\"" \
          " xmlns:b=\"http://www.ietf.org\"" \
          " attr=\"I am\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>",
          c14n(document))
      end
    end

    class SubsetCanonicalization < self
      # A subtree canonicalized as a document subset pulls the in-scope
      # namespaces of its ancestors into the apex element.
      def test_inherited_namespaces_on_apex
        document = REXML::Document.new(
          "<root xmlns:a=\"http://a\" xmlns=\"http://default\">" \
          "<a:wrap><child a:x=\"1\" plain=\"2\"/></a:wrap></root>")
        child = document.root.elements["a:wrap/child"]
        assert_equal(
          "<child xmlns=\"http://default\" xmlns:a=\"http://a\"" \
          " plain=\"2\" a:x=\"1\"></child>",
          c14n(child))
      end

      # A prefixed apex does not visibly utilize the default namespace, so
      # it is rendered on the inner element that does.
      def test_default_namespace_deferred_to_using_element
        document = REXML::Document.new(
          "<root xmlns=\"http://default\">" \
          "<ns:sub xmlns:ns=\"http://ns\"><plain/></ns:sub></root>")
        assert_equal(
          "<ns:sub xmlns:ns=\"http://ns\">" \
          "<plain xmlns=\"http://default\"></plain></ns:sub>",
          c14n(document.root.elements["ns:sub"]))
        assert_equal(
          "<plain xmlns=\"http://default\" xmlns:ns=\"http://ns\"></plain>",
          c14n(document.root.elements["ns:sub/plain"]))
      end

      # Canonical XML 1.1, section 2.4: xml:lang and xml:space are copied
      # from the nearest ancestor outside the subset.
      def test_inherited_xml_lang_and_space
        document = REXML::Document.new(
          "<root xml:lang=\"en\" xml:space=\"preserve\">" \
          "<mid xml:lang=\"fr\"><leaf/></mid></root>")
        assert_equal(
          "<leaf xml:lang=\"fr\" xml:space=\"preserve\"></leaf>",
          c14n(document.root.elements["mid/leaf"]))
      end

      # Canonical XML 1.1, section 2.4: relative xml:base values of the
      # ancestors are joined with the apex element's own.
      def test_inherited_xml_base_is_joined
        document = REXML::Document.new(
          "<root xml:base=\"http://example.com/a/b/c.xml\">" \
          "<mid xml:base=\"../d/\"><leaf xml:base=\"e.xml\"/></mid></root>")
        assert_equal(
          "<leaf xml:base=\"http://example.com/a/d/e.xml\"></leaf>",
          c14n(document.root.elements["mid/leaf"]))
      end

      def test_absolute_xml_base_wins
        document = REXML::Document.new(
          "<root xml:base=\"http://example.com/a/\">" \
          "<leaf xml:base=\"http://other.example/x.xml\"/></root>")
        assert_equal(
          "<leaf xml:base=\"http://other.example/x.xml\"></leaf>",
          c14n(document.root.elements["leaf"]))
      end
    end

    class Escaping < self
      def test_text_escaping
        document = REXML::Document.new(
          "<a>t &lt; u &gt; v &amp; w</a>")
        assert_equal("<a>t &lt; u &gt; v &amp; w</a>", c14n(document))
      end

      def test_cdata_becomes_escaped_text
        document = REXML::Document.new("<a><![CDATA[x < y & z]]></a>")
        assert_equal("<a>x &lt; y &amp; z</a>", c14n(document))
      end

      def test_attribute_escaping
        document = REXML::Document.new(
          "<a x=\"1&lt;2&#x9;&#xA;&quot;q&quot; &amp; more\"/>")
        assert_equal(
          "<a x=\"1&lt;2&#x9;&#xA;&quot;q&quot; &amp; more\"></a>",
          c14n(document))
      end
    end

    class DigestEquivalence < self
      # Surface-different but canonically equivalent inputs must produce
      # identical digests.
      def test_equivalent_documents_have_equal_digests
        variants = [
          "<a b=\"1\" c=\"2\">text</a>",
          "<a c=\"2\" b=\"1\">text</a>",
          "<a b=\"1\" c=\"2\" >text</a >",
          "<a b=\"&#49;\" c=\"&#50;\">text</a>",
          "<a b='1' c='2'>text</a>",
          "<a b=\"1\" c=\"2\"><![CDATA[text]]></a>",
        ]
        digests = variants.map do |xml|
          digest(REXML::Document.new(xml))
        end
        assert_equal(1, digests.uniq.size,
                     "expected all variants to share one digest")
      end

      def test_equivalent_subtrees_have_equal_digests
        xml1 = "<root xmlns:n=\"http://n\"><n:a n:x=\"1\" y=\"2\"/></root>"
        xml2 = "<root xmlns:n=\"http://n\"><n:a y=\"2\" n:x=\"1\"></n:a></root>"
        node1 = REXML::Document.new(xml1).root.elements["n:a"]
        node2 = REXML::Document.new(xml2).root.elements["n:a"]
        assert_equal(digest(node1), digest(node2))
      end

      # Semantically different content must not be merged.
      def test_different_documents_have_different_digests
        documents = [
          "<a>text</a>",
          "<a>text </a>",          # trailing whitespace is significant
          "<a>textx</a>",          # different character data
          "<a b=\"1\"/>",          # different attribute set
          "<b>text</b>",           # different element name
        ]
        digests = documents.map do |xml|
          digest(REXML::Document.new(xml))
        end
        assert_equal(documents.size, digests.uniq.size,
                     "expected all documents to have distinct digests")
      end

      def test_namespace_uri_is_significant
        xml1 = "<n:a xmlns:n=\"http://n1\"/>"
        xml2 = "<n:a xmlns:n=\"http://n2\"/>"
        assert_not_equal(digest(REXML::Document.new(xml1)),
                         digest(REXML::Document.new(xml2)))
      end

      def test_comments_change_digest_only_when_included
        with_comment = REXML::Document.new("<a><!--note-->t</a>")
        without_comment = REXML::Document.new("<a>t</a>")
        assert_equal(digest(with_comment), digest(without_comment))
        assert_not_equal(digest(with_comment, true),
                         digest(without_comment, true))
      end
    end

    class TreePreservation < self
      def test_source_tree_is_not_modified
        xml = "<root xmlns:n=\"http://n\" xml:lang=\"en\">" \
              "<n:a z=\"1\" n:y=\"2\">t<!--c--></n:a></root>"
        document = REXML::Document.new(xml)
        before = document.to_s
        c14n(document.root.elements["n:a"], true)
        assert_equal(before, document.to_s)
      end
    end
  end
end

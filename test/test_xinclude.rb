# frozen_string_literal: false

require_relative "helper"
require "rexml/xinclude"

module REXMLTests
  class TestXInclude < Test::Unit::TestCase
    include REXML

    XI = REXML::XInclude::XINCLUDE_NAMESPACE

    # In-memory resource table.  No file or network access happens anywhere in
    # these tests; the resolver is the sole provider of resource content.
    def resolver(store = @store, denied: [])
      ControlledResolver.new(store, denied)
    end

    class ControlledResolver
      def initialize(store, denied = [])
        @store = store
        @denied = denied
        @reads = []
        @authorization_checks = []
      end

      attr_reader :reads, :authorization_checks

      def authorized?(uri)
        @authorization_checks << uri
        !@denied.include?(uri)
      end

      def read(uri)
        @reads << uri
        unless @store.key?(uri)
          raise REXML::XInclude::ResourceError.missing!(uri)
        end
        @store[uri]
      end
    end

    def setup
      @store = {
        "mem:/main.xml" => <<~XML,
          <config xmlns:xi="#{XI}" xml:base="mem:/main.xml">
            <db><xi:include href="db/connection.xml"/></db>
            <greeting><xi:include href="text/hello.txt" parse="text"/></greeting>
          </config>
        XML
        "mem:/db/connection.xml" => <<~XML,
          <connection xmlns:xi="#{XI}">
            <url><xi:include href="../secrets/url.txt" parse="text"/></url>
          </connection>
        XML
        "mem:/secrets/url.txt" => "postgres://host/db?a=1&b=2",
        "mem:/text/hello.txt" => "Hi <world> & friends",
      }
      @original = @store["mem:/main.xml"].dup
    end

    def test_module_loaded_under_rexml
      assert_equal("http://www.w3.org/2001/XInclude",
                   REXML::XInclude::XINCLUDE_NAMESPACE)
    end

    def test_expands_nested_xml_and_text_includes
      doc = Document.new(@store["mem:/main.xml"])
      result = REXML::XInclude.include(doc, resolver,
                                       base_uri: "mem:/main.xml")

      # Nested XML include was inlined.
      connection = result.document.elements["//connection"]
      assert_not_nil(connection)
      # Text include content is stored unescaped as a REXML::Text node.
      assert_equal("postgres://host/db?a=1&b=2",
                   connection.elements["url"].text)
      greeting = result.document.elements["//greeting"]
      assert_equal("Hi <world> & friends", greeting.text)
      # Serialization escapes the literal text.
      assert_include(greeting.to_s, "Hi &lt;world&gt; &amp; friends")
    end

    def test_only_resolver_resources_are_read
      doc = Document.new(@store["mem:/main.xml"])
      r = resolver
      REXML::XInclude.include(doc, r, base_uri: "mem:/main.xml")

      assert_equal(
        ["mem:/db/connection.xml", "mem:/secrets/url.txt",
         "mem:/text/hello.txt"],
        r.reads)
    end

    def test_distinguishes_xml_and_text_modes
      doc = Document.new(@store["mem:/main.xml"])
      result = REXML::XInclude.include(doc, resolver,
                                       base_uri: "mem:/main.xml")

      modes = result.sources.values.map(&:mode).uniq.sort
      assert_equal([:text, :xml], modes)
    end

    def test_records_provenance_for_every_inserted_node
      doc = Document.new(@store["mem:/main.xml"])
      result = REXML::XInclude.include(doc, resolver,
                                       base_uri: "mem:/main.xml")

      connection = result.document.elements["//connection"]
      source = result.source_of(connection)
      assert_equal("mem:/db/connection.xml", source.uri)
      assert_equal(:xml, source.mode)
      assert_equal("db/connection.xml", source.href)
      assert_equal("mem:/main.xml", source.base)

      # The text node inside the nested include records its own origin.
      url_text = connection.elements["url"].children.first
      text_source = result.source_of(url_text)
      assert_equal("mem:/secrets/url.txt", text_source.uri)
      assert_equal(:text, text_source.mode)
      assert_equal(["mem:/db/connection.xml", "mem:/secrets/url.txt"],
                   text_source.chain)
    end

    def test_does_not_mutate_the_input_document
      doc = Document.new(@store["mem:/main.xml"])
      before = doc.to_s
      result = REXML::XInclude.include(doc, resolver,
                                       base_uri: "mem:/main.xml")

      assert_equal(before, doc.to_s)
      assert_not_same(result.document, doc)
      assert_include(doc.to_s, "xi:include")
    end

    def test_nested_xml_base_resolution
      @store["mem:/base/main.xml"] = <<~XML
        <root xmlns:xi="#{XI}" xml:base="mem:/base/main.xml">
          <group xml:base="subdir/"><xi:include href="g.xml"/></group>
        </root>
      XML
      @store["mem:/base/subdir/g.xml"] = <<~XML
        <g xml:base="../../shared/" xmlns:xi="#{XI}">
          <xi:include href="deep.xml"/>
        </g>
      XML
      @store["mem:/shared/deep.xml"] = "<deep>ok</deep>"

      doc = Document.new(@store["mem:/base/main.xml"])
      r = resolver
      result = REXML::XInclude.include(doc, r,
                                       base_uri: "mem:/base/main.xml")

      assert_include(r.reads, "mem:/shared/deep.xml")
      assert_not_nil(result.document.elements["//deep"])
      g = result.document.elements["//g"]
      assert_equal("mem:/shared/", g.attributes["xml:base"])
    end

    def test_base_uri_fixup_is_written_for_included_element
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}" xml:base="mem:/main.xml">
          <xi:include href="part.xml"/>
        </root>
      XML
      @store["mem:/part.xml"] = "<part>x</part>"

      result = REXML::XInclude.include(doc, resolver,
                                       base_uri: "mem:/main.xml")
      part = result.document.elements["//part"]
      assert_equal("mem:/part.xml", part.attributes["xml:base"])
    end

    def test_denied_resource_never_calls_read_and_is_fatal
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="secret.xml">
            <xi:fallback><f>should not appear</f></xi:fallback>
          </xi:include>
        </root>
      XML
      @store["mem:/secret.xml"] = "<s>top secret</s>"

      r = resolver(denied: ["mem:/secret.xml"])
      before = doc.to_s
      assert_raise(REXML::XInclude::AuthorizationDenied) do
        REXML::XInclude.include(doc, r, base_uri: "mem:/main.xml")
      end

      assert_empty(r.reads)
      assert_include(r.authorization_checks, "mem:/secret.xml")
      assert_equal(before, doc.to_s)
    end

    def test_authorization_denied_raised_by_resolver_skips_read
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}"><xi:include href="s.xml"/></root>
      XML
      @store["mem:/s.xml"] = "<x/>"
      r = Object.new
      reads = []
      r.define_singleton_method(:authorized?) do |uri|
        raise REXML::XInclude::AuthorizationDenied, "deny #{uri}"
      end
      r.define_singleton_method(:read) { |uri| reads << uri }

      assert_raise(REXML::XInclude::AuthorizationDenied) do
        REXML::XInclude.include(doc, r, base_uri: "mem:/main.xml")
      end
      assert_empty(reads)
    end

    def test_include_cycle_is_fatal_and_does_not_retry
      @store["mem:/a.xml"] = <<~XML
        <a xmlns:xi="#{XI}">
          <xi:include href="b.xml">
            <xi:fallback><f>fallback</f></xi:fallback>
          </xi:include>
        </a>
      XML
      @store["mem:/b.xml"] = <<~XML
        <b xmlns:xi="#{XI}"><xi:include href="a.xml"/></b>
      XML
      doc = Document.new(@store["mem:/a.xml"])
      before = doc.to_s

      assert_raise(REXML::XInclude::IncludeCycle) do
        REXML::XInclude.include(doc, resolver, base_uri: "mem:/a.xml")
      end
      # Fallback must not have substituted content on a cycle, and the
      # original document is untouched (the include element is still present).
      assert_equal(before, doc.to_s)
      assert_not_nil(doc.elements["//xi:include"])
      assert_nil(doc.root.get_elements("f").first,
                 "fallback content must not be promoted on a cycle")
    end

    def test_depth_limit_is_fatal
      (1..25).each do |i|
        @store["mem:/n#{i}.xml"] =
          "<n#{i} xmlns:xi=\"#{XI}\"><xi:include href=\"n#{i + 1}.xml\"/></n#{i}>"
      end
      @store["mem:/n26.xml"] = "<end/>"
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}"><xi:include href="n1.xml"/></root>
      XML

      assert_raise(REXML::XInclude::LimitExceeded) do
        REXML::XInclude.include(doc, resolver,
                                base_uri: "mem:/root.xml", max_depth: 4)
      end
    end

    def test_include_count_limit_is_fatal
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          #{"<xi:include href=\"p.xml\"/>" * 8}
        </root>
      XML
      @store["mem:/p.xml"] = "<p/>"

      assert_raise(REXML::XInclude::LimitExceeded) do
        REXML::XInclude.include(doc, resolver,
                                base_uri: "mem:/root.xml", max_includes: 3)
      end
    end

    def test_missing_resource_uses_fallback
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="missing.xml">
            <xi:fallback><default>ok</default></xi:fallback>
          </xi:include>
        </root>
      XML
      result = REXML::XInclude.include(doc, resolver,
                                       base_uri: "mem:/main.xml")
      assert_not_nil(result.document.elements["//default"])
    end

    def test_missing_resource_without_fallback_raises_missing
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}"><xi:include href="nope.xml"/></root>
      XML
      error = assert_raise(REXML::XInclude::ResourceError) do
        REXML::XInclude.include(doc, resolver, base_uri: "mem:/main.xml")
      end
      assert_predicate(error, :missing?)
    end

    def test_malformed_xml_is_fatal_even_with_fallback
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="bad.xml">
            <xi:fallback><f>fallback</f></xi:fallback>
          </xi:include>
        </root>
      XML
      @store["mem:/bad.xml"] = "<unclosed>"
      before = doc.to_s

      assert_raise(REXML::XInclude::MalformedResource) do
        REXML::XInclude.include(doc, resolver, base_uri: "mem:/main.xml")
      end
      assert_equal(before, doc.to_s)
      assert_not_nil(doc.elements["//xi:include"])
      assert_nil(doc.root.get_elements("f").first,
                 "fallback content must not be promoted on a parse error")
    end

    def test_non_missing_fetch_failure_ignores_fallback
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="x.xml">
            <xi:fallback><f>fallback</f></xi:fallback>
          </xi:include>
        </root>
      XML
      r = Object.new
      r.define_singleton_method(:read) do |uri|
        raise REXML::XInclude::ResourceError.new(
          "transport down", REXML::XInclude::ResourceError::FETCH_FAILED)
      end

      error = assert_raise(REXML::XInclude::ResourceError) do
        REXML::XInclude.include(doc, r, base_uri: "mem:/main.xml")
      end
      assert_not_predicate(error, :missing?)
    end

    def test_proc_resolver_is_treated_as_read
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}"><xi:include href="a.xml"/></root>
      XML
      @store["mem:/a.xml"] = "<a>value</a>"
      reads = []
      proc_resolver = lambda do |uri|
        reads << uri
        @store.fetch(uri)
      end
      result = REXML::XInclude.include(doc, proc_resolver,
                                       base_uri: "mem:/main.xml")
      assert_equal("value", result.document.elements["//a"].text)
      assert_equal(["mem:/a.xml"], reads)
    end

    def test_unsupported_xpointer_is_a_configuration_error
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="a.xml" xpointer="xpointer(/a)"/>
        </root>
      XML
      assert_raise(REXML::XInclude::ConfigurationError) do
        REXML::XInclude.include(doc, resolver, base_uri: "mem:/main.xml")
      end
    end

    def test_fragment_identifier_is_a_configuration_error
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="a.xml#section"/>
        </root>
      XML
      assert_raise(REXML::XInclude::ConfigurationError) do
        REXML::XInclude.include(doc, resolver, base_uri: "mem:/main.xml")
      end
    end

    def test_multiple_fallbacks_is_a_configuration_error
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="a.xml">
            <xi:fallback>one</xi:fallback>
            <xi:fallback>two</xi:fallback>
          </xi:include>
        </root>
      XML
      assert_raise(REXML::XInclude::ConfigurationError) do
        REXML::XInclude.include(doc, resolver, base_uri: "mem:/main.xml")
      end
    end

    def test_unknown_parse_attribute_is_a_configuration_error
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <xi:include href="a.xml" parse="binary"/>
        </root>
      XML
      assert_raise(REXML::XInclude::ConfigurationError) do
        REXML::XInclude.include(doc, resolver, base_uri: "mem:/main.xml")
      end
    end

    def test_audit_events_record_reads_and_denials
      doc = Document.new(<<~XML)
        <root xmlns:xi="#{XI}">
          <ok><xi:include href="a.xml"/></ok>
          <denied><xi:include href="secret.xml"/></denied>
        </root>
      XML
      @store["mem:/a.xml"] = "<a/>"
      r = resolver(denied: ["mem:/secret.xml"])

      assert_raise(REXML::XInclude::AuthorizationDenied) do
        REXML::XInclude.include(doc, r, base_uri: "mem:/main.xml")
      end
      statuses = r.authorization_checks.map { |uri| uri }
      assert_include(statuses, "mem:/secret.xml")
    end
  end
end

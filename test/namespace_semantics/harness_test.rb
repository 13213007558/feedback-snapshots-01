# frozen_string_literal: true

require_relative "../helper"
require_relative "runner"

module REXMLTests
  module NamespaceSemantics
    class HarnessTest < Test::Unit::TestCase
      def setup
        @generator = Generator.new(7)
      end

      def test_generation_is_seeded
        first = @generator.document(0).to_xml
        second = Generator.new(7).document(0).to_xml
        assert_equal(first, second)

        other = Generator.new(8).document(0).to_xml
        assert_not_equal(first, other)
      end

      def test_generated_documents_are_well_formed
        16.times do |index|
          xml = @generator.document(index).to_xml
          assert_nothing_raised do
            REXML::Document.new(xml)
          end
        end
      end

      def test_namespace_oracle_and_projections_agree_on_names
        16.times do |index|
          xml = @generator.document(index).to_xml
          divergences = Checker.divergences(xml)
          namespace_divergences = divergences.select(&:namespace?)
          message =
            if namespace_divergences.empty?
              ""
            else
              namespace_divergences.map(&:describe).join("\n\n")
            end
          assert_equal([], namespace_divergences, message)
        end
      end

      def test_every_hazard_family_is_reachable
        xmls = 4.times.map { |index| @generator.document(index).to_xml }
        documents = xmls.map { |xml| RawDocument.parse(xml) }
        assert(documents.any? { |document| default_undeclare?(document.root) },
               documents.map { |document| document.root.to_xml }.join("\n"))
        assert(documents.any? { |document| prefix_alias?(document.root) })
        assert(documents.any? { |document| same_local_attributes?(document.root) })
        assert(documents.any? { |document| sibling_restore?(document.root) })
      end

      # The deliberate mutation the task asks for.  A projector that
      # omits the scope pop at end_element must fail this harness; if it
      # does not, the property test above is not checking restoration.
      #
      # This test is intentionally written as a demonstration: it proves
      # the harness would catch a regression, while the real REXML code
      # currently restores scopes correctly.
      def test_MUTATION_scope_restore_omitted_is_caught
        sample = "<r xmlns:p=\"urn:cfg:trusted\"><m xmlns:p=\"urn:cfg:other\">" \
                 "<p:a p:role=\"admin\"/></m><p:b p:role=\"admin\"/></r>"
        broken = BrokenScopeRestore.new
        divergences = Checker.divergences(sample, apis: [:sax], projector: broken)
        assert_equal([:sax], divergences.map(&:api))
        assert_true(divergences.any?(&:namespace?))
        broken_descriptions = divergences.map(&:describe).join("\n")
        assert_include(broken_descriptions, "p:b")
      end

      def test_shrinker_preserves_the_divergence_and_replays
        xml = %(<config xmlns="urn:cfg:trusted"><item><node role="a&#38;b"/>) +
              %(<entry mode="v0"/></item><value flag="allow"/></config>)
        assert_true(Checker.diverged?(xml))
        minimized = Shrinker.shrink(xml, apis: [:sax])
        assert_true(Checker.diverged?(minimized))
        assert_operator(minimized.length, :<=, xml.length)
        # The minimized document must stand alone: parse it from a string
        # and re-check without going through the generator.
        assert_nothing_raised { RawDocument.parse(minimized) }
        assert_true(Checker.diverged?(minimized))
      end

      def test_numeric_character_reference_in_uri_is_caught
        # A namespace URI written with a numeric character reference is
        # the same URI per XML, so it must authorize the same names.
        # SAX2Parser currently runs attribute values through
        # BaseParser#normalize, which turns `&#101;` into the text
        # `&amp;#101;`; the expanded name then differs from DOM and Pull.
        # This test states the contract and is expected to fail until
        # that rewrite is removed.
        xml = %(<r xmlns="urn:cfg:trust&#101;d"><c/></r>)
        pend("SAX2Parser rewrites numeric character references in attribute values") do
          assert_no_namespace_divergences(xml)
        end
      end

      def test_numeric_character_reference_in_value_is_caught
        # Same root cause on an ordinary attribute value.
        xml = %(<r role="a&#38;b"/>)
        pend("SAX2Parser rewrites numeric character references in attribute values") do
          assert_no_value_divergences(xml)
        end
      end

      def test_named_entities_are_compared_semantically
        # `&amp;`/`&lt;` survive SAX as lexical text and a consumer
        # decodes them; no API disagreement should remain.
        xml = %(<r xmlns:p="urn:cfg:trusted" p:role="a&amp;b" mode="x&lt;y"/>)
        assert_no_divergences(xml)
      end

      def test_default_namespace_undeclare_matches_across_apis
        xml = %(<r xmlns="urn:cfg:trusted"><c xmlns=""><d/></c><s/></r>)
        assert_no_divergences(xml)
      end

      def test_prefix_alias_matches_across_apis
        xml = %(<r xmlns:p="urn:cfg:trusted" xmlns:q="urn:cfg:trusted">) +
              %(<p:a q:role="v0" p:mode="deny"/></r>)
        assert_no_divergences(xml)
      end

      def test_same_local_attributes_match_across_apis
        xml = %(<r xmlns:p="urn:cfg:trusted" xmlns:q="urn:cfg:other" ) +
              %(p:role="admin" q:role="v0" role="deny"/>)
        assert_no_divergences(xml)
      end

      def test_interacting_hazards_match_across_apis
        documents = [
          # Withdraw the default namespace while rebinding a prefix, then
          # restore both for the following sibling.
          %(<r xmlns="urn:cfg:trusted" xmlns:p="urn:cfg:trusted">) +
            %(<m xmlns="" xmlns:p="urn:cfg:other"><p:a p:role="admin"/></m>) +
            %(<p:b p:role="admin"/></r>),
          # Split a prefix alias in a child, then come back to the alias.
          %(<r xmlns:p="urn:cfg:trusted" xmlns:q="urn:cfg:trusted">) +
            %(<p:a q:role="v0"/><m xmlns:q="urn:cfg:other"><p:b p:mode="deny"/></m>) +
            %(<q:c q:flag="allow"/></r>),
          # Restore across two nested default-namespace changes.
          %(<r xmlns="urn:cfg:trusted"><m xmlns="urn:cfg:other">) +
            %(<n xmlns="urn:cfg:third"><a/></n><b/></m><c/></r>),
        ]
        documents.each { |xml| assert_no_divergences(xml) }
      end

      def test_sibling_scope_restore_matches_across_apis
        xml = %(<r xmlns:p="urn:cfg:trusted"><m xmlns:p="urn:cfg:other">) +
              %(<p:a/></m><p:b p:role="admin"/></r>)
        assert_no_divergences(xml)
      end

      private

      def assert_no_divergences(xml)
        divergences = Checker.divergences(xml)
        message = divergences.map(&:describe).join("\n\n")
        assert_equal([], divergences.map { |divergence| [divergence.api, divergence.kinds] }, message)
      end

      def assert_no_namespace_divergences(xml)
        divergences = Checker.namespace_divergences(xml)
        message = divergences.map(&:describe).join("\n\n")
        assert_equal([], divergences.map { |divergence| [divergence.api, divergence.kinds] }, message)
      end

      def assert_no_value_divergences(xml)
        divergences = Checker.value_divergences(xml)
        message = divergences.map(&:describe).join("\n\n")
        assert_equal([], divergences.map { |divergence| [divergence.api, divergence.kinds] }, message)
      end

      def default_undeclare?(element)
        root_has_default = element.attributes.any? { |name, value| name == "xmlns" && !value.empty? }
        child_undeclares = element.children.any? do |child|
          child.attributes.any? { |name, value| name == "xmlns" && value.empty? }
        end
        root_has_default && child_undeclares
      end

      def prefix_alias?(element)
        declarations = element.attributes.select { |name, _| name.start_with?("xmlns:") }
        declarations.size >= 2 && declarations.map(&:last).uniq.size == 1
      end

      def same_local_attributes?(element)
        locals = element.ordinary_attributes.map { |name, _| name.split(":", 2).last }
        locals.uniq.size < locals.size
      end

      def sibling_restore?(element)
        return false if element.children.length < 2

        rebinding, restored, *rest = element.children
        outer = element.attributes.select { |name, _| name == "xmlns" || name.start_with?("xmlns:") }.to_h
        inner = rebinding.attributes.select { |name, _| name == "xmlns" || name.start_with?("xmlns:") }.to_h
        rebound_prefixes = (inner.keys & outer.keys) - ["xmlns"]
        return false if rebound_prefixes.empty?
        return false unless rebound_prefixes.all? { |name| inner[name] != outer[name] }

        used = rebound_prefixes.first.delete_prefix("xmlns:")
        children_use_it = rebinding.children.any? { |child| child.qname.start_with?("#{used}:") }
        restored_uses_it = restored.qname.start_with?("#{used}:")
        children_use_it && restored_uses_it && !rest.empty?
      end
    end
  end
end

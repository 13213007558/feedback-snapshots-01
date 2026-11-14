# frozen_string_literal: true

require_relative "../helper"

module REXMLTests
  module NamespaceSemantics
    # These tests pin the traps a trusted-configuration consumer can fall
    # into when it uses each API's shortest namespace lookup method.  They
    # assert the behavior that makes the lookup unsafe, and the strict
    # alternative that is safe, rather than asserting that unsafe lookup
    # is "correct".
    class AuthorizationTest < Test::Unit::TestCase
      TRUSTED = "urn:cfg:trusted"

      def setup
        @xml = %(<r xmlns="#{TRUSTED}" xmlns:q="urn:cfg:other" q:role="admin" role="deny"/>)
        @element = REXML::Document.new(@xml).root
      end

      def test_dom_attribute_name_and_namespace_falls_back_to_no_namespace
        # The convenience overload answers with the unprefixed attribute
        # even though that attribute is in no namespace; a consumer that
        # trusted this answer would read "role=deny" as belonging to the
        # trusted default namespace.
        found = @element.attribute("role", TRUSTED)
        assert_not_nil(found)
        assert_equal("deny", found.value)
        assert_equal("", found.namespace)
        assert_equal("", found.prefix)
      end

      def test_dom_strict_lookup_rejects_the_same_lookup
        # The strict API is the one to use for authorization.
        assert_nil(@element.attributes.get_attribute_ns(TRUSTED, "role"))
        foreign = @element.attributes.get_attribute_ns("urn:cfg:other", "role")
        assert_not_nil(foreign)
        assert_equal("admin", foreign.value)
        assert_equal("urn:cfg:other", foreign.namespace)
      end

      def test_dom_attribute_lookup_by_expanded_name
        # Attributes are not namespace-declaration-tagged the way elements
        # are; matching by the resolved pair avoids the fallback entirely.
        matches = @element.attributes.each_attribute.select do |attribute|
          !attribute.namespace_declaration? &&
            attribute.name == "role" &&
            attribute.namespace == TRUSTED
        end
        assert_equal([], matches)

        matches = @element.attributes.each_attribute.select do |attribute|
          !attribute.namespace_declaration? &&
            attribute.name == "role" &&
            attribute.namespace == "urn:cfg:other"
        end
        assert_equal(["admin"], matches.map(&:value))
      end

      def test_default_namespace_withdrawal_changes_element_identity
        xml = %(<r xmlns="#{TRUSTED}"><c xmlns=""><d/></c><e/></r>)
        root = REXML::Document.new(xml).root
        child, sibling = root.elements.to_a
        assert_equal(TRUSTED, root.namespace)
        assert_equal("", child.namespace)
        assert_equal("", child.elements[1].namespace)
        assert_equal(TRUSTED, sibling.namespace)
      end

      def test_prefix_rebinding_restores_for_sibling
        xml = %(<r xmlns:p="#{TRUSTED}"><m xmlns:p="urn:cfg:other"><p:a/></m><p:b/></r>)
        root = REXML::Document.new(xml).root
        shadow, restored = root.elements.to_a
        assert_equal("urn:cfg:other", shadow.elements[1].namespace)
        assert_equal(TRUSTED, restored.namespace)
      end
    end
  end
end

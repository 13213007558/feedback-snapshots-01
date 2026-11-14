# frozen_string_literal: false

require_relative "../helper"
require "rexml/restricted_xpath"

module REXMLTests
  class TestRestrictedXPath < Test::Unit::TestCase
    def setup
      @document = REXML::Document.new(<<-XML)
<platform>
  <tenant id="a">
    <config><secret>ALPHA-SECRET</secret><region>us-east</region></config>
    <user role="admin">alice</user>
  </tenant>
  <tenant id="b">
    <config><secret>BETA-SECRET</secret><region>eu-west</region></config>
    <user role="reader">bob</user>
  </tenant>
</platform>
      XML
      @tenant_a = @document.root.elements["tenant[@id='a']"]
      @tenant_b = @document.root.elements["tenant[@id='b']"]
      @scope = REXML::RestrictedXPath.new(@tenant_a)
    end

    def test_root_is_exposed
      assert_equal(@tenant_a, @scope.root)
    end

    def test_requires_a_node
      assert_raise(TypeError) { REXML::RestrictedXPath.new("not a node") }
    end

    # Allowed capabilities: ordinary downward, positional and functional
    # queries inside the subtree.
    def test_child_path
      assert_equal(["ALPHA-SECRET"],
                   @scope.match("config/secret").map(&:text))
    end

    def test_descendant_path_anchored_at_context
      assert_equal(["ALPHA-SECRET"],
                   @scope.match(".//secret").map(&:text))
    end

    def test_wildcard
      assert_equal(%w[config user], @scope.match("*").map(&:name))
    end

    def test_attribute_axis
      assert_equal(["admin"], @scope.match("user/@role").map(&:value))
    end

    def test_positional_predicate
      assert_equal(["region"], @scope.match("config/*[2]").map(&:name))
    end

    def test_predicate_filter
      assert_equal(["alice"],
                   @scope.match("user[@role='admin']").map(&:text))
    end

    def test_position_and_last_functions
      assert_equal("user", @scope.first("*[position()=2]").name)
      assert_equal("config", @scope.first("*[last()-1]").name)
    end

    def test_count_function
      assert_equal([1], @scope.match("count(.//user)"))
    end

    def test_string_function_and_arithmetic
      assert_equal([true],
                   @scope.match("starts-with(.//secret,'ALPHA')"))
      assert_equal([5.0], @scope.match("count(.//*) + 1"))
    end

    def test_self_axis
      assert_equal([@tenant_a], @scope.match("."))
    end

    def test_first_and_each
      assert_equal("config", @scope.first("*").name)
      names = []
      @scope.each("*") { |node| names << node.name }
      assert_equal(%w[config user], names)
    end

    def test_each_without_block_returns_enumerator
      enumerator = @scope.each("*")
      assert_kind_of(Enumerator, enumerator)
      assert_equal(%w[config user], enumerator.map(&:name))
    end

    def test_default_path
      assert_equal(%w[config user], @scope.match.map(&:name))
    end

    def test_namespace_prefixed_query
      document = REXML::Document.new(<<-XML)
<root xmlns="http://example.io/v1">
  <tenant id="a"><secret>ALPHA</secret></tenant>
  <tenant id="b"><secret>BETA</secret></tenant>
</root>
      XML
      tenant = document.root.elements["tenant[@id='a']"]
      scope = REXML::RestrictedXPath.new(
        tenant, {"v" => "http://example.io/v1"}
      )
      assert_equal(["ALPHA"], scope.match("v:secret").map(&:text))
      assert_equal(["ALPHA"], scope.match(".//v:secret").map(&:text))
    end

    def test_other_tenant_keeps_its_own_secret
      scope_b = REXML::RestrictedXPath.new(@tenant_b)
      assert_equal(["BETA-SECRET"], scope_b.match("config/secret").map(&:text))
      assert_equal(["ALPHA-SECRET"],
                   @scope.match("config/secret").map(&:text))
    end

    # Forbidden capabilities: each must raise rather than return a trimmed set.
    def test_parent_axis_via_abbreviation
      assert_boundary_error("..")
      assert_boundary_error("../tenant[@id='b']/config/secret")
    end

    def test_parent_axis_explicit
      assert_boundary_error("parent::*/tenant")
    end

    def test_absolute_path
      assert_boundary_error("/platform/tenant[2]/config/secret")
    end

    def test_double_slash_is_document_rooted
      assert_boundary_error("//tenant[@id='b']")
    end

    def test_ancestor_axes
      assert_boundary_error("ancestor::platform")
      assert_boundary_error("ancestor-or-self::*")
    end

    def test_sibling_and_document_axes
      assert_boundary_error("following-sibling::tenant")
      assert_boundary_error("preceding-sibling::*")
      assert_boundary_error("following::secret")
      assert_boundary_error("preceding::*")
    end

    def test_namespace_axis
      assert_boundary_error("namespace::*")
    end

    def test_union_expression
      assert_boundary_error("config/secret | ../../tenant[2]")
    end

    def test_union_even_when_both_branches_are_inside
      # Union is rejected as a capability regardless of its operands, because
      # it evaluates two independent paths and is a classic smuggling shape.
      assert_boundary_error("config | user")
    end

    def test_node_variable
      assert_boundary_error("$other/secret")
    end

    def test_lang_function_walks_ancestors
      assert_boundary_error("lang('en')")
    end

    def test_forbidden_step_inside_predicate_is_inspected
      assert_boundary_error("config[not(ancestor::platform)]")
      assert_boundary_error("user[../@id='b']")
    end

    def test_forbidden_step_inside_function_argument_is_inspected
      assert_boundary_error("count(//user)")
      assert_boundary_error("concat(../secret, 'x')")
    end

    def test_forbidden_step_inside_group_is_inspected
      assert_boundary_error("(//secret)")
    end

    def test_error_is_a_parse_exception
      error = assert_raise(REXML::XPathBoundaryError) { @scope.match("..") }
      assert_kind_of(REXML::ParseException, error)
      assert_match(/:parent/, error.message)
    end

    def test_rejected_expression_is_not_evaluated
      # Even a syntactically valid in-subtree branch after a forbidden step
      # never runs: the whole query is rejected up front.
      assert_raise(REXML::XPathBoundaryError) do
        @scope.match("../tenant[@id='b'] | config/secret")
      end
    end

    # Defence in depth: independently confirm the runtime guard rejects any
    # out-of-subtree node, even if a node somehow reached it.
    def test_runtime_guard_independently_enforces_boundary
      leaked = @document.root.elements["tenant[@id='b']/config/secret"]
      scope = REXML::RestrictedXPath.new(@tenant_a)

      assert_raise(REXML::XPathBoundaryError) do
        scope.send(:enforce_boundary, [leaked])
      end
      # In-subtree nodes and scalar results pass through untouched.
      inside = @tenant_a.elements["config/secret"]
      assert_equal([inside], scope.send(:enforce_boundary, [inside]))
      assert_equal([true], scope.send(:enforce_boundary, [true]))
    end

    private

    def assert_boundary_error(expression)
      assert_raise(REXML::XPathBoundaryError) do
        @scope.match(expression)
      end
    end
  end
end

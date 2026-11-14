require_relative '../test'

class RenderableClassifierTests < Minitest::Test
  def setup
    @tracker = BrakemanTester.new_tracker
    parse_classes <<-RUBY
      module ViewComponent
        class Base
        end
      end

      module Phlex
        class HTML
        end
      end

      class PlainComponent
        def render_in
        end
      end

      class InheritedComponent < PlainComponent
      end

      class MissingParentComponent < UndefinedParent
      end

      class CycleA < CycleB
        def render_in
        end
      end

      class CycleB < CycleA
      end

      class ComponentWithUnknownRenderIn < SomeGemParent
        def render_in
        end
      end
    RUBY
    @classifier = Brakeman::RenderableClassifier.new(@tracker)
  end

  def test_known_view_component_ancestor_is_confirmed
    assert_confirmed :"ViewComponent::Base", "known renderable ancestor"
  end

  def test_known_phlex_ancestor_is_confirmed
    assert_confirmed :"Phlex::HTML", "known renderable ancestor"
  end

  def test_render_in_in_source_is_confirmed
    assert_confirmed :PlainComponent, "render_in"
  end

  def test_render_in_inherited_from_source_parent_is_confirmed
    assert_confirmed :InheritedComponent, "render_in"
  end

  def test_missing_parent_class_is_unknown
    assert_unknown :MissingParentComponent, "ancestor UndefinedParent is not defined in the source"
  end

  def test_cyclic_inheritance_is_unknown_even_with_render_in
    result = classify_class(:CycleA)
    assert result.unknown?
    assert_match(/cyclic inheritance chain/, result.evidence)
  end

  def test_undefined_class_is_unknown
    result = classify_class(:NeverDefined)
    assert result.unknown?
    assert_match(/not defined in the source/, result.evidence)
  end

  def test_render_in_with_unresolved_parent_is_unknown
    result = classify_class(:ComponentWithUnknownRenderIn)
    assert result.unknown?
  end

  def test_ordinary_call_is_not_classified
    assert_nil @classifier.classify(s(:call, s(:params), :[], s(:lit, :x)))
    assert_nil @classifier.classify(s(:dstr, "x/", s(:evstr, s(:lvar, :y))))
  end

  def test_dynamically_resolved_constant_is_not_classified
    # const_get(...).new has a call receiver rather than a literal constant,
    # so the classifier must not treat it as a confirmed component.
    dynamic = s(:call,
      s(:call, s(:const, :Kernel), :const_get, s(:call, s(:params), :[], s(:lit, :k))),
      :new)

    assert_nil @classifier.classify(dynamic)
  end

  def test_similar_name_without_renderable_evidence_is_unknown
    parse_classes "class NotActuallyAViewComponent; end"
    result = classify_class(:NotActuallyAViewComponent)
    assert result.unknown?
    assert_match(/no known renderable ancestor/, result.evidence)
  end

  def test_new_call_on_unknown_constant_is_unknown
    result = @classifier.classify(
      s(:call, s(:const, :NeverDefined), :new, s(:call, s(:params), :require, s(:lit, :x)))
    )
    assert result.unknown?
    assert_equal :NeverDefined, result.class_name
  end

  def test_new_call_on_known_component_is_confirmed
    result = @classifier.classify(
      s(:call, s(:const, :PlainComponent), :new, s(:call, s(:params), :require, s(:lit, :x)))
    )
    assert result.confirmed?
  end

  def test_dynamic_builder_method_is_unknown
    result = @classifier.classify(
      s(:call, s(:const, :PlainComponent), :build, s(:call, s(:params), :[], s(:lit, :x)))
    )
    assert result.unknown?
    assert_match(/dynamic construction/, result.evidence)
  end

  def test_with_content_unwraps_to_inner_component
    inner = s(:call, s(:const, :PlainComponent), :new)
    result = @classifier.classify(s(:call, inner, :with_content, s(:str, "x")))
    assert result.confirmed?
  end

  def test_with_content_on_unknown_component_is_unknown
    inner = s(:call, s(:const, :NeverDefined), :new)
    result = @classifier.classify(s(:call, inner, :with_content, s(:str, "x")))
    assert result.unknown?
  end

  # The same render call must resolve to the same status regardless of how
  # many times it is classified or what was classified before it.
  def test_classification_is_stable_across_calls_and_order
    names = [:"ViewComponent::Base", :PlainComponent, :CycleA, :MissingParentComponent, :NeverDefined]
    expressions = names.map { |name| s(:call, s(:const, name), :new) }

    baseline = expressions.map { |exp| @classifier.classify(exp).status }

    5.times do
      expressions.shuffle.each { |exp| @classifier.classify(exp) }
    end

    expressions.each_with_index do |exp, index|
      assert_equal baseline[index], @classifier.classify(exp).status
    end
  end

  # A fresh classifier over the same tracker must reach the identical result,
  # proving no per-run mutable state can flip the classification.
  def test_classification_is_independent_of_classifier_instance
    names = [:"ViewComponent::Base", :PlainComponent, :CycleA, :MissingParentComponent]
    names.each do |name|
      exp = s(:call, s(:const, name), :new)
      first = @classifier.classify(exp)
      second = Brakeman::RenderableClassifier.new(@tracker).classify(exp)
      assert_equal first.status, second.status
      assert_equal first.evidence, second.evidence
    end
  end

  private

  def classify_class name
    @classifier.classify_class(name)
  end

  def assert_confirmed name, evidence_fragment
    result = classify_class(name)
    assert result.confirmed?, "expected #{name} to be confirmed, got #{result.inspect}"
    assert_match(/#{evidence_fragment}/, result.evidence)
  end

  def assert_unknown name, evidence_fragment
    result = classify_class(name)
    assert result.unknown?, "expected #{name} to be unknown, got #{result.inspect}"
    assert_match(/#{evidence_fragment}/, result.evidence)
  end

  def parse_classes source
    ast = RubyParser.new.parse(source)
    Brakeman::LibraryProcessor.new(@tracker).process_library(ast, 'fake_file_name.rb')
  end
end

class RenderableArgumentDetectionTests < Minitest::Test
  def setup
    @tracker = BrakemanTester.new_tracker
    @check = Brakeman::CheckRender.new(@tracker)
  end

  def test_finds_user_input_in_constructor_arguments
    exp = s(:call, s(:const, :Unknown), :new,
      s(:call, s(:params), :[], s(:lit, :x)))

    match = @check.send(:user_input_in_renderable_arguments, exp)
    assert_kind_of Brakeman::BaseCheck::Match, match
    assert_equal :params, match.type
  end

  def test_returns_false_for_static_constructor_arguments
    exp = s(:call, s(:const, :Unknown), :new, s(:str, "static"))

    refute @check.send(:user_input_in_renderable_arguments, exp)
  end

  def test_finds_user_input_through_with_content_chain
    inner = s(:call, s(:const, :Unknown), :new,
      s(:call, s(:params), :require, s(:lit, :name)))
    exp = s(:call, inner, :with_content, s(:str, "content"))

    match = @check.send(:user_input_in_renderable_arguments, exp)
    assert_kind_of Brakeman::BaseCheck::Match, match
    assert_equal :params, match.type
  end
end

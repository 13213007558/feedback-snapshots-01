require 'brakeman/util'

# Classifies the first argument of a +render+ call when it looks like a
# renderable object (e.g. +SomeComponent.new(...)+ or +obj.with_content(...)+).
#
# A renderable exemption must never be granted on an unverified value. The
# classification is one of:
#
# - +:confirmed+  - a tracked class with a known renderable ancestor
#   (+ViewComponent::Base+, +ViewComponentContrib::Base+, +Phlex::HTML+) or a
#   +render_in+ method definition that can be located in the source.
# - +:unknown+    - the value is shaped like an object render, but the class or
#   its inheritance chain cannot be resolved (dynamic construction, unknown
#   constant, missing parent class, cyclic inheritance, ...). The render path
#   warning is kept.
#
# The classification only decides whether the value is exempt from the
# *dynamic render path* check. Even a confirmed component can contain XSS in
# what it renders, which is handled by the cross-site scripting checks.
class Brakeman::RenderableClassifier
  include Brakeman::Util

  KNOWN_RENDERABLE_ANCESTORS = [
    :"ViewComponent::Base",
    :"ViewComponentContrib::Base",
    :"Phlex::HTML"
  ].freeze

  # Methods that return the object that should be rendered. +new+ builds a
  # component instance and +with_content+ wraps an existing component.
  RENDERABLE_BUILDERS = [:new, :with_content].freeze

  Classification = Struct.new(:status, :class_name, :evidence, keyword_init: true) do
    def confirmed?
      status == :confirmed
    end

    def unknown?
      status == :unknown
    end
  end

  attr_reader :tracker

  def initialize tracker
    @tracker = tracker
  end

  # Returns a Classification when +exp+ has the shape of an object render
  # (a method call on a constant), otherwise +nil+ so the caller treats the
  # value as an ordinary, potentially dangerous, template name.
  def classify exp
    return nil unless call?(exp)

    if exp.method == :with_content
      # with_content wraps the component built by the inner call; unwrap it.
      return classify(exp.target) if call?(exp.target)

      return unknown(nil, "with_content called on a non-component value")
    end

    return nil unless constant?(exp.target)

    return unknown(nil, "dynamic construction via ##{exp.method}") unless RENDERABLE_BUILDERS.include?(exp.method)

    target_class_name = class_name(exp.target)
    classify_class(target_class_name)
  end

  def classify_class target_class_name
    unless target_class_name.is_a? Symbol
      return unknown(target_class_name, "class name could not be resolved")
    end

    if tracker.find_class(target_class_name).nil?
      return unknown(target_class_name,
        "class #{target_class_name} is not defined in the source")
    end

    status, evidence = resolve_class(target_class_name, [])

    case status
    when :confirmed
      confirmed(target_class_name, evidence)
    when :unknown
      unknown(target_class_name, evidence)
    else
      unknown(target_class_name,
        "no known renderable ancestor or render_in method found")
    end
  end

  private

  def confirmed class_name, evidence
    Classification.new(:status => :confirmed, :class_name => class_name, :evidence => evidence)
  end

  def unknown class_name, evidence
    Classification.new(:status => :unknown, :class_name => class_name, :evidence => evidence)
  end

  # Depth-first walk of the class, its parent chain and its included modules.
  # +seen+ is the ordered list of classes already visited, used to break
  # cycles. Returns a [status, evidence] pair:
  #
  # - +:confirmed+  - a known renderable ancestor or a located render_in
  # - +:unknown+    - a cyclic chain or an ancestor name that cannot be read
  # - +:not_found+  - the resolved chain proves nothing renderable
  #
  # The parent chain is validated before any local render_in is trusted, so a
  # cycle yields :unknown even when render_in exists on a class in the chain.
  def resolve_class class_name, seen
    return [:unknown, "cyclic inheritance chain at #{class_name}"] if seen.include?(class_name)

    seen = seen.dup
    seen << class_name
    klass = tracker.find_class(class_name)
    return [:not_found, nil] if klass.nil?

    # Known framework ancestors are matched by name so they do not need a
    # tracked definition in the application source.
    return [:confirmed, "descends from a known renderable ancestor"] if
      KNOWN_RENDERABLE_ANCESTORS.include?(klass.name)

    # Walk the ancestors first so a cyclic chain is reported as unknown before
    # a local render_in could grant the exemption.
    status, evidence = resolve_ancestors(klass, seen)
    return [status, evidence] unless status == :not_found

    return [:confirmed, "defines render_in in the source"] if
      klass.get_instance_method(:render_in)

    [:not_found, nil]
  end

  # Resolves the parent first, then included modules. A parent that points at
  # a known framework ancestor (such as Phlex::HTML) terminates the chain as
  # confirmed; a parent that is otherwise unresolvable is unknown, and a class
  # with no parent (nil) simply has nothing more to walk.
  def resolve_ancestors klass, seen
    status, evidence = resolve_named_ancestor(klass.parent, seen)
    return [status, evidence] unless status == :not_found

    klass.includes.each do |included_name|
      status, evidence = resolve_named_ancestor(included_name, seen)
      return [status, evidence] unless status == :not_found
    end

    [:not_found, nil]
  end

  def resolve_named_ancestor name, seen
    return [:not_found, nil] if name.nil?

    unless name.is_a? Symbol
      return [:unknown, "ancestor #{name} could not be resolved"]
    end

    return [:unknown, "cyclic inheritance chain at #{name}"] if seen.include?(name)

    # A known framework ancestor terminates the chain successfully even when
    # the framework itself is not present in the application source.
    return [:confirmed, "descends from a known renderable ancestor"] if
      KNOWN_RENDERABLE_ANCESTORS.include?(name)

    # Any other ancestor that cannot be located leaves renderability unknown:
    # the missing class could itself be the renderable base or override
    # render_in, so it must not be silently skipped.
    return [:unknown, "ancestor #{name} is not defined in the source"] if
      tracker.find_class(name).nil?

    resolve_class(name, seen)
  end
end

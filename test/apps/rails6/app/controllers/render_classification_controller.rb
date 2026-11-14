class RenderClassificationController < ApplicationController
  # 1. Confirmed components: known ancestor or a render_in located in source.
  def confirmed_ancestor
    render(TestViewComponent.new(params.require(:name)))
  end

  def confirmed_render_in
    render(RawRenderableComponent.new(params.require(:name)))
  end

  # A confirmed renderable can still contain unsafe output internally; that is
  # the domain of the XSS checks, not the dynamic render path check.
  def confirmed_renderable_with_unsafe_output
    render(UnsafeOutputComponent.new(params.require(:name)))
  end

  # 2. Still a dangerous template name: string path, not an object render.
  def dangerous_template_name
    render(params[:template])
  end

  def dangerous_interpolated_template
    render("groups/#{params[:template]}")
  end

  # 3. Unresolvable objects: unknown class, dynamic factory, broken chain.
  def undefined_class
    render(UndefinedComponent.new(params.require(:name)))
  end

  def missing_parent
    render(MissingParentComponent.new(params.require(:name)))
  end

  def cyclic_chain
    render(CyclicComponentA.new(params.require(:name)))
  end

  def dynamic_factory
    render(ComponentFactory.build(params[:component]))
  end

  # Classified unknown, but the constructor only gets a hardcoded value, so
  # there is no user input to report.
  def static_unknown_object
    render(UndefinedComponent.new("hardcoded"))
  end

  def non_builder_call
    render(TestViewComponent.dup_for(params.require(:name)))
  end
end

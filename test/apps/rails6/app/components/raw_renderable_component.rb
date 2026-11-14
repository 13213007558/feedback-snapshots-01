# Not a ViewComponent/Phlex subclass, but render_in is defined in the source.
class RawRenderableComponent
  def initialize(prop)
    @prop = prop
  end

  def render_in
    "raw"
  end
end

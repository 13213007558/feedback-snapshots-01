# Parent class is never defined in the source, so its renderability cannot
# be confirmed from the inheritance chain.
class MissingParentComponent < UndefinedRenderableParent
  def initialize(prop)
    @prop = prop
  end
end

# Cyclic inheritance: the parent chain cannot establish a renderable ancestor.
class CyclicComponentA < CyclicComponentB
  def initialize(prop)
    @prop = prop
  end
end

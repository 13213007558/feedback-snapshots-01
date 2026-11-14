# Dynamic factory: the returned constant is constructed at runtime, so the
# concrete class cannot be resolved statically.
class ComponentFactory
  def self.build(name)
    name.to_s.camelize.constantize.new(name)
  end
end

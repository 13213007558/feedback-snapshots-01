# frozen_string_literal: true

# A plain business object whose policy lives in the Organization namespace
# (see Organization::ResourcePolicy), reached via the `[:organization, ...]`
# namespaced record syntax.
class Resource
  attr_reader :owner

  def initialize(owner = nil)
    @owner = owner
  end
end

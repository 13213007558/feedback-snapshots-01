# frozen_string_literal: true

# Plain business object that records whether its mutating action ran, so specs
# can prove that processing never happens when a combined authorization fails.
class Approvable
  attr_reader :owner, :approved_with

  def initialize(owner = nil)
    @owner = owner
    @approved_with = nil
  end

  def approve!(resource)
    @approved_with = resource
  end

  def approved?
    !@approved_with.nil?
  end
end

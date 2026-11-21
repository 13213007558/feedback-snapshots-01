# frozen_string_literal: true

class Profile
  ASSIGNABLE_ATTRIBUTES = %i[name bio role verified].freeze

  attr_accessor(*ASSIGNABLE_ATTRIBUTES)
  attr_reader :owner

  def initialize(owner: nil, **attributes)
    @owner = owner
    update(attributes)
  end

  def update(attributes)
    attributes.each do |name, value|
      public_send(:"#{name}=", value)
    end
  end
end

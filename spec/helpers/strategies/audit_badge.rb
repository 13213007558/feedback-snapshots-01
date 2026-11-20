# encoding: utf-8
# frozen_string_literal: true
Warden::Strategies.add(:audit_badge) do
  def authenticate!
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << :audit_badge
    fail!("Badge was rejected")
  end
end

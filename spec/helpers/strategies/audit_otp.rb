# encoding: utf-8
# frozen_string_literal: true
Warden::Strategies.add(:audit_otp) do
  def authenticate!
    request.env['warden.spec.strategies'] ||= []
    request.env['warden.spec.strategies'] << :audit_otp
    fail!("OTP has expired")
  end
end

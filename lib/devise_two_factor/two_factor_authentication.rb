require 'devise_two_factor/two_factor_authentication/status'
require 'devise_two_factor/two_factor_authentication/session'
require 'devise_two_factor/two_factor_authentication/controller_helpers'

module Devise
  module TwoFactorAuthentication
    # Removes the per-session two-factor state when a scope is signed out, so a
    # later account using the same browser session starts from a clean slate.
    def self.install_warden_hooks!
      return if @warden_hooks_installed
      @warden_hooks_installed = true

      Warden::Manager.before_logout do |_record, warden, options|
        scope = options[:scope] || warden.config.default_scope
        session = warden.request.session
        session.delete("devise_two_factor.#{scope}") if session
      end
    end
  end
end

Devise::TwoFactorAuthentication.install_warden_hooks!

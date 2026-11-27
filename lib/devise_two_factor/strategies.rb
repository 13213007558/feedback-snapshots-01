require 'devise_two_factor/audit'
require 'devise_two_factor/strategies/two_factor_authenticatable'
require 'devise_two_factor/strategies/two_factor_backupable'

DeviseTwoFactor::Audit.install_warden_session_hook!

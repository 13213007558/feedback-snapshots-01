class Admin::SettingsController < Admin::BaseController
  skip_before_action :authenticate_user!
  before_action :authenticate_user!, if: :sso_enforced?

  def update
  end

  private

  def sso_enforced?
  end
end

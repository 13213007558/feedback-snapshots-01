class Admin::DashboardController < Admin::BaseController
  skip_before_action :authenticate_user!

  # Fixed public action, exempted via :public_actions configuration
  def overview
  end

  def stats
  end
end

class Admin::UsersController < Admin::BaseController
  skip_before_action :authenticate_user!, only: [:index, :destroy]
  before_action :authenticate_user!, only: [:index]

  def index
  end

  def show
  end

  def destroy
  end

  # Public but not routable: a helper, not an action
  def audit_trail
  end

  private

  def stats_helper
  end
end

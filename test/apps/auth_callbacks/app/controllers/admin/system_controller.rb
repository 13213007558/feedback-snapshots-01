class Admin::SystemController < Admin::BaseController
  skip_before_action :authenticate_user!
  before_action :authenticate_user!, except: [:health]

  def health
  end

  def status
  end
end

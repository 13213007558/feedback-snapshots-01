class Admin::ReportsController < Admin::BaseController
  skip_before_action :authenticate_user!, only: [:download]
  prepend_before_action :authenticate_user!, only: [:download]

  def index
  end

  def download
  end
end

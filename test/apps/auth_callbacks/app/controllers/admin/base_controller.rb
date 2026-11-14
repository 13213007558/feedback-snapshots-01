class Admin::BaseController < ApplicationController
  include AdminAuthentication

  before_action :load_admin_context

  private

  def load_admin_context
  end
end

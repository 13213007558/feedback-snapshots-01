class Admin::AuditController < ApplicationController
  before_action :authenticate_user!, only: [:index]

  def index
  end

  def download
  end
end

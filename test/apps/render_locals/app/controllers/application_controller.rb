class ApplicationController < ActionController::Base
  def widget_content
    params[:c]
  end
end

class AlphaController < ApplicationController
  # Processed first, with user-controlled value
  def show
    render :partial => "shared/widget", :locals => { :content => params[:content] }
  end
end

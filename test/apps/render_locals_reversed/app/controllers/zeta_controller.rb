class ZetaController < ApplicationController
  # Processed second, with trusted constant
  def show
    render :partial => "shared/widget", :locals => { :content => "trusted" }
  end
end

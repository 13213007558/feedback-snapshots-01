class ZetaController < ApplicationController
  # Same partials as AlphaController, but with user-controlled values.
  # Processed after AlphaController.

  def show
    render :partial => "shared/widget", :locals => { :content => params[:content] }
  end

  def nested
    render :partial => "shared/outer", :locals => { :content => params[:content] }
  end

  def items
    render :partial => "shared/thing", :collection => @things, :as => :thing
  end

  def helper_value
    render :partial => "shared/from_helper", :locals => { :content => widget_content }
  end

  def shadowed
    # Action template renders shared/shadow with a tainted local
    @content = "trusted"
  end

  def recursive
    render :partial => "shared/recursive", :locals => { :content => params[:content] }
  end
end

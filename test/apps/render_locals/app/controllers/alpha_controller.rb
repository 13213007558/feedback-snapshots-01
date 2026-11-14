class AlphaController < ApplicationController
  # Renders the same partials as ZetaController, but with trusted constants.
  # AlphaController is processed first (controllers are sorted by name),
  # so these renders populate the template cache first.

  def show
    render :partial => "shared/widget", :locals => { :content => "trusted" }
  end

  def nested
    render :partial => "shared/outer", :locals => { :content => "trusted" }
  end

  def items
    render :partial => "shared/thing", :locals => { :thing => "trusted" }
  end

  def helper_value
    render :partial => "shared/from_helper", :locals => { :content => "trusted" }
  end

  def shadowed
    # Action template renders shared/shadow with a safe local
    @content = "trusted"
  end
end

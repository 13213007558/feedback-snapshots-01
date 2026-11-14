Rails.application.routes.draw do
  get "alpha/:action", :controller => :alpha
  get "zeta/:action", :controller => :zeta
end

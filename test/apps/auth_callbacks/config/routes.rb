Rails.application.routes.draw do
  namespace :admin do
    get "users/index"
    get "users/show"
    delete "users/destroy"
    get "reports/index"
    get "reports/download"
    get "dashboard/overview"
    get "dashboard/stats"
    get "settings/update"
    get "system/health"
    get "system/status"
    get "audit/index"
    get "audit/download"
  end

  get "sessions/new"
end

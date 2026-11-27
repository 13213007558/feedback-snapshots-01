# frozen_string_literal: true

# Host-side stand-in for the pages an OpenID Connect provider shows during an
# authorization: account selection (`prompt=select_account`) and
# reauthentication (`prompt=login`). The Doorkeeper OIDC initializer redirects
# here, and these actions complete the per-request authorization binding the
# gem manages before sending the user-agent back to the authorize endpoint.
class OidcFlowsController < ApplicationController
  # Reaches the per-request authorization binding helpers
  # (`oidc_bind_selected_resource_owner!`, ...) the gem mixes into Doorkeeper's
  # controller helper.
  include Doorkeeper::Helpers::Controller

  skip_forgery_protection only: :select_account

  # GET /select_account?return_to=...
  def choose_account
    @users = User.order(:id)
    @return_to = params[:return_to].to_s
  end

  # POST /select_account
  #
  # Binds the chosen account to the *current* authorization request through the
  # gem's per-request session binding, then resumes the authorize endpoint. A
  # concurrent request (for example a `prompt=none` authorization in another
  # tab) has its own binding key and can never read this selection.
  def select_account
    oidc_bind_selected_resource_owner!(
      params[:resource_owner_id],
      return_to: params[:return_to],
    )

    redirect_to params[:return_to].presence || "/", allow_other_host: true
  end

  # GET /reauthenticate
  def reauthenticate; end
end

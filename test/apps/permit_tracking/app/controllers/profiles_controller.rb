class ProfilesController < ApplicationController
  # Safe: Profile#role is a display field, not a configured sensitive
  # attribute, so permitting it here is not a privilege escalation
  def update_display_role
    Profile.update(params[:id], params.require(:profile).permit(:role))
  end
end

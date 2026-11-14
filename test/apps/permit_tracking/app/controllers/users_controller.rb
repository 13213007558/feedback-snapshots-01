class UsersController < ApplicationController
  # Dangerous: :role is permitted inline and flows into User.update
  def update_role_inline
    User.update(params[:id], params.require(:user).permit(:name, :role))
  end

  # Dangerous: same keys, different order - must warn identically
  def update_role_reordered
    User.update(params[:id], params.require(:user).permit(:role, :name))
  end

  # Safe: only display fields and a nested address hash are permitted
  def update_address
    User.update(params[:id], params.require(:user).permit(:name, address: [:street, :city]))
  end

  # Dangerous: sensitive nested path account.plan is permitted
  def update_nested_account
    User.update(params[:id], params.require(:user).permit(:name, account: [:plan]))
  end

  # Dangerous: sensitive array declaration roles: []
  def update_roles_array
    User.update(params[:id], params.require(:user).permit(:name, roles: []))
  end

  # Dangerous: permitted hash flows through an intermediate variable
  def update_via_variable
    attrs = params.require(:user).permit(:name, :role)
    User.update(params[:id], attrs)
  end

  # Safe: dangerous permit is overwritten before the write
  def update_reassigned
    attrs = params.require(:user).permit(:role)
    attrs = params.require(:user).permit(:name)
    User.update(params[:id], attrs)
  end

  # Dangerous: permitted hash returned from a strong-params method
  def update_via_method
    User.update(params[:id], user_params)
  end

  # Safe: strong-params method only permits display fields
  def update_safe_method
    User.update(params[:id], address_params)
  end

  # Dangerous: permit! allows every key, including sensitive ones
  def update_permit_bang
    User.update(params[:id], params.require(:user).permit!)
  end

  # Safe: merging a trusted literal set by the application
  def update_merge_trusted
    User.update(params[:id], params.require(:user).permit(:name).merge(role: "admin"))
  end

  # Dangerous: merging unpermitted parameters
  def update_merge_params
    User.update(params[:id], params.require(:user).permit(:name).merge(params[:extra]))
  end

  # Uncertain: permitted keys cannot be determined statically
  def update_dynamic_keys
    User.update(params[:id], params.require(:user).permit(*allowed_keys))
  end

  # Safe: create with only display fields
  def create_user
    User.create(params.require(:user).permit(:name, :email))
  end

  private

  def user_params
    params.require(:user).permit(:name, :role)
  end

  def address_params
    params.require(:user).permit(:name, address: [:street, :city])
  end

  def allowed_keys
    [:name]
  end
end

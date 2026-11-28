# frozen_string_literal: true

class AddClientCapabilitiesToApplications < ActiveRecord::Migration[6.0]
  def change
    add_column :oauth_applications, :registered_space, :string
    add_column :oauth_applications, :registered_grant_types, :string
    add_column :oauth_applications, :registered_response_types, :string
    add_column :oauth_applications, :registered_token_endpoint_auth_method, :string
  end
end

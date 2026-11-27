# frozen_string_literal: true

class AddSubjectBindingToOauthGrantsAndTokens < ActiveRecord::Migration[7.0]
  def change
    change_table :oauth_access_grants do |table|
      table.string :oidc_subject
      table.string :oidc_subject_type
      table.string :oidc_subject_sector
      table.string :oidc_subject_fingerprint
    end

    change_table :oauth_access_tokens do |table|
      table.string :oidc_subject
      table.string :oidc_subject_type
      table.string :oidc_subject_sector
      table.string :oidc_subject_fingerprint
    end
  end
end

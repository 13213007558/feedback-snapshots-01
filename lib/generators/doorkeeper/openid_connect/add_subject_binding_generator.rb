# frozen_string_literal: true

require "rails/generators/active_record"

module Doorkeeper
  module OpenidConnect
    # Adds the columns that pin the OpenID Connect subject policy (public or
    # pairwise) onto access grants and access tokens. Pairwise subject
    # identifiers can only stay stable across refresh and UserInfo when the
    # policy in force at issuance is persisted, so this migration is required
    # before enabling a pairwise `subject_type`. New installations get the
    # columns through the regular install migration as well.
    class AddSubjectBindingGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration
      source_root File.expand_path("templates", __dir__)
      desc "Adds the OIDC subject binding columns to oauth_access_grants and oauth_access_tokens."

      def install
        migration_template(
          "add_subject_binding.rb.erb",
          "db/migrate/add_subject_binding_to_oauth_grants_and_tokens.rb",
          migration_version: migration_version,
        )
      end

      def self.next_migration_number(dirname)
        ActiveRecord::Generators::Base.next_migration_number(dirname)
      end

      private

      def migration_version
        return unless ActiveRecord::VERSION::MAJOR >= 5

        "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
      end
    end
  end
end

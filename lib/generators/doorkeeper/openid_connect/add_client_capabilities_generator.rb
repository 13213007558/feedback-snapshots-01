# frozen_string_literal: true

require "rails/generators/active_record"

module Doorkeeper
  module OpenidConnect
    # Adds the columns that record which registration space approved a
    # dynamically registered client and the exact capability set it was
    # approved for. Existing installations upgrading to per-space capability
    # policies need this migration; new installations already get the columns
    # through the regular install migration.
    class AddClientCapabilitiesGenerator < ::Rails::Generators::Base
      include ::Rails::Generators::Migration
      source_root File.expand_path("templates", __dir__)
      desc "Adds the registration-space capability columns to oauth_applications (existing installs)."

      def install
        migration_template(
          "add_client_capabilities.rb.erb",
          "db/migrate/add_client_capabilities_to_oauth_applications.rb",
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

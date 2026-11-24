# frozen_string_literal: true

module Grape
  module DSL
    module UploadHandover
      # Declares upload params whose client filenames are internal
      # diagnostics only: the endpoint sees a generated placeholder in
      # +params+, while the original name stays in the upload registry's
      # audit trail.
      #
      #   internal_upload_names :diagnostics
      #   params do
      #     requires :attachment, type: File
      #     requires :diagnostics, type: File
      #   end
      def internal_upload_names(*names)
        route_setting :upload_internal_names, names.flatten.map(&:to_s)
      end
    end
  end
end

# frozen_string_literal: true

module Grape
  module Middleware
    # Owns the multipart tempfiles of a request on the endpoint's behalf:
    # tracks them in a +Grape::UploadRegistry+ before the endpoint runs and
    # closes whichever ones the endpoint did not take over once the request
    # is answered, however it ended -- rendered, halted or failed validation.
    class UploadHandover < Base
      def before
        return unless multipart_form?

        registry = Grape::UploadRegistry.new(internal_names: internal_upload_names)
        env[Grape::Env::GRAPE_UPLOAD_REGISTRY] = registry
        registry.track_request(Rack::Request.new(env))
      rescue *Grape::RACK_ERRORS
        # A malformed or over-limit body is answered 400 when Grape builds
        # the params, exactly as without this middleware; there is simply
        # nothing to track.
        env.delete(Grape::Env::GRAPE_UPLOAD_REGISTRY)
      end

      def after
        env[Grape::Env::GRAPE_UPLOAD_REGISTRY]&.close_retained!
        nil
      end

      private

      def multipart_form?
        Rack::Request.new(env).media_type == 'multipart/form-data'
      end

      def internal_upload_names
        Array(context&.inheritable_setting&.route_settings&.[](:upload_internal_names)).map(&:to_s)
      end
    end
  end
end

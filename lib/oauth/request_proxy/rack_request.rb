# frozen_string_literal: true

require "oauth/request_proxy/base"
require "uri"
require "rack"

module OAuth
  module RequestProxy
    class RackRequest < OAuth::RequestProxy::Base
      proxies ::Rack::Request

      # Methods that Rack::MethodOverride will accept as an override.
      METHOD_OVERRIDE_METHODS = %w[GET HEAD PUT POST DELETE OPTIONS PATCH LINK UNLINK].freeze

      # Form parameter and header used by Rack::MethodOverride.
      METHOD_OVERRIDE_PARAM = "_method"
      METHOD_OVERRIDE_HEADER = "HTTP_X_HTTP_METHOD_OVERRIDE"

      # How the method used in the signature base string accounts for a
      # Rack::MethodOverride style override.
      #
      # :bound     - (default) The override must be covered by the signature.
      #              A form override is only honored when the signed parameter
      #              set contains +_method+ with the overridden value, in which
      #              case the original method is signed. A header override
      #              cannot be carried in an OAuth 1.0 signature, so the
      #              effective method is signed instead.
      # :effective - Always sign the method that the application will run.
      # :original  - Legacy behavior: always sign the method received on the
      #              wire, ignoring the override (vulnerable to action
      #              substitution when an override is added by an attacker).
      METHOD_OVERRIDE_POLICIES = %i[bound effective original].freeze

      def method
        case method_override_policy
        when :original
          original_method
        when :effective
          effective_method
        else
          bound_method
        end
      end

      def method_override_policy
        policy = (options[:method_override] || :bound).to_sym
        return policy if METHOD_OVERRIDE_POLICIES.include?(policy)

        raise ArgumentError,
              "Unknown :method_override policy #{policy.inspect}, expected one of #{METHOD_OVERRIDE_POLICIES.inspect}"
      end

      def uri
        request.url
      end

      def parameters
        if options[:clobber_request]
          options[:parameters] || {}
        else
          params = request_params.merge(query_params).merge(header_params)
          params.merge(options[:parameters] || {})
        end
      end

      def signature
        parameters["oauth_signature"]
      end

      protected

      def query_params
        request.GET
      end

      def request_params
        if request.content_type && request.content_type.to_s.downcase.start_with?("application/x-www-form-urlencoded")
          request.POST
        else
          {}
        end
      end

      private

      # The method the application will actually dispatch to.
      def bound_method
        return effective_method unless override_source == :form

        form_override_signed? ? original_method : effective_method
      end

      # The method as it arrived on the wire, before any override.
      def original_method
        env = request.env
        (env["rack.methodoverride.original_method"] || env["REQUEST_METHOD"]).to_s.upcase
      end

      # The method the application will actually dispatch to.
      #
      # Mirrors Rack::MethodOverride: only POST is eligible, a form +_method+
      # shadows the header entirely (even when its value is invalid), and the
      # resulting value must be in METHOD_OVERRIDE_METHODS.
      def effective_method
        env = request.env
        return env["REQUEST_METHOD"].to_s.upcase if env["rack.methodoverride.original_method"]

        base = original_method
        return base unless base == "POST"

        form_present, form_value = form_override
        candidate = form_present ? normalize_override_method(form_value) : header_override_value
        candidate || base
      end

      # Which input supplied the override that Rack applied.
      def override_source
        applied = effective_method
        return nil if applied == original_method

        form_present, form_value = form_override
        form_present && normalize_override_method(form_value) == applied ? :form : :header
      end

      # Returns [present?, raw_value] for the form _method key.
      def form_override
        return [false, nil] unless request.form_data?

        params = request.POST
        return [false, nil] unless params.key?(METHOD_OVERRIDE_PARAM)

        [true, params[METHOD_OVERRIDE_PARAM]]
      rescue StandardError
        [false, nil]
      end

      def header_override_value
        normalize_override_method(request.env[METHOD_OVERRIDE_HEADER])
      end

      def normalize_override_method(value)
        return nil unless value.is_a?(String)

        value = value.upcase
        METHOD_OVERRIDE_METHODS.include?(value) ? value : nil
      end

      # A form override is only safe when the signed parameter set covers it.
      # Otherwise an attacker can append +_method+ to a signed request body.
      def form_override_signed?
        signed = parameters_for_signature[METHOD_OVERRIDE_PARAM]
        return false if signed.nil?

        values = signed.is_a?(Array) ? signed : [signed]
        values.any? { |value| value.to_s.upcase == effective_method }
      end
    end
  end
end

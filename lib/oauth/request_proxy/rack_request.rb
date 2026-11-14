# frozen_string_literal: true

require "oauth/request_proxy/base"
require "oauth/errors/problem"
require "uri"
require "rack"

module OAuth
  module RequestProxy
    class RackRequest < OAuth::RequestProxy::Base
      proxies ::Rack::Request

      def method
        request.env["rack.methodoverride.original_method"] || request.request_method
      end

      def uri
        request.url
      end

      def parameters
        if options[:clobber_request]
          options[:parameters] || {}
        else
          reject_ambiguous_oauth_locations! unless options[:allow_duplicate_oauth_locations]

          params = request_params.merge(query_params).merge(header_params)
          params.merge(options[:parameters] || {})
        end
      end

      def signature
        parameters["oauth_signature"]
      end

      # The OAuth protocol parameter names that actually appear in each
      # credential carrier, keyed by location. Only +oauth_*+ protocol
      # parameters are considered, so an ordinary business field that happens
      # to share a name never trips this check.
      def oauth_parameters_by_location
        {
          body: oauth_names(request_params),
          query: oauth_names(query_params),
          header: oauth_names(header_params)
        }
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

      def oauth_names(params)
        params.keys.select { |name| OAuth::PARAMETERS.include?(name) }.sort
      end

      # Reject requests that carry OAuth protocol fields in more than one
      # location (header + query, header + body, query + body, or all three).
      # Merging them would silently let one carrier override the other, which
      # hides misconfigured or actively split-credential clients.
      def reject_ambiguous_oauth_locations!
        present = oauth_parameters_by_location.select { |_location, names| names.any? }
        return if present.size <= 1

        duplicated = present.values.inject(:&)
        # Different oauth_* names split across locations are still ambiguous
        # even when no single name is literally duplicated.
        duplicated = present.values.flatten.uniq.sort if duplicated.empty?

        raise OAuth::AmbiguousCredentials.new(present.keys, duplicated)
      end
    end
  end
end

# frozen_string_literal: true

require 'rack/protection'

module Rack
  module Protection
    ##
    # Prevented attack::   CSRF
    # Supported browsers:: all
    # More infos::         http://flask.pocoo.org/docs/0.10/security/#json-security
    #                      http://haacked.com/archive/2008/11/20/anatomy-of-a-subtle-json-vulnerability.aspx
    #
    # JSON GET APIs are vulnerable to being embedded as JavaScript when the
    # Array prototype has been patched to track data. Checks the referrer
    # even on GET requests if the content type is JSON.
    #
    # If request includes Origin HTTP header, defers to HttpOrigin to determine
    # if the request is safe. Please refer to the documentation for more info.
    #
    # The `:allow_if` option can be set to a proc to use custom allow/deny logic.
    #
    # Because this check depends on the response's <tt>content-type</tt>, the
    # protection decision is made after the application has returned. Reactions
    # therefore follow the response-dependent contract described in
    # Rack::Protection::Base: +:report+ keeps the original response and records
    # the finding, while a denial reaction must return a Rack response triple
    # and the original body is closed exactly once without being iterated.
    class JsonCsrf < Base
      default_options allow_if: nil

      def call(env)
        request = Request.new(env)

        check_response(env) do |_status, headers, _body|
          has_vector?(request, headers)
        end
      end

      def has_vector?(request, headers)
        return false if request.xhr?
        return false if options[:allow_if]&.call(request.env)
        return false unless headers['content-type'].to_s.split(';', 2).first =~ %r{^\s*application/json\s*$}

        origin(request.env).nil? and referrer(request.env) != request.host
      end
    end
  end
end

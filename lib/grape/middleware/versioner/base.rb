# frozen_string_literal: true

module Grape
  module Middleware
    module Versioner
      class Base < Grape::Middleware::Base
        extend Forwardable
        include Grape::Middleware::PrecomputedContentTypes

        Options = Data.define(
          :content_types, :format, :mount_path, :prefix, :version_options, :versions
        ) do
          def initialize(
            content_types: nil, format: nil, mount_path: nil, prefix: nil,
            version_options: Grape::DSL::VersionOptions.new, versions: nil
          )
            super
          end
        end

        CASCADE_PASS_HEADER = { 'x-cascade' => 'pass' }.freeze

        # Request header names a strategy negotiates on, listed on the +Vary+
        # of every response when +version+'s +vary:+ is on. A shared cache
        # keys a stored response on the +Vary+ it answered with, so a response
        # negotiated on an input it does not list could go to a request that
        # input does not match. Strategies reading no request header (:path,
        # :param) keep it empty.
        VARY_HEADER_NAMES = [].freeze

        def self.inherited(klass)
          super
          Versioner.register(klass)
        end

        attr_reader :available_media_types, :error_headers, :versions

        # Read off ivars rather than delegated through +version_options+ into
        # +config+: the versioners ask for +vendor+, +strict+ or +parameter+ on
        # every request, and each read went two Forwardable frames and two Data
        # readers deep for a value fixed when the middleware was built.
        attr_reader :cascade, :parameter, :strict, :vendor, :vary_headers

        def_delegators :config, :mount_path, :prefix, :version_options

        def initialize(app, **options)
          super
          @cascade = version_options.cascade
          @parameter = version_options.parameter
          @strict = version_options.strict
          # Media types are case-insensitive, and Grape::Util::MediaType parses
          # an Accept header into lowercase; a vendor declared with capitals
          # would otherwise never match one.
          @vendor = version_options.vendor&.downcase
          @vary_headers = version_options.vary ? self.class::VARY_HEADER_NAMES : []
          @versions = config.versions&.map(&:to_s) # making sure versions are strings to ease potential match
          @error_headers = merge_vary(cascade ? CASCADE_PASS_HEADER.dup : {})
          @available_media_types = build_available_media_types
        end

        def potential_version_match?(potential_version)
          versions.nil? || versions.empty? || versions.include?(potential_version)
        end

        def after
          merge_vary(response_headers) if @app_response
          nil
        end

        def version_not_found!
          throw :error, Grape::Exceptions::ErrorResponse.new(status: 404, message: '404 API Version Not Found', headers: CASCADE_PASS_HEADER)
        end

        private

        # Appends the strategy's negotiation inputs to a response's +Vary+,
        # keeping the names an app set itself: a +Vary: *+ already covers
        # every input, and a name already listed is not repeated. Anything
        # else on the response, such as a +Cache-Control+ keeping it out of
        # shared caches, is untouched.
        def merge_vary(headers)
          return headers if vary_headers.empty?

          key = headers.keys.find { |name| name.casecmp?('vary') }
          names = key ? headers[key].split(',').map(&:strip) : []
          return headers if names.include?('*')

          additions = vary_headers.reject { |name| names.any? { |listed| listed.casecmp?(name) } }
          return headers if additions.empty?

          headers[key || 'vary'] = (names + additions).join(', ')
          headers
        end

        def response_headers
          @app_response.is_a?(Rack::Response) ? @app_response.headers : @app_response[1]
        end

        def build_available_media_types
          media_types = []
          base_media_type = "application/vnd.#{vendor}"
          versions&.reverse_each { |version| append_media_types(media_types, "#{base_media_type}-#{version}") }
          append_media_types(media_types, base_media_type)
          media_types.concat(content_types.values.flatten)
          # Media types are case-insensitive, and Grape::Util::MediaType matches
          # an Accept header in lowercase; a version or content type declared
          # with capitals would otherwise never match one.
          media_types.map!(&:downcase)
        end

        # +base+ with each content type's extension, then +base+ alone.
        def append_media_types(media_types, base)
          content_types.each_key { |extension| media_types << "#{base}+#{extension}" }
          media_types << base
        end
      end
    end
  end
end

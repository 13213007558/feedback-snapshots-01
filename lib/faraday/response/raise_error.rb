# frozen_string_literal: true

module Faraday
  class Response
    # RaiseError is a Faraday middleware that raises exceptions on common HTTP
    # client or server error responses.
    class RaiseError < Middleware
      # rubocop:disable Naming/ConstantName
      ClientErrorStatuses = (400...500)
      ServerErrorStatuses = (500...600)
      ClientErrorStatusesWithCustomExceptions = {
        400 => Faraday::BadRequestError,
        401 => Faraday::UnauthorizedError,
        403 => Faraday::ForbiddenError,
        404 => Faraday::ResourceNotFound,
        408 => Faraday::RequestTimeoutError,
        409 => Faraday::ConflictError,
        422 => Faraday::UnprocessableContentError,
        429 => Faraday::TooManyRequestsError
      }.freeze
      # rubocop:enable Naming/ConstantName

      DEFAULT_OPTIONS = { include_request: true, allowed_statuses: [].freeze }.freeze

      def on_request(env)
        # Announce the opt-out on the shared Env so that errors raised by other
        # middlewares (e.g. ParsingError from the Json middleware) honor it too.
        env[:include_request] = false unless options[:include_request]
      end

      def on_complete(env)
        return if Array(options[:allowed_statuses]).include?(env[:status])

        policy = disclosure_policy(env)
        return raise_with_disclosure(env, policy) if policy

        case env[:status]
        when *ClientErrorStatusesWithCustomExceptions.keys
          raise ClientErrorStatusesWithCustomExceptions[env[:status]], response_values(env)
        when 407
          # mimic the behavior that we get with proxy requests with HTTPS
          msg = %(407 "Proxy Authentication Required")
          raise Faraday::ProxyAuthError.new(msg, response_values(env))
        when ClientErrorStatuses
          raise Faraday::ClientError, response_values(env)
        when ServerErrorStatuses
          raise Faraday::ServerError, response_values(env)
        when nil
          raise Faraday::NilStatusError, response_values(env)
        end
      end

      # Returns a hash of response data with the following keys:
      #   - status
      #   - headers
      #   - body
      #   - request
      #
      # The `request` key is omitted when the middleware is explicitly
      # configured with the option `include_request: false`.
      #
      # When the connection carries a disclosure policy, the hash is limited to
      # the selected response and request attributes.
      def response_values(env)
        policy = disclosure_policy(env)
        return disclosed_response_values(env, policy) if policy

        response = {
          status: env.status,
          headers: env.response_headers,
          body: env.body
        }

        # Include the request data by default. If the middleware was explicitly
        # configured to _not_ include request data, then omit it.
        return response unless options[:include_request]

        response.merge(request: legacy_request_values(env))
      end

      def query_params(env)
        env.request.params_encoder ||= Faraday::Utils.default_params_encoder
        env.params_encoder.decode(env.url.query)
      end

      private

      # Request attributes in the shape RaiseError has always used.
      LEGACY_REQUEST_VALUES = {
        method: :method,
        url: :url,
        url_path: :url_path,
        params: :params,
        headers: :request_headers,
        body: :request_body
      }.freeze

      def disclosure_policy(env)
        Faraday::Disclosure.policy_for(env)
      end

      def disclosed_response_values(env, policy)
        response = { status: env.status }
        response[:headers] = env.response_headers if policy.error_detail?(:response_headers)
        response[:body] = Faraday::Disclosure.response_body(env) if policy.error_detail?(:response_body)

        return response unless options[:include_request]
        return response unless policy.request_policy?

        response.merge(request: disclosed_request_values(env, policy))
      end

      def legacy_request_values(env)
        LEGACY_REQUEST_VALUES.transform_values { |attribute| request_attribute(env, attribute) }
      end

      def disclosed_request_values(env, policy)
        LEGACY_REQUEST_VALUES.each_with_object({}) do |(key, attribute), values|
          next unless policy.request_attribute?(key)

          values[key] = request_attribute(env, attribute)
        end
      end

      def request_attribute(env, attribute)
        case attribute
        when :url_path then env.url.path
        when :params then query_params(env)
        else env.public_send(attribute)
        end
      end

      def raise_with_disclosure(env, policy)
        message = disclosed_message(env, policy)
        values = response_values(env)

        case env[:status]
        when *ClientErrorStatusesWithCustomExceptions.keys
          raise ClientErrorStatusesWithCustomExceptions[env[:status]].new(message, values)
        when 407
          raise Faraday::ProxyAuthError.new(%(407 "Proxy Authentication Required"), values)
        when ClientErrorStatuses
          raise Faraday::ClientError.new(message, values)
        when ServerErrorStatuses
          raise Faraday::ServerError.new(message, values)
        when nil
          raise Faraday::NilStatusError, values
        end
      end

      def disclosed_message(env, policy)
        unless options[:include_request]
          return "the server responded with status #{env.status} - method and url are not available " \
                 'due to include_request: false on Faraday::Response::RaiseError middleware'
        end

        Faraday::Disclosure.status_message(
          env.status,
          policy.request_attribute?(:method) ? env.method : nil,
          Faraday::Disclosure.request_url(env, policy)
        )
      end
    end
  end
end

Faraday::Response.register_middleware(raise_error: Faraday::Response::RaiseError)

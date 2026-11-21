# frozen_string_literal: true

module Faraday
  # @!parse
  #   # RequestOptions contains the configurable properties for a Faraday request.
  #   #
  #   # @!attribute params_encoder
  #   #   @return [Object] the params encoder used to serialize the request params
  #   #
  #   # @!attribute proxy
  #   #   @return [ProxyOptions] proxy options for this request
  #   #
  #   # @!attribute proxy_required
  #   #   @return [Boolean] when true, the request must use a proxy that was
  #   #     explicitly configured for the request or the connection. If none is
  #   #     configured, {Faraday::ProxyRequiredError} is raised instead of
  #   #     falling back to the environment proxy or a direct connection.
  #   #
  #   # @!attribute bind
  #   #   @return [Hash] the local host and port to bind the connection to
  #   #
  #   # @!attribute timeout
  #   #   @return [Integer] time limit for the entire request (in seconds)
  #   #
  #   # @!attribute open_timeout
  #   #   @return [Integer] time limit for just the connection phase (in seconds)
  #   #
  #   # @!attribute read_timeout
  #   #   @return [Integer] time limit for the first response byte received from
  #   #           the server (in seconds)
  #   #
  #   # @!attribute write_timeout
  #   #   @return [Integer] time limit for the client to send the request to the
  #   #           server (in seconds)
  #   #
  #   # @!attribute boundary
  #   #   @return [String] the boundary used for multipart request bodies
  #   #
  #   # @!attribute oauth
  #   #   @return [Hash] OAuth options used by the OAuth middleware
  #   #
  #   # @!attribute context
  #   #   @return [Hash] free-form storage carried alongside the request
  #   #
  #   # @!attribute on_data
  #   #   @return [Proc] callback invoked with each chunk when streaming the response
  #   class RequestOptions < Options; end
  RequestOptions = Options.new(:params_encoder, :proxy, :bind,
                               :timeout, :open_timeout, :read_timeout,
                               :write_timeout, :boundary, :oauth,
                               :context, :on_data, :proxy_required) do
    def []=(key, value)
      if key && key.to_sym == :proxy
        super(key, value ? ProxyOptions.from(value) : nil)
      else
        super
      end
    end

    # Normalise a proxy passed straight to the constructor, which Struct would
    # otherwise assign without coercion.
    #
    # @api private
    def initialize(...)
      super
      proxy = self[:proxy]
      self[:proxy] = proxy if proxy
    end

    # Coerce every proxy assignment, including plain writer calls that do not
    # go through {#[]=}.
    #
    # The Struct-generated writer is replaced rather than wrapped to avoid a
    # recursion warning.
    #
    # @api private
    remove_method :proxy= if method_defined?(:proxy=, false)

    # @param value [ProxyOptions, Hash, URI, String, nil]
    def proxy=(value)
      self[:proxy] = value
    end

    # Give each request its own proxy options, so changing the proxy of one
    # request cannot leak into the connection defaults or the next request.
    #
    # @api private
    def initialize_copy(other)
      super
      self[:proxy] = other[:proxy] if other[:proxy]
    end

    def stream_response?
      on_data.is_a?(Proc)
    end
  end
end

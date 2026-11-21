# frozen_string_literal: true

require 'faraday/options_like'
require 'faraday/base_options'

module Faraday
  # Selects which request attributes and error details Faraday may hand to
  # shared sinks, such as the Logger middleware and errors raised by the
  # RaiseError middleware.
  #
  # A policy is configured on the connection (or per request) as:
  #
  #   Faraday.new(disclosure: {
  #     request: %i[method url_path],
  #     error: %i[message response_body]
  #   })
  #
  # The response status and the error class are always disclosed, so failures
  # remain identifiable. A `nil` policy keeps the historical behavior of each
  # middleware.
  #
  # @!attribute request
  #   @return [Array<Symbol>, nil] request attributes allowed in shared output
  #
  # @!attribute error
  #   @return [Array<Symbol>, nil] error details allowed in shared output
  class DisclosureOptions < BaseOptions
    MEMBERS = %i[request error].freeze

    # Request attributes that can be selected for disclosure.
    REQUEST_MEMBERS = %i[method url url_path params headers body].freeze

    # Error details that can be selected for disclosure.
    ERROR_MEMBERS = %i[message response_headers response_body wrapped_exception backtrace].freeze

    REQUEST_ALIASES = {
      request_headers: :headers,
      request_body: :body
    }.freeze

    ERROR_ALIASES = {
      headers: :response_headers,
      body: :response_body,
      exception: :wrapped_exception
    }.freeze

    attr_writer :request, :error

    def update(obj)
      super
      validate!
    end

    def merge!(obj)
      super
      validate!
    end

    # Validates every configured attribute name, raising ArgumentError for
    # unknowns. Readers validate lazily too, so a policy can be inspected
    # without mutating it.
    #
    # @return [DisclosureOptions] self
    def validate!
      request
      error
      self
    end

    # Normalizes the accepted forms into a {DisclosureOptions} instance.
    #
    # `nil` and `false` mean "no policy configured". `true` means the strict
    # policy: neither request attributes nor error details are disclosed.
    # An omitted dimension keeps its legacy behavior; an explicit empty array
    # selects nothing for that dimension.
    #
    # @param value [nil, Boolean, Hash, #to_hash, DisclosureOptions]
    # @return [DisclosureOptions, nil]
    def self.from(value)
      case value
      when nil, false then nil
      when true
        new.tap do |options|
          options.request = []
          options.error = []
        end
      else
        return value.deep_dup if value.is_a?(self)

        new(value)
      end
    end

    # @return [Array<Symbol>, nil] selected request attributes, or nil when
    #   this dimension was not configured
    def request
      normalize(@request, REQUEST_MEMBERS, REQUEST_ALIASES, :request)
    end

    # @return [Array<Symbol>, nil] selected error details, or nil when this
    #   dimension was not configured
    def error
      normalize(@error, ERROR_MEMBERS, ERROR_ALIASES, :error)
    end

    # @return [Boolean] whether the request dimension was configured
    def request_configured?
      !@request.nil?
    end

    # @return [Boolean] whether the error dimension was configured
    def error_configured?
      !@error.nil?
    end

    # @return [Boolean] whether any request attribute may be disclosed
    def request_policy?
      !request_configured? || !request.empty?
    end

    # @return [Boolean] whether any error detail may be disclosed
    def error_policy?
      !error_configured? || !error.empty?
    end

    # @param name [Symbol, String] a request attribute
    # @return [Boolean] whether the attribute may be disclosed
    def request_attribute?(name)
      return true unless request_configured?

      request.include?(canonical(name, REQUEST_ALIASES))
    end

    # @param name [Symbol, String] an error detail
    # @return [Boolean] whether the detail may be disclosed
    def error_detail?(name)
      return true unless error_configured?

      error.include?(canonical(name, ERROR_ALIASES))
    end

    def inspect
      "#<#{self.class} request=#{request.inspect} error=#{error.inspect}>"
    end

    # Policies compare by the attributes they select, so a copied policy is
    # equal to its source.
    def ==(other)
      other.is_a?(self.class) && request == other.request && error == other.error
    end
    alias eql? ==

    def hash
      [self.class, request, error].hash
    end

    private

    def normalize(value, members, aliases, kind)
      return nil if value.nil?

      list =
        case value
        when Symbol, String then [value]
        else value.to_a
        end

      list.map do |name|
        canonical = canonical(name, aliases)
        unless members.include?(canonical)
          raise ArgumentError, "unknown #{kind} disclosure attribute: #{name.inspect}"
        end
        canonical
      end.uniq
    end

    def canonical(name, aliases)
      symbol = name.to_sym
      aliases.fetch(symbol, symbol)
    end
  end
end

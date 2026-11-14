# encoding: utf-8
# frozen_string_literal: true
require 'mail/parsers/authentication_results_parser'
require 'mail/utilities'

module Mail
  # Structured representation of one Authentication-Results header
  # instance (RFC 8601).
  #
  # WARNING: a successfully parsed element is NOT proof of
  # authentication. Anyone on the delivery path (including the sender)
  # can prepend forged Authentication-Results headers. Use
  # Mail::AuthenticationResults.trusted to select only the header
  # instances your own receiving infrastructure added before feeding
  # any result into a security decision.
  class AuthenticationResultsElement
    # One ptype.property=value property of a method result.
    class Property
      attr_reader :type, :property, :value

      def initialize(struct)
        @type = struct.type
        @property = struct.property
        @value = struct.value
      end

      def to_s
        "#{type}.#{property}=#{value}"
      end
    end

    # One method=result entry of an Authentication-Results header.
    class MethodResult
      attr_reader :method, :method_version, :result, :reason, :properties, :comments

      def initialize(struct)
        @method = struct.method
        @method_version = struct.method_version
        @result = struct.result
        @reason = struct.reason
        @properties = struct.properties.map { |prop| Property.new(prop) }
        @comments = struct.comments.dup
      end

      # Case-insensitive method name comparison; RFC 8601 keywords are
      # case-insensitive. Unknown methods are preserved, never aliased
      # to a known one.
      def method?(name)
        !method.nil? && method.casecmp(name.to_s) == 0
      end

      # True when the recorded result is "pass" (case-insensitive).
      # This only reports what the header says; it says nothing about
      # whether the header itself is trustworthy.
      def pass?
        !result.nil? && result.casecmp('pass') == 0
      end

      # Value of the first matching ptype.property, e.g.
      #   result.property('header', 'from')
      def property(type, name)
        found = properties.find { |prop|
          prop.type.to_s.casecmp(type.to_s) == 0 &&
            prop.property.to_s.casecmp(name.to_s) == 0
        }
        found && found.value
      end

      def to_s
        string = +"#{method}"
        string << "/#{method_version}" if method_version
        string << "=#{result}"
        string << " reason=#{reason.inspect}" if reason
        properties.each { |prop| string << " #{prop}" }
        string
      end
    end

    attr_reader :authserv_id, :version, :results, :comments

    def initialize(string)
      if Utilities.blank?(string)
        @authserv_id = nil
        @version = nil
        @none = false
        @results = []
        @comments = []
      else
        parsed = Mail::Parsers::AuthenticationResultsParser.parse(string)
        @authserv_id = parsed.authserv_id
        @version = parsed.version
        @none = parsed.none
        @results = parsed.results.map { |result| MethodResult.new(result) }
        @comments = parsed.comments
      end
    end

    # True when the header records the special "none" payload (no
    # authentication results were recorded by the authserv-id).
    def none?
      @none
    end

    # First result entry recorded for +method+ (case-insensitive),
    # or nil. nil means the header carries no result for that method;
    # it is not a "pass".
    def result_for(method)
      results.find { |result| result.method?(method) }
    end

    def to_s
      string = +"#{authserv_id}"
      string << "/#{version}" if version
      string << "; none" if none?
      results.each { |result| string << "; #{result}" }
      string
    end
  end
end

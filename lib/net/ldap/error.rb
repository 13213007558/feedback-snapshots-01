class Net::LDAP
  class Error < StandardError; end

  class AlreadyOpenedError < Error; end
  class SocketError < Error; end
  class ConnectionError < Error
    def self.new(errors)
      error = errors.first.first
      if errors.size == 1
        return error if error.is_a? Errno::ECONNREFUSED

        return Net::LDAP::Error.new(error.message)
      end

      super
    end

    def initialize(errors)
      message = "Unable to connect to any given server: \n  #{errors.map { |e, h, p| "#{e.class}: #{e.message} (#{h}:#{p})" }.join("\n  ")}"
      super(message)
    end
  end
  class NoOpenSSLError < Error; end
  class NoStartTLSResultError < Error; end
  class NoSearchBaseError < Error; end
  class StartTLSError < Error; end
  class EncryptionUnsupportedError < Error; end
  class EncMethodUnsupportedError < Error; end
  class AuthMethodUnsupportedError < Error; end
  class BindingInformationInvalidError < Error; end
  class NoBindResultError < Error; end
  class SASLChallengeOverflowError < Error; end
  class SearchSizeInvalidError < Error; end
  class SearchScopeInvalidError < Error; end
  class ResponseTypeInvalidError < Error; end
  class ResponseMissingOrInvalidError < Error; end
  class EmptyDNError < Error; end
  class InvalidDNError < Error; end
  class HashTypeUnsupportedError < Error; end
  class OperatorError < Error; end
  class SubstringFilterError < Error; end
  class SearchFilterError < Error; end
  class BERInvalidError < Error; end
  class SearchFilterTypeUnknownError < Error; end
  class BadAttributeError < Error; end
  class FilterTypeUnknownError < Error; end
  class FilterSyntaxInvalidError < Error; end
  class EntryOverflowError < Error; end
  class AttributeRangeError < Error; end
  class InvalidAttributeRangeError < AttributeRangeError; end

  # Raised when a complete attribute value set is required but the read did
  # not finish. Partial values remain available through
  # RangedAttributeResult#partial_values for diagnostics, but must not be used
  # as an authorization snapshot.
  class IncompleteAttributeError < AttributeRangeError
    attr_reader :result

    def initialize(result = nil)
      if result.respond_to?(:attribute) && result.respond_to?(:dn)
        @result = result
        super(
          "attribute #{result.attribute.inspect} on #{result.dn.inspect} is not " \
          "complete (#{result.reason}); refusing to expose partial values",
        )
      else
        super(result)
      end
    end
  end
end

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

  # Base class for errors raised while coordinating an RFC 5805 LDAP
  # transaction (programming/coordination failures rather than ordinary
  # server result codes, which are reported on the transaction result).
  class TransactionError < Error; end

  # Raised when a transaction is started while another transaction is already
  # active on the same Net::LDAP object. RFC 5805 forbids nesting.
  class NestedTransactionError < TransactionError; end

  # Raised when an operation that must not participate in, or coexist with, a
  # transaction is attempted while one is outstanding (e.g. a Bind, or an
  # update that cannot be attached to the transaction).
  class OperationNotAllowedInTransactionError < TransactionError; end

  # Raised when code inside a transaction block tries to use a different
  # connection than the one the transaction was started on. A transaction
  # identifier is scoped to a single LDAP association (RFC 5805 section 5).
  class TransactionConnectionError < TransactionError; end

  # Raised internally when an update request that is part of a transaction
  # returns a non-success response. The transaction is aborted as a result.
  # Carries the failing operation name and its result PDU.
  class TransactionOperationError < TransactionError
    attr_reader :operation, :operation_result

    def initialize(message, operation, operation_result)
      super(message)
      @operation = operation
      @operation_result = operation_result
    end
  end
end

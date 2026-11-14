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

  # Raised when the server sends an unsolicited Notice of Disconnection
  # (RFC 4511 section 4.4.1). Carries the result code and diagnostic
  # message supplied by the server so every operation waiting on the
  # connection fails with the same, authoritative reason.
  class NoticeOfDisconnectionError < Error
    attr_reader :result_code, :error_message, :matched_dn

    def initialize(result_code, error_message = "", matched_dn = "")
      @result_code = result_code
      @error_message = error_message
      @matched_dn = matched_dn

      suffix = error_message.to_s.empty? ? "" : ": #{error_message}"
      super("Connection disconnected by server (#{result_code})#{suffix}")
    end
  end

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
end

# -*- ruby encoding: utf-8 -*-
require 'stringio'

class Net::LDAP
  # Parsed representation of the Password Policy Response control returned by
  # a directory server in a BindResponse (and, for some servers, other
  # responses).
  #
  # The control is defined by the "Password Policy for LDAP Directories"
  # draft (draft-behera-ldap-password-policy) and carries the OID
  # {Net::LDAP::LDAPControls::PASSWORD_POLICY_RESPONSE}. Its value is a BER
  # SEQUENCE wrapped in the control's OCTET STRING:
  #
  #   PasswordPolicyResponseValue ::= SEQUENCE {
  #     warning [0] PPolicyWarning OPTIONAL,
  #     error   [1] PPolicyError   OPTIONAL }
  #
  #   PPolicyWarning ::= ENUMERATED {
  #     timeBeforeExpiration  (0),
  #     graceAuthNsRemaining  (1) }
  #
  #   PPolicyError ::= ENUMERATED {
  #     passwordExpired       (0),
  #     accountLocked         (1),
  #     changeAfterReset      (2),
  #     passwordModNotAllowed (3),
  #     mustSupplyOldPassword (4),
  #     insufficientPasswordQuality (5),
  #     passwordTooShort      (6),
  #     passwordTooYoung      (7),
  #     passwordInHistory     (8) }
  #
  # The warning and error values are each context-specific INTEGERs, so the
  # numeric tag (0x80..0x83) has to be preserved while decoding. The generic
  # BER syntax would collapse those into plain integers and lose the tag, so
  # this class walks the TLVs itself.
  #
  # Instances are created from the raw control value with
  # {.from_control_value}. A value that cannot be parsed is not fatal to the
  # bind: the resulting object simply reports {#malformed?} and leaves the
  # warning/error attributes nil.
  class PasswordPolicyResponse
    # Tag bytes used inside the control value (context-specific, primitive).
    TIME_BEFORE_EXPIRATION_TAG = 0x80
    GRACE_AUTHNS_REMAINING_TAG = 0x81
    ERROR_TAG = 0x82

    # PPolicyError enumeration values (draft-behera section 5.3).
    ERROR_PASSWORD_EXPIRED = 0
    ERROR_ACCOUNT_LOCKED = 1
    ERROR_CHANGE_AFTER_RESET = 2
    ERROR_PASSWORD_MOD_NOT_ALLOWED = 3
    ERROR_MUST_SUPPLY_OLD_PASSWORD = 4
    ERROR_INSUFFICIENT_PASSWORD_QUALITY = 5
    ERROR_PASSWORD_TOO_SHORT = 6
    ERROR_PASSWORD_TOO_YOUNG = 7
    ERROR_PASSWORD_IN_HISTORY = 8

    ErrorCodes = {
      ERROR_PASSWORD_EXPIRED => :passwordExpired,
      ERROR_ACCOUNT_LOCKED => :accountLocked,
      ERROR_CHANGE_AFTER_RESET => :changeAfterReset,
      ERROR_PASSWORD_MOD_NOT_ALLOWED => :passwordModNotAllowed,
      ERROR_MUST_SUPPLY_OLD_PASSWORD => :mustSupplyOldPassword,
      ERROR_INSUFFICIENT_PASSWORD_QUALITY => :insufficientPasswordQuality,
      ERROR_PASSWORD_TOO_SHORT => :passwordTooShort,
      ERROR_PASSWORD_TOO_YOUNG => :passwordTooYoung,
      ERROR_PASSWORD_IN_HISTORY => :passwordInHistory,
    }.freeze

    # Human-readable names for the error codes, mirroring
    # Net::LDAP::ResultStrings.
    ErrorStrings = {
      ERROR_PASSWORD_EXPIRED => "Password expired",
      ERROR_ACCOUNT_LOCKED => "Account locked",
      ERROR_CHANGE_AFTER_RESET => "Change password after reset",
      ERROR_PASSWORD_MOD_NOT_ALLOWED => "Password modification not allowed",
      ERROR_MUST_SUPPLY_OLD_PASSWORD => "Must supply old password",
      ERROR_INSUFFICIENT_PASSWORD_QUALITY => "Insufficient password quality",
      ERROR_PASSWORD_TOO_SHORT => "Password too short",
      ERROR_PASSWORD_TOO_YOUNG => "Password too young",
      ERROR_PASSWORD_IN_HISTORY => "Password in history",
    }.freeze

    # Seconds remaining until the password expires. Only set when the server
    # returns a timeBeforeExpiration warning.
    attr_reader :time_before_expiration

    # Number of grace authentications remaining once the password has
    # expired. Only set when the server returns a graceAuthNsRemaining
    # warning.
    attr_reader :grace_authn_remaining

    # Numeric PPolicyError code from the control, or nil when no error was
    # returned. Use {#error} for the symbolic name.
    attr_reader :error_code

    # True when the control value could not be decoded according to the
    # password-policy grammar. Such a control is reported but never raised.
    attr_reader :malformed
    alias_method :malformed?, :malformed

    # Number of additional Password Policy Response controls seen in the same
    # response beyond the first one. Set by the PDU parser; non-zero means a
    # non-conforming server repeated the control.
    attr_accessor :duplicate_controls

    ##
    # Build a response object from the raw OCTET STRING carried in a parsed
    # control (the +value+ of an OpenStruct produced by
    # Net::LDAP::PDU#parse_controls). Returns nil when +value+ is nil, which
    # is the normal case for a control sent without a value.
    def self.from_control_value(value)
      return if value.nil?

      new(value)
    end

    def initialize(raw_value)
      @malformed = false
      @duplicate_controls = 0
      parse(raw_value)
    end

    # Symbolic PPolicyError name (e.g. +:passwordExpired+), or nil when the
    # control carried no error or held an unrecognised error code.
    def error
      ErrorCodes[@error_code]
    end

    # Human-readable description of the error code, or nil when there is no
    # error. Unknown numeric codes render generically rather than returning
    # nil so callers never see a blank reason.
    def error_message
      ErrorStrings[@error_code] ||
        (@error_code.nil? ? nil : "Unknown password policy error (#{@error_code})")
    end

    # True when the server returned a timeBeforeExpiration warning.
    def time_before_expiration?
      !@time_before_expiration.nil?
    end

    # True when the server returned a graceAuthNsRemaining warning.
    def grace_authn_remaining?
      !@grace_authn_remaining.nil?
    end

    # True when the control carried any warning element.
    def warning?
      time_before_expiration? || grace_authn_remaining?
    end

    # True when the control carried an error element.
    def error?
      !@error_code.nil?
    end

    # Whether the policy state constrains an otherwise successful bind to a
    # password change rather than full system access. Both draft-behera
    # password-expired/reset errors and the grace-login window land here.
    def password_change_required?
      case error
      when :passwordExpired, :changeAfterReset
        true
      else
        grace_authn_remaining?
      end
    end

    # Symbolic login outcome derived from this control combined with the
    # LDAP result code of the bind response.
    #
    # +result_code+ is the numeric LDAP resultCode from the BindResponse.
    # Return values:
    #
    # +:password_change_required+:: the credential was accepted (or a grace
    #   login is available) but normal access is not permitted until the
    #   password is changed.
    # +:account_locked+:: the directory rejected the bind because the account
    #   is locked.
    # +:policy_error+:: the bind failed for another password-policy reason
    #   (password too young, in history, etc.).
    # +:warning+:: the bind succeeded and only a warning was returned.
    # +:success+:: the bind succeeded with no policy information.
    # +:failure+:: the bind failed for a non-policy reason.
    def bind_status(result_code)
      return classify_error if error?
      return :warning if warning?

      result_code == Net::LDAP::ResultCodeSuccess ? :success : :failure
    end

    def to_h
      {
        time_before_expiration: @time_before_expiration,
        grace_authn_remaining: @grace_authn_remaining,
        error_code: @error_code,
        error: error,
        error_message: error_message,
        malformed: @malformed,
        duplicate_controls: @duplicate_controls,
      }
    end

    private

    def classify_error
      case error
      when :passwordExpired, :changeAfterReset
        :password_change_required
      when :accountLocked
        :account_locked
      else
        :policy_error
      end
    end

    # Walk the TLVs of the inner SEQUENCE. Each element is a single-byte
    # context-specific tag followed by an INTEGER; preserving the tag lets us
    # tell timeBeforeExpiration apart from graceAuthNsRemaining and the error
    # code. Unknown or malformed elements mark the whole control malformed
    # instead of raising.
    def parse(raw_value)
      content = unwrap_sequence(raw_value)
      return if content.nil?

      io = StringIO.new(content)
      until io.eof?
        tag = io.getbyte
        length = read_length(io)
        return mark_malformed if tag.nil? || length.nil? || length > io.size - io.pos

        bytes = io.read(length)
        return mark_malformed if bytes.nil? || bytes.bytesize != length

        assign_element(tag, bytes)
      end
    rescue Net::BER::BerError
      mark_malformed
    end

    # The control value is an OCTET STRING whose content is the
    # PasswordPolicyResponseValue SEQUENCE. Drop the outer OCTET STRING /
    # SEQUENCE framing and hand back just the encoded elements.
    def unwrap_sequence(raw_value)
      bytes = raw_value.to_s
      # A control may legitimately be present without a value.
      return "" if bytes.empty?

      io = StringIO.new(bytes)
      tag = io.getbyte
      return mark_malformed if tag.nil?

      length = read_length(io)
      return mark_malformed if length.nil? || length > io.size - io.pos

      content = io.read(length)
      return mark_malformed if content.nil? || content.bytesize != length

      # A well-formed value wraps the elements in a SEQUENCE (0x30). A value
      # whose outer framing is already a single context-specific element is
      # tolerated by treating that element's content directly.
      if (tag & 0x1f) == 0x10
        content
      elsif (tag & 0xc0) == 0x80
        bytes
      else
        mark_malformed
      end
    end

    def assign_element(tag, bytes)
      integer = decode_integer(bytes)
      case tag
      when TIME_BEFORE_EXPIRATION_TAG
        @time_before_expiration = integer
      when GRACE_AUTHNS_REMAINING_TAG
        @grace_authn_remaining = integer
      when ERROR_TAG
        @error_code = integer
      else
        # Unknown tags (including a future warning/error enumeration) do not
        # invalidate the elements we understand, but record that the value
        # did not strictly match the grammar we know.
        @malformed = true
      end
    end

    def decode_integer(bytes)
      negative = (bytes.getbyte(0) & 0x80) != 0
      value = 0
      bytes.each_byte { |byte| value = (value << 8) + (negative ? 255 - byte : byte) }
      negative ? (value + 1) * -1 : value
    end

    def read_length(io)
      first = io.getbyte
      return if first.nil?

      if first <= 0x7f
        first
      elsif first == 0x80
        nil # indefinite length is not valid here
      elsif first == 0xff
        nil
      else
        count = first & 0x7f
        bytes = io.read(count)
        return if bytes.nil? || bytes.bytesize != count

        bytes.each_byte.reduce(0) { |acc, byte| (acc << 8) + byte }
      end
    end

    def mark_malformed
      @malformed = true
      nil
    end
  end
end

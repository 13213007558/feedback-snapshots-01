# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/utilities'

module Mail
  # Parsed representation of a +message/delivery-status+ part as defined by
  # RFC 3464.  A delivery status notification (DSN) contains a single block of
  # per-message fields followed by one or more blocks of per-recipient fields,
  # each recipient block describing the delivery attempt for exactly one
  # recipient.
  #
  # Parsing a DSN only proves that the body is *syntactically* a delivery
  # status report.  It can never prove that the report was actually issued by a
  # trusted mail server: DSNs are ordinary mail and can be forged (see RFC
  # 3464 section 4.1).  The trust decision is therefore kept separate in
  # +trusted?+ and always defaults to +false+ until the caller marks the
  # report as trusted through +trust!+.
  class DeliveryStatus
    # Position of a piece of evidence inside the parsed message.  Offsets are
    # measured in bytes and lines are 1-based so the values can be used to
    # point an investigator at the original, unparsed source.
    class Evidence
      attr_reader :mime_part_index, :byte_offset, :line_number, :end_byte_offset, :end_line_number, :raw_text

      def initialize(mime_part_index:, byte_offset:, line_number:, end_byte_offset:, end_line_number:, raw_text:)
        @mime_part_index = mime_part_index
        @byte_offset = byte_offset
        @line_number = line_number
        @end_byte_offset = end_byte_offset
        @end_line_number = end_line_number
        @raw_text = raw_text
      end

      def to_h
        {
          mime_part_index: mime_part_index,
          byte_offset: byte_offset,
          line_number: line_number,
          end_byte_offset: end_byte_offset,
          end_line_number: end_line_number,
          raw_text: raw_text
        }
      end
    end

    # The parsed delivery information for a single per-recipient field group.
    # Every accessor may return +nil+ when the reporting MTA omitted the
    # field; RFC 3464 only mandates Final-Recipient, Action and Status.
    class Recipient
      attr_reader :final_recipient, :original_recipient, :action, :status,
                  :diagnostic_code, :remote_mta, :last_attempt_date,
                  :final_log_id, :will_retry_until, :fields, :evidence

      def initialize(final_recipient:, original_recipient:, action:, status:,
                     diagnostic_code:, remote_mta:, last_attempt_date:,
                     final_log_id:, will_retry_until:, fields:, evidence:)
        @final_recipient   = final_recipient
        @original_recipient = original_recipient
        @action            = action
        @status            = status
        @diagnostic_code   = diagnostic_code
        @remote_mta        = remote_mta
        @last_attempt_date = last_attempt_date
        @final_log_id      = final_log_id
        @will_retry_until  = will_retry_until
        @fields            = fields
        @evidence          = evidence
      end

      # Returns only the address portion of a typed field such as
      # +"rfc822; user@example.com"+, preserving +nil+ when the field is
      # missing.
      def self.address_of(typed_value)
        return nil if typed_value.nil?

        value = typed_value.to_s
        value.include?(';') ? value.split(';', 2).last.strip : value.strip
      end

      def final_recipient_address
        self.class.address_of(final_recipient)
      end

      def original_recipient_address
        self.class.address_of(original_recipient)
      end

      def failed?
        !!(action && action =~ /failed/i)
      end

      def delayed?
        !!(action && action =~ /delayed/i)
      end

      def delivered?
        !!(action && action =~ /delivered/i)
      end

      def relayed?
        !!(action && action =~ /relayed/i)
      end

      def expanded?
        !!(action && action =~ /expanded/i)
      end

      # A 4xx enhanced status code denotes a transient (retryable) failure,
      # while a 5xx code is permanent.  Missing or malformed statuses are not
      # treated as retryable.
      def retryable?
        !!(status && status =~ /\A\s*4/)
      end

      def permanent_failure?
        !!(status && status =~ /\A\s*5/)
      end

      def temporary_failure?
        retryable?
      end

      def to_h
        {
          final_recipient: final_recipient,
          original_recipient: original_recipient,
          action: action,
          status: status,
          diagnostic_code: diagnostic_code,
          remote_mta: remote_mta,
          last_attempt_date: last_attempt_date,
          final_log_id: final_log_id,
          will_retry_until: will_retry_until,
          fields: fields,
          evidence: evidence.to_h
        }
      end
    end

    attr_reader :message_fields, :recipients, :evidence, :charset, :parse_errors

    def initialize(message_fields:, recipients:, evidence:, charset:, parse_errors:)
      @message_fields = message_fields
      @recipients     = recipients
      @evidence       = evidence
      @charset        = charset
      @parse_errors   = parse_errors
      @trusted        = false
    end

    def reporting_mta
      @message_fields['reporting-mta']
    end

    def arrival_date
      @message_fields['arrival-date']
    end

    def received_from_mta
      @message_fields['received-from-mta']
    end

    # Parses the decoded body of a +message/delivery-status+ part.
    #
    # +content+ is the transfer-decoded body text and +mime_part_index+ the
    # position of the part inside the surrounding multipart message, used only
    # for evidence bookkeeping.  The parser never raises on malformed input:
    # recoverable problems are recorded in +parse_errors+ so that partially
    # usable reports can still be inspected.
    def self.parse(content, mime_part_index: nil, charset: nil)
      new(
        message_fields: {},
        recipients: [],
        evidence: nil,
        charset: charset,
        parse_errors: []
      ).tap { |status| status.send(:parse!, content, mime_part_index) }
    end

    # Marks the report as originating from a trusted mail server.  Only the
    # caller is in a position to make that decision (for example by checking
    # the authenticated transport, DKIM/SPF results or a trusted Reporting-MTA
    # allowlist); parsing alone must never set this flag.
    def trust!
      @trusted = true
      self
    end

    def trusted?
      @trusted
    end

    def untrusted?
      !@trusted
    end

    # Recipients whose Action is +failed+.  These are the only addresses a
    # security process should consider for automatic suppression, and only
    # when +trusted?+ is true.
    def failed_recipients
      recipients.select(&:failed?)
    end

    private

    def parse!(content, mime_part_index)
      text = normalize_encoding(content)
      groups, group_offsets = split_groups(text)
      record_part_evidence(text, mime_part_index)

      if groups.empty?
        @parse_errors << 'delivery-status part contains no field groups'
        return
      end

      parse_message_group(groups.first, group_offsets.first)
      groups[1..].each_with_index do |group, index|
        parse_recipient_group(group, group_offsets[index + 1], mime_part_index, text)
      end
    rescue StandardError => error
      @parse_errors << "#{error.class}: #{error.message}"
    end

    # Re-encodes non-standard or undeclared character sets into UTF-8 without
    # ever raising, so a strange charset cannot crash incident handling.
    def normalize_encoding(content)
      text = content.to_s.dup
      text = Utilities.to_crlf(text)
      declared = lookup_encoding(charset)
      return text if text.ascii_only? && declared.nil?

      encoding = declared || text.encoding
      text.force_encoding(encoding) unless encoding.nil?
      text.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: '?')
    rescue StandardError
      text.force_encoding(Encoding::UTF_8)
      text.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: '?')
    end

    def lookup_encoding(name)
      return nil if Utilities.blank?(name)

      Encoding.find(name)
    rescue ArgumentError
      begin
        Encoding.find(name.tr('_', '-'))
      rescue ArgumentError
        @parse_errors << "unknown charset #{name.inspect}; falling back to UTF-8"
        nil
      end
    end

    # Splits the body on blank lines (RFC 3464 field group separators) while
    # recording the byte/line span of each group for later evidence.
    def split_groups(text)
      groups = []
      offsets = []

      current = []
      group_start_line = 1
      group_start_byte = 0
      line_number = 0
      byte_offset = 0

      text.each_line do |line|
        line_number += 1
        line_bytes = line.bytesize
        content = line.sub(Constants::LAX_CRLF, '')
        line_start_byte = byte_offset
        byte_offset += line_bytes

        if content.strip.empty?
          next if current.empty?

          groups << current
          offsets << [group_start_line, group_start_byte, line_number - 1, line_start_byte]
          current = []
          group_start_line = line_number + 1
          group_start_byte = byte_offset
        else
          current << content
        end
      end

      unless current.empty?
        groups << current
        offsets << [group_start_line, group_start_byte, line_number, byte_offset]
      end

      [groups, offsets]
    end

    def record_part_evidence(text, mime_part_index)
      @evidence = Evidence.new(
        mime_part_index: mime_part_index,
        byte_offset: 0,
        line_number: 1,
        end_byte_offset: text.bytesize,
        end_line_number: text.count("\n") + 1,
        raw_text: text
      )
    end

    def parse_message_group(lines, offset)
      fields = parse_fields(lines)
      fields.each do |name, value|
        @message_fields[name] = value
      end
    end

    def parse_recipient_group(lines, offset, mime_part_index, text)
      fields = parse_fields(lines)
      typed = {}
      fields.each do |name, value|
        if typed.key?(name)
          typed[name] = Array(typed[name]) << value
        else
          typed[name] = value
        end
      end

      start_line, start_byte, end_line, end_byte = offset
      evidence = Evidence.new(
        mime_part_index: mime_part_index,
        byte_offset: start_byte,
        line_number: start_line,
        end_byte_offset: end_byte,
        end_line_number: end_line,
        raw_text: text.byteslice(start_byte, end_byte - start_byte)
      )

      @recipients << Recipient.new(
        final_recipient: scalar(typed, 'final-recipient'),
        original_recipient: scalar(typed, 'original-recipient'),
        action: scalar(typed, 'action'),
        status: scalar(typed, 'status'),
        diagnostic_code: scalar(typed, 'diagnostic-code'),
        remote_mta: scalar(typed, 'remote-mta'),
        last_attempt_date: scalar(typed, 'last-attempt-date'),
        final_log_id: scalar(typed, 'final-log-id'),
        will_retry_until: scalar(typed, 'will-retry-until'),
        fields: fields,
        evidence: evidence
      )

      return unless recipients.last.final_recipient.nil?

      @parse_errors << "recipient block at line #{start_line} is missing the mandatory Final-Recipient field"
    end

    # Unfolds continuation lines and splits +Name: value+ pairs.  Field names
    # are normalized to lowercase so callers never depend on spelling.
    def parse_fields(lines)
      unfolded = []
      lines.each do |line|
        if line =~ /\A[ \t]/ && !unfolded.empty?
          unfolded[-1] = "#{unfolded[-1].rstrip} #{line.strip}"
        else
          unfolded << line
        end
      end

      unfolded.each_with_object([]) do |line, result|
        match = line.match(/\A([!-9;-~]+?)\s*:\s*(.*)\z/)
        if match
          result << [match[1].downcase, match[2].strip]
        else
          @parse_errors << "ignoring malformed DSN line: #{line.inspect}"
        end
      end
    end

    def scalar(typed, name)
      value = typed[name]
      value.is_a?(Array) ? value.first : value
    end
  end
end

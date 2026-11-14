# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/utilities'
require 'mail/delivery_status'

module Mail
  class Part < Message
    # Creates a new empty Content-ID field and inserts it in the correct order
    # into the Header.  The ContentIdField object will automatically generate
    # a unique content ID if you try and encode it or output it to_s without
    # specifying a content id.
    #
    # It will preserve the content ID you specify if you do.
    def add_content_id(content_id_val = '')
      header['content-id'] = content_id_val
    end

    # Returns true if the part has a content ID field, the field may or may
    # not have a value, but the field exists or not.
    def has_content_id?
      header.has_content_id?
    end

    def cid
      add_content_id unless has_content_id?
      Utilities.uri_escape(Utilities.unbracket(content_id))
    end

    def url
      "cid:#{cid}"
    end

    def inline?
      header[:content_disposition].disposition_type == 'inline' if header[:content_disposition].respond_to?(:disposition_type)
    end

    def add_required_fields
      super
      add_content_id if !has_content_id? && inline?
    end

    def add_required_message_fields
      # Override so we don't add Date, MIME-Version, or Message-ID.
    end

    # Only a part whose declared media type is exactly message/delivery-status
    # may be treated as a DSN.  A text/plain body that merely mentions
    # "Status:" can never satisfy this check, so human-readable bounce prose
    # cannot impersonate a machine-readable delivery-status part.  The body
    # must additionally contain at least one RFC 3464 field; reports that omit
    # the usual Status field but still carry Final-Recipient/Action remain
    # readable, while free-form prose under the media type does not qualify.
    def delivery_status_report_part?
      main_type.to_s =~ /\Amessage\z/i &&
        sub_type.to_s =~ /\Adelivery-status\z/i &&
        body.to_s =~ /^[\x21-\x39\x3b-\x7e]+[ \t]*:/
    end

    def delivery_status_data
      delivery_status_report_part? ? parse_delivery_status_report : {}
    end

    # Structured, per-recipient view of the message/delivery-status body as
    # defined by RFC 3464.  Returns nil when this part is not a
    # delivery-status part.  The returned Mail::DeliveryStatus is never
    # trusted on its own: see Mail::DeliveryStatus#trusted? and
    # Mail::Message#mark_delivery_status_trusted!.
    def delivery_status(mime_part_index: nil)
      @delivery_status ||=
        if delivery_status_report_part?
          Mail::DeliveryStatus.parse(
            body.raw_source.to_s,
            mime_part_index: mime_part_index,
            charset: delivery_status_charset
          )
        end
    end

    # Each recipient block as a Mail::DeliveryStatus::Recipient, preserving
    # the order and every field found in the report.
    def delivery_status_recipients
      delivery_status ? delivery_status.recipients : []
    end

    def bounced?
      if action.is_a?(Array)
        !!(action.first =~ /failed/i)
      else
        !!(action =~ /failed/i)
      end
    end

    # True when at least one recipient block reports a failed action.  Unlike
    # +bounced?+ this inspects every recipient block instead of only the first
    # one, which matters for partial-failure reports.
    def any_recipient_failed?
      delivery_status_recipients.any?(&:failed?)
    end

    # Either returns the action if the message has just a single report, or an
    # array of all the actions, one for each report
    def action
      get_return_values('action')
    end

    def final_recipient
      get_return_values('final-recipient')
    end

    def error_status
      get_return_values('status')
    end

    def diagnostic_code
      get_return_values('diagnostic-code')
    end

    def remote_mta
      get_return_values('remote-mta')
    end

    def retryable?
      values = Array(error_status).compact
      return false if values.empty?

      values.none? { |status| status =~ /\A\s*5/ }
    end

    private

    def delivery_status_charset
      parameters = content_type_parameters rescue nil
      parameters && parameters['charset']
    end

    def get_return_values(key)
      values = delivery_status_recipients.flat_map do |recipient|
        recipient.fields.select { |name, _| name == key }.map { |_, value| value }
      end
      return nil if values.empty?

      values.length == 1 ? values.first : values
    end

    # A part may not have a header.... so, just init a body if no header
    def parse_message
      header_part, body_part = raw_source.split(/#{Constants::LAX_CRLF}#{Constants::WSP}*#{Constants::LAX_CRLF}/m, 2)
      if header_part =~ Constants::HEADER_LINE
        self.header = header_part
        self.body   = body_part
      else
        self.header = "Content-Type: text/plain\r\n"
        self.body   = raw_source
      end
    end

    def parse_delivery_status_report
      @delivery_status_data ||= Header.new(body.to_s.gsub("\r\n\r\n", "\r\n"))
    end

  end

end

# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe "RFC 3464 delivery status report reading" do
  let(:bounce) { read_fixture('emails', 'multipart_report_emails', 'partial_failure_bounce.eml') }

  describe "report discovery" do
    it "recognises a multipart/report delivery-status message" do
      expect(bounce).to be_delivery_status_report
      expect(bounce.delivery_status_part).not_to be_nil
    end

    it "never treats a human-readable part as a delivery-status part" do
      prose = bounce.parts.first
      expect(prose.mime_type).to eq('text/plain')
      expect(prose).not_to be_delivery_status_report_part
      expect(bounce.delivery_status_recipients.map(&:final_recipient_address))
        .not_to include('prose')
    end

    it "ignores delivery-status content when the outer report type is changed" do
      raw = read_raw_fixture('emails', 'multipart_report_emails', 'partial_failure_bounce.eml')
      mail = Mail.read_from_string(raw.sub('multipart/report; report-type=delivery-status;',
                                           'multipart/mixed;'))
      expect(mail.delivery_status_part).to be_nil
      expect(mail.delivery_status).to be_nil
      expect(mail.delivery_status_recipients).to eq([])
    end
  end

  describe "per-recipient results" do
    it "returns one entry per recipient block in report order" do
      recipients = bounce.delivery_status_recipients
      expect(recipients.size).to eq(3)
      expect(recipients.map(&:final_recipient_address)).to eq(
        %w[bounced-user@example.org active-user@example.com delayed-user@example.net]
      )
    end

    it "exposes status, action and diagnostics for each recipient" do
      failed, delivered, delayed = bounce.delivery_status_recipients

      expect(failed.action).to eq('failed')
      expect(failed.status).to eq('5.1.1')
      expect(failed.diagnostic_code).to start_with('smtp; 550 5.1.1')
      expect(failed.remote_mta).to eq('dns; mx.example.org')
      expect(failed.original_recipient).to eq('rfc822;bounced-user@example.org')
      expect(failed).to be_failed
      expect(failed).to be_permanent_failure
      expect(failed).not_to be_retryable

      expect(delivered.action).to eq('delivered')
      expect(delivered.status).to eq('2.0.0')
      expect(delivered).to be_delivered
      expect(delivered).not_to be_failed

      expect(delayed.action).to eq('delayed')
      expect(delayed.status).to eq('4.7.1')
      expect(delayed).to be_delayed
      expect(delayed).to be_retryable
      expect(delayed).not_to be_permanent_failure
    end

    it "lists only the failed recipients" do
      expect(bounce.failed_delivery_recipients.map(&:final_recipient_address))
        .to eq(['bounced-user@example.org'])
    end

    it "keeps every field, including unknown extension fields" do
      failed = bounce.delivery_status_recipients.first
      names = failed.fields.map(&:first)
      expect(names).to include('final-recipient', 'action', 'status', 'diagnostic-code')
    end
  end

  describe "evidence location" do
    it "points at the exact MIME part and line range of each recipient block" do
      failed = bounce.delivery_status_recipients.first
      evidence = failed.evidence

      expect(evidence.mime_part_index).to eq(1)
      expect(evidence.line_number).to be < evidence.end_line_number
      part_body = bounce.delivery_status.evidence.raw_text
      referenced = part_body.byteslice(
        evidence.byte_offset,
        evidence.end_byte_offset - evidence.byte_offset
      )
      expect(evidence.raw_text).to eq(referenced)
      expect(evidence.raw_text).to start_with('Original-Recipient:')
      expect(evidence.raw_text).to include('Status: 5.1.1')
    end

    it "records the part-level evidence separately from recipient blocks" do
      status = bounce.delivery_status
      expect(status.evidence.mime_part_index).to eq(1)
      expect(status.evidence.line_number).to eq(1)
      expect(status.evidence.raw_text).to include('Reporting-MTA:')
    end
  end

  describe "trust flag" do
    it "is untrusted immediately after a successful parse" do
      expect(bounce.delivery_status).not_to be_nil
      expect(bounce.delivery_status).to be_untrusted
      expect(bounce).to be_delivery_status_untrusted
      expect(bounce).not_to be_delivery_status_trusted
    end

    it "stays untrusted unless the caller explicitly marks it" do
      expect { bounce.delivery_status_recipients }.not_to change { bounce.delivery_status_trusted? }
      bounce.mark_delivery_status_trusted!
      expect(bounce).to be_delivery_status_trusted
      expect(bounce.delivery_status).to be_trusted
    end

    it "keeps trust separate from the legacy bounced? predicate" do
      expect(bounce).to be_bounced
      expect(bounce).not_to be_delivery_status_trusted
    end
  end

  describe "the nested returned message" do
    it "exposes the original message without mixing it into DSN fields" do
      expect(bounce.returned_message_part.mime_type).to eq('message/rfc822')
      expect(bounce.returned_message.subject).to eq('Quarterly newsletter')
      expect(bounce.delivery_status_recipients.size).to eq(3)
    end

    it "does not parse Status headers found only inside the returned message" do
      addresses = bounce.delivery_status_recipients.map(&:final_recipient_address)
      expect(addresses).not_to include('this-is-inside-the-returned-message')
    end
  end

  describe "malformed and unusual reports" do
    def report(body_headers, content_type = 'message/delivery-status')
      Mail.read_from_string(
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"b\"\r\n" \
        "MIME-Version: 1.0\r\n\r\n" \
        "--b\r\nContent-Type: #{content_type}\r\n\r\n#{body_headers}\r\n--b--\r\n"
      )
    end

    it "keeps duplicate fields while exposing the first value through accessors" do
      mail = report(
        "Reporting-MTA: dns; mta\r\n\r\n" \
        "Final-Recipient: rfc822; dup@example.com\r\n" \
        "Action: failed\r\nStatus: 5.1.1\r\n" \
        "Diagnostic-Code: smtp; first\r\nDiagnostic-Code: smtp; second\r\n"
      )
      recipient = mail.delivery_status_recipients.first
      expect(recipient.diagnostic_code).to eq('smtp; first')
      expect(recipient.fields.select { |name, _| name == 'diagnostic-code' }.map(&:last))
        .to eq(['smtp; first', 'smtp; second'])
    end

    it "survives a recipient block missing the mandatory Status field" do
      mail = report(
        "Reporting-MTA: dns; mta\r\n\r\n" \
        "Final-Recipient: rfc822; no-status@example.com\r\nAction: delayed\r\n"
      )
      recipient = mail.delivery_status_recipients.first
      expect(recipient.status).to be_nil
      expect(recipient.action).to eq('delayed')
      expect(recipient).not_to be_retryable
    end

    it "records a parse error when Final-Recipient is absent but keeps the block" do
      mail = report(
        "Reporting-MTA: dns; mta\r\n\r\nAction: failed\r\nStatus: 5.1.1\r\n"
      )
      expect(mail.delivery_status_recipients.size).to eq(1)
      expect(mail.delivery_status.parse_errors.join).to include('Final-Recipient')
    end

    it "unfolds continuation lines into a single field value" do
      mail = report(
        "Reporting-MTA: dns; mta\r\n\r\n" \
        "Final-Recipient: rfc822; folded@example.com\r\nAction: failed\r\n" \
        "Status: 5.1.1\r\n" \
        "Diagnostic-Code: smtp; line one\r\n    continuation line\r\n"
      )
      recipient = mail.delivery_status_recipients.first
      expect(recipient.diagnostic_code).to eq('smtp; line one continuation line')
    end

    it "handles a declared ISO-8859-1 charset by re-encoding to UTF-8" do
      raw =
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"b\"\r\n" \
        "MIME-Version: 1.0\r\n\r\n--b\r\n" \
        "Content-Type: message/delivery-status; charset=ISO-8859-1\r\n" \
        "Content-Transfer-Encoding: 8bit\r\n\r\n" \
        "Reporting-MTA: dns; mta\r\n\r\n" \
        "Final-Recipient: rfc822; caf\xE9@example.com\r\n" \
        "Action: failed\r\nStatus: 5.1.1\r\n\r\n--b--\r\n".b
      mail = Mail.read_from_string(raw)
      expect(mail.delivery_status_recipients.first.final_recipient)
        .to eq('rfc822; café@example.com')
    end

    it "falls back gracefully on an unknown charset label" do
      mail = report(
        "Reporting-MTA: dns; mta\r\n\r\n" \
        "Final-Recipient: rfc822; x@example.com\r\nAction: failed\r\nStatus: 5.1.1\r\n",
        'message/delivery-status; charset=X-KLUDGE-9000'
      )
      expect(mail.delivery_status_recipients.size).to eq(1)
      expect(mail.delivery_status.parse_errors.join).to include('X-KLUDGE-9000')
    end

    it "returns an empty recipient list for a part without any fields" do
      mail = report("This is only human readable prose, no DSN fields.\r\n")
      expect(mail.delivery_status_part).to be_nil
    end
  end

  describe "partial-failure incident handling" do
    # Models the security workflow: a bounce's human-readable body claims a
    # general delivery failure, but the machine-readable DSN only fails one of
    # three recipients.  Suppression must be per-recipient, evidence-backed and
    # gated on an independent trust decision.
    it "bans only the single failed recipient and never the others" do
      all_recipients = bounce.delivery_status_recipients
      expect(all_recipients.size).to eq(3)

      ban_list = lambda do |report|
        return [] unless report.delivery_status_trusted?

        report.failed_delivery_recipients.map(&:final_recipient_address)
      end

      # An unauthenticated report, however well-formed, bans nobody.
      expect(ban_list.call(bounce)).to eq([])
      expect(bounce).to be_delivery_status_untrusted

      # The incident responder authenticates the source out of band, then marks
      # the report trusted before any automatic action is taken.
      bounce.mark_delivery_status_trusted!
      expect(ban_list.call(bounce)).to eq(['bounced-user@example.org'])

      untouched = all_recipients.reject(&:failed?).map(&:final_recipient_address)
      expect(untouched).to eq(
        %w[active-user@example.com delayed-user@example.net]
      )
      expect(ban_list.call(bounce) & untouched).to eq([])
    end

    it "keeps evidence for every ban decision" do
      bounce.mark_delivery_status_trusted!
      bounce.failed_delivery_recipients.each do |recipient|
        evidence = recipient.evidence
        expect(evidence.mime_part_index).to eq(1)
        expect(evidence.raw_text).to include("Final-Recipient: rfc822; #{recipient.final_recipient_address}")
        expect(evidence.raw_text).to include("Status: #{recipient.status}")
      end
    end
  end
end

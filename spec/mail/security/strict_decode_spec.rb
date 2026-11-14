# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'
require 'mail/security/strict_decode'
require_relative 'corpus'

RSpec.describe Mail::Security::StrictDecode do
  include SecurityCorpus

  describe 'a fully valid message' do
    it 'reports both stages complete and exposes strict and lenient text' do
      result = clean_mail.strict_decode

      expect(result.transfer_encoding_complete?).to be(true)
      expect(result.charset_complete?).to be(true)
      expect(result.complete?).to be(true)
      expect(result.safe_to_scan?).to be(true)
      expect(result.issues).to be_empty
      expect(result.strict_text).to eq('all clean text here')
      expect(result.strict_bytes).to eq('all clean text here'.b)
      expect(result.lenient_text).to eq(result.strict_text)
    end
  end

  describe 'damaged messages' do
    it 'marks every damaged mail incomplete while keeping a lenient display result' do
      damaged_mails.each do |name, mail|
        result = mail.strict_decode

        expect(result.complete?).to be(false), "expected #{name} to be incomplete"
        expect(result.safe_to_scan?).to be(false)
        expect(result.strict_text).to be_nil
        expect(result.lenient_text).to be_a(String)
        expect(result.issues).not_to be_empty
      end
    end

    it 'flags bad base64 at the transfer encoding stage with raw offsets' do
      result = bad_base64_mail.strict_decode

      expect(result.transfer_encoding_complete?).to be(false)
      expect(result.charset_complete?).to be(false)
      reasons = result.transfer_encoding_issues.map(&:reason)
      expect(reasons).to include(:illegal_base64_character)
      expect(result.transfer_encoding_issues.first.bytes).to eq('!')
      expect(result.charset_issues.map(&:reason))
        .to eq([:stage_skipped_after_transfer_failure])
    end

    it 'flags a truncated quoted-printable escape at its raw offset' do
      result = truncated_quoted_printable_mail.strict_decode
      issue = result.transfer_encoding_issues.first

      expect(result.transfer_encoding_complete?).to be(false)
      expect(issue.reason).to eq(:malformed_quoted_printable_escape)
      expect(issue.offset).to eq(23)
    end

    it 'separates a clean transfer stage from a failed charset stage' do
      result = wrong_charset_mail.strict_decode

      expect(result.transfer_encoding_complete?).to be(true)
      expect(result.charset_complete?).to be(false)
      expect(result.transfer_encoding_issues).to be_empty
      expect(result.charset_issues.first.reason).to eq(:invalid_byte_sequence)
    end

    it 'reports multibyte truncation with the unexplainable tail bytes' do
      result = multibyte_truncation_mail.strict_decode
      issue = result.charset_issues.first

      expect(issue.reason).to eq(:truncated_multibyte_sequence)
      expect(issue.offset).to eq(20)
      expect(issue.bytes).to eq("\xE3\x81".b)
    end

    it 'reports unknown charsets without silently treating bytes as binary' do
      result = unknown_charset_mail.strict_decode
      expect(result.charset_issues.map(&:reason)).to eq([:unknown_charset])
      expect(result.complete?).to be(false)
    end

    it 'reports 7bit violations at the transfer encoding stage' do
      result = seven_bit_violation_mail.strict_decode
      expect(result.transfer_encoding_complete?).to be(false)
      expect(result.transfer_encoding_issues.first.reason)
        .to eq(:non_ascii_seven_bit_byte)
    end

    it 'does not treat lenient output as a completed strict decode' do
      damaged_mails.each_value do |mail|
        result = mail.strict_decode
        expect(result.lenient_text).not_to be_nil
        expect(result.safe_to_scan?).to be(false)
      end
    end

    it 'refuses a safe verdict even when the lenient text keeps the dangerous token' do
      damaged_mails.each do |name, mail|
        result = mail.strict_decode
        next unless result.lenient_text.include?(SecurityCorpus::DANGEROUS_TOKEN)

        expect(result.complete?).to be(false), "#{name} must not be complete"
        expect(mail.security_scan(/EVIL\.example/).verdict)
          .to eq(:indeterminate), "#{name} must not auto-complete the scan"
      end
    end
  end

  describe '.decode directly' do
    it 'records an unknown transfer encoding instead of raising' do
      result = described_class.decode('abc', transfer_encoding: 'x-uuencode',
                                             charset: 'US-ASCII')
      expect(result.transfer_encoding_issues.map(&:reason))
        .to eq([:unknown_transfer_encoding])
      expect(result.complete?).to be(false)
    end

    it 'exposes every unexplainable raw byte range' do
      result = multibyte_truncation_mail.strict_decode
      expect(result.unexplainable_bytes).to eq(["\xE3\x81".b])
    end

    it 'skips the charset stage for non-text media passed directly' do
      result = described_class.decode(["\xFF".b].pack('m0'),
                                      transfer_encoding: 'base64',
                                      charset: 'UTF-8',
                                      media_type: 'image')
      expect(result.charset_applicable?).to be(false)
      expect(result.complete?).to be(true)
      expect(result.transfer_decoded_bytes).to eq("\xFF".b)
    end

    it 'treats an empty body as a complete decode' do
      mail = Mail.new("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
      result = mail.strict_decode
      expect(result.complete?).to be(true)
      expect(result.strict_text).to eq('')
    end

    it 'does not apply charset validation to non-text media types' do
      mail = Mail.new(
        "Content-Transfer-Encoding: base64\r\n" \
        "Content-Type: application/octet-stream\r\n\r\n" \
        "#{["\x00\x01\xFF".b].pack('m0')}\r\n"
      )
      result = mail.strict_decode

      expect(result.charset_applicable?).to be(false)
      expect(result.charset_issues).to be_empty
      expect(result.transfer_encoding_complete?).to be(true)
      expect(result.safe_to_scan?).to be(true)
      expect(result.strict_text).to be_nil
      expect(result.transfer_decoded_bytes).to eq("\x00\x01\xFF".b)
    end
  end
end

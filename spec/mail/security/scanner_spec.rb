# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'
require 'mail/security/scanner'
require_relative 'corpus'

RSpec.describe Mail::Security::Scanner do
  include SecurityCorpus

  let(:pattern) { /EVIL\.example/ }
  let(:scanner) { described_class.new(pattern) }

  describe '#scan verdicts' do
    it 'returns dangerous for a complete decode containing the pattern' do
      report = scanner.scan(clean_dangerous_mail)
      expect(report.verdict).to eq(:dangerous)
      expect(report.dangerous?).to be(true)
      expect(report.matches.first.matches.first[:match]).to eq(SecurityCorpus::DANGEROUS_TOKEN)
    end

    it 'returns clean when every byte decodes and nothing matches' do
      report = scanner.scan(clean_mail)
      expect(report.verdict).to eq(:clean)
      expect(report.clean?).to be(true)
      expect(report.indeterminate?).to be(false)
    end

    it 'never returns clean for a damaged message even with no lenient match' do
      damaged_mails.each do |name, mail|
        report = scanner.scan(mail)
        expect(report.verdict).to eq(:indeterminate), "expected #{name} indeterminate"
        expect(report.clean?).to be(false)
        expect(report.dangerous?).to be(false)
        expect(report.issues).not_to be_empty
      end
    end

    it 'does not scan lenient text, so a masked payload cannot look safe' do
      # The tolerant decoder replaces the invalid tail, leaving a message that
      # still contains the token. Strict scanning refuses to trust either the
      # match or its absence and reports indeterminate instead.
      mail = multibyte_truncation_mail
      report = scanner.scan(mail)
      expect(report.verdict).to eq(:indeterminate)
      expect(report.part_scans.first.matches).to be_empty
    end
  end

  describe 'multipart messages' do
    it 'scans every leaf and aggregates an indeterminate verdict' do
      mail = Mail.new do
        text_part do
          body 'harmless text'
        end
        html_part do
          content_type 'text/html; charset=UTF-8'
          content_transfer_encoding 'base64'
          body ["browse #{SecurityCorpus::DANGEROUS_TOKEN}".b].pack('m0')
        end
      end

      report = scanner.scan(mail)
      expect(report.part_scans.length).to eq(2)
      expect(report.verdict).to eq(:dangerous)
    end

    it 'stays indeterminate when only one part fails decoding' do
      damaged = damaged_mails[:multibyte_truncation]
      mail = Mail.new do
        text_part { body 'harmless text' }
      end
      mail.add_part(damaged)

      report = scanner.scan(mail)
      expect(report.verdict).to eq(:indeterminate)
      expect(report.part_scans.map(&:verdict)).to include(:indeterminate)
    end
  end

  describe 'Mail::Message convenience entry point' do
    it 'is available as #security_scan' do
      expect(clean_mail.security_scan(pattern).verdict).to eq(:clean)
      expect(bad_base64_mail.security_scan(pattern).verdict).to eq(:indeterminate)
    end
  end
end

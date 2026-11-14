# encoding: utf-8
# frozen_string_literal: true

require 'spec_helper'
require 'mail/security/charset_decoder'

RSpec.describe Mail::Security::CharsetDecoder do
  describe '.decode' do
    it 'transcodes valid declared bytes losslessly to UTF-8' do
      text, issues = described_class.decode("caf\xE9".b, 'ISO-8859-1')
      expect(issues).to be_empty
      expect(text).to eq('café')
      expect(text.encoding).to eq(Encoding::UTF_8)
      expect(text.valid_encoding?).to be(true)
    end

    it 'accepts valid UTF-8 without modification' do
      text, issues = described_class.decode("あ".b, 'UTF-8')
      expect(issues).to be_empty
      expect(text).to eq('あ')
    end

    it 'defaults a missing charset to US-ASCII and accepts plain ASCII' do
      text, issues = described_class.decode('plain'.b, nil)
      expect(issues).to be_empty
      expect(text).to eq('plain')
    end

    it 'reports every invalid byte when UTF-8 is wrongly declared' do
      payload = "EVIL \xE3\x81\x82".b
      _text, issues = described_class.decode(payload, 'US-ASCII')
      expect(issues).not_to be_empty
      expect(issues.all? { |i| i.stage == :charset }).to be(true)
      expect(issues.first.offset).to eq(6)
      expect(issues.first.bytes).to eq("\xE3".b)
    end

    it 'locates a truncated multibyte sequence at the end of input' do
      payload = "EVIL \xE3\x81".b
      text, issues = described_class.decode(payload, 'UTF-8')
      expect(text).to be_nil
      expect(issues.map(&:reason)).to eq([:truncated_multibyte_sequence])
      issue = issues.first
      expect(issue.offset).to eq(5)
      expect(issue.bytes).to eq("\xE3\x81".b)
    end

    it 'continues after an invalid byte and records each failure' do
      _text, issues = described_class.decode("a\xffb\xFE".b, 'UTF-8')
      expect(issues.map(&:reason)).to eq([:invalid_byte_sequence, :invalid_byte_sequence])
      expect(issues.map(&:offset)).to eq([2, 4])
    end

    it 'reports an unresolvable charset instead of falling back to binary' do
      text, issues = described_class.decode('anything'.b, 'X-MADE-UP')
      expect(text).to be_nil
      expect(issues.map(&:reason)).to eq([:unknown_charset])
      expect(issues.first.bytes).to eq('anything'.b)
    end

    it 'never inserts a replacement character into the strict result' do
      text, _issues = described_class.decode("a\xffb".b, 'UTF-8')
      expect(text).to be_nil
    end
  end
end

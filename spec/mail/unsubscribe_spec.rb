# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'mail/unsubscribe'

RSpec.describe Mail::Unsubscribe do
  def message(headers)
    Mail.new("#{headers}\r\nbody\r\n")
  end

  def signed_headers
    "List-Unsubscribe: <mailto:list@example.com?subject=unsubscribe>, <https://example.com/u>\r\n" \
      "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
  end

  def evidence
    Mail::Unsubscribe::Evidence.new(%w[List-Unsubscribe List-Unsubscribe-Post], signature: 'example.com')
  end

  describe '.parse' do
    it 'accepts a raw message string' do
      action = described_class.parse(signed_headers, evidence)

      expect(action).to be_a(Mail::Unsubscribe::Action)
      expect(action.target.to_s).to eq 'https://example.com/u'
    end

    it 'accepts a Mail::Message' do
      expect(described_class.parse(message(signed_headers), evidence)).to be_a(Mail::Unsubscribe::Action)
    end

    it 'accepts a Mail::Header' do
      expect(described_class.parse(Mail::Header.new(signed_headers), evidence)).to be_a(Mail::Unsubscribe::Action)
    end

    it 'accepts evidence through keyword arguments' do
      expect(described_class.parse(message(signed_headers), dkim_evidence: evidence)).to be_a(Mail::Unsubscribe::Action)
    end
  end

  describe '.parse!' do
    it 'raises a descriptive error when the message does not qualify' do
      expect {
        described_class.parse!(message(signed_headers), Mail::Unsubscribe::Evidence.new(%w[Subject]))
      }.to raise_error(Mail::Unsubscribe::NotEligibleError, /uncovered_list_unsubscribe_post/)
    end
  end

  describe '.analyze' do
    it 'returns the refusal reason alongside a nil action' do
      result = described_class.analyze(message(signed_headers), nil)

      expect(result.action).to be_nil
      expect(result.reason).to eq :missing_dkim_evidence
    end
  end

  describe Mail::Unsubscribe::Evidence do
    it 'never treats itself as valid unless told so' do
      expect(described_class.new(%w[List-Unsubscribe]).valid?).to be true
      expect(described_class.new(%w[List-Unsubscribe], valid: false).valid?).to be false
    end

    it 'coerces hashes and verifier-like objects' do
      expect(Mail::Unsubscribe::Evidence.coerce(covered_fields: %w[List-Unsubscribe], valid: false).valid?).to be false

      verifier_result = Struct.new(:covered_fields, :valid?, :signature)
      source = verifier_result.new(%w[List-Unsubscribe], false, 'sig')
      coerced = Mail::Unsubscribe::Evidence.coerce(source)

      expect(coerced.covered_fields).to eq %w[List-Unsubscribe]
      expect(coerced.valid?).to be false
      expect(coerced.signature).to eq 'sig'
    end

    it 'supports an occurrences/explicit selector syntax' do
      parsed = Mail::Unsubscribe::Evidence.new(['List-Unsubscribe:1'])
      expect(parsed.entries).to eq [['List-Unsubscribe', 1, nil]]
    end
  end
end

# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'mail/unsubscribe'
require 'net/http'

RSpec.describe Mail::Unsubscribe::Parser do
  def evidence(fields, valid: true, signature: 'example.com')
    Mail::Unsubscribe::Evidence.new(fields, valid: valid, signature: signature)
  end

  def message(headers, body = "body\r\n")
    Mail.new("#{headers}\r\n#{body}")
  end

  def eligible_headers
    "List-Unsubscribe: <mailto:list@example.com?subject=unsubscribe>, <https://example.com/unsubscribe/opaque>\r\n" \
      "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
  end

  def signed_both
    evidence(%w[List-Unsubscribe List-Unsubscribe-Post])
  end

  describe '#parse' do
    it 'produces a pending action for a correctly signed one-click message' do
      action = described_class.new(message(eligible_headers)).parse(signed_both)

      expect(action).to be_a(Mail::Unsubscribe::Action)
      expect(action).to be_pending
      expect(action.uri).to be_a(URI::HTTPS)
      expect(action.target.to_s).to eq 'https://example.com/unsubscribe/opaque'
      expect(action.mailto_candidates.map(&:raw)).to eq ['mailto:list@example.com?subject=unsubscribe']
    end

    it 'exposes both List-Unsubscribe candidates while choosing the single HTTPS target' do
      action = described_class.new(message(eligible_headers)).parse(signed_both)

      expect(action.candidates.map(&:scheme)).to eq %w[mailto https]
      expect(action.candidates.count(&:https?)).to eq 1
    end

    it 'returns nil without evidence' do
      expect(described_class.new(message(eligible_headers)).parse).to be_nil
    end

    it 'returns nil when the only evidence is invalid' do
      expect(described_class.new(message(eligible_headers)).parse(evidence(%w[List-Unsubscribe List-Unsubscribe-Post], valid: false))).to be_nil
    end

    it 'returns nil when evidence covers only List-Unsubscribe' do
      expect(described_class.new(message(eligible_headers)).parse(evidence(%w[List-Unsubscribe]))).to be_nil
    end

    it 'returns nil when evidence covers only List-Unsubscribe-Post' do
      expect(described_class.new(message(eligible_headers)).parse(evidence(%w[List-Unsubscribe-Post]))).to be_nil
    end

    it 'returns nil when the List-Unsubscribe-Post value is not exactly One-Click' do
      headers = eligible_headers.sub('List-Unsubscribe=One-Click', 'List-Unsubscribe=one-click-please')

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'is case-insensitive for the header names and the post value' do
      headers = "list-unsubscribe: <https://example.com/u>\r\n" \
                "list-unsubscribe-post: list-unsubscribe=ONE-CLICK\r\n"
      evidence = evidence(%w[list-unsubscribe list-unsubscribe-post])

      expect(described_class.new(message(headers)).parse(evidence)).to be_a(Mail::Unsubscribe::Action)
    end
  end

  describe 'refusal reasons' do
    it 'reports a missing List-Unsubscribe-Post field' do
      headers = eligible_headers.sub(/List-Unsubscribe-Post.*\r\n/, '')
      result = described_class.new(message(headers)).analyze(signed_both)

      expect(result.action).to be_nil
      expect(result.reason).to eq :missing_list_unsubscribe_post
    end

    it 'reports an invalid post field' do
      headers = eligible_headers.sub('List-Unsubscribe=One-Click', 'List-Unsubscribe=One-Click, List-Unsubscribe=Other')
      result = described_class.new(message(headers)).analyze(signed_both)

      expect(result.reason).to eq :invalid_list_unsubscribe_post
    end

    it 'reports uncovered evidence' do
      result = described_class.new(message(eligible_headers)).analyze(evidence(%w[Subject]))

      expect(result.reason).to eq :uncovered_list_unsubscribe_post
    end

    it 'reports malformed unsubscription URIs' do
      headers = eligible_headers.sub('<https://example.com/unsubscribe/opaque>', '<https://example.com/unsubscribe/opaque')
      result = described_class.new(message(headers)).analyze(signed_both)

      expect(result.reason).to eq :invalid_list_unsubscribe
    end
  end

  describe 'duplicate header instances' do
    def duplicate_unsubscribe_headers
      "List-Unsubscribe: <https://example.com/protected>\r\n" \
        "List-Unsubscribe: <https://evil.example/forged>\r\n" \
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    end

    it 'never lets a bare name resolve to a forged trailing duplicate' do
      # Without an explicit selector the covered instance is the bottom-most
      # one, which here is the appended forged field.  Refusing is safer than
      # silently acting on a header the signature may not have covered.
      action = described_class.new(message(duplicate_unsubscribe_headers)).parse(
        evidence(['List-Unsubscribe', 'List-Unsubscribe-Post'])
      )

      expect(action).to be_nil
    end

    it 'does not treat one covered name as covering every duplicate' do
      action = described_class.new(message(duplicate_unsubscribe_headers)).parse(signed_both)

      expect(action).to be_nil
    end

    it 'uses the bottom-based explicit index supplied by the verifier' do
      # DKIM counts same-name instances from the bottom: index 0 is the
      # forged trailing field, index 1 is the original protected field.
      explicit = evidence(['List-Unsubscribe:1', 'List-Unsubscribe-Post:0'])
      action = described_class.new(message(duplicate_unsubscribe_headers)).parse(explicit)

      expect(action).not_to be_nil
      expect(action.target.to_s).to eq 'https://example.com/protected'
    end

    it 'binds coverage by exact value as well as name' do
      explicit = evidence([
        { name: 'List-Unsubscribe', value: '<https://example.com/protected>' },
        { name: 'List-Unsubscribe-Post', value: 'List-Unsubscribe=One-Click' }
      ])
      action = described_class.new(message(duplicate_unsubscribe_headers)).parse(explicit)

      expect(action.target.to_s).to eq 'https://example.com/protected'
    end

    it 'never silently substitutes the uncovered duplicate even when only the forged instance is covered' do
      explicit = evidence(['List-Unsubscribe:0', 'List-Unsubscribe-Post:0'])
      action = described_class.new(message(duplicate_unsubscribe_headers)).parse(explicit)

      expect(action).not_to be_nil
      expect(action.target.to_s).to eq 'https://evil.example/forged'
    end

    it 'refuses an appended signed-looking post header that would replace the covered one' do
      headers = "List-Unsubscribe: <mailto:list@example.com>, <https://example.com/protected>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
      action = described_class.new(message(headers)).parse(
        evidence(['List-Unsubscribe', 'List-Unsubscribe-Post'])
      )

      expect(action).to be_nil
    end

    it 'does not accept duplicate post fields even if both are covered explicitly' do
      headers = "List-Unsubscribe: <https://example.com/protected>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

      expect(described_class.new(message(headers)).parse(
        evidence(['List-Unsubscribe', 'List-Unsubscribe-Post:0', 'List-Unsubscribe-Post:1'])
      )).to be_nil
    end
  end

  describe 'multiple signatures' do
    it 'accepts one valid signature even when another is invalid' do
      action = described_class.new(message(eligible_headers)).parse([
        evidence(%w[Subject], signature: 'bad.example'),
        evidence(%w[List-Unsubscribe List-Unsubscribe-Post], signature: 'good.example')
      ])

      expect(action).to be_a(Mail::Unsubscribe::Action)
      expect(action.evidence.signature).to eq 'good.example'
    end

    it 'refuses when two valid signatures merely repeat a bare name over duplicates' do
      headers = "List-Unsubscribe: <https://one.example/u>\r\n" \
                "List-Unsubscribe: <https://two.example/u>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

      # Each h= entry lists the name once, so per DKIM each signature covers
      # only the bottom-most instance.  Neither names the instance it means.
      expect(described_class.new(message(headers)).parse([
        evidence(['List-Unsubscribe', 'List-Unsubscribe-Post']),
        evidence(['List-Unsubscribe', 'List-Unsubscribe-Post'])
      ])).to be_nil
    end

    it 'refuses when two valid signatures point at different targets' do
      headers = "List-Unsubscribe: <https://one.example/u>\r\n" \
                "List-Unsubscribe: <https://two.example/u>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
      action = described_class.new(message(headers)).parse([
        evidence(['List-Unsubscribe:1', 'List-Unsubscribe-Post:0']),
        evidence(['List-Unsubscribe:0', 'List-Unsubscribe-Post:0'])
      ])

      expect(action).to be_nil
    end
  end

  describe 'URI candidates and malformed parameters' do
    it 'rejects a field containing two HTTPS candidates' do
      headers = "List-Unsubscribe: <https://one.example/u>, <https://two.example/u>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'rejects a field with no HTTPS candidate' do
      headers = "List-Unsubscribe: <mailto:list@example.com?subject=unsubscribe>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'rejects non-HTTP(S) schemes' do
      headers = eligible_headers.sub('<https://example.com/unsubscribe/opaque>', '<ftp://example.com/u>')

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'rejects plain http candidates because one-click requires HTTPS' do
      headers = eligible_headers.sub('<https://example.com/unsubscribe/opaque>', '<http://example.com/u>')

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'rejects trailing garbage after a candidate' do
      headers = eligible_headers.sub('<https://example.com/unsubscribe/opaque>', '<https://example.com/u> trailing')

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'rejects a comma without a following candidate' do
      headers = eligible_headers.sub('<https://example.com/unsubscribe/opaque>', '<https://example.com/u>, ')

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'accepts folded lists with whitespace between candidates' do
      headers = "List-Unsubscribe:\r\n  <mailto:list@example.com?subject=unsubscribe>,\r\n  <https://example.com/u>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

      action = described_class.new(message(headers)).parse(signed_both)
      expect(action.target.to_s).to eq 'https://example.com/u'
    end

    it 'rejects URIs with a fragment' do
      headers = eligible_headers.sub('<https://example.com/unsubscribe/opaque>', '<https://example.com/u#frag>')

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end

    it 'rejects URIs containing userinfo credentials' do
      headers = eligible_headers.sub('<https://example.com/unsubscribe/opaque>', '<https://user:pass@example.com/u>')

      expect(described_class.new(message(headers)).parse(signed_both)).to be_nil
    end
  end

  describe 'no I/O during parsing' do
    it 'never resolves or fetches any candidate while parsing' do
      expect(URI::HTTPS).not_to receive(:open)
      expect(Net::HTTP).not_to receive(:get)
      expect(Net::HTTP).not_to receive(:post)
      expect(Net::HTTP).not_to receive(:start)

      expect(described_class.new(message(eligible_headers)).parse(signed_both)).to be_a(Mail::Unsubscribe::Action)
    end

    it 'does not hand anything to a transport while parsing' do
      transport = double('transport')
      expect(transport).not_to receive(:post)

      action = described_class.new(message(eligible_headers)).parse(signed_both)
      expect(action).to be_pending
      expect(action.request.method).to eq :post
    end
  end
end

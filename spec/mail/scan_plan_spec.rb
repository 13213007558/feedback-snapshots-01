# frozen_string_literal: true

require 'spec_helper'
require 'base64'

RSpec.describe Mail::ScanPlan do
  MARKER = 'X-EICAR-DEMO-MARKER'

  # A fake, in-process scanner: no real antivirus service is involved. It must
  # decode each item itself and then look for the demo marker.
  class FakeScanner
    attr_reader :hits

    def initialize(marker)
      @marker = marker
      @hits = []
    end

    def scan(plan)
      plan.each do |item|
        next unless item.decodable?

        if item.decoded && item.decoded.include?(@marker)
          item.mark_threat!
          @hits << item.path
        else
          item.mark_clean!
        end
      end
    end
  end

  def build_nested_message
    inner_blob = Base64.strict_encode64("#{MARKER} inside base64 blob")
    <<~INNER
      MIME-Version: 1.0
      Content-Type: multipart/mixed; boundary=INNER

      --INNER
      Content-Type: text/plain

      #{MARKER} nested text body
      --INNER
      Content-Type: application/octet-stream; name="deep.bin"
      Content-Transfer-Encoding: base64

      #{inner_blob}
      --INNER--
    INNER
  end

  def build_benign_nested_message
    inner_blob = Base64.strict_encode64('benign encoded blob')
    <<~INNER
      MIME-Version: 1.0
      Content-Type: multipart/mixed; boundary=INNER

      --INNER
      Content-Type: text/plain

      benign nested text body
      --INNER
      Content-Type: application/octet-stream; name="deep.bin"
      Content-Transfer-Encoding: base64

      #{inner_blob}
      --INNER--
    INNER
  end

  def build_full_message(inner: build_nested_message)
    <<~OUTER
      MIME-Version: 1.0
      Content-Type: multipart/mixed; boundary=OUTER

      #{MARKER} multipart preamble text
      --OUTER
      Content-Type: multipart/alternative; boundary=ALT

      --ALT
      Content-Type: text/plain; charset=US-ASCII

      #{MARKER} plain alternative branch
      --ALT
      Content-Type: text/html; charset=ISO-8859-1
      Content-Transfer-Encoding: quoted-printable

      <p>#{MARKER} html alternative branch</p>
      --ALT--
      --OUTER
      Content-Type: message/rfc822; name="forwarded.eml"

      #{inner}
      --OUTER
      Content-Type: application/octet-stream; name="undecodable.bin"
      Content-Transfer-Encoding: x-frobnicate
      Content-Disposition: attachment; filename="undecodable.bin"

      #{MARKER} hidden behind an unknown transfer encoding
      --OUTER--

      #{MARKER} multipart epilogue text
    OUTER
  end

  let(:mail) { Mail.new(build_full_message) }
  let(:plan) { mail.scan_plan }

  describe 'node inventory' do
    it 'is enumerable and includes every content-bearing node' do
      expect(plan).to be_a(Enumerable)
      expect(plan.map(&:path)).to eq(
        %w[
          preamble
          1.1
          1.2
          2
          2.1
          2.2
          3
          epilogue
        ]
      )
      expect(plan.size).to eq(8)
    end

    it 'lists both branches of multipart/alternative, not only text_part' do
      alt_leaves = plan.select { |item| item.path.start_with?('1.') }
      expect(alt_leaves.map(&:mime_type)).to eq(%w[text/plain text/html])
      expect(alt_leaves.map(&:kind)).to all(eq(Mail::ScanPlan::Kind::LEAF))
    end

    it 'lists the nested message/rfc822 node and its inner nodes' do
      container = plan.find { |item| item.path == '2' }
      expect(container.kind).to eq(Mail::ScanPlan::Kind::MESSAGE)
      expect(container.mime_type).to eq('message/rfc822')

      inner_paths = plan.select { |item| item.path.start_with?('2.') }.map(&:path)
      expect(inner_paths).to eq(%w[2.1 2.2])
    end

    it 'lists preamble and epilogue as their own nodes' do
      expect(plan.find(&:preamble?).path).to eq('preamble')
      expect(plan.find(&:epilogue?).path).to eq('epilogue')
      expect(plan.find(&:preamble?).decoded).to include(MARKER)
      expect(plan.find(&:epilogue?).decoded).to include(MARKER)
    end

    it 'records the decoding steps required per node' do
      html = plan.find { |item| item.path == '1.2' }
      expect(html.decoding_steps).to eq(
        ['transfer-decode:quoted-printable', 'charset-transcode:ISO-8859-1>UTF-8']
      )

      base64_part = plan.find { |item| item.path == '2.2' }
      expect(base64_part.decoding_steps).to eq(['transfer-decode:base64'])

      message_node = plan.find { |item| item.path == '2' }
      expect(message_node.decoding_steps).to eq(
        ['transfer-decode:7bit', 'parse-message/rfc822']
      )
    end
  end

  describe 'coverage against the convenience accessors' do
    it 'finds markers in nodes that text_part, html_part and attachments miss' do
      # The convenience accessors surface one text part, one html part and the
      # attachment parts, but never the multipart preamble/epilogue and never
      # the message/rfc822 container itself. The scan plan covers all of them.
      expect(mail.text_part.decoded).to include(MARKER)
      expect(mail.html_part.decoded).to include(MARKER)

      paths_with_markers = plan.select { |item| item.decodable? && item.decoded&.include?(MARKER) }
                               .map(&:path)
      expect(paths_with_markers).to include('preamble', 'epilogue', '2', '2.1', '2.2')

      accessor_blind_spots = [mail.text_part.decoded, mail.html_part.decoded]
      mail.attachments.each { |attachment| accessor_blind_spots << attachment.decoded rescue nil }
      expect(accessor_blind_spots.join).not_to include('multipart preamble text')
      expect(accessor_blind_spots.join).not_to include('multipart epilogue text')
    end

    it 'decodes transfer encodings before matching, so base64 hides the raw marker' do
      base64_part = plan.find { |item| item.path == '2.2' }
      expect(base64_part.part.body.raw_source).not_to include(MARKER)
      expect(base64_part.decoded).to include(MARKER)
    end
  end

  describe 'undecodable nodes' do
    let(:undecodable) { plan.find { |item| item.path == '3' } }

    it 'is reported as not decodable while remaining in the plan' do
      expect(undecodable.decodable?).to eq(false)
      expect(undecodable.transfer_encoding).to eq('x-frobnicate')
      expect(plan.undecodable_items.map(&:path)).to eq(['3'])
      expect(undecodable.decoded).to be_nil
      expect(undecodable.decode_error).to include('x-frobnicate')
    end

    it 'prevents an all-clear result while unresolved' do
      FakeScanner.new(MARKER).scan(plan)

      expect(plan.fully_scanned?).to eq(false)
      expect(plan.pending?).to eq(true)
      expect(plan.all_clear?).to eq(false)
    end

    it 'refuses to mark the node clean or as a threat without inspecting it' do
      expect { undecodable.mark_clean! }.to raise_error(Mail::ScanPlan::UndecodableContentError)
      expect { undecodable.mark_threat! }.to raise_error(Mail::ScanPlan::UndecodableContentError)
      expect(undecodable).to be_pending
    end

    it 'lets the caller explicitly reject the node' do
      undecodable.reject!('unsupported transfer encoding; quarantined')

      expect(undecodable).to be_rejected
      expect(undecodable.reject_reason).to include('quarantined')
      expect(plan.rejected_items.map(&:path)).to eq(['3'])
    end
  end

  describe 'overall disposition' do
    it 'detects the marker in every decodable hiding place' do
      scanner = FakeScanner.new(MARKER)
      scanner.scan(plan)

      expect(scanner.hits).to match_array(%w[preamble 1.1 1.2 2 2.1 2.2 epilogue])
      expect(plan.threats.size).to eq(7)
    end

    it 'is not all-clear while threats are present, even after rejecting undecodable' do
      FakeScanner.new(MARKER).scan(plan)
      plan.undecodable_items.each { |item| item.reject!('policy') }

      expect(plan.fully_scanned?).to eq(true)
      expect(plan.all_clear?).to eq(false)
      expect(plan.threats.map(&:path)).to match_array(%w[preamble 1.1 1.2 2 2.1 2.2 epilogue])
    end

    it 'is all-clear only when every node is clean or explicitly rejected' do
      # Same MIME structure with marker-free bodies, including a benign base64
      # blob (a string replace would not change the pre-encoded payload).
      clean_source = build_full_message(inner: build_benign_nested_message)
                          .gsub(MARKER, 'benign-content')
      clean_plan = Mail.new(clean_source).scan_plan

      FakeScanner.new(MARKER).scan(clean_plan)
      expect(clean_plan.threats).to be_empty
      expect(clean_plan.all_clear?).to eq(false)
      expect(clean_plan.undecodable_items.map(&:path)).to eq(['3'])

      clean_plan.undecodable_items.each { |item| item.reject!('cannot decode, dropped') }
      expect(clean_plan.fully_scanned?).to eq(true)
      expect(clean_plan.all_clear?).to eq(true)
    end
  end

  describe 'simple, non-multipart messages' do
    it 'exposes the single body as one leaf node' do
      simple = Mail.new("Content-Type: text/plain; charset=UTF-8\r\nSubject: hi\r\n\r\nplain body text\r\n")
      simple_plan = simple.scan_plan

      expect(simple_plan.size).to eq(1)
      item = simple_plan.first
      expect(item).to be_leaf
      expect(item.mime_type).to eq('text/plain')
      expect(item.decoding_steps).to eq(['transfer-decode:7bit'])
      expect(item.decoded).to eq("plain body text\n")

      item.mark_clean!
      expect(simple_plan.all_clear?).to eq(true)
    end
  end

  describe 'undecodable message/rfc822' do
    it 'lists the container without recursing into its hidden inner message' do
      raw = <<~RAW
        MIME-Version: 1.0
        Content-Type: multipart/mixed; boundary=B

        --B
        Content-Type: message/rfc822
        Content-Transfer-Encoding: x-frobnicate

        From: a@b
        Subject: hidden inner

        DANGER content that must not be silently walked
        --B--
      RAW
      nested_plan = Mail.new(raw).scan_plan

      expect(nested_plan.size).to eq(1)
      container = nested_plan.first
      expect(container).to be_message
      expect(container).not_to be_decodable
      expect(container.decoded).to be_nil
      expect(container.decode_error).to include('x-frobnicate')
      expect(nested_plan.all_clear?).to eq(false)

      container.reject!('undecodable forwarded message dropped')
      expect(nested_plan.all_clear?).to eq(true)
      expect(nested_plan.fully_scanned?).to eq(true)
    end
  end
end

# encoding: binary
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::RawEvidence do
  # A nested multipart message exercising non-ASCII bytes and mixed line
  # endings (CRLF, LF and a final line without any line ending).
  let(:nested_source) do
    "From: a@example.com\r\n" \
    "Subject: =?UTF-8?B?5rWL6K+V?=\r\n" \
    "Received: first\n" \
    "Received: second\n" \
    "X-Folded: one\r\n two\r\n" \
    "Content-Type: multipart/mixed; boundary=\"OUT\"\r\n" \
    "\r\n" \
    "preamble text\n" \
    "--OUT\r\n" \
    "Content-Type: multipart/alternative; boundary=\"IN\"\n" \
    "\n" \
    "--IN\n" \
    "Content-Type: text/plain; charset=UTF-8\n" \
    "\n" \
    "héllo wörld\n" \
    "--IN\r\n" \
    "Content-Type: text/html\r\n" \
    "\r\n" \
    "<b>hi</b>\r\n" \
    "--IN--\r\n" \
    "--OUT\r\n" \
    "Content-Type: text/plain\r\n" \
    "\r\n" \
    "tail part\r\n" \
    "--OUT--\r\n" \
    "epilogue without newline"
  end

  let(:mail) { Mail.new(nested_source) }
  let(:evidence) { mail.raw_evidence }

  def immediate_children(node)
    return [] unless node.evidence
    if node.evidence.is_a?(Mail::RawEvidence)
      node.evidence.node.evidence&.nodes || []
    else
      node.evidence.nodes
    end
  end

  def assert_slices_back(evidence, source, node)
    return unless node.anchored?
    expect(node.start_offset).to be >= 0
    expect(node.end_offset).to be <= source.bytesize
    expect(node.end_offset).to be >= node.start_offset
    expect(evidence.slice(node.start_offset, node.end_offset)).to eq(
      source.byteslice(node.start_offset, node.end_offset - node.start_offset)
    )
  end

  def assert_disjoint_and_contained(evidence, source, node = evidence.node)
    assert_slices_back(evidence, source, node)
    children = immediate_children(node).select(&:anchored?)
    children.sort_by(&:start_offset).each_cons(2) do |left, right|
      expect(left.end_offset).to be <= right.start_offset
    end
    if node.anchored?
      children.each do |child|
        expect(child.start_offset).to be >= node.start_offset
        expect(child.end_offset).to be <= node.end_offset
      end
    end
    children.each { |child| assert_disjoint_and_contained(evidence, source, child) }
  end

  describe 'Message integration' do
    it 'is available on a message parsed from a string' do
      expect(mail.evidenced?).to be true
      expect(evidence).to be_a(described_class)
    end

    it 'lets every range be re-verified directly against the original bytes' do
      original = nested_source.dup.force_encoding(Encoding::BINARY)
      evidence.nodes.each do |node|
        next unless node.anchored?
        # The range is an absolute half-open byte range into the received mail.
        expect(original.byteslice(node.range)).to eq(node.bytes(original))
        expect(evidence.slice(node.start_offset, node.end_offset)).to eq(
          original.byteslice(node.start_offset, node.end_offset - node.start_offset)
        )
      end
    end

    it 'returns nil evidence for a message built from a hash' do
      built = Mail.new(to: 'a@b', body: 'x')
      expect(built.evidenced?).to be false
      expect(built.raw_evidence).to be_nil
      expect(built.evidence_current?).to be false
    end

    it 'memoizes the evidence object' do
      expect(mail.raw_evidence).to equal(evidence)
    end

    it 'digests the exact received bytes and not the normalized source' do
      expect(evidence.digest).to eq(Digest::SHA256.hexdigest(nested_source))
      expect(evidence.source).to eq(nested_source)
    end
  end

  describe 'received byte fidelity' do
    it 'keeps the mbox From line and leading whitespace that parsing strips' do
      mbox = "From sender Mon Jan 1 00:00:00 2024\nTo: x@y\r\nSubject: s\r\n\r\nbody"
      message = Mail.new(mbox)
      expect(message.received_source).to eq(mbox)
      expect(message.raw_source).not_to eq(mbox)
      expect(message.raw_evidence.digest).to eq(Digest::SHA256.hexdigest(mbox))
    end

    it 'maps every anchored node back onto the original bytes' do
      assert_disjoint_and_contained(evidence, evidence.source)
    end

    it 'preserves non-ASCII body bytes without re-encoding' do
      inner = evidence.multipart.parts.first.evidence.multipart
      text_part = inner.parts.first
      body = text_part.evidence.nodes.find { |node| node.kind == :body }
      bytes = evidence.slice(body.start_offset, body.end_offset)
      expect(bytes).to include("héllo wörld".b)
    end

    it 'preserves mixed line endings in each range' do
      header = evidence.nodes.find { |node| node.kind == :header }
      header_bytes = evidence.slice(header.start_offset, header.end_offset)
      expect(header_bytes).to include("Received: first\n")
      expect(header_bytes).to include("From: a@example.com\r\n")
    end
  end

  describe 'header fields' do
    it 'keeps folded continuation lines inside their field range' do
      folded = evidence.fields.find { |field| field.name == 'x-folded' }
      expect(evidence.slice(folded.start_offset, folded.end_offset)).to eq(
        "X-Folded: one\r\n two\r\n"
      )
    end

    it 'exposes duplicate headers as separate, non-overlapping ranges' do
      received = evidence.fields.select { |field| field.name == 'received' }
      expect(received.size).to eq(2)
      expect(received[0].end_offset).to be <= received[1].start_offset
      received.each do |field|
        expect(evidence.slice(field.start_offset, field.end_offset)).to start_with('Received:')
      end
    end
  end

  describe 'multipart structure' do
    it 'records preamble and epilogue ranges' do
      multipart = evidence.multipart
      expect(evidence.slice(multipart.preamble.start_offset,
                            multipart.preamble.end_offset)).to eq("preamble text\n")
      expect(evidence.slice(multipart.epilogue.start_offset,
                            multipart.epilogue.end_offset)).to eq('epilogue without newline')
    end

    it 'maps every boundary delimiter to its real line' do
      evidence.nodes.select { |node| node.kind == :boundary }.each do |delimiter|
        expect(evidence.slice(delimiter.start_offset, delimiter.end_offset)).to start_with('--')
      end
    end

    it 'recurses into nested multipart parts with absolute offsets' do
      outer = evidence.multipart.parts
      expect(outer.size).to eq(2)
      inner = outer.first.evidence.multipart
      expect(inner.closed?).to be true
      expect(inner.parts.size).to eq(2)
      inner.parts.each do |part|
        expect(part.anchored?).to be true
        expect(part.evidence.fields).not_to be_empty
      end
    end

    it 'keeps nested part fields out of the root field list' do
      expect(evidence.fields.map(&:name)).to eq(
        %w[from subject received received x-folded content-type]
      )
      nested_text = evidence.multipart.parts.first.evidence.multipart.parts.first
      expect(nested_text.evidence.fields.map(&:name)).to eq(['content-type'])
    end

    it 'marks a missing closing boundary without inventing one' do
      truncated =
        "Content-Type: multipart/mixed; boundary=B\r\n\r\n" \
        "preamble\r\n--B\r\nContent-Type: text/plain\r\n\r\nonly part\r\n"
      message = Mail.new(truncated)
      result = message.raw_evidence
      expect(result.multipart.closed?).to be false
      closing = result.nodes.select do |node|
        node.kind == :boundary &&
          result.slice(node.start_offset, node.end_offset).include?('B--')
      end
      expect(closing).to be_empty
      assert_disjoint_and_contained(result, result.source)
    end

    it 'does not fabricate an evidence range for a parser-added part' do
      source = "Content-Type: multipart/mixed; boundary=B\r\n\r\n" \
               "--B\r\nContent-Type: text/plain\r\n\r\none\r\n--B--\r\n"
      message = Mail.new(source)
      result = message.raw_evidence
      original_count = result.part_nodes.size
      message.add_part(Mail::Part.new("Content-Type: text/plain\r\n\r\ntwo"))
      expect(result.part_nodes.size).to eq(original_count)
    end

    it 'records a discarded empty segment without inventing a part' do
      source = "Content-Type: multipart/mixed; boundary=B\r\n\r\n" \
               "--B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nreal\r\n--B--\r\n"
      message = Mail.new(source)
      result = message.raw_evidence
      expect(message.parts.size).to eq(1)
      expect(result.part_nodes.size).to eq(1)
      segment = result.multipart.parts.find { |node| node.kind == :segment }
      expect(segment).to be_a(Mail::RawEvidence::Node)
      expect(result.slice(segment.start_offset, segment.end_offset)).to eq('')
      assert_disjoint_and_contained(result, result.source)
    end

    it 'handles CR-only line endings' do
      source = "To: a@b\rSubject: hi\r\rbody\rcr"
      message = Mail.new(source)
      result = message.raw_evidence
      expect(result.fields.map(&:name)).to eq(%w[to subject])
      body = result.nodes.find { |node| node.kind == :body }
      expect(result.slice(body.start_offset, body.end_offset)).to eq("body\rcr")
      assert_disjoint_and_contained(result, result.source)
    end
  end

  describe 'message/rfc822' do
    it 'evidences the embedded message with root-absolute offsets' do
      inner = "From: nested@x\r\nSubject: inner\r\nContent-Type: text/plain\r\n\r\nnested body"
      source = "Content-Type: multipart/mixed; boundary=B\r\n\r\n" \
               "--B\r\nContent-Type: message/rfc822\r\n\r\n#{inner}\r\n--B--\r\n"
      message = Mail.new(source)
      part = message.raw_evidence.part_nodes.first
      body = part.evidence.nodes.find { |node| node.kind == :body }
      embedded = body.evidence
      expect(embedded).to be_a(described_class)
      subject = embedded.fields.find { |field| field.name == 'subject' }
      expect(embedded.slice(subject.start_offset, subject.end_offset)).to include('inner')
      expect(message.raw_evidence.slice(subject.start_offset, subject.end_offset)).to eq(
        embedded.slice(subject.start_offset, subject.end_offset)
      )
    end
  end

  describe 'staleness' do
    it 'stays current under normal read-only access and keeps the digest stable' do
      digest_before = evidence.digest
      mail.subject
      mail.to
      mail.errors
      mail.header.fields.each(&:value)
      mail.body.decoded
      evidence.nodes
      evidence.fields
      evidence.part_nodes
      expect(evidence.digest).to eq(digest_before)
      expect(mail.evidence_current?).to be true
      expect(mail.evidence_stale?).to be false
    end

    it 'becomes stale after a header change but retains the old bytes' do
      old_subject = evidence.fields.find { |field| field.name == 'subject' }
      old_bytes = evidence.slice(old_subject.start_offset, old_subject.end_offset)
      mail.subject = 'replacement'
      expect(mail.evidence_stale?).to be true
      expect(evidence.digest).to eq(Digest::SHA256.hexdigest(nested_source))
      expect(evidence.slice(old_subject.start_offset, old_subject.end_offset)).to eq(old_bytes)
    end

    it 'becomes stale after a body change' do
      message = Mail.new("To: a@b\r\n\r\noriginal")
      message.body = 'replacement'
      expect(message.evidence_stale?).to be true
      expect(message.raw_evidence.digest).to eq(
        Digest::SHA256.hexdigest("To: a@b\r\n\r\noriginal")
      )
    end

    it 'becomes stale after a nested part is modified' do
      mail.parts.first.header['x-new'] = 'v'
      expect(mail.evidence_stale?).to be true
      expect(evidence.digest).to eq(Digest::SHA256.hexdigest(nested_source))
    end
  end

  describe 'simple non-multipart messages' do
    it 'maps an LF-only message exactly' do
      source = "To: a@b\nSubject: hi\n\nline1\nline2"
      message = Mail.new(source)
      result = message.raw_evidence
      body = result.nodes.find { |node| node.kind == :body }
      expect(result.slice(body.start_offset, body.end_offset)).to eq("line1\nline2")
      expect(result.fields.map(&:name)).to eq(%w[to subject])
    end

    it 'handles a message with no body' do
      source = "To: a@b\r\nSubject: hi\r\n"
      message = Mail.new(source)
      expect { message.raw_evidence }.not_to raise_error
      expect(message.raw_evidence.fields.map(&:name)).to eq(%w[to subject])
    end
  end
end

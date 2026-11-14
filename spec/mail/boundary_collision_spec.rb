# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'digest'

RSpec.describe "MIME boundary collision handling" do

  def leaf_digests(message)
    if message.multipart?
      message.parts.flat_map { |part| leaf_digests(part) }
    else
      [Digest::SHA256.hexdigest(message.decoded)]
    end
  end

  def structure(message)
    if message.multipart?
      [message.parts.map { |part| structure(part) }.sort_by(&:inspect)]
    else
      :leaf
    end
  end

  def build_colliding_mail(boundary, colliding_body)
    mail = Mail.new
    mail.from "sender@example.com"
    mail.to "rcpt@example.com"
    mail.subject "boundary collision"
    mail.part :content_type => "text/plain", :body => colliding_body
    mail.part :content_type => "text/plain", :body => "unrelated second part"
    mail.content_type = "multipart/mixed; boundary=#{boundary}"
    mail.body.boundary = boundary
    mail
  end

  describe "caller-specified boundary colliding with content" do
    it "replaces the boundary when the content holds an exact delimiter line" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED\nworld")
      expect { mail.ready_to_send! }.to change { mail.boundary }.from("FIXED")
    end

    it "replaces the boundary when the content holds a closing delimiter line" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED--\nworld")
      expect(mail.ready_to_send!.length).to eq 1
      expect(mail.boundary).not_to eq "FIXED"
    end

    it "replaces the boundary when the content holds a near-boundary line" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXEDsuffix\nworld")
      expect(mail.ready_to_send!.length).to eq 1
      expect(mail.boundary).not_to eq "FIXED"
    end

    it "replaces the boundary when the content holds a delimiter with transport padding" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED \nworld")
      expect(mail.ready_to_send!.length).to eq 1
      expect(mail.boundary).not_to eq "FIXED"
    end

    it "keeps part count, content digests and hierarchy after serialize/parse" do
      body = "hello\n--FIXED\nworld\n--FIXED--\n--FIXEDsuffix\n--FIXED padded \n"
      mail = build_colliding_mail("FIXED", body)
      expected_digests = leaf_digests(mail)
      expected_structure = structure(mail)

      mail.encoded
      reparsed = Mail.new(mail.encoded)

      expect(reparsed.parts.length).to eq 2
      expect(leaf_digests(reparsed).sort).to eq expected_digests.sort
      expect(structure(reparsed)).to eq expected_structure
      expect(reparsed.parts.map(&:decoded)).to include(a_string_including(body))
    end

    it "reports the substitution in the ready_to_send! return value" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED\nworld")
      changes = mail.ready_to_send!
      expect(changes.length).to eq 1
      expect(changes.first[:level]).to eq 0
      expect(changes.first[:old_boundary]).to eq "FIXED"
      expect(changes.first[:new_boundary]).to eq mail.boundary
      expect(changes.first[:line]).to eq "--FIXED"
    end

    it "exposes the substitution through #boundary_changes after encoding" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED\nworld")
      mail.encoded
      expect(mail.boundary_changes.length).to eq 1
      expect(mail.boundary_changes.first[:old_boundary]).to eq "FIXED"
    end

    it "updates the Content-Type boundary parameter in the serialized output" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED\nworld")
      encoded = mail.encoded
      expect(encoded).to include(%(boundary="#{mail.boundary}"))
      expect(encoded).not_to include("boundary=FIXED")
      expect(encoded).not_to include('boundary="FIXED"')
    end
  end

  describe "collision-free caller-specified boundary" do
    it "is preserved and reports no changes" do
      mail = build_colliding_mail("KEEPME", "totally safe content")
      changes = mail.ready_to_send!
      expect(changes).to eq []
      expect(mail.boundary).to eq "KEEPME"
      expect(mail.encoded).to include("KEEPME")
    end
  end

  describe "nested multipart messages" do
    def build_nested_mail
      inner = Mail::Part.new
      inner.part :content_type => "text/plain", :body => "plain\n--INNER--\ntail"
      inner.part :content_type => "text/html", :body => "<b>hi</b>"
      inner.content_type = "multipart/alternative; boundary=INNER"
      inner.body.boundary = "INNER"

      mail = Mail.new
      mail.from "sender@example.com"
      mail.add_part inner
      mail.part :content_type => "text/plain", :body => "outer text\n--OUTER\n"
      mail.content_type = "multipart/mixed; boundary=OUTER"
      mail.body.boundary = "OUTER"
      mail
    end

    it "resolves collisions at every nesting level and reports their hierarchy" do
      mail = build_nested_mail
      changes = mail.ready_to_send!

      expect(changes.length).to eq 2
      inner_change = changes.find { |c| c[:old_boundary] == "INNER" }
      outer_change = changes.find { |c| c[:old_boundary] == "OUTER" }
      expect(inner_change[:level]).to eq 1
      expect(outer_change[:level]).to eq 0
      expect(mail.boundary).to eq outer_change[:new_boundary]
    end

    it "keeps nested part count, content digests and hierarchy after serialize/parse" do
      mail = build_nested_mail
      expected_digests = leaf_digests(mail)
      expected_structure = structure(mail)

      reparsed = Mail.new(mail.encoded)

      expect(reparsed.parts.length).to eq 2
      inner = reparsed.parts.find(&:multipart?)
      expect(inner).not_to be_nil
      expect(inner.parts.length).to eq 2
      expect(inner.parts.map(&:decoded)).to include(a_string_including("plain\n--INNER--\ntail"))
      expect(leaf_digests(reparsed).sort).to eq expected_digests.sort
      expect(structure(reparsed)).to eq expected_structure
    end

    it "detects a collision of the outer boundary inside a nested part" do
      mail = build_nested_mail
      mail.ready_to_send!
      inner = mail.parts.find(&:multipart?)
      expect(inner.boundary).not_to eq "INNER"
      expect(mail.boundary).not_to eq "OUTER"
    end
  end

  describe "checks apply to the final transfer bytes" do
    it "ignores boundary-like lines that only exist before base64 encoding" do
      mail = Mail.new
      mail.from "sender@example.com"
      part = Mail::Part.new(:content_type => "text/plain",
                            :content_transfer_encoding => "base64")
      part.body = "line\n--B64\nmore"
      mail.add_part part
      mail.content_type = "multipart/mixed; boundary=B64"
      mail.body.boundary = "B64"

      expect(mail.ready_to_send!).to eq []
      expect(mail.boundary).to eq "B64"
    end

    it "detects boundary lines passed through by quoted-printable encoding" do
      mail = Mail.new
      mail.from "sender@example.com"
      part = Mail::Part.new(:content_type => "text/plain; charset=UTF-8",
                            :content_transfer_encoding => "quoted-printable")
      part.body = "café\n--QP\nmore"
      mail.add_part part
      mail.content_type = "multipart/mixed; boundary=QP"
      mail.body.boundary = "QP"

      expect(mail.ready_to_send!.length).to eq 1
      expect(mail.boundary).not_to eq "QP"
    end

    it "produces output that reparses without further boundary changes" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED\nworld")
      reparsed = Mail.new(mail.encoded)
      expect(reparsed.ready_to_send!).to eq []
      expect(reparsed.boundary).to eq mail.boundary
    end
  end

  describe "regeneration failure" do
    it "raises Mail::BoundaryCollisionError when no safe boundary can be found" do
      mail = build_colliding_mail("FIXED", "hello\n--FIXED\nworld")
      allow(Mail::ContentTypeField).to receive(:generate_boundary).and_return("FIXED")
      expect { mail.ready_to_send! }.to raise_error(Mail::BoundaryCollisionError, /collision-free/)
    end
  end
end

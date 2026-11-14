# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::Message, "MIME-scoped cid resolution" do
  def html_parts(mail)
    mail.all_parts.select { |p| p.mime_type == 'text/html' }
  end

  def image_parts(mail)
    mail.all_parts.select { |p| p.mime_type == 'image/png' }
  end

  describe "two emails sharing one Content-ID with different layouts" do
    it "layout A: resolves to the inline part of the selected body's related group, not the earlier top-level decoy" do
      mail = read_fixture('emails', 'mime_emails', 'cid_scope_layout_a.eml')
      decoy, real = image_parts(mail)
      expect(decoy.decoded).to eq 'DECOY-IMAGE-A'
      expect(real.decoded).to eq 'REAL-IMAGE-A'
      expect(mail.parts.first).to eq decoy # decoy comes first in document order

      resolved = mail.find_part_by_cid('cid:logo@example.com')
      expect(resolved).to eq real
      expect(resolved.decoded).to eq 'REAL-IMAGE-A'
    end

    it "layout B: each selected body resolves to the image of its own related group" do
      mail = read_fixture('emails', 'mime_emails', 'cid_scope_layout_b.eml')
      body_one, body_two = html_parts(mail)
      image_one, image_two = image_parts(mail)

      expect(mail.find_part_by_cid('cid:logo@example.com', from: body_one)).to eq image_one
      expect(mail.find_part_by_cid('cid:logo@example.com', from: body_one).decoded).to eq 'IMAGE-B1'

      expect(mail.find_part_by_cid('cid:logo@example.com', from: body_two)).to eq image_two
      expect(mail.find_part_by_cid('cid:logo@example.com', from: body_two).decoded).to eq 'IMAGE-B2'
    end
  end

  describe "cid URL normalization" do
    it "percent-decodes encoded cids before matching" do
      mail = read_fixture('emails', 'mime_emails', 'cid_scope_layout_b.eml')
      body_two = html_parts(mail).last
      expect(mail.find_part_by_cid('cid:logo%40example.com', from: body_two).decoded).to eq 'IMAGE-B2'
    end

    it "accepts bare and bracketed cids, and round-trips Part#url" do
      mail = read_fixture('emails', 'mime_emails', 'cid_scope_layout_a.eml')
      real = image_parts(mail).last
      expect(mail.find_part_by_cid('logo@example.com')).to eq real
      expect(mail.find_part_by_cid('<logo@example.com>')).to eq real
      expect(mail.find_part_by_cid(real.url)).to eq real
    end
  end

  describe "scoping rules" do
    it "ignores parts in unselected multipart/alternative branches" do
      mail = Mail.new do
        content_type 'multipart/alternative'
        part do |p|
          p.content_type 'multipart/related'
          p.part content_type: 'text/html', body: '<img src="cid:logo@example.com">'
          p.part content_type: 'image/png', content_id: '<logo@example.com>', body: 'UNSELECTED-BRANCH-IMAGE'
        end
        part content_type: 'text/html', body: '<img src="cid:logo@example.com">'
      end
      selected = html_parts(mail).last
      expect(mail.find_part_by_cid('cid:logo@example.com', from: selected)).to be_nil
    end

    it "resolves nested multipart/related parts from the outer body, but not outer siblings from the nested body" do
      mail = Mail.new do
        content_type 'multipart/related'
        part content_type: 'text/html', body: 'outer body'
        part content_type: 'image/png', content_id: '<outer@example.com>', body: 'OUTER-IMAGE'
        part do |p|
          p.content_type 'multipart/related'
          p.part content_type: 'text/html', body: 'nested body'
          p.part content_type: 'image/png', content_id: '<nested@example.com>', body: 'NESTED-IMAGE'
        end
      end
      outer_body, nested_body = html_parts(mail)

      expect(mail.find_part_by_cid('cid:nested@example.com', from: outer_body).decoded).to eq 'NESTED-IMAGE'
      expect(mail.find_part_by_cid('cid:outer@example.com', from: outer_body).decoded).to eq 'OUTER-IMAGE'

      expect(mail.find_part_by_cid('cid:nested@example.com', from: nested_body).decoded).to eq 'NESTED-IMAGE'
      expect(mail.find_part_by_cid('cid:outer@example.com', from: nested_body)).to be_nil
    end

    it "returns nil when the selected body is not enclosed in any multipart/related" do
      mail = Mail.new do
        content_type 'multipart/mixed'
        part content_type: 'text/html', body: '<img src="cid:logo@example.com">'
        part content_type: 'image/png', content_id: '<logo@example.com>', body: 'IMAGE'
      end
      expect(mail.find_part_by_cid('cid:logo@example.com')).to be_nil
    end
  end

  describe "ambiguity and error handling" do
    it "returns nil instead of guessing when the scope contains duplicate Content-IDs" do
      mail = Mail.new do
        content_type 'multipart/related'
        part content_type: 'text/html', body: '<img src="cid:dup@example.com">'
        part content_type: 'image/png', content_id: '<dup@example.com>', body: 'FIRST'
        part content_type: 'image/png', content_id: '<dup@example.com>', body: 'SECOND'
      end
      expect(mail.find_part_by_cid('cid:dup@example.com')).to be_nil
    end

    it "returns nil when nothing in scope matches" do
      mail = read_fixture('emails', 'mime_emails', 'cid_scope_layout_a.eml')
      expect(mail.find_part_by_cid('cid:missing@example.com')).to be_nil
    end

    it "raises ArgumentError when the :from part does not belong to the message" do
      mail = read_fixture('emails', 'mime_emails', 'cid_scope_layout_a.eml')
      foreign = Mail::Part.new(content_type: 'text/html', body: 'foreign')
      expect { mail.find_part_by_cid('cid:logo@example.com', from: foreign) }.to raise_error(ArgumentError)
    end
  end
end

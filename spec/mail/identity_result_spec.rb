# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

# Contrast samples: each example pairs the lenient display accessor
# (Mail::Message#from) with the strict identity extractor
# (Mail::Message#from_identity) on the same message, documenting what
# each interface promises.
#
#   lenient #from          -> always returns something displayable,
#                             even raw unparsed text. For humans only.
#   strict  #from_identity -> only reports an identity verified by the
#                             structured address parser as exactly one
#                             mailbox; every other outcome is an
#                             explicit non-authorizable status.
RSpec.describe Mail::IdentityResult do

  def message_with(from_header)
    Mail.new("From: #{from_header}\r\n\r\nbody")
  end

  describe "a single, well-formed mailbox" do
    it "is usable for authorization" do
      mail = message_with('Mikel Lindsaar <mikel@test.lindsaar.net>')
      result = mail.from_identity
      expect(result.status).to eq Mail::IdentityResult::OK
      expect(result).to be_ok
      expect(result).to be_usable_for_authorization
      expect(result.address).to eq 'mikel@test.lindsaar.net'
    end

    it "keeps the original displayable field value" do
      mail = message_with('Mikel Lindsaar <mikel@test.lindsaar.net>')
      expect(mail.from_identity.display).to eq 'Mikel Lindsaar <mikel@test.lindsaar.net>'
    end
  end

  describe "contrast: multiple From mailboxes" do
    let(:mail) { message_with('a@example.com, b@example.com') }

    it "lenient #from lists every address" do
      expect(mail.from).to eq ['a@example.com', 'b@example.com']
    end

    it "strict extraction refuses to pick one" do
      result = mail.from_identity
      expect(result.status).to eq Mail::IdentityResult::AMBIGUOUS
      expect(result).not_to be_usable_for_authorization
      expect(result.address).to be_nil
      expect(result.addresses).to eq ['a@example.com', 'b@example.com']
    end
  end

  describe "contrast: empty group" do
    let(:mail) { message_with('undisclosed-recipients:;') }

    it "lenient #from returns an empty list" do
      expect(mail.from).to eq []
    end

    it "strict extraction reports no identity" do
      result = mail.from_identity
      expect(result.status).to eq Mail::IdentityResult::EMPTY
      expect(result).not_to be_usable_for_authorization
    end
  end

  describe "comments" do
    it "ignores comments structurally and extracts the mailbox" do
      mail = message_with('user@example.com (the boss)')
      expect(mail.from_identity.status).to eq Mail::IdentityResult::OK
      expect(mail.from_identity.address).to eq 'user@example.com'
    end

    it "does not mistake an email-like comment for the identity" do
      mail = message_with('user@example.com (contact admin@other.example)')
      expect(mail.from_identity.address).to eq 'user@example.com'
    end
  end

  describe "quoted separators" do
    it "does not split a quoted display name on the comma" do
      mail = message_with('"Last, First" <user@example.com>')
      result = mail.from_identity
      expect(result.status).to eq Mail::IdentityResult::OK
      expect(result.address).to eq 'user@example.com'
      expect(result.addresses).to eq ['user@example.com']
    end
  end

  describe "pseudo-address inside the display name" do
    let(:mail) { message_with('"attacker@evil.example" <real@example.com>') }

    it "extracts only the structural mailbox" do
      expect(mail.from_identity.address).to eq 'real@example.com'
    end

    it "never mines the display name for an email-looking fragment" do
      expect(mail.from_identity.address).not_to eq 'attacker@evil.example'
      expect(mail.from_identity.addresses).to eq ['real@example.com']
    end

    it "still preserves the raw field for display" do
      expect(mail.from_identity.display).to eq '"attacker@evil.example" <real@example.com>'
    end
  end

  describe "contrast: unparseable field degrading to plain text" do
    let(:mail) { message_with('not an address <<<>>>') }

    it "lenient #from falls back to the raw string" do
      expect(mail.from).to eq 'not an address <<<>>>'
    end

    it "strict extraction reports an explicit non-authorizable status" do
      result = mail.from_identity
      expect(result.status).to eq Mail::IdentityResult::UNPARSEABLE
      expect(result).not_to be_usable_for_authorization
      expect(result.address).to be_nil
      expect(result.reason).to match(/degraded to plain text/)
    end

    it "keeps the raw field displayable without re-parsing it" do
      expect(mail.from_identity.display).to eq 'not an address <<<>>>'
    end
  end

  describe "missing From field" do
    it "reports :missing" do
      mail = Mail.new("Subject: no from\r\n\r\nbody")
      result = mail.from_identity
      expect(result.status).to eq Mail::IdentityResult::MISSING
      expect(result).not_to be_usable_for_authorization
      expect(result.display).to be_nil
    end
  end

  describe "blank From field" do
    it "reports :empty" do
      mail = message_with('')
      expect(mail.from_identity.status).to eq Mail::IdentityResult::EMPTY
    end
  end

  describe ".extract" do
    it "accepts nil for a missing field" do
      result = Mail::IdentityResult.extract(nil)
      expect(result.status).to eq Mail::IdentityResult::MISSING
    end

    it "works with any structured address field, not only From" do
      mail = Mail.new("Sender: bot@example.com\r\n\r\nbody")
      result = Mail::IdentityResult.extract(mail[:sender])
      expect(result.status).to eq Mail::IdentityResult::OK
      expect(result.address).to eq 'bot@example.com'
    end
  end

  describe "result value semantics" do
    it "is equal to another result with the same status and address" do
      mail = message_with('a@example.com')
      expect(mail.from_identity).to eq mail.from_identity
    end

    it "differs across statuses" do
      ok = message_with('a@example.com').from_identity
      bad = message_with('not an address <<<>>>').from_identity
      expect(ok).not_to eq bad
    end
  end
end

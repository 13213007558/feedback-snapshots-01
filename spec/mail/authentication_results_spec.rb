# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::AuthenticationResults do
  def message_with(*auth_results_headers)
    lines = auth_results_headers.map { |value| "Authentication-Results: #{value}" }
    lines += ["From: sender@example.com", "To: victim@example.com", "Subject: hi", "", "body"]
    Mail.new(lines.join("\r\n"))
  end

  describe '.trusted' do
    it "returns only results from the trusted authserv-id within the header boundary" do
      mail = message_with(
        'mx.example.com; dkim=fail header.d=evil.example',
        'attacker.example; dkim=pass header.d=evil.example'
      )
      trusted = Mail::AuthenticationResults.trusted(mail, authserv_ids: 'mx.example.com', within: 1)
      expect(trusted.size).to eq 1
      expect(trusted.first.authserv_id).to eq 'mx.example.com'
      expect(trusted.first.result_for('dkim').result).to eq 'fail'
    end

    it "proves an attacker-pre-inserted pass cannot replace the receiver's own conclusion" do
      # The attacker prepended a forged "pass" before handing the message
      # to mx.example.com, which then added its own verdict on top.
      mail = message_with(
        'mx.example.com; dkim=fail header.d=evil.example; spf=fail smtp.mailfrom=evil.example',
        'attacker.example; dkim=pass header.d=evil.example; spf=pass smtp.mailfrom=evil.example'
      )

      # A naive scan over every header would believe the attacker.
      naive = mail.authentication_results.flat_map(&:results).find { |r| r.method?('dkim') && r.pass? }
      expect(naive).not_to be_nil

      # The trusted selection only contains the receiver's own verdict.
      dkim = Mail::AuthenticationResults.trusted_result_for(mail, 'dkim', authserv_ids: 'mx.example.com', within: 1)
      expect(dkim.result).to eq 'fail'
      expect(dkim).not_to be_pass
      spf = Mail::AuthenticationResults.trusted_result_for(mail, 'spf', authserv_ids: 'mx.example.com', within: 1)
      expect(spf.result).to eq 'fail'
    end

    it "ignores a forged header that copies the trusted authserv-id beyond the boundary" do
      mail = message_with(
        'mx.example.com; dkim=fail header.d=evil.example',
        'mx.example.com; dkim=pass header.d=evil.example'
      )
      trusted = Mail::AuthenticationResults.trusted(mail, authserv_ids: 'mx.example.com', within: 1)
      expect(trusted.size).to eq 1
      expect(trusted.first.result_for('dkim').result).to eq 'fail'
    end

    it "supports several trusted receiving nodes within a wider boundary" do
      mail = message_with(
        'mx2.example.com; dkim=pass header.d=example.com',
        'mx1.example.com; spf=pass smtp.mailfrom=example.com',
        'attacker.example; dkim=pass header.d=example.com'
      )
      trusted = Mail::AuthenticationResults.trusted(mail,
        authserv_ids: %w[mx1.example.com mx2.example.com], within: 2)
      expect(trusted.map(&:authserv_id)).to eq %w[mx2.example.com mx1.example.com]
    end

    it "excludes headers inside the boundary whose authserv-id is not trusted" do
      mail = message_with(
        'attacker.example; dkim=pass header.d=evil.example',
        'mx.example.com; dkim=fail header.d=evil.example'
      )
      trusted = Mail::AuthenticationResults.trusted(mail, authserv_ids: 'mx.example.com', within: 2)
      expect(trusted.map(&:authserv_id)).to eq %w[mx.example.com]
    end

    it "matches authserv-ids case-insensitively" do
      mail = message_with('MX.Example.COM; dkim=pass header.d=example.com')
      trusted = Mail::AuthenticationResults.trusted(mail, authserv_ids: 'mx.example.com', within: 1)
      expect(trusted.size).to eq 1
    end

    it "excludes unparseable headers from security decisions" do
      mail = message_with(
        'mx.example.com; dkim=pass header.from',
        'mx.example.com; dkim=fail header.d=evil.example'
      )
      trusted = Mail::AuthenticationResults.trusted(mail, authserv_ids: 'mx.example.com', within: 2)
      expect(trusted.size).to eq 1
      expect(trusted.first.result_for('dkim').result).to eq 'fail'
    end

    it "does not let a pass hidden in a comment count as a result" do
      mail = message_with('mx.example.com (dkim=pass header.d=evil.example); none')
      dkim = Mail::AuthenticationResults.trusted_result_for(mail, 'dkim', authserv_ids: 'mx.example.com', within: 1)
      expect(dkim).to be_nil
    end

    it "keeps unknown methods distinct from known ones" do
      mail = message_with('mx.example.com; x-dkim=pass header.d=evil.example')
      expect(Mail::AuthenticationResults.trusted_result_for(mail, 'dkim',
        authserv_ids: 'mx.example.com', within: 1)).to be_nil
      unknown = Mail::AuthenticationResults.trusted_result_for(mail, 'x-dkim',
        authserv_ids: 'mx.example.com', within: 1)
      expect(unknown).not_to be_nil
    end

    it "requires at least one trusted authserv-id" do
      mail = message_with('mx.example.com; none')
      expect {
        Mail::AuthenticationResults.trusted(mail, authserv_ids: [], within: 1)
      }.to raise_error(ArgumentError)
    end

    it "requires a header boundary of at least one" do
      mail = message_with('mx.example.com; none')
      expect {
        Mail::AuthenticationResults.trusted(mail, authserv_ids: 'mx.example.com', within: 0)
      }.to raise_error(ArgumentError)
    end
  end

  describe '.trusted_result_for' do
    it "returns nil instead of a result when no trusted node recorded the method" do
      mail = message_with('attacker.example; dkim=pass header.d=evil.example')
      expect(Mail::AuthenticationResults.trusted_result_for(mail, 'dkim',
        authserv_ids: 'mx.example.com', within: 1)).to be_nil
    end

    it "prefers the topmost trusted header when several record the method" do
      mail = message_with(
        'mx.example.com; dkim=fail header.d=evil.example',
        'mx.example.com; dkim=pass header.d=evil.example'
      )
      dkim = Mail::AuthenticationResults.trusted_result_for(mail, 'dkim',
        authserv_ids: 'mx.example.com', within: 2)
      expect(dkim.result).to eq 'fail'
    end
  end
end

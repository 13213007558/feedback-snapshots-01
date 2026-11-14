# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::AuthenticationResultsField do

  it "initializes" do
    expect { Mail::AuthenticationResultsField.new('mx.example.com; dkim=pass header.d=example.com') }.not_to raise_error
  end

  it "has the canonical field name" do
    expect(Mail::AuthenticationResultsField.new('mx.example.com; none').name).to eq 'Authentication-Results'
  end

  it "exposes the authserv-id" do
    field = Mail::AuthenticationResultsField.new('mx.example.com; dkim=pass header.d=example.com')
    expect(field.authserv_id).to eq 'mx.example.com'
  end

  it "exposes the parsed element and its results" do
    field = Mail::AuthenticationResultsField.new('mx.example.com; dkim=pass header.d=example.com; spf=fail smtp.mailfrom=evil.example')
    expect(field.element).to be_a Mail::AuthenticationResultsElement
    expect(field.results.size).to eq 2
    expect(field.result_for('dkim').result).to eq 'pass'
    expect(field.result_for('spf').result).to eq 'fail'
  end

  it "encodes the field" do
    field = Mail::AuthenticationResultsField.new('mx.example.com; dkim=pass header.d=example.com')
    expect(field.encoded).to eq "Authentication-Results: mx.example.com; dkim=pass header.d=example.com\r\n"
  end

  it "decodes the field" do
    field = Mail::AuthenticationResultsField.new('mx.example.com; dkim=pass header.d=example.com')
    expect(field.decoded).to eq 'mx.example.com; dkim=pass header.d=example.com'
  end

  it "handles a blank value" do
    field = Mail::AuthenticationResultsField.new('')
    expect(field.decoded).to eq ''
    expect(field.encoded).to eq "Authentication-Results: \r\n"
  end

  it "is selected for the authentication-results header name" do
    expect(Mail::Field.field_class_for('authentication-results')).to eq Mail::AuthenticationResultsField
    expect(Mail::Field.field_class_for('Authentication-Results')).to eq Mail::AuthenticationResultsField
  end

  it "parses from a raw message and keeps every instance in order" do
    mail = Mail.new("Authentication-Results: mx.example.com; dkim=fail header.d=evil.example\r\n" \
                    "Authentication-Results: attacker.example; dkim=pass header.d=evil.example\r\n" \
                    "From: sender@example.com\r\n\r\nbody")
    fields = mail.authentication_results
    expect(fields.size).to eq 2
    expect(fields[0].authserv_id).to eq 'mx.example.com'
    expect(fields[1].authserv_id).to eq 'attacker.example'
    expect(fields[0].result_for('dkim').result).to eq 'fail'
    expect(fields[1].result_for('dkim').result).to eq 'pass'
  end

  it "falls back to an unstructured field with errors for malformed values" do
    mail = Mail.new("Authentication-Results: mx.example.com; dkim=pass header.from\r\n" \
                    "From: sender@example.com\r\n\r\nbody")
    field = mail.header.fields.first
    expect(field.field).to be_a Mail::UnstructuredField
    expect(field.field.errors.size).to eq 1
  end
end

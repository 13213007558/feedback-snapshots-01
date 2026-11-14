# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::AuthenticationResultsElement do

  it "parses the authserv-id and no results" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com')
    expect(element.authserv_id).to eq 'mx.example.com'
    expect(element.results).to eq []
    expect(element).not_to be_none
  end

  it "parses an authserv-id version" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com/1; none')
    expect(element.version).to eq '1'
    expect(element).to be_none
  end

  it "parses method results with properties" do
    element = Mail::AuthenticationResultsElement.new(
      'mx.example.com; dkim=pass header.d=example.com header.s=sel1 header.b=abc/Def=; ' \
      'spf=fail smtp.mailfrom=evil@example.org'
    )
    expect(element.results.size).to eq 2

    dkim = element.result_for('dkim')
    expect(dkim.result).to eq 'pass'
    expect(dkim).to be_pass
    expect(dkim.property('header', 'd')).to eq 'example.com'
    expect(dkim.property('header', 's')).to eq 'sel1'
    expect(dkim.property('header', 'b')).to eq 'abc/Def='

    spf = element.result_for('spf')
    expect(spf.result).to eq 'fail'
    expect(spf).not_to be_pass
    expect(spf.property('smtp', 'mailfrom')).to eq 'evil@example.org'
  end

  it "matches method and property names case-insensitively" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com; DKIM=Pass header.D=example.com')
    dkim = element.result_for('dkim')
    expect(dkim).not_to be_nil
    expect(dkim.method).to eq 'DKIM'
    expect(dkim).to be_pass
    expect(dkim.property('HEADER', 'd')).to eq 'example.com'
  end

  it "parses quoted-string reasons and values" do
    element = Mail::AuthenticationResultsElement.new(
      'mx.example.com; dkim=fail reason="stale signature" header.from="User <user@example.com>"'
    )
    dkim = element.result_for('dkim')
    expect(dkim.reason).to eq 'stale signature'
    expect(dkim.property('header', 'from')).to eq 'User <user@example.com>'
  end

  it "parses a method version" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com; dkim/1=pass header.d=example.com')
    expect(element.result_for('dkim').method_version).to eq '1'
  end

  it "keeps comment text separate from results" do
    element = Mail::AuthenticationResultsElement.new(
      'mx.example.com; dkim=pass (dkim=fail was here) header.d=example.com'
    )
    dkim = element.result_for('dkim')
    expect(dkim.result).to eq 'pass'
    expect(dkim.comments).to eq ['dkim=fail was here']
    expect(dkim.properties.size).to eq 1
  end

  it "does not treat a result-looking comment as a result" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com (dkim=pass header.d=evil.example); none')
    expect(element.result_for('dkim')).to be_nil
    expect(element.comments).to eq ['dkim=pass header.d=evil.example']
    expect(element).to be_none
  end

  it "keeps nested comments as comment text" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com; dkim=pass (outer (dkim=fail) inner) header.d=example.com')
    dkim = element.result_for('dkim')
    expect(dkim.comments).to eq ['outer (dkim=fail) inner']
    expect(dkim.result).to eq 'pass'
  end

  it "preserves unknown authentication methods" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com; x-made-up=pass; dkim=neutral header.i=@example.com')
    unknown = element.result_for('x-made-up')
    expect(unknown).not_to be_nil
    expect(unknown.result).to eq 'pass'
    expect(element.result_for('dkim').result).to eq 'neutral'
  end

  it "returns nil for methods that have no result" do
    element = Mail::AuthenticationResultsElement.new('mx.example.com; spf=pass smtp.mailfrom=example.com')
    expect(element.result_for('dkim')).to be_nil
  end

  it "raises a ParseError for a malformed property" do
    expect {
      Mail::AuthenticationResultsElement.new('mx.example.com; dkim=pass header.from')
    }.to raise_error(Mail::Field::ParseError)
  end

  it "raises a ParseError when the authserv-id is missing" do
    expect {
      Mail::AuthenticationResultsElement.new('; dkim=pass')
    }.to raise_error(Mail::Field::ParseError)
  end

  it "raises a ParseError for a result without a method" do
    expect {
      Mail::AuthenticationResultsElement.new('mx.example.com; =pass')
    }.to raise_error(Mail::Field::ParseError)
  end

  it "handles a blank value" do
    element = Mail::AuthenticationResultsElement.new('')
    expect(element.authserv_id).to be_nil
    expect(element.results).to eq []
    expect(element).not_to be_none
  end

  it "parses folded headers with comments" do
    element = Mail::AuthenticationResultsElement.new(
      "mx.example.com;\r\n\tdkim=pass (folded\r\n\tcomment) header.d=example.com"
    )
    dkim = element.result_for('dkim')
    expect(dkim.result).to eq 'pass'
    expect(dkim.comments).to eq ["folded\r\n\tcomment"]
  end
end

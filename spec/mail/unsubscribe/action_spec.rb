# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'
require 'mail/unsubscribe'
require 'net/http'

RSpec.describe Mail::Unsubscribe::Action do
  class RecordingTransport
    attr_reader :requests

    def initialize
      @requests = []
    end

    def post(request)
      @requests << request
      :accepted
    end

    def call(request)
      @requests << request
      :called
    end
  end

  def message(headers = nil)
    headers ||= "List-Unsubscribe: <https://example.com/unsubscribe/opaque>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
    Mail.new("#{headers}\r\nbody\r\n")
  end

  def evidence(fields = %w[List-Unsubscribe List-Unsubscribe-Post], valid: true)
    Mail::Unsubscribe::Evidence.new(fields, valid: valid)
  end

  def action_for(mail = message, evidence_value = evidence)
    described_class.new(
      uri: URI.parse('https://example.com/unsubscribe/opaque'),
      candidates: [],
      list_unsubscribe: Mail::Unsubscribe::HeaderField.new('List-Unsubscribe', '<https://example.com/unsubscribe/opaque>', 0),
      list_unsubscribe_post: Mail::Unsubscribe::HeaderField.new('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click', 0),
      evidence: evidence_value
    )
  end

  describe 'lifecycle' do
    it 'starts pending and performs no work on construction' do
      expect(action_for).to be_pending
      expect(action_for).not_to be_confirmed
    end

    it 'exposes only a POST request' do
      request = action_for.request

      expect(request.method).to eq :post
      expect(request).to be_post
      expect(request).not_to be_get
      expect(request.body).to eq 'List-Unsubscribe=One-Click'
      expect(request.uri.to_s).to eq 'https://example.com/unsubscribe/opaque'
    end

    it 'does not expose a GET operation on the action' do
      action = action_for

      %i[get get! prefetch prefetch! fetch fetch! head head! open].each do |method_name|
        expect(action).not_to respond_to(method_name), "Action unexpectedly responds to ##{method_name}"
      end

      expect(Mail::Unsubscribe::Request.instance_methods(false)).to include(:post?)
      expect(Mail::Unsubscribe::Request.instance_methods(false)).not_to include(:get)
      expect(action.request).not_to be_get
    end

    it 'hands a POST request to a transport on explicit confirmation' do
      transport = RecordingTransport.new
      action = action_for

      expect(action.confirm!(transport)).to eq :accepted
      expect(action).to be_confirmed
      expect(action.confirmed_at).to be_a(Time)
      expect(transport.requests.map(&:method)).to eq [:post]
    end

    it 'accepts a callable transport and a block' do
      seen = []
      action = action_for

      action.confirm!(->(request) { seen << request.method })
      expect(seen).to eq [:post]

      expect { action_for.confirm { |request| request.method } }.not_to raise_error
    end

    it 'refuses confirmation without a transport' do
      expect { action_for.confirm!(nil) }.to raise_error(Mail::Unsubscribe::TransportRequiredError)
    end

    it 'refuses a transport that cannot post' do
      expect { action_for.confirm!(Object.new) }.to raise_error(Mail::Unsubscribe::InvalidTransportError)
    end

    it 'refuses to confirm twice' do
      action = action_for
      action.confirm!(RecordingTransport.new)

      expect { action.confirm!(RecordingTransport.new) }.to raise_error(Mail::Unsubscribe::AlreadyConfirmedError)
    end
  end

  describe 'no I/O before confirmation' do
    it 'does not call a transport when the action is parsed or inspected' do
      transport = RecordingTransport.new
      action = Mail.new("List-Unsubscribe: <https://example.com/u>\r\n" \
                        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\r\n")
                   .unsubscribe_action(evidence)

      action.to_h
      action.request
      action.pending?

      expect(transport.requests).to be_empty
      expect(action).to be_pending
    end

    it 'is unaffected by GET-style prefetch helpers' do
      action = action_for
      expect(URI::HTTPS).not_to receive(:open)
      expect(Net::HTTP).not_to receive(:get)
      expect(Net::HTTP).not_to receive(:post)
      expect(Net::HTTP).not_to receive(:start)

      action.to_h
      expect(action).to be_pending
    end
  end

  describe 'forged unprotected headers' do
    it 'cannot replace the protected target with a trailing duplicate' do
      headers = "List-Unsubscribe: <https://example.com/protected>\r\n" \
                "List-Unsubscribe: <https://evil.example/forged>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
      mail = message(headers)

      # A verifier that only reports the bare name must not have its
      # coverage stretched across both same-name fields.
      expect(mail.unsubscribe_action(evidence(%w[List-Unsubscribe List-Unsubscribe-Post]))).to be_nil

      # Even with an explicit instance selector, only that instance is used.
      action = mail.unsubscribe_action(evidence(['List-Unsubscribe:1', 'List-Unsubscribe-Post:0']))
      expect(action.target.to_s).to eq 'https://example.com/protected'
      expect(action.request.uri.to_s).not_to include 'evil.example'
    end

    it 'cannot add one-click capability with an appended post header' do
      headers = "List-Unsubscribe: <https://example.com/protected>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

      expect(message(headers).unsubscribe_action(evidence)).to be_nil
    end

    it 'cannot use an unsigned target for a signature that covers another field' do
      headers = "List-Unsubscribe: <https://evil.example/forged>\r\n" \
                "List-Unsubscribe: <https://example.com/protected>\r\n" \
                "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"

      expect(message(headers).unsubscribe_action(evidence(%w[Subject List-Unsubscribe-Post]))).to be_nil
      expect(message(headers).unsubscribe_action(evidence)).to be_nil
    end
  end
end

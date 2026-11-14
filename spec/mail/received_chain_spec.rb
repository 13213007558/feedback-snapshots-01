# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::ReceivedChain do
  def chain_for(raw, options = {})
    Mail::ReceivedChain.new(Mail.new(raw), options)
  end

  def hop(index, from: 'a.example', by: 'b.example', protocol: 'ESMTP',
          timestamp: 'Tue, 10 May 2005 17:26:50 +0000', id: nil, extra: nil)
    parts = ["from #{from}", "by #{by}", "with #{protocol}"]
    parts << "id #{id}" if id
    parts << extra if extra
    "Received: #{parts.join(' ')}; #{timestamp}"
  end

  def message(*hops, body: 'nothing here')
    (hops + ["Subject: trace", "From: sender@example.com", "To: rcpt@example.com"]).join("\r\n") + "\r\n\r\n#{body}\r\n"
  end

  describe 'raw order' do
    it 'keeps header order even when timestamps are descending' do
      raw = message(
        hop(0, from: 'newest.example', by: 'mx.example', timestamp: 'Tue, 10 May 2005 18:00:00 +0000'),
        hop(1, from: 'middle.example', by: 'newest.example', timestamp: 'Tue, 10 May 2005 17:30:00 +0000'),
        hop(2, from: 'oldest.example', by: 'middle.example', timestamp: 'Tue, 10 May 2005 17:00:00 +0000')
      )
      chain = chain_for(raw)

      expect(chain.size).to eq 3
      expect(chain.raw_order).to eq [0, 1, 2]
      expect(chain.map { |entry| entry.from.host }).to eq ['newest.example', 'middle.example', 'oldest.example']
      expect(chain.conclusions.map { |entry| entry['value'] }.first(3)).to eq ['mx.example', 'newest.example', '2005-05-10T18:00:00Z']
    end

    it 'does not repair a reversed chain by sorting on time' do
      raw = message(
        hop(0, from: 'c.example', by: 'd.example', timestamp: 'Tue, 10 May 2005 17:00:00 +0000'),
        hop(1, from: 'a.example', by: 'b.example', timestamp: 'Tue, 10 May 2005 18:00:00 +0000')
      )
      chain = chain_for(raw)

      expect(chain.raw_order).to eq [0, 1]
      expect(chain.hops.map { |entry| entry.timestamp.utc.iso8601 }).to eq [
        '2005-05-10T17:00:00Z', '2005-05-10T18:00:00Z'
      ]
      expect(chain.time_ordering.first['status']).to eq 'time_reversal'
      expect(chain.time_anomalies.map { |entry| entry['kind'] }).to include 'time_reversal'
    end

    it 'tracks the position of each hop both in Received order and in the raw header' do
      raw = "Subject: s\r\n#{hop(0, from: 'first.example')}\r\nX-Note: n\r\n#{hop(1, from: 'second.example')}\r\n\r\nbody"
      chain = chain_for(raw)

      expect(chain.hops.map(&:index)).to eq [0, 1]
      expect(chain.hops.map(&:field_index)).to eq [0, 1]
      expect(chain.hops.map(&:raw_index)).to eq [1, 3]
    end
  end

  describe 'raw evidence' do
    it 'keeps the original field text, a digest, and marks it as preserved' do
      field = 'Received: from a.example (a.example [192.0.2.1]) by b.example with ESMTP id X1; Tue, 10 May 2005 17:26:50 +0000'
      chain = chain_for(message(field))

      hop = chain.first
      expect(hop.raw_field).to eq field
      expect(hop.raw_preserved).to be true
      expect(hop.raw_sha256).to eq Digest::SHA256.hexdigest(field)
      expect(hop.value).to eq 'from a.example (a.example [192.0.2.1]) by b.example with ESMTP id X1; Tue, 10 May 2005 17:26:50 +0000'
    end

    it 'exposes structured host, address, protocol, id and time fields' do
      field = hop(0, from: 'a.example', by: 'mx.example', protocol: 'ESMTPS', id: 'ABC123',
                  timestamp: 'Tue, 10 May 2005 17:26:50 -0500 (EST)')
      hop = chain_for(message(field)).first

      expect(hop.from.host).to eq 'a.example'
      expect(hop.from.address).to eq nil
      expect(hop.by.host).to eq 'mx.example'
      expect(hop.protocol).to eq 'esmtps'
      expect(hop.with).to eq 'ESMTPS'
      expect(hop.id).to eq 'ABC123'
      expect(hop.timestamp.raw).to eq 'Tue, 10 May 2005 17:26:50 -0500 (EST)'
      expect(hop.timestamp.utc.iso8601).to eq '2005-05-10T22:26:50Z'
      expect(hop.timestamp.offset_text).to eq '-0500'
      expect(hop.timestamp.zone_label).to eq 'EST'
      expect(hop.timestamp.offset_consistent).to be true
    end

    it 'records comma and bracket address literals without inventing a host' do
      field = 'Received: from [192.0.2.9] (relay.example [198.51.100.7]) by mx.example; Tue, 10 May 2005 17:26:50 +0000'
      hop = chain_for(message(field)).first

      expect(hop.from.host).to eq '192.0.2.9'
      expect(hop.from.address).to eq '192.0.2.9'
      expect(hop.from.address_source).to eq :address_literal
      expect(hop.from.comment_addresses.map(&:address)).to eq ['198.51.100.7']
    end

    it 'does not treat a bracket comment such as [unix socket] as an address' do
      field = 'Received: from acomputer ([unix socket]) by mx.example; Tue, 10 May 2005 17:26:50 +0000'
      hop = chain_for(message(field)).first

      expect(hop.from.host).to eq 'acomputer'
      expect(hop.from.address).to be_nil
      expect(hop.from.comment_addresses.first.ip).to be false
    end

    it 'keeps an unparsable timestamp as evidence instead of dropping the hop' do
      field = 'Received: from a.example by b.example; Mon, 29 Jul 2013 25:12:46 +0900'
      hop = chain_for(message(field)).first

      expect(hop.timestamp.valid?).to be false
      expect(hop.timestamp.error).to include 'invalid date'
      expect(chain_for(message(field)).time_anomalies.map { |entry| entry['kind'] }).to include 'timestamp_invalid'
    end
  end

  describe 'comments and forged hops' do
    it 'keeps a clause-like host inside a comment as a rejected claim, not a hop' do
      field = 'Received: from real.example (real.example [192.0.2.1]) ' \
              '(outer (inner by forged.example [198.51.100.99]) note) ' \
              'by mx.example with ESMTP; Tue, 10 May 2005 17:26:50 +0000'
      chain = chain_for(message(field))

      expect(chain.size).to eq 1
      hop = chain.first
      expect(hop.from.host).to eq 'real.example'
      expect(hop.by.host).to eq 'mx.example'
      expect(hop.comments.map(&:depth)).to include 2
      expect(hop.comments.flat_map(&:claims)).to include(
        hash_including('keyword' => 'by', 'target' => 'forged.example', 'treated_as_hop' => false)
      )
      expect(chain.observations.map { |entry| entry['kind'] }).to include 'comment_clause_claim'
    end

    it 'does not use an address only found in a nested comment as the hop address' do
      field = 'Received: from real.example (real.example [192.0.2.1]) ' \
              '(outer (inner by forged.example [198.51.100.99]) note) ' \
              'by mx.example; Tue, 10 May 2005 17:26:50 +0000'
      hop = chain_for(message(field)).first

      expect(hop.from.address).to eq '192.0.2.1'
      expect(hop.from.address_depth).to eq 1
      expect(hop.from.comment_addresses.map(&:address)).to include '198.51.100.99'
    end

    it 'ignores a Received line in the message body' do
      body = "This is prose.\r\n\r\nReceived: from body.example by body-mx.example; Tue, 10 May 2005 18:00:00 +0000"
      raw = message(hop(0, from: 'header.example', by: 'mx.example'), body: body)
      chain = chain_for(raw)

      expect(chain.size).to eq 1
      expect(chain.first.from.host).to eq 'header.example'
      expect(chain.conclusions.none? { |entry| entry['value'] == 'body.example' }).to be true
    end

    it 'treats a comment-only hop as evidence without a from/by host' do
      raw = message('Received: (qmail 24365 invoked by uid 99); 25 Jan 2011 12:31:11 -0000')
      hop = chain_for(raw).first

      expect(hop.from).to be_nil
      expect(hop.by).to be_nil
      expect(hop.leading).to eq '(qmail 24365 invoked by uid 99)'
      expect(hop.timestamp.offset_meaning).to eq 'unknown'
    end
  end

  describe 'timestamps' do
    it 'compares instants across differing UTC offsets' do
      raw = message(
        hop(0, from: 'b.example', by: 'mx.example', timestamp: 'Tue, 10 May 2005 18:05:00 -0400'),
        hop(1, from: 'a.example', by: 'b.example', timestamp: 'Tue, 10 May 2005 17:00:00 -0500')
      )
      chain = chain_for(raw)

      expect(chain.time_ordering.first['status']).to eq 'consistent_descending'
      expect(chain.observations.map { |entry| entry['kind'] }).to include 'timezone_shift'
      expect(chain.observations.find { |entry| entry['kind'] == 'timezone_shift' }['offset_delta_seconds']).to eq 3600
    end

    it 'flags time going backwards and records a negative travel time' do
      raw = message(
        hop(0, from: 'b.example', by: 'mx.example', timestamp: 'Tue, 10 May 2005 17:00:00 +0000'),
        hop(1, from: 'a.example', by: 'b.example', timestamp: 'Tue, 10 May 2005 18:00:00 +0000')
      )
      chain = chain_for(raw)

      expect(chain.time_ordering.first['status']).to eq 'time_reversal'
      expect(chain.hop_travel.first['elapsed_seconds']).to eq(-3600)
      expect(chain.time_anomalies.map { |entry| entry['kind'] }).to include 'negative_travel_time'
    end

    it 'does not compare timestamps with an unknown -0000 offset' do
      raw = message(
        hop(0, from: 'b.example', by: 'mx.example', timestamp: 'Tue, 10 May 2005 17:00:00 +0000'),
        hop(1, from: 'a.example', by: 'b.example', timestamp: 'Tue, 10 May 2005 18:00:00 -0000')
      )
      chain = chain_for(raw)

      expect(chain.hops[1].timestamp.offset_meaning).to eq 'unknown'
      expect(chain.hops[1].timestamp_comparable?).to be false
      expect(chain.time_ordering.first['status']).to eq 'not_comparable'
      expect(chain.time_anomalies.map { |entry| entry['kind'] }).to include 'offset_unknown'
    end

    it 'does not treat an unknown alphabetic zone as a comparable instant' do
      raw = message(hop(0, timestamp: 'Tue, 10 May 2005 17:00:00 XYZ'))
      chain = chain_for(raw)

      expect(chain.first.timestamp.offset_meaning).to eq 'unrecognized_zone'
      expect(chain.first.timestamp.comparable).to be false
      expect(chain.time_anomalies.map { |entry| entry['kind'] }).to include 'offset_unrecognized'
    end

    it 'flags a numeric offset that contradicts its zone label' do
      raw = message(hop(0, timestamp: 'Tue, 10 May 2005 17:00:00 -0500 (EDT)'))
      chain = chain_for(raw)

      expect(chain.first.timestamp.offset_consistent).to be false
      expect(chain.time_anomalies.map { |entry| entry['kind'] }).to include 'offset_label_mismatch'
    end

    it 'annotates but never reorders using a derived chronological view' do
      raw = message(
        hop(0, from: 'late.example', by: 'mx.example', timestamp: 'Tue, 10 May 2005 19:00:00 +0000'),
        hop(1, from: 'early.example', by: 'late.example', timestamp: 'Tue, 10 May 2005 18:00:00 +0000')
      )
      chain = chain_for(raw)
      chronological = chain.chronological_order

      expect(chronological['annotation_only']).to be true
      expect(chronological['order'].map { |entry| entry['index'] }).to eq [1, 0]
      expect(chain.raw_order).to eq [0, 1]
    end
  end

  describe 'trust boundary' do
    let(:raw) do
      message(
        hop(0, from: 'edge.example', by: 'mx.corp.example', timestamp: 'Tue, 10 May 2005 18:00:00 +0000'),
        hop(1, from: 'relay.example', by: 'edge.example', timestamp: 'Tue, 10 May 2005 17:50:00 +0000'),
        hop(2, from: 'workstation.example', by: 'relay.example', timestamp: 'Tue, 10 May 2005 17:40:00 +0000')
      )
    end

    it 'treats every hop as self-asserted without a boundary' do
      chain = chain_for(raw)

      expect(chain.trusted_hops).to be_empty
      expect(chain.self_asserted_hops.size).to eq 3
      expect(chain.trust_summary['boundary']['method']).to eq 'none'
      expect(chain.conclusions.map { |entry| entry['evidence'] }.uniq).to eq ['mail_self_report']
    end

    it 'marks the matching receiver and the hops above it as trusted' do
      chain = chain_for(raw, trusted_receivers: ['mx.corp.example'])

      expect(chain.trusted_boundary).to eq 0
      expect(chain.trusted_hops.map(&:index)).to eq [0]
      expect(chain.self_asserted_hops.map(&:index)).to eq [1, 2]
      expect(chain.first.evidence).to eq 'trusted_source'
    end

    it 'trusts a hop named by its by clause even if it appears further down' do
      chain = chain_for(raw, trusted_receivers: ['edge.example'])

      expect(chain.trusted_boundary).to eq 1
      expect(chain.trusted_hops.map(&:index)).to eq [0, 1]
      expect(chain.hops[1].trust).to eq :trusted
      expect(chain.hops[2].trust).to eq :self_asserted
    end

    it 'accepts an explicit boundary index' do
      chain = chain_for(raw, trusted_boundary: 1)

      expect(chain.trust_summary['boundary']['method']).to eq 'explicit_index'
      expect(chain.trusted_hops.map(&:index)).to eq [0, 1]
    end

    it 'does not trust anything when the boundary cannot be resolved' do
      chain = chain_for(raw, trusted_receivers: ['unknown.example'])

      expect(chain.trusted_hops).to be_empty
      expect(chain.trust_summary['boundary']['note']).to include 'None of the trusted receivers'
    end

    it 'labels conclusions by source, keeping from-clause peer claims distinct' do
      chain = chain_for(raw, trusted_receivers: ['mx.corp.example'])
      trusted_hop = chain.conclusions.select { |entry| entry['hop'] == 0 }

      expect(trusted_hop.find { |entry| entry['subject'] == 'by' }['evidence']).to eq 'trusted_source'
      expect(trusted_hop.find { |entry| entry['subject'] == 'from' }['evidence']).to eq 'trusted_observation'
      expect(chain.conclusions.select { |entry| entry['hop'] == 2 }.map { |entry| entry['evidence'] }.uniq).to eq ['mail_self_report']
    end

    it 'marks mixed edges when only one side is trusted' do
      raw = message(
        hop(0, from: 'b.example', by: 'mx.example', timestamp: 'Tue, 10 May 2005 17:00:00 +0000'),
        hop(1, from: 'a.example', by: 'b.example', timestamp: 'Tue, 10 May 2005 18:00:00 +0000')
      )
      chain = chain_for(raw, trusted_receivers: ['mx.example'])

      expect(chain.time_ordering.first['evidence']).to eq 'mixed'
    end
  end

  describe 'integration points' do
    it 'is available from Message#received_chain without changing #received' do
      raw = message(hop(0)) + message(hop(0))
      mail = Mail.new(raw)

      expect(mail.received_chain).to be_a Mail::ReceivedChain
      expect(mail.received).to be_a Mail::Field
      expect(mail.received.field).to be_a Mail::ReceivedField
      expect(mail.received_chain.first.raw_field).to include 'Received: from a.example'
    end

    it 'works on a bare Mail::Header' do
      header = Mail::Header.new(hop(0))
      expect(header.received_chain.size).to eq 1
    end

    it 'accepts a raw message string' do
      expect(Mail::ReceivedChain.new(message(hop(0))).size).to eq 1
    end

    it 'includes a programmatically added Received field but marks it as not raw' do
      mail = Mail.new("Subject: s\r\n\r\nbody")
      mail.received = 'from added.example by mx.example; Tue, 10 May 2005 17:26:50 +0000'

      expect(mail.received_chain.size).to eq 1
      expect(mail.received_chain.first.raw_preserved).to be false
      expect(mail.received_chain.first.from.host).to eq 'added.example'
    end

    it 'serializes the whole evidence set with to_h' do
      chain = chain_for(message(hop(0, by: 'mx.example')), trusted_receivers: ['mx.example'])
      hash = chain.to_h

      expect(hash.keys).to include('hop_count', 'raw_order', 'trust', 'conclusions', 'time_ordering', 'time_anomalies', 'observations')
      expect(hash['raw_order'].first.keys).to include('raw_field', 'from', 'by', 'protocol', 'timestamp', 'trust')
      expect(hash['raw_order'].first['from']['evidence']).to eq 'trusted_observation'
    end
  end

  describe 'fixture analysis' do
    it 'analyses the mixed fixture without repairing order or trusting body text' do
      mail = Mail.read(fixture_path('emails', 'received_chain', 'forensic_sample.eml'))
      chain = Mail::ReceivedChain.new(mail, trusted_receivers: ['edge-a.example'])

      expect(chain.size).to eq 4
      expect(chain.map { |hop| hop.from.host }).to eq [
        'edge-a.example', 'relay-b.example', 'workstation.example', 'gateway.example'
      ]
      expect(chain.trusted_hops.map(&:index)).to eq [0, 1]
      expect(chain.observations.map { |entry| entry['kind'] }).to include 'timezone_shift', 'nested_comment_address_unused'
      expect(chain.conclusions.none? { |entry| entry['value'] == 'body-forged.example' }).to be true
      expect(chain.time_anomalies.count { |entry| entry['kind'] == 'time_reversal' }).to eq 2
      expect(chain.hop_travel.map { |entry| entry['elapsed_seconds'] }).to eq [-2700, -2400, 12600]
    end
  end
end

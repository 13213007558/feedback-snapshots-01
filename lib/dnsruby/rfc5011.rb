# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require 'base64'
require 'digest'
require 'fileutils'
require 'json'
require 'tempfile'

module Dnsruby
  # Optional RFC 5011 automated trust-anchor update for one or more DNSKEY
  # trust points.
  #
  # A manager keeps its own set of accepted anchors. These are published to a
  # SingleVerifier through the managed-anchor API and are deliberately kept
  # separate from anchors added with Dnssec.add_trust_anchor. A key first seen
  # in a DNSKEY RRSet is only a candidate: it remains in AddPend until a later
  # authenticated observation at or after its hold-down deadline. The manager
  # never treats an observation as authenticated unless an existing configured
  # or previously accepted key validates the DNSKEY RRSet.
  #
  # State may be persisted with +store_path+. Timers are stored as absolute
  # timestamps, so an AddPend, Missing, Revoked, or Removed transition continues
  # from the same point after a process restart. A pending key is never promoted
  # merely because its deadline elapsed while the process was down; a new
  # authenticated observation is required. +clock+ may be any object with a #now
  # method (including the bundled Rfc5011::Clock), or a callable. Each
  # observation may also supply +at:+ for deterministic testing.
  class Rfc5011
    STATE_START = 'Start'.freeze
    STATE_ADD_PENDING = 'AddPend'.freeze
    STATE_VALID = 'Valid'.freeze
    STATE_MISSING = 'Missing'.freeze
    STATE_REVOKED = 'Revoked'.freeze
    STATE_REMOVED = 'Removed'.freeze

    DEFAULT_ADD_HOLD_DOWN = 30 * 24 * 60 * 60
    DEFAULT_REMOVE_HOLD_DOWN = 30 * 24 * 60 * 60
    STATE_VERSION = 1
    ANCHOR_EXPIRATION = Time.utc(9999, 12, 31, 23, 59, 59).to_i

    # Small explicitly advanceable clock for deterministic callers and tests.
    class Clock
      def initialize(time = Time.now)
        @time = time
        @mutex = Mutex.new
      end

      def now
        @mutex.synchronize { @time }
      end

      def advance(seconds)
        @mutex.synchronize { @time += seconds }
        self
      end

      def set(time)
        @mutex.synchronize { @time = time }
        self
      end
    end

    class StateError < StandardError; end
    class AuthenticationError < StandardError; end

    attr_reader :store_path, :clock, :verifier

    # Options:
    # * +store_path+ - JSON file for atomic persistence (optional).
    # * +verifier+ - SingleVerifier that supplies existing trust and receives
    #   accepted managed anchors.
    # * +clock+ - Time-like object responding to #now, or a callable (default Time).
    # * +add_hold_down+ / +remove_hold_down+ - explicit policy overrides in
    #   seconds. The RFC defaults are 30 days; an accepted addition also waits at
    #   least the DNSKEY RRSet's Original TTL.
    def initialize(store_path: nil, verifier: nil, clock: Time,
                   add_hold_down: nil, remove_hold_down: nil)
      @store_path = store_path && File.expand_path(store_path)
      @verifier = verifier
      @clock = clock || Time
      @add_hold_down = positive_seconds(add_hold_down, 'add_hold_down')
      @remove_hold_down = positive_seconds(remove_hold_down, 'remove_hold_down')
      @mutex = Mutex.new
      @trust_points = {}
      reload if @store_path && File.exist?(@store_path)
      @mutex.synchronize { publish_accepted_anchors }
    end

    # Attach or replace the verifier that supplies existing trust and receives
    # accepted anchors. This does not promote a pending key.
    def verifier=(verifier)
      @mutex.synchronize do
        @verifier = verifier
        publish_accepted_anchors
      end
    end

    # Current time according to the configured clock, as an Integer.
    def now
      timestamp(@clock.respond_to?(:now) ? @clock.now : @clock.call)
    end

    # Reload persisted state. Absolute deadlines are retained; no pending key is
    # promoted just because its deadline passed while the process was down.
    def reload
      @mutex.synchronize do
        @trust_points = {}
        load_state if @store_path && File.exist?(@store_path)
        publish_accepted_anchors
      end
      self
    end

    def save
      @mutex.synchronize { persist_state }
      self
    end

    # Observe a DNSKEY RRSet or a Message containing exactly one DNSKEY RRSet.
    # The observation is authenticated by an isolated view of the verifier's
    # existing configured, learned, and managed trust. Unauthenticated input
    # returns false and does not alter in-memory or persisted state.
    #
    # A valid self-signature by a revoked key is sufficient only for that key's
    # revocation transition; it cannot add keys or advance unrelated state.
    def observe(observation, at: nil, verifier: nil)
      rrset = dnskey_rrset(observation)
      return false unless rrset
      source = verifier || @verifier
      return false unless source

      observation_time = timestamp(at || now)
      @mutex.synchronize do
        view = isolated_verifier(source)
        authenticated = authenticated_observation?(rrset, view, observation_time)
        revoked = revoked_identities(rrset, view, observation_time)
        return false unless authenticated || !revoked.empty?

        validators = authenticated ? validating_signer_identities(rrset, view, observation_time) : []
        changed = apply_observation(rrset, observation_time, authenticated,
                                    revoked, validators, source)
        persist_state if changed
        true
      end
    end
    alias observe_dnskey_rrset observe
    alias process observe

    # State for a DNSKEY record, or for a key at a trust point.
    def state(key_or_name, key = nil)
      @mutex.synchronize do
        if key_or_name.is_a?(RR::DNSKEY)
          record = record_for_key(key_or_name)
          record && record['state']
        else
          tp = @trust_points[canonical_name(key_or_name)]
          return nil unless tp
          if key
            record = tp['keys'][self.class.identity_without_revocation(key)]
            record && record['state']
          else
            tp['keys'].values.map { |record| record['state'] }
          end
        end
      end
    end

    def state_for(key)
      state(key)
    end

    # Public state records, without trust-anchor key material.
    def records(name = nil)
      @mutex.synchronize do
        names = name ? [canonical_name(name)] : @trust_points.keys
        names.filter_map { |tp_name| @trust_points[tp_name] }.flat_map do |tp|
          tp['keys'].values.map do |record|
            {
              name: record['name'],
              key_tag: record['key_tag'],
              pre_revoked_key_tag: record['pre_revoked_key_tag'],
              state: record['state'],
              first_seen: record['first_seen'],
              hold_until: record['hold_until'],
              missing_since: record['missing_since']
            }
          end
        end
      end
    end

    def pending_keys(name = nil)
      keys_in_states([STATE_ADD_PENDING], name)
    end

    # Accepted anchors, including Valid keys temporarily absent from the last
    # authenticated observation. AddPend, Revoked, and Removed are excluded.
    def trust_anchors(name = nil)
      keys_in_states([STATE_VALID, STATE_MISSING], name)
    end
    alias managed_trust_anchors trust_anchors

    def configured_anchors(name = nil)
      @mutex.synchronize do
        return [] unless @verifier
        @verifier.trust_anchors.select do |anchor|
          anchor.type == Types.DNSKEY &&
            !managed_identity?(anchor) &&
            (!name || anchor.name.canonical == Name.create(name).canonical)
        end
      end
    end

    # Remove an accepted managed anchor. The state record is retained so RFC
    # 5011 revocation and restart behavior remain coherent.
    def remove_managed_anchor(key)
      time = timestamp(now)
      @mutex.synchronize do
        record = record_for_key(key)
        return nil unless record
        record['state'] = STATE_REVOKED
        record['missing_since'] = time
        record['validators'] = []
        @verifier.remove_managed_trust_anchor(key_from_record(record)) if @verifier
        persist_state
        true
      end
    end

    # Seed an RFC 5011-managed valid anchor out of band. This is the only path
    # that bypasses the add hold-down; use it for an initial trusted key or
    # after manual recovery. The seed is recorded as Valid so restart and
    # revocation processing can continue from a durable identity.
    def add_trust_anchor(key, at: nil)
      add_trust_anchors([key], at: at)
    end

    def add_trust_anchors(keys, at: nil)
      time = timestamp(at || now)
      list = keys.respond_to?(:rrs) ? keys.rrs : Array(keys)
      list.each do |key|
        unless key.is_a?(RR::DNSKEY) && key.zone_key? && !key.revoked?
          raise ArgumentError, 'RFC 5011 trust anchors must be unrevoked zone DNSKEYs'
        end
      end
      @mutex.synchronize do
        list.each do |key|
          identity = self.class.identity_without_revocation(key)
          record = new_valid_record(key, time)
          trust_point(key.name)['keys'][identity] = record
        end
        publish_accepted_anchors
        persist_state
      end
      self
    end

    def new_valid_record(key, time)
      {
        'name' => canonical_name(key.name),
        'klass' => key.klass.code,
        'flags' => key.flags,
        'protocol' => key.protocol,
        'algorithm' => key.algorithm.code,
        'key' => Base64.strict_encode64(key.key),
        'key_tag' => key.key_tag,
        'pre_revoked_key_tag' => key.key_tag_pre_revoked,
        'state' => STATE_VALID,
        'first_seen' => time,
        'hold_until' => nil,
        'missing_since' => nil,
        'validators' => []
      }
    end

    def self.key_identity(key)
      name_data = MessageEncoder.new { |encoder| encoder.put_name(key.name, true) }.to_s
      rdata = [key.klass.code, key.flags, key.protocol, key.algorithm.code].pack('nCCC') + key.key
      Digest::SHA256.hexdigest(name_data + rdata)
    end
    def self.identity_without_revocation(key)
      key.revoked? ? key_identity(without_revocation_flag(key)) : key_identity(key)
    end

    def self.without_revocation_flag(key)
      copy = key.clone
      copy.revoked = false
      copy
    end

    private

    def positive_seconds(value, name)
      return nil if value.nil?
      raise ArgumentError, "#{name} must be a positive number" unless value.is_a?(Numeric) && value.positive?
      value
    end

    def timestamp(value)
      value.respond_to?(:to_i) ? value.to_i : Integer(value)
    end

    def dnskey_rrset(observation)
      if observation.is_a?(RRSet)
        return observation.type == Types.DNSKEY ? observation : nil
      end
      return nil unless observation.is_a?(Message)

      rrsets = observation.answer.rrsets(Types.DNSKEY)
      rrsets = observation.authority.rrsets(Types.DNSKEY) if rrsets.empty?
      rrsets = observation.additional.rrsets(Types.DNSKEY) if rrsets.empty?
      rrsets.length == 1 ? rrsets.first : nil
    end

    def canonical_name(name)
      value = Name.create(name).downcase
      value.to_s == '' ? '.' : value.to_s
    end

    def record_for_key(key)
      tp = @trust_points[canonical_name(key.name)]
      tp && tp['keys'][self.class.identity_without_revocation(key)]
    end

    # Verification is performed in an isolated verifier so authentication can
    # reuse the normal DNSSEC code without publishing anything from an attacker
    # observation into the caller's cache.
    def isolated_verifier(source)
      view = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)
      anchors = source.trust_anchors + source.managed_trust_anchors + source.trusted_keys
      anchors.each do |anchor|
        case anchor.type
        when Types.DNSKEY
          view.add_trust_anchor_with_expiration(anchor, ANCHOR_EXPIRATION)
        when Types.DS, Types.DLV
          view.add_trust_anchor(anchor)
        end
      end
      view
    end

    def authenticated_observation?(rrset, view, at)
      trusted = trusted_signer_identities(rrset, view)
      return false if trusted.empty?
      rrset.sigs.any? do |signature|
        next false unless signature_valid_for?(rrset, signature, at)
        signer = rrset.rrs.find do |candidate|
          !candidate.revoked? &&
            candidate.key_tag == signature.key_tag &&
            candidate.algorithm == signature.algorithm &&
            candidate.name.canonical == signature.signers_name.canonical
        end
        next false unless signer && trusted[self.class.identity_without_revocation(signer)]
        begin
          view.verify_rrset_signature(rrset, signer, signature, at: at)
          true
        rescue VerifyError, OpenSSL::OpenSSLError
          false
        end
      end
    end

    # DNSKEYs admitted as existing trust for this observation: configured or
    # managed DNSKEY anchors, previously learned DNSKEYs, and DNSKEYs matching a
    # configured DS/DLV anchor. A DS-derived signer is trusted only when its
    # signature actually validates the supplied RRSet (checked by the caller).
    def trusted_signer_identities(rrset, view)
      identities = {}
      view.get_keys_to_check.each do |key|
        identities[self.class.identity_without_revocation(key)] = true if key.type == Types.DNSKEY
      end
      view.trust_anchors.each do |anchor|
        case anchor.type
        when Types.DNSKEY
          identities[self.class.identity_without_revocation(anchor)] = true
        when Types.DS, Types.DLV
          rrset.rrs.each do |candidate|
            next if candidate.revoked? || !candidate.zone_key?
            identities[self.class.identity_without_revocation(candidate)] = true if anchor.check_key(candidate)
          end
        end
      end
      identities
    end

    def signature_valid_for?(rrset, signature, at)
      rrset.name.canonical == signature.name.canonical &&
        rrset.klass == signature.klass &&
        signature.type_covered == Types.DNSKEY &&
        signature.inception <= at && signature.expiration >= at
    end

    def revoked_identities(rrset, view, at)
      rrset.rrs.filter_map do |candidate|
        next unless candidate.revoked?
        identity = self.class.identity_without_revocation(candidate)
        record = @trust_points.dig(canonical_name(rrset.name), 'keys', identity)
        next unless record && [STATE_VALID, STATE_MISSING].include?(record['state'])
        signatures = rrset.sigs.select do |signature|
          signature_valid_for?(rrset, signature, at) &&
            signature.key_tag == candidate.key_tag &&
            signature.algorithm == candidate.algorithm &&
            signature.signers_name.canonical == candidate.name.canonical
        end
        verified = signatures.any? do |signature|
          begin
            view.verify_rrset_signature(rrset, candidate, signature, at: at)
          rescue VerifyError, OpenSSL::OpenSSLError
            false
          end
        end
        verified ? identity : nil
      end.uniq
    end

    def validating_signer_identities(rrset, view, at)
      rrset.sigs.filter_map do |signature|
        next unless signature_valid_for?(rrset, signature, at)
        signer = rrset.rrs.find do |candidate|
          !candidate.revoked? &&
            candidate.key_tag == signature.key_tag &&
            candidate.algorithm == signature.algorithm &&
            candidate.name.canonical == signature.signers_name.canonical
        end
        next unless signer
        begin
          view.verify_rrset_signature(rrset, signer, signature, at: at)
          self.class.identity_without_revocation(signer)
        rescue VerifyError, OpenSSL::OpenSSLError
          nil
        end
      end.uniq
    end

    def apply_observation(rrset, at, authenticated, revoked_ids, validators, source)
      tp = trust_point(rrset.name)
      changed = false
      present = {}
      revoked_present = {}
      rrset.rrs.each do |candidate|
        if candidate.revoked?
          revoked_present[self.class.identity_without_revocation(candidate)] = candidate
        else
          present[self.class.identity_without_revocation(candidate)] = candidate
        end
      end
      revoked = revoked_ids.each_with_object({}) { |identity, hash| hash[identity] = true }

      tp['keys'].each do |identity, record|
        case record['state']
        when STATE_VALID, STATE_MISSING
          if revoked[identity]
            record['state'] = STATE_REVOKED
            record['missing_since'] = nil
            record['validators'] = []
            unpublish_managed_anchor(record)
            changed = true
          elsif authenticated
            if present[identity]
              if record['state'] == STATE_MISSING
                record['state'] = STATE_VALID
                record['missing_since'] = nil
                changed = true
              end
              add_managed_anchor(record)
            elsif record['state'] == STATE_VALID
              record['state'] = STATE_MISSING
              record['missing_since'] = at
              changed = true
            end
          end
        when STATE_ADD_PENDING
          original = Array(record['validators'])
          all_revoked = !original.empty? && (original - revoked.keys).empty?
          # Any authenticated observation omitting a pending key cancels the
          # acceptance process. A revoked validator similarly cancels it.
          if all_revoked || (authenticated && !present[identity])
            tp['keys'].delete(identity)
            changed = true
          elsif authenticated && present[identity] && at >= record['hold_until'].to_i
            record['state'] = STATE_VALID
            record['missing_since'] = nil
            record['validators'] = []
            add_managed_anchor(record)
            changed = true
          end
        when STATE_REVOKED
          if revoked_present[identity]
            if record['missing_since']
              record['missing_since'] = nil
              changed = true
            end
          elsif authenticated && present[identity]
            # A revoked key that reappears without the REVOKE bit can never
            # become trusted again. Keep removal state as it is.
            next
          elsif authenticated
            record['missing_since'] ||= at
            changed = true
            if at >= record['missing_since'].to_i + remove_hold_down
              record['state'] = STATE_REMOVED
              record['missing_since'] = nil
              unpublish_managed_anchor(record)
              changed = true
            end
          end
        when STATE_REMOVED
          # A Removed key is a tombstone. RFC 5011 says it must not be treated
          # as a trust anchor; seeing it again does not revive it.
          if authenticated && !present[identity] && !revoked_present[identity]
            tp['keys'].delete(identity)
            changed = true
          end
        end
      end

      if authenticated
        manual = manual_anchor_identities(source)
        present.each do |identity, candidate|
          next if tp['keys'].key?(identity) || manual[identity]
          next unless candidate.zone_key? && candidate.sep_key?
          record = new_record(candidate, identity, at, rrset, validators)
          tp['keys'][identity] = record
          changed = true
        end
      end

      if tp['keys'].empty?
        @trust_points.delete(canonical_name(rrset.name))
      end
      changed
    end

    def trust_point(name)
      canonical = canonical_name(name)
      @trust_points[canonical] ||= { 'name' => canonical, 'keys' => {} }
    end

    def new_record(key, identity, at, rrset, validators)
      {
        'name' => canonical_name(key.name),
        'klass' => key.klass.code,
        'flags' => key.flags,
        'protocol' => key.protocol,
        'algorithm' => key.algorithm.code,
        'key' => Base64.strict_encode64(key.key),
        'key_tag' => key.key_tag,
        'pre_revoked_key_tag' => key.key_tag_pre_revoked,
        'state' => STATE_ADD_PENDING,
        'first_seen' => at,
        'hold_until' => at + add_hold_down(rrset),
        'missing_since' => nil,
        'validators' => validators
      }
    end

    def add_hold_down(rrset)
      return @add_hold_down if @add_hold_down
      original_ttl = rrset.sigs.map { |signature| signature.original_ttl.to_i }.max.to_i
      [DEFAULT_ADD_HOLD_DOWN, original_ttl].max
    end

    def remove_hold_down
      @remove_hold_down || DEFAULT_REMOVE_HOLD_DOWN
    end

    def manual_anchor_identities(source)
      source.trust_anchors.each_with_object({}) do |anchor, identities|
        if anchor.type == Types.DNSKEY && !managed_identity?(anchor)
          identities[self.class.identity_without_revocation(anchor)] = true
        end
      end
    end

    def managed_identity?(key)
      @trust_points.any? do |_name, tp|
        tp['keys'].key?(self.class.identity_without_revocation(key))
      end
    end

    def add_managed_anchor(record)
      @verifier.add_managed_trust_anchor(key_from_record(record)) if @verifier
    end

    def unpublish_managed_anchor(record)
      @verifier.remove_managed_trust_anchor(key_from_record(record)) if @verifier
    end

    def publish_accepted_anchors
      return unless @verifier
      @trust_points.each_value do |tp|
        tp['keys'].each_value do |record|
          case record['state']
          when STATE_VALID, STATE_MISSING
            @verifier.add_managed_trust_anchor(key_from_record(record))
          when STATE_REVOKED, STATE_REMOVED
            @verifier.remove_managed_trust_anchor(key_from_record(record))
          end
        end
      end
    end

    def keys_in_states(states, name)
      @mutex.synchronize do
        names = name ? [canonical_name(name)] : @trust_points.keys
        names.filter_map { |tp_name| @trust_points[tp_name] }.flat_map do |tp|
          tp['keys'].values.select { |record| states.include?(record['state']) }
            .map { |record| key_from_record(record) }
        end
      end
    end

    def key_from_record(record)
      RR.create(name: record['name'], type: Types.DNSKEY, ttl: 0,
                klass: Integer(record.fetch('klass', Classes::IN)),
                flags: Integer(record['flags']),
                protocol: Integer(record['protocol']),
                algorithm: Integer(record['algorithm']),
                key: Base64.strict_encode64(Base64.strict_decode64(record['key'])))
    rescue StandardError => error
      raise StateError, "Invalid persisted RFC 5011 key: #{error.message}"
    end

    def load_state
      data = JSON.parse(File.read(@store_path))
      unless data.is_a?(Hash) && data['version'].to_i == STATE_VERSION &&
             data['trust_points'].is_a?(Array)
        raise StateError, "Unsupported RFC 5011 state file #{@store_path}"
      end

      loaded = {}
      data['trust_points'].each do |tp|
        unless tp.is_a?(Hash) && tp['name'].is_a?(String) && tp['keys'].is_a?(Array)
          raise StateError, "Malformed RFC 5011 trust point in #{@store_path}"
        end
        name = canonical_name(tp['name'])
        keys = {}
        tp['keys'].each do |record|
          unless record.is_a?(Hash) && record['identity'].is_a?(String)
            raise StateError, "Malformed RFC 5011 key record in #{@store_path}"
          end
          key = key_from_record(record)
          identity = self.class.key_identity(key)
          unless identity == record['identity']
            raise StateError, "RFC 5011 key identity mismatch in #{@store_path}"
          end
          record = record.merge(
            'name' => name,
            'first_seen' => Integer(record['first_seen']),
            'hold_until' => record['hold_until'] && Integer(record['hold_until']),
            'missing_since' => record['missing_since'] && Integer(record['missing_since']),
            'key_tag' => Integer(record['key_tag']),
            'pre_revoked_key_tag' => Integer(record['pre_revoked_key_tag']),
            'validators' => Array(record['validators']).map(&:to_s)
          )
          keys[identity] = record
        end
        loaded[name] = { 'name' => name, 'keys' => keys }
      end
      @trust_points = loaded
    rescue JSON::ParserError, ArgumentError, TypeError => error
      raise StateError, "Invalid RFC 5011 state file #{@store_path}: #{error.message}"
    end

    def persist_state
      return unless @store_path
      directory = File.dirname(@store_path)
      FileUtils.mkdir_p(directory)
      serialized = {
        'version' => STATE_VERSION,
        'trust_points' => @trust_points.keys.sort.map do |name|
          tp = @trust_points[name]
          {
            'name' => name,
            'keys' => tp['keys'].keys.sort.map do |identity|
              tp['keys'][identity].merge('identity' => identity)
            end
          }
        end
      }
      Tempfile.create(['.rfc5011-', '.tmp'], directory) do |file|
        file.chmod(0600)
        file.write(JSON.pretty_generate(serialized))
        file.flush
        file.fsync
        file.close
        File.rename(file.path, @store_path)
      end
    end
  end

  RFC5011 = Rfc5011
  Rfc5011Manager = Rfc5011
end

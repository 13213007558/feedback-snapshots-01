# frozen_string_literal: true

require "monitor"

module Doorkeeper
  module OpenidConnect
    # Holds the signing-key generations for an issuer and drives their rotation.
    #
    # A key moves through two phases. `prepare` validates a candidate and parks
    # it in a private pending slot that no public surface (discovery, JWKS or
    # the signing entry point) can read. `commit` is the only state transition
    # that publishes a key: it persists a snapshot first and only swaps the
    # active generation when persistence succeeds, so a failed validation or a
    # failed write leaves every reader on the previous, still-usable
    # configuration. All state is guarded by a Monitor, so a token issued
    # across the commit boundary is always signed by exactly one generation and
    # that generation is identifiable through its `kid` (see `generation_for`).
    class KeyRing
      autoload :Entry, "doorkeeper/openid_connect/key_ring/entry"

      # A no-op persistence backend. Rotation still performs the full
      # validate-then-swap sequence; the "write" simply succeeds.
      module NullPersister
        def self.call(_snapshot); end
      end

      # @param entries [Array<Hash>] normalized `{ key: }` entries, active first
      # @param builder [#call] turns a normalized entry into a `JWT::JWK`
      # @param persister [#call, nil] receives a snapshot Hash before each commit
      MISSING_KEY = "doorkeeper.openid_connect.errors.messages.signing_key_not_configured"
      private_constant :MISSING_KEY

      def initialize(entries:, builder:, persister: nil)
        if entries.empty?
          raise Errors::InvalidConfiguration, I18n.translate(MISSING_KEY)
        end

        @builder = builder
        @persister = persister || NullPersister
        @monitor = Monitor.new
        normalized = entries.map { |entry| normalize(entry) }
        # Preserve declaration order: the first entry is the active signing key.
        # Number generations from the oldest (last entry) upward so a newer key
        # always carries a higher generation number.
        @entries = normalized.each_with_index.map do |raw, index|
          Entry.new(normalized.size - 1 - index, raw, @builder)
        end
        @sequence = normalized.size
        @pending = nil
      end

      # The entry that signs newly issued ID tokens.
      def active_entry
        synchronize { @entries.first }
      end

      # Every published entry, active first. The pending candidate is excluded:
      # a key that has not been committed must not appear in the JWKS.
      def published_entries
        synchronize { @entries.dup }
      end

      # The generation a token was signed with, resolved from its JWS `kid`.
      # Returns nil for an unknown `kid` (e.g. a key already removed).
      def generation_for(kid)
        synchronize do
          @entries.find { |entry| entry.kid == kid }&.generation
        end
      end

      def pending?
        synchronize { !@pending.nil? }
      end

      def pending_entry
        synchronize { @pending }
      end

      # Validates a candidate and parks it as pending. Building the JWK here is
      # the validation step: an unparseable key raises and never reaches the
      # pending slot, leaving the active configuration untouched.
      def prepare(raw)
        candidate = Entry.new(@sequence, normalize(raw), @builder)
        candidate.jwk # force validation before any state change
        synchronize { @pending = candidate }
        candidate
      end

      # Publishes the pending key. The persistence snapshot is written before
      # the swap; a raising persister aborts the commit and leaves the prior
      # generation active, so discovery/JWKS/signing stay on the old config.
      def commit
        synchronize do
          raise Errors::InvalidConfiguration, "no pending signing key to commit" if @pending.nil?

          @persister.call(snapshot)
          @entries = [@pending, *@entries]
          @sequence += 1
          committed = @pending
          @pending = nil
          committed
        end
      end

      # Discards the pending candidate without touching the active generation.
      def rollback
        synchronize { rolled_back = @pending; @pending = nil; rolled_back }
      end

      # Serializable view of the ring, handed to the persister and used by the
      # discovery/JWKS layers and tests. Pending is reported separately and is
      # never part of `generations`.
      def snapshot
        synchronize do
          {
            active_generation: @entries.first.generation,
            generations: @entries.map { |entry| entry_summary(entry) },
            pending: @pending ? entry_summary(@pending) : nil,
          }
        end
      end

      # Allows tests and operational tooling to substitute a persister that
      # simulates a write failure.
      def persister=(persister)
        synchronize { @persister = persister || NullPersister }
      end

      private

      # Canonicalizes a raw configuration entry: a bare key value (a PEM
      # string for asymmetric algorithms or a shared secret for HMAC) is wrapped
      # into the `{ key: }` shape the builder expects, while a per-key options
      # Hash passes through unchanged.
      def normalize(entry)
        entry.is_a?(Hash) ? entry : { key: entry }
      end

      def entry_summary(entry)
        { generation: entry.generation, kid: entry.kid, kty: entry.export[:kty] }
      end

      def synchronize(&block)
        @monitor.synchronize(&block)
      end
    end
  end
end

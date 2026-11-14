require 'net/ssh/known_hosts'

module Net
  module SSH
    module Verifiers
      # Optional, opt-in evidence for a single host-key trust decision.
      #
      # The strict verifiers (Verifiers::Always and its AcceptNew subclasses)
      # build one of these only when the +:verify_host_key_evidence+ option is
      # true, and attach it to the Net::SSH::HostKeyError they raise. It records
      # enough for an operator to see *why* a key was refused without having to
      # re-run the connection by hand:
      #
      # - every pinned, @cert-authority and @revoked known-hosts entry that
      #   matched the host, with its source file, line number, the host pattern
      #   that matched and the entry/key type;
      # - which presented key the entries were compared with;
      # - the per-check state of certificate constraints (host name, validity
      #   window, certificate type, critical options), each one of
      #   +:not_run+, +:pass+ or +:fail+;
      # - the final decision and the reason string used in the exception.
      #
      # Design constraints:
      #
      # - Collection never changes which key is selected. Entries are only
      #   observed, in the same order the verifier already walks them.
      # - A @revoked entry wins even when the same key is also pinned as
      #   trusted: both entries are recorded and the decision stays +:rejected+
      #   with reason +:revoked+.
      # - Hashed known-hosts lines (|1|...) are redacted to
      #   HostKeyEntryLocation::HASHED_PATTERN, so the evidence cannot be used
      #   offline to recover the list of hosts in the file.
      # - A check that was never executed stays +:not_run+; it is never reported
      #   as +:pass+.
      class TrustEvidence
        CHECKS = %i[certificate_hostname certificate_validity certificate_type critical_options].freeze
        STATUSES = %i[not_run pass fail].freeze

        # :accepted when the presented key was trusted, :rejected otherwise.
        attr_reader :decision
        # Machine-readable reason for a rejection, e.g. :revoked, :unknown,
        # :mismatch, :revoked, :certificate_validity.
        attr_reader :reason
        # Human-readable detail, identical to the HostKeyError message suffix.
        attr_reader :detail
        attr_reader :presented_key_type, :presented_fingerprint, :host, :checks

        def initialize(host:, key:, fingerprint: nil)
          @host = host
          @presented_key_type = key.ssh_type
          @presented_fingerprint = fingerprint
          @entries = []
          @decision = nil
          @reason = nil
          @detail = nil
          @checks = CHECKS.each_with_object({}) { |name, memo| memo[name] = :not_run }
        end

        # Records a known-hosts entry (a HostKeyEntries::PubKey, CertAuthority
        # or Revoked) that matched the looked-up host, together with whether its
        # key matched the presented key. Entries are kept in search order.
        def record_entry(entry, key_match:)
          @entries << entry_summary(entry, key_match)
        end

        # Records the outcome of one certificate constraint check. +status+ is
        # :pass or :fail; checks never executed keep their initial :not_run.
        def record_check(name, status)
          raise ArgumentError, "unknown check #{name.inspect}" unless CHECKS.include?(name)
          raise ArgumentError, "invalid status #{status.inspect}" unless STATUSES.include?(status) && status != :not_run

          @checks[name] = status
        end

        def reject(reason, detail)
          @decision = :rejected
          @reason = reason
          @detail = detail
          self
        end

        def accept
          @decision = :accepted
          @reason = nil
          @detail = nil
          self
        end

        def rejected?
          decision == :rejected
        end

        def accepted?
          decision == :accepted
        end

        # The recorded entries, in search order.
        def entries
          @entries.dup
        end

        def matching_revocations
          @entries.select { |entry| entry[:entry_kind] == :revoked && entry[:key_match] }
        end

        def to_h
          {
            host: host,
            presented_key_type: presented_key_type,
            presented_fingerprint: presented_fingerprint,
            decision: decision,
            reason: reason,
            detail: detail,
            checks: checks.dup,
            entries: entries
          }
        end

        def inspect
          "#<#{self.class} #{to_h.inspect}>"
        end

        private

        def entry_summary(entry, key_match)
          {
            entry_kind: entry.entry_kind,
            key_type: entry.ssh_type,
            key_match: key_match,
            location: entry.location&.to_h
          }
        end
      end
    end
  end
end

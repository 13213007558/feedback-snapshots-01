# -*- ruby encoding: utf-8 -*-
require "set"

class Net::LDAP::Sync
  ##
  # Consumes the messages of exactly one RFC 4533 +refreshOnly+ operation
  # and produces an atomic replacement for a locally held mirror.
  #
  # == Safety model
  #
  # The consumer never mutates the caller's existing mirror. Every message
  # is applied to private staging state. A replacement snapshot, the change
  # ledger and the next checkpoint cookie are published together, and only
  # once +#process+ has observed a successful SearchResultDone carrying a
  # valid Sync Done Control.
  #
  # If the stream is truncated, the server returns an error (including
  # e-syncRefreshRequired), or the messages contradict one another, an
  # exception is raised and +#result+ stays unavailable. The previous mirror
  # and checkpoint must then be retained untouched and the whole refresh
  # retried; a half-applied refresh can never be used because the
  # present/delete bookkeeping is only meaningful for a complete refresh.
  class RefreshConsumer
    # The materialized output of a completed refresh.
    Result = Struct.new(:entries, :cookie, :refresh_deletes, :changelog, keyword_init: true)

    # Build a consumer for an incremental refresh.
    #
    # +previous_entries+ maps entryUUID (16-byte binary strings) to the
    # Net::LDAP::Entry last confirmed by a completed refresh. It is only
    # read from; the caller's hash is never modified. Pass an empty hash for
    # an initial content poll.
    def initialize(previous_entries = {})
      @previous = previous_entries
      @staged = {}

      # Final, per-UUID verdict across the whole refresh. A UUID touched in
      # both phases (present then delete) collapses to the later verdict.
      @verdicts = {}

      # Phase bookkeeping. A refresh is a present phase, a delete phase, or
      # a present phase followed by a delete phase.
      @phase = nil
      @two_phase = false
      @boundary_seen = false

      # UUIDs given a verdict inside the phase currently being processed
      # (duplicate detection) and across the whole refresh (snapshot
      # composition in present mode). They are deliberately separate.
      @phase_touched = Set.new
      @seen = Set.new
      @deleted_uuids = Set.new

      @cookies = []
      @finished = false
      @result = nil
    end

    # Apply one decoded PDU from the search stream. Returns +true+ when the
    # PDU was consumed, +false+ when it is unrelated to the sync operation
    # so a connection loop can ignore it.
    def process(pdu)
      raise ProtocolError, "refresh has already finished" if @finished

      info = Codec.info_message(pdu)
      return handle_info(info) if info

      if pdu.respond_to?(:app_tag) && pdu.app_tag == Net::LDAP::PDU::SearchReturnedData
        state = Codec.state_control(pdu)
        raise ProtocolError, "SearchResultEntry without a Sync State Control" unless state

        handle_entry(state, pdu.search_entry)
        return true
      end

      if pdu.respond_to?(:app_tag) && pdu.app_tag == Net::LDAP::PDU::SearchResult
        handle_result_done(pdu)
        return true
      end

      false
    end

    # True only after a clean SearchResultDone with a Sync Done Control.
    def finished?
      @finished
    end

    # Every cookie observed on the stream, in arrival order. The Sync Done
    # cookie is the authoritative checkpoint; earlier cookies are retained
    # for diagnostics but must never be checkpointed early.
    attr_reader :cookies

    # The atomic replacement for the mirror, available only after the
    # terminal SearchResultDone has been accepted.
    def result
      raise IncompleteRefreshError, "refresh did not complete; no replacement is available" unless @result

      @result
    end

    private

    def handle_info(info)
      record_cookie(info[:cookie])

      case info[:type]
      when :newcookie
        # A standalone cookie update carries no content semantics.
        true
      when :refresh_present
        # RFC 4533 3.3.2: in refreshOnly this marker always has
        # refreshDone=FALSE and delimits the present phase from the delete
        # phase. (A refreshDone=TRUE marker only terminates the refresh stage
        # of refreshAndPersist, which this consumer does not model.)
        if info[:refresh_done]
          raise ProtocolError, "refreshPresent with refreshDone=TRUE is invalid in refreshOnly"
        end

        enter_phase(:present)
        @boundary_seen = true
        true
      when :refresh_delete
        # refreshDelete markers belong to refreshAndPersist, not refreshOnly.
        raise ProtocolError, "refreshDelete Sync Info is invalid in refreshOnly"
      when :sync_id_set
        phase = info[:refresh_deletes] ? :delete : :present
        enter_phase(phase)
        info[:uuids].each do |uuid|
          info[:refresh_deletes] ? record_delete(uuid) : record_present(uuid)
        end
        true
      else
        raise ProtocolError, "unknown syncInfoValue type #{info[:type].inspect}"
      end
    end

    def handle_entry(state, entry)
      record_cookie(state[:cookie])
      uuid = state[:uuid]

      case state[:state]
      when STATE_PRESENT
        enter_phase(:present)
        record_present(uuid)
      when STATE_DELETE
        enter_phase(:delete)
        record_delete(uuid)
      when STATE_ADD, STATE_MODIFY
        enter_phase(:present)
        record_change(uuid, state[:state], entry)
      else
        raise ProtocolError, "unknown sync state #{state[:state].inspect}"
      end
    end

    def handle_result_done(pdu)
      result_code = pdu.result_code

      if result_code == RESULT_SYNC_REFRESH_REQUIRED
        done = Codec.done_control(pdu)
        raise RefreshRequiredError.new(cookie: done && done[:cookie])
      end

      unless result_code == Net::LDAP::ResultCodeSuccess
        raise IncompleteRefreshError,
              "sync refresh terminated with result code #{result_code}: #{pdu.error_message}"
      end

      done = Codec.done_control(pdu)
      raise ProtocolError, "successful refresh ended without a Sync Done Control" unless done

      record_cookie(done[:cookie])
      claimed_phase = done[:refresh_deletes] ? :delete : :present
      verify_terminal_phase(claimed_phase)
      materialize(done)
    end

    # Move into +phase+, enforcing the legal ordering of phases.
    def enter_phase(phase)
      if @phase.nil?
        @phase = phase
        return
      end

      return if @phase == phase

      if @phase == :present && phase == :delete
        unless @boundary_seen
          raise ProtocolError,
                "delete phase began without a refreshPresent refreshDone=FALSE boundary"
        end

        @phase = :delete
        @two_phase = true
        @phase_touched = Set.new
        return
      end

      raise ProtocolError, "illegal phase transition #{@phase.inspect} -> #{phase.inspect}"
    end

    def verify_terminal_phase(claimed_phase)
      if @phase.nil?
        # An empty refresh is legal; the done control alone defines its mode.
        @phase = claimed_phase
        return
      end

      unless @phase == claimed_phase
        raise ProtocolError,
              "Sync Done refreshDeletes=#{claimed_phase == :delete} does not match the active phase"
      end

      if @two_phase && claimed_phase != :delete
        raise ProtocolError, "two-phase refresh must end with a delete-phase Sync Done Control"
      end
    end

    def record_present(uuid)
      guard_duplicate(uuid, :present)
      unless @previous.key?(uuid)
        raise ProtocolError, "present state for UUID not held in the previous mirror"
      end

      mark_seen(uuid)
      @staged[uuid] = @previous[uuid]
      @verdicts[uuid] = :present
    end

    def record_delete(uuid)
      guard_duplicate(uuid, :delete)
      unless @previous.key?(uuid)
        raise ProtocolError, "delete state for UUID absent from the previous mirror"
      end

      mark_seen(uuid)
      @deleted_uuids << uuid
      @staged.delete(uuid)
      @verdicts[uuid] = :delete
    end

    def record_change(uuid, state, entry)
      guard_duplicate(uuid, STATE_NAMES[state])
      raise ProtocolError, "add/modify entry carried no attributes" if entry.nil?

      mark_seen(uuid)
      @staged[uuid] = entry
      @verdicts[uuid] = STATE_NAMES[state]
    end

    def mark_seen(uuid)
      @phase_touched << uuid
      @seen << uuid
    end

    # One verdict per UUID per phase. Two verdicts in the same phase are a
    # contradiction: acting on either could retain or remove the wrong
    # permission, so the whole refresh is rejected.
    def guard_duplicate(uuid, label)
      return unless @phase_touched.include?(uuid)

      raise ProtocolError,
            "UUID #{uuid_hash(uuid)} received a conflicting #{label} verdict within one phase"
    end

    def materialize(done)
      entries = compose_snapshot(done[:refresh_deletes])
      changelog = build_changelog

      @finished = true
      @result = Result.new(
        entries: entries,
        cookie: done[:cookie],
        refresh_deletes: done[:refresh_deletes],
        changelog: changelog,
      )
    end

    def compose_snapshot(refresh_deletes)
      if refresh_deletes
        # Delete phase: retain every previous entry except explicit
        # deletions, then overlay staged adds/modifications.
        @previous.reject { |uuid, _| @deleted_uuids.include?(uuid) }.merge(@staged)
      else
        # Present phase: the server enumerated every surviving entry. Entries
        # never named are gone; staged adds/modifications win.
        @previous.select { |uuid, _| @seen.include?(uuid) }.merge(@staged)
      end
    end

    def build_changelog
      changelog = { add: [], modify: [], present: [], delete: [] }
      @verdicts.each do |uuid, verdict|
        changelog[verdict] << uuid
      end
      changelog
    end

    def record_cookie(cookie)
      @cookies << cookie if cookie && !cookie.empty?
    end

    def uuid_hash(uuid)
      uuid.unpack1("H*")
    end
  end
end

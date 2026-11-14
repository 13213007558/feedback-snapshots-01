# -*- ruby encoding: utf-8 -*-
##
# Support for the LDAP Content Synchronization Operation described in
# RFC 4533.
#
# The pieces in this file are deliberately split into two layers:
#
# * Net::LDAP::Sync::Codec knows how to build and parse the BER control and
#   intermediate-response values defined by RFC 4533. It performs no state
#   tracking and can be unit tested against hand-built protocol sequences.
# * Net::LDAP::Sync::RefreshConsumer is a state machine that consumes the
#   decoded messages of a single refreshOnly operation and only exposes a
#   replacement data set once the refresh has terminated cleanly.
#
# See Net::LDAP#sync_refresh for the entry point used by application code.
class Net::LDAP
  class Sync
    # Object identifiers assigned by RFC 4533 section 2.
    module OID
      # Sync Request Control (section 2.2).
      REQUEST = "1.3.6.1.4.1.4203.1.9.1.1".freeze
      # Sync State Control (section 2.3).
      STATE = "1.3.6.1.4.1.4203.1.9.1.2".freeze
      # Sync Done Control (section 2.4).
      DONE = "1.3.6.1.4.1.4203.1.9.1.3".freeze
      # Sync Info Intermediate Response (section 2.5).
      INFO = "1.3.6.1.4.1.4203.1.9.1.4".freeze
    end

    # syncRequestValue mode ENUMERATED values (section 2.2).
    MODE_REFRESH_ONLY = 1
    MODE_REFRESH_AND_PERSIST = 3

    # syncStateValue state ENUMERATED values (section 2.3).
    STATE_PRESENT = 0
    STATE_ADD = 1
    STATE_MODIFY = 2
    STATE_DELETE = 3

    # Names used for the state values, exposed so callers do not have to
    # remember the integer codes.
    STATE_NAMES = {
      STATE_PRESENT => :present,
      STATE_ADD => :add,
      STATE_MODIFY => :modify,
      STATE_DELETE => :delete,
    }.freeze

    # e-syncRefreshRequired result code (RFC 4533 section 2.6).
    RESULT_SYNC_REFRESH_REQUIRED = 4096

    # Tags of the syncInfoValue CHOICE alternatives (section 2.5). The
    # constructed bit is already included because these values are read back
    # from the BER identifier byte.
    INFO_NEW_COOKIE = 0x80
    INFO_REFRESH_DELETE = 0xA1
    INFO_REFRESH_PRESENT = 0xA2
    INFO_SYNC_ID_SET = 0xA3

    # Raised when a refresh cannot be completed safely. The in-progress
    # mirror must be discarded whenever one of these is raised; no partial
    # state is ever exposed to the caller.
    class Error < Net::LDAP::Error; end

    # The server closed the refresh stream before sending a SearchResultDone
    # with a Sync Done Control, or sent a non-success result code.
    class IncompleteRefreshError < Error; end

    # The server asked for a full/incremental reload
    # (e-syncRefreshRequired). The caller must restart without trusting the
    # half-applied refresh.
    class RefreshRequiredError < Error
      attr_reader :cookie

      def initialize(message = nil, cookie: nil)
        super(message || "LDAP server returned e-syncRefreshRequired")
        @cookie = cookie
      end
    end

    # The sequence of sync messages violated RFC 4533 (unknown choice,
    # contradictory phase markers, an entry seen with two incompatible
    # states, a missing Sync Done Control, and so on).
    class ProtocolError < Error; end
  end
end

require_relative "sync/codec"
require_relative "sync/refresh_consumer"

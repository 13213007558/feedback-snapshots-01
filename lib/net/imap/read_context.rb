# frozen_string_literal: true

module Net
  class IMAP < Protocol

    # A ReadContext binds an approved mailbox, UIDVALIDITY, and a finite set
    # of message UIDs to subsequent fetches on a Net::IMAP connection.  It
    # represents a limited grant—e.g. an approval from a customer-service
    # console to read a few specific messages—and ensures that only those
    # messages can be read while the connection remains in the exact same
    # mailbox selection.
    #
    # Create a read context with Net::IMAP#read_context, and read with
    # #uid_fetch:
    #
    #   imap.select("INBOX")
    #   uidvalidity = imap.responses("UIDVALIDITY", &:last)
    #   ctx = imap.read_context("INBOX", uidvalidity: uidvalidity, uids: 101..105)
    #   ctx.uid_fetch(101..102, %w[FLAGS BODY.PEEK[]])
    #
    # Message UIDs are used exclusively—never message sequence numbers, which
    # are mutable and could identify different messages after an expunge.
    #
    # A read context is only usable while the connection remains in the
    # selection that was current when the context was created.  The context
    # becomes unusable—ReadContextError is raised before anything is sent—
    # after any of the following:
    # * another SELECT or EXAMINE command (successful or not),
    # * CLOSE or UNSELECT,
    # * an unsolicited +CLOSED+ response code from the server,
    # * a changed UIDVALIDITY,
    # * logout or disconnection.
    #
    # FETCH responses that the server sends for any other messages (e.g.
    # unsolicited updates) are never returned as authorized content: only
    # results whose UID is covered by the context's UID set are returned.
    class ReadContext
      # The mailbox name this context authorizes reading from.
      attr_reader :mailbox

      # The UIDVALIDITY this context was authorized for.
      attr_reader :uidvalidity

      # The finite SequenceSet of UIDs this context authorizes reading.
      attr_reader :uids

      # :call-seq:
      #   uid_fetch(set, attr, changedsince: nil, partial: nil) -> array of FetchData
      #
      # Sends a +UID FETCH+ command for +set+, after verifying—while holding
      # the connection lock, so the check and the command cannot be split by
      # a concurrent mailbox switch—that the connection is still in this
      # context's selection and that every UID in +set+ is authorized.
      #
      # Raises ReadContextError before sending anything when the context is
      # no longer valid or +set+ contains unauthorized UIDs.  Only FetchData
      # whose UID is authorized is returned; any other FETCH responses the
      # server may have included are dropped.
      #
      # +attr+, +changedsince+, and +partial+ behave as in IMAP#uid_fetch.
      def uid_fetch(set, attr, partial: nil, changedsince: nil)
        @client.__send__(:fetch_with_read_context, self, set, attr,
                         partial: partial, changedsince: changedsince)
      end

      def inspect
        "#<%s mailbox=%p uidvalidity=%d uids=%p>" % [
          self.class.name, mailbox, uidvalidity, uids.to_s
        ]
      end

      # NOTE: ReadContext objects are created by IMAP#read_context, which
      # captures the connection's current selection generation while holding
      # the connection lock.
      def initialize(client:, mailbox:, uidvalidity:, uids:, generation:) # :nodoc:
        @client       = client
        @mailbox      = mailbox
        @uidvalidity  = uidvalidity
        @uids         = uids
        @generation   = generation
        freeze
      end

      # The selection generation captured when this context was created.
      # Compared against the connection's current generation, under lock, on
      # every #uid_fetch.  :nodoc:
      def generation; @generation end
    end

  end
end

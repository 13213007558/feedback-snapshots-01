# frozen_string_literal: true

# = net/lmtp.rb
#
# This program is free software. You can re-distribute and/or
# modify this program under the same terms as Ruby itself.
#
# See Net::LMTP for documentation.

require_relative 'smtp'

module Net
  #
  # == What is This Library?
  #
  # This library provides functionality to deliver mail to a local mail
  # delivery agent via \LMTP, the Local Mail Transfer Protocol, defined in
  # {RFC2033[https://www.rfc-editor.org/rfc/rfc2033.html]}.
  #
  # \LMTP is a variant of \SMTP.  The differences that matter to a client
  # are:
  #
  # * The session is opened with +LHLO+ instead of +HELO+/+EHLO+.
  # * After the final <CR><LF>.<CR><LF> of the +DATA+ command, the server
  #   sends one reply for _each_ recipient that was accepted with +RCPT TO+,
  #   in the same order.  A single reply code never covers the whole message.
  #
  # Net::LMTP is a subclass of Net::SMTP, so connection handling, TLS,
  # STARTTLS and authentication work exactly as they do for Net::SMTP.
  # Plain Net::SMTP behavior is unchanged; \LMTP support is only active
  # when you explicitly use Net::LMTP (and +require 'net/lmtp'+).
  #
  # == Examples
  #
  #   require 'net/lmtp'
  #
  #   Net::LMTP.start('localhost', 24) do |lmtp|
  #     delivery = lmtp.send_message msgstr,
  #                                  'from@example.com',
  #                                  ['user1@example.com', 'user2@example.com']
  #     delivery.each do |recipient|
  #       if recipient.delivered?
  #         puts "#{recipient.address}: delivered"
  #       else
  #         puts "#{recipient.address}: failed (#{recipient.response&.status})"
  #       end
  #     end
  #   end
  #
  # === Per-recipient results
  #
  # #send_message and #open_message_stream return a Net::LMTP::Delivery
  # instead of raising on individual recipient failures.  The Delivery
  # holds one Net::LMTP::Recipient per +RCPT TO+ address, in the original
  # order, and each Recipient carries its own outcome:
  #
  # * recipients rejected at +RCPT TO+ time keep that rejection response;
  # * recipients accepted at +RCPT TO+ time get their own final reply
  #   after +DATA+;
  # * a recipient is only reported as delivered when its own final reply
  #   is a 2xx reply.  Recipients whose final reply never arrived (short
  #   reply count, closed connection) are never reported as delivered.
  #
  # If the server sends fewer replies than there are accepted recipients,
  # sends more replies than there are accepted recipients, or drops the
  # connection in the middle of the reply list, the session is poisoned:
  # an exception is raised and no further commands are sent on the
  # connection, so a stray reply can never be attributed to the next
  # message.
  #
  class LMTP < SMTP
    # The default LMTP port number, 24.
    def LMTP.default_port
      24
    end

    # Raised when the server violates the LMTP reply rules, e.g. when the
    # number of post-DATA replies does not match the number of accepted
    # recipients.  The session is unusable after this error.
    class ProtocolError < SMTPUnknownError
    end

    # The outcome of a single recipient of an LMTP transaction.
    class Recipient
      # The recipient address as given to RCPT TO.
      attr_reader :address

      # The reply to the RCPT TO command for this recipient, or nil if
      # the reply could not be obtained.
      attr_reader :rcpt_response

      # The final reply for this recipient, sent by the server after the
      # end of DATA.  nil if the server never confirmed this recipient.
      attr_reader :response

      def initialize(address, rcpt_response = nil) # :nodoc:
        @address = address
        @rcpt_response = rcpt_response
        @response = nil
      end

      # true if the server accepted this recipient with RCPT TO.
      def accepted?
        !!@rcpt_response&.success?
      end

      # true if the server sent a final reply for this recipient after
      # the end of DATA.
      def confirmed?
        !@response.nil?
      end

      # true only if this recipient's own final reply is a 2xx reply.
      def delivered?
        confirmed? && @response.success?
      end

      def confirm(response) # :nodoc:
        @response = response
      end
    end

    # The result of an LMTP message delivery: one Recipient per RCPT TO
    # address, in the order the addresses were given.
    class Delivery
      include Enumerable

      # All Recipient objects, in RCPT TO order.
      attr_reader :recipients

      def initialize(recipients) # :nodoc:
        @recipients = recipients
      end

      def each(&block)
        @recipients.each(&block)
      end

      # Recipients confirmed as delivered by their own final 2xx reply.
      def delivered
        @recipients.select(&:delivered?)
      end

      # Recipients not confirmed as delivered: rejected at RCPT TO,
      # failed after DATA, or never confirmed at all.
      def failed
        @recipients.reject(&:delivered?)
      end

      # true if every recipient was confirmed as delivered.
      def success?
        @recipients.all?(&:delivered?)
      end
    end

    #
    # Creates a new Net::LMTP object.  Same parameters as Net::SMTP.new,
    # except that +port+ defaults to Net::LMTP.default_port (24).
    #
    def initialize(address, port = nil, **kwargs)
      super(address, port || LMTP.default_port, **kwargs)
      @lmtp_recipients = []
    end

    # Sends the LHLO command, the LMTP greeting (RFC 2033).
    def lhlo(domain)
      getok("LHLO #{domain}")
    end

    # +from_addr+ is +String+ or +Net::SMTP::Address+
    def mailfrom(from_addr)
      @lmtp_recipients = []
      super
    end

    # Aborts the current mail transaction and forgets its recipients.
    def rset
      @lmtp_recipients = []
      super
    end

    # +to_addr+ is +String+ or +Net::SMTP::Address+
    def rcptto(to_addr)
      res = super
      @lmtp_recipients.push(Recipient.new(Address.new(to_addr).address, res))
      res
    end

    def rcptto_list(to_addrs)
      raise ArgumentError, 'mail destination not given' if to_addrs.empty?
      to_addrs.flatten.each do |addr|
        begin
          rcptto addr
        rescue SMTPError => e
          @lmtp_recipients.push(Recipient.new(Address.new(addr).address, e.response))
        end
      end
      if @lmtp_recipients.any?(&:accepted?)
        yield
      else
        # No recipient accepted the message: DATA must not be sent.
        Delivery.new(@lmtp_recipients)
      end
    end

    # Sends a message like Net::SMTP#data, but consumes exactly one reply
    # per recipient accepted with RCPT TO, in order, and returns a
    # Net::LMTP::Delivery with the per-recipient results.
    #
    # Individual failure replies are recorded in the Delivery, not raised.
    # A missing reply, a dropped connection, or extra replies raise an
    # exception and poison the session, so replies can never leak into
    # the next message.
    def data(msgstr = nil, &block)   #:yield: stream
      if msgstr and block
        raise ArgumentError, "message and block are exclusive"
      end
      unless msgstr or block
        raise ArgumentError, "message or block is required"
      end
      accepted = @lmtp_recipients.select(&:accepted?)
      if accepted.empty?
        raise ArgumentError, 'DATA requires at least one accepted recipient'
      end
      responses = critical {
        check_continue get_response('DATA')
        socket_sync_bak = @socket.io.sync
        begin
          @socket.io.sync = false
          if msgstr
            @socket.write_message msgstr
          else
            @socket.write_message_by_block(&block)
          end
        ensure
          @socket.io.flush
          @socket.io.sync = socket_sync_bak
        end
        # RFC 2033: one reply per accepted recipient, in RCPT TO order.
        # A short reply list or a dropped connection raises here, inside
        # +critical+, which poisons the session.
        accepted.map { recv_response() }
      }
      if responses.is_a?(Array)
        accepted.zip(responses) do |recipient, res|
          recipient.confirm(res)
        end
        check_no_extra_lmtp_response
      end
      # When the session was already poisoned, +critical+ returned a
      # dummy response: no recipient gets confirmed, so none of them can
      # be reported as delivered.
      Delivery.new(@lmtp_recipients)
    end

    private

    def do_helo(helo_domain)
      # LMTP has no HELO/EHLO fallback: LHLO is mandatory (RFC 2033).
      @capabilities = lhlo(helo_domain).capabilities
    end

    # If the server sent more replies than there are accepted recipients,
    # the extra replies would be mistaken for replies to the next
    # command.  Poison the session instead of letting them leak.
    def check_no_extra_lmtp_response
      return unless lmtp_extra_response_pending?
      @error_occurred = true
      raise ProtocolError, 'LMTP server sent more replies than there are ' \
                           'accepted recipients; session closed so the ' \
                           'extra replies cannot be attributed to another message'
    end

    def lmtp_extra_response_pending?
      socket = @socket
      if socket.respond_to?(:rbuf_size, true) && socket.send(:rbuf_size) > 0
        return true
      end
      io = socket.io
      return true if io.respond_to?(:pending) && io.pending > 0
      io.to_io.wait_readable(0) ? true : false
    end
  end   # class LMTP
end

# frozen_string_literal: true

module Net
  class SMTP < Protocol
    # Structured support for the SMTP Delivery Status Notification extension
    # (DSN) defined in [RFC3461[https://www.rfc-editor.org/rfc/rfc3461.txt]].
    #
    # These value objects keep the four DSN parameters bound to the correct
    # SMTP command instead of asking callers to hand-build MAIL/RCPT argument
    # strings:
    #
    # * Net::SMTP::DSN::Sender carries +ENVID+ and +RET+, which belong to the
    #   MAIL command.
    # * Net::SMTP::DSN::Recipient carries +NOTIFY+ and +ORCPT+, which belong
    #   to the RCPT command.  Each recipient keeps its own ORCPT so the values
    #   of multiple recipients can never be exchanged.
    #
    # Values that may contain spaces, "+", "=", or non-ASCII octets are encoded
    # as the +xtext+ production described in section 4 of RFC 3461.  Invalid
    # arguments raise ArgumentError when the object is built, so mistakes are
    # reported before an SMTP mail transaction begins.
    #
    # The parameters are only sent when the connected server advertises the
    # DSN extension; otherwise Net::SMTP raises Net::SMTPUnsupportedCommand
    # before issuing MAIL or RCPT.
    #
    # === Example
    #
    #   sender = Net::SMTP::DSN::Sender.new(
    #     'alice@example.org', envid: 'tx-42', ret: :hdrs
    #   )
    #   recipients = [
    #     Net::SMTP::DSN::Recipient.new(
    #       'bob@example.com', notify: [:success, :failure],
    #       orcpt: 'bob@example.com'
    #     ),
    #     Net::SMTP::DSN::Recipient.new('carol@example.org', notify: :never)
    #   ]
    #   Net::SMTP.start('smtp.example.com') do |smtp|
    #     smtp.send_message msgstr, sender, recipients
    #   end
    #
    # This produces, on a DSN-capable server:
    #
    #   MAIL FROM:<alice@example.org> RET=HDRS ENVID=tx-42
    #   RCPT TO:<bob@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;bob@example.com
    #   RCPT TO:<carol@example.org> NOTIFY=NEVER
    module DSN
      # Keywords allowed in a RCPT NOTIFY parameter.
      NOTIFY_KEYWORDS = %w[NEVER SUCCESS FAILURE DELAY].freeze

      # Keywords allowed in a MAIL RET parameter.
      RET_KEYWORDS = %w[FULL HDRS].freeze

      module_function

      # Encodes an octet sequence as the RFC 3461 "xtext" production.
      #
      # Printable ASCII characters between "!" and "~" (except "+" and "=")
      # are emitted as themselves; every other octet - notably spaces, "+",
      # "=", control characters and non-ASCII bytes - becomes "+XX" with two
      # upper-case hexadecimal digits.
      def encode_xtext(value)
        value.b.each_byte.map do |byte|
          if byte >= 0x21 && byte <= 0x7E && byte != 0x2B && byte != 0x3D
            byte.chr
          else
            format('+%02X', byte)
          end
        end.join
      end

      # Rejects the non-printable control characters that RFC 3461 forbids in
      # the raw (pre-encoding) ENVID and ORCPT values.  Whitespace such as a
      # space is printable and therefore allowed; it is encoded by xtext.
      def check_printable!(label, value)
        value.each_byte do |byte|
          if byte < 0x20 || byte == 0x7F
            raise ArgumentError,
                  "#{label} must consist of printable characters (got byte #{byte})"
          end
        end
      end

      # Normalizes a NOTIFY argument into the validated, comma-joined wire
      # value.  NEVER is mutually exclusive with every other keyword.
      def normalize_notify(notify)
        list = Array(notify).flatten.map do |keyword|
          word = keyword.to_s.upcase
          unless NOTIFY_KEYWORDS.include?(word)
            raise ArgumentError,
                  "invalid NOTIFY keyword #{keyword.inspect} " \
                  "(expected one of #{NOTIFY_KEYWORDS.join(', ')})"
          end
          word
        end
        raise ArgumentError, 'NOTIFY requires at least one keyword' if list.empty?
        if list.include?('NEVER') && list.uniq.size > 1
          raise ArgumentError, 'NOTIFY=NEVER cannot be combined with other NOTIFY keywords'
        end
        list.uniq.join(',')
      end

      # Normalizes a RET argument into FULL or HDRS.
      def normalize_ret(ret)
        word = ret.to_s.upcase
        unless RET_KEYWORDS.include?(word)
          raise ArgumentError,
                "invalid RET value #{ret.inspect} (expected FULL or HDRS)"
        end
        word
      end

      # Validates the addr-type portion of an ORCPT parameter.
      def check_addr_type!(addr_type)
        type = addr_type.to_s
        if type.empty?
          raise ArgumentError, 'ORCPT address type must not be empty'
        end
        if type.include?(';') || type.match?(/[\s\x7F]/) || !type.ascii_only?
          raise ArgumentError, "invalid ORCPT address type #{addr_type.inspect}"
        end
        type
      end

      # Envelope-level DSN parameters for the MAIL command.
      #
      # +envid+:: envelope identifier (ENVID), encoded as xtext.
      # +ret+:: +:full+ or +:hdrs+ (RET), controlling how much of a failed
      #         message is returned.
      class Sender < Address
        # Raw, unencoded envelope identifier given by the caller.
        attr_reader :envid
        # Normalized RET keyword ("FULL" or "HDRS"), or nil.
        attr_reader :ret

        def initialize(address, envid: nil, ret: nil)
          super(address)
          @envid = nil
          @ret = nil
          if envid
            DSN.check_printable!('ENVID', envid)
            @envid = envid
          end
          @ret = DSN.normalize_ret(ret) if ret
        end

        # Always identifies this object as carrying DSN parameters.
        def dsn?
          true
        end

        def parameters
          params = []
          params << "RET=#{@ret}" if @ret
          params << "ENVID=#{DSN.encode_xtext(@envid)}" if @envid
          super + params
        end
      end

      # Per-recipient DSN parameters for the RCPT command.
      #
      # +notify+:: one or more of +:never+, +:success+, +:failure+, +:delay+
      #            (NOTIFY).  +:never+ is mutually exclusive with the others.
      # +orcpt+:: the original recipient address (ORCPT), encoded as xtext.
      # +addr_type+:: address type prefix for ORCPT, defaulting to +rfc822+.
      class Recipient < Address
        # Normalized, comma-joined NOTIFY value, or nil.
        attr_reader :notify
        # Raw, unencoded original recipient address given by the caller.
        attr_reader :orcpt
        # Validated ORCPT address type prefix.
        attr_reader :addr_type

        def initialize(address, notify: nil, orcpt: nil, addr_type: 'rfc822')
          super(address)
          @notify = nil
          @orcpt = nil
          @addr_type = nil
          @notify = DSN.normalize_notify(notify) if notify
          if orcpt
            DSN.check_printable!('ORCPT', orcpt)
            @addr_type = DSN.check_addr_type!(addr_type)
            @orcpt = orcpt
          end
        end

        # Always identifies this object as carrying DSN parameters.
        def dsn?
          true
        end

        def parameters
          params = []
          params << "NOTIFY=#{@notify}" if @notify
          if @orcpt
            params << "ORCPT=#{@addr_type};#{DSN.encode_xtext(@orcpt)}"
          end
          super + params
        end
      end
    end
  end
end

# frozen_string_literal: true

require_relative "errors"

module Net
  class IMAP < Protocol

    # A MailboxIdentity ties together the three things that must never be
    # silently confused when a deployment migrates from legacy IMAP mailbox
    # names (modified UTF-7, RFC 3501 §5.1.3) to UTF-8 mailbox names
    # (RFC 6855, <tt>ENABLE UTF8=ACCEPT</tt>):
    #
    # [+logical_name+] the approved logical mailbox name, as a UTF-8 String.
    #                  This is what an authorization whitelist stores, and it
    #                  is compared by exact codepoints—never by display
    #                  similarity and never after Unicode normalization.
    # [+mode+]         the negotiated mode, either +:legacy+ (modified UTF-7
    #                  on the wire) or +:utf8+ (UTF-8 on the wire).  The mode
    #                  comes from the connection (whether +UTF8=ACCEPT+ was
    #                  enabled); it is never guessed from the name bytes.
    # [+wire_bytes+]   the actual bytes that are sent to (or received from)
    #                  the server, as a frozen binary String.
    #
    # Two names that look alike (e.g. NFC vs NFD, or a literal "&" vs its
    # "&-" encoding) are *different* identities unless their logical names
    # are exactly equal.  The only exception is +INBOX+, which is
    # case-insensitive per RFC 3501 §5.1; that special case is handled here
    # and nowhere else.
    #
    # Use MailboxIdentity::Adapter to encode, decode, authorize, and migrate
    # mailbox names for a connection.
    class MailboxIdentity

      # Base class for mailbox identity errors.
      class Error < Net::IMAP::Error; end

      # Raised when a mailbox name cannot be strictly decoded or encoded.
      # The input is never "repaired" (no replacement characters, no
      # normalization, no lenient ampersand handling).
      class MailboxNameError < Error; end

      # Raised when a mailbox name would be sent using an encoding the
      # server has not negotiated (e.g. UTF-8 before +UTF8=ACCEPT+).
      class ModeError < Error; end

      # Raised when a logical name is not on the approval whitelist.
      class AuthorizationError < Error; end

      # Raised when a migration report with unresolved conflicts is
      # committed.  Carries the MigrationReport for inspection.
      class MigrationConflictError < Error
        attr_reader :report

        def initialize(report)
          @report = report
          super("mailbox migration has #{report.conflicts.size} unresolved " \
                "conflict(s); manual confirmation required")
        end
      end

      # Strict modified UTF-7 codec (RFC 3501 §5.1.3).
      #
      # Unlike Net::IMAP.decode_utf7, this codec refuses to silently fix
      # anything: a bare "&", a missing terminator, non-canonical base64
      # (non-zero trailing bits), invalid UTF-16 (odd byte count, lone
      # surrogates), and shifted sections that encode printable ASCII all
      # raise MailboxNameError.
      module Codec
        # Matches a shifted section's base64 payload ("," for "/", no "=").
        SHIFTED_RE = /\A[A-Za-z0-9+,]+\z/n

        BASE64_VALUE = {}.tap do |table|
          ("A".."Z").each_with_index { |c, i| table[c] = i }
          ("a".."z").each_with_index { |c, i| table[c] = i + 26 }
          ("0".."9").each_with_index { |c, i| table[c] = i + 52 }
          table["+"] = 62
          table[","] = 63
        end.freeze

        module_function

        # Strictly encode a logical (UTF-8) mailbox name to modified UTF-7
        # wire bytes.  Raises MailboxNameError for invalid UTF-8 input.
        def encode_utf7(logical_name)
          utf8 = logical_name.encode(Encoding::UTF_8)
          unless utf8.valid_encoding?
            raise MailboxNameError,
                  "mailbox name is not valid UTF-8: #{logical_name.inspect}"
          end
          utf8.gsub(/(&)|([^\x20-\x7e]+)/) do
            if Regexp.last_match(1)
              "&-"
            else
              "&" + encode_shifted(Regexp.last_match(2)) + "-"
            end
          end.force_encoding(Encoding::ASCII_8BIT)
        end

        # Strictly decode modified UTF-7 wire bytes to a logical (UTF-8)
        # mailbox name.  Raises MailboxNameError for anything malformed or
        # non-canonical.
        def decode_utf7(wire_bytes)
          wire = wire_bytes.b
          unless wire.ascii_only?
            raise MailboxNameError,
                  "legacy mailbox name contains non-ASCII bytes: " \
                  "#{wire_bytes.inspect}"
          end
          out = +"".b
          pos = 0
          while pos < wire.bytesize
            byte = wire.getbyte(pos)
            if byte == 0x26 # "&"
              decoded, pos = decode_shifted_at(wire, pos)
              out << decoded
            elsif byte < 0x20 || byte > 0x7e
              raise MailboxNameError,
                    "control byte 0x%02x in mailbox name" % [byte]
            else
              out << byte.chr
              pos += 1
            end
          end
          out.force_encoding(Encoding::UTF_8)
        end

        # Encode a UTF-8 string to the shifted-section base64 payload.
        def encode_shifted(string)
          [string.encode(Encoding::UTF_16BE)].pack("m0").delete("=").tr("/", ",")
        end

        # Decode one shifted section starting at +amp+ (the "&" offset) in
        # +wire+.  Returns [decoded_utf8_string, next_position].
        def decode_shifted_at(wire, amp)
          pos = amp + 1
          if wire.getbyte(pos) == 0x2d # "-"
            return "&", pos + 1
          end
          start = pos
          pos += 1 while pos < wire.bytesize &&
                          BASE64_VALUE.key?(wire.getbyte(pos).chr)
          section = wire.byteslice(start...pos)
          if section.empty?
            raise MailboxNameError,
                  "bare '&' in mailbox name: #{wire.inspect}"
          end
          if wire.getbyte(pos) != 0x2d
            raise MailboxNameError,
                  "unterminated shifted section in mailbox name: #{wire.inspect}"
          end
          [decode_shifted(section, wire), pos + 1]
        end

        # Strictly decode a shifted-section payload to UTF-8.
        def decode_shifted(section, wire = section)
          unless SHIFTED_RE.match?(section)
            raise MailboxNameError,
                  "invalid base64 in shifted section: #{wire.inspect}"
          end
          if section.length % 4 == 1
            raise MailboxNameError,
                  "impossible base64 length in shifted section: #{wire.inspect}"
          end
          raw = decode_base64_strict(section)
          if raw.bytesize.odd?
            raise MailboxNameError,
                  "odd UTF-16 byte count in shifted section: #{wire.inspect}"
          end
          decoded = begin
            raw.force_encoding(Encoding::UTF_16BE).encode(Encoding::UTF_8)
          rescue Encoding::InvalidByteSequenceError,
                 Encoding::UndefinedConversionError => error
            raise MailboxNameError,
                  "invalid UTF-16 in shifted section (#{error.message}): " \
                  "#{wire.inspect}"
          end
          unless encode_shifted(decoded) == section
            raise MailboxNameError,
                  "non-canonical base64 in shifted section: #{wire.inspect}"
          end
          if decoded.match?(/[\x20-\x7e]/)
            raise MailboxNameError,
                  "non-canonical shifted section encodes printable ASCII: " \
                  "#{wire.inspect}"
          end
          decoded
        end

        # Decode unpadded base64 ("," already maps to "/") with no leniency:
        # every character must be in the alphabet and the bit count must
        # yield whole bytes.
        def decode_base64_strict(section)
          bits = 0
          section.each_char do |char|
            bits = (bits << 6) | BASE64_VALUE.fetch(char)
          end
          leftover = section.length * 6 % 8
          bits >>= leftover
          bytes = []
          (section.length * 6 / 8 - 1).downto(0) do |shift|
            bytes << ((bits >> (shift * 8)) & 0xff)
          end
          bytes.pack("C*")
        end
      end

      # The approved logical mailbox name (UTF-8, frozen).
      attr_reader :logical_name

      # The negotiated mode: +:legacy+ or +:utf8+.
      attr_reader :mode

      # The actual bytes sent to / received from the server (binary, frozen).
      attr_reader :wire_bytes

      def initialize(logical_name:, mode:, wire_bytes:)
        @logical_name = logical_name.encode(Encoding::UTF_8).freeze
        @mode         = mode
        @wire_bytes   = wire_bytes.b.freeze
        freeze
      end

      # INBOX (in any case) is the only mailbox name with case-insensitive
      # identity (RFC 3501 §5.1).  All other names are case-sensitive.
      def inbox?
        logical_name.ascii_only? && logical_name.casecmp?("INBOX")
      end

      # The identity key used for authorization and equality: "INBOX" for
      # the special inbox name, otherwise the exact logical name.
      def key
        inbox? ? "INBOX" : logical_name
      end

      def ==(other)
        other.is_a?(MailboxIdentity) && key == other.key
      end
      alias eql? ==

      def hash = key.hash

      def inspect
        "#<%s %p mode=%p wire=%p>" % [self.class.name, logical_name, mode,
                                      wire_bytes]
      end

      # Adapts logical mailbox names to a connection's negotiated encoding
      # mode, and guards an approval whitelist so that switching encodings
      # can never make an approved name point at a different mailbox.
      #
      # The hierarchy delimiter is supplied by the connection (e.g. from a
      # LIST response); it is never assumed to be "/".
      class Adapter
        # The connection-provided hierarchy delimiter, or nil if unknown.
        attr_reader :delimiter

        # +utf8+::      whether the connection has negotiated UTF-8 mailbox
        #               names (RFC 6855 +UTF8=ACCEPT+ / IMAP4rev2).  When
        #               false, UTF-8 wire bytes are never produced.
        # +delimiter+:: the hierarchy delimiter reported by the server.
        def initialize(utf8: false, delimiter: nil)
          @utf8      = !!utf8
          @delimiter = delimiter&.freeze
          @approved  = {}
        end

        def utf8_enabled? = @utf8

        # The negotiated mode: +:utf8+ when enabled, else +:legacy+.
        def mode = @utf8 ? :utf8 : :legacy

        # Build the MailboxIdentity for +logical_name+ in +mode+ (the
        # negotiated mode by default).  Raises ModeError when UTF-8 wire
        # bytes are requested but the server has not enabled them.
        def identity_for(logical_name, mode: self.mode)
          wire = encode_wire(logical_name, mode)
          MailboxIdentity.new(logical_name: logical_name, mode: mode,
                              wire_bytes: wire)
        end

        # Strictly decode +wire_bytes+ received in +mode+ (the negotiated
        # mode by default) back to a MailboxIdentity.
        def parse(wire_bytes, mode: self.mode)
          logical = decode_wire(wire_bytes, mode)
          identity_for(logical, mode: mode)
        end

        # Add +logical_name+ to the approval whitelist.  The whitelist
        # stores logical names only, so it is stable across encoding modes.
        def approve(logical_name)
          key = key_for(logical_name)
          @approved[key] = logical_name.encode(Encoding::UTF_8).freeze
        end

        # The approved logical names, in approval order.
        def approved_names = @approved.values

        def approved?(logical_name) = @approved.key?(key_for(logical_name))

        # Return the MailboxIdentity for an approved logical name, or raise
        # AuthorizationError.  Nothing is sent and nothing is mutated when
        # authorization fails.
        def authorized_identity(logical_name, mode: self.mode)
          unless approved?(logical_name)
            raise AuthorizationError,
                  "mailbox is not approved: #{logical_name.inspect}"
          end
          identity_for(logical_name, mode: mode)
        end

        # Authorize +logical_name+ and issue +SELECT+ through +transport+
        # (anything responding to <tt>command(name, wire_bytes)</tt>).
        # When authorization fails, the transport is never touched.
        def select(transport, logical_name)
          identity = authorized_identity(logical_name)
          transport.command("SELECT", identity.wire_bytes)
          identity
        end

        # Split a logical name using the connection-provided delimiter.
        # Raises ModeError when the delimiter is unknown.
        def segments(logical_name)
          delimiter or raise ModeError,
            "hierarchy delimiter is unknown for this connection"
          logical_name.split(delimiter, -1)
        end

        # Join hierarchy segments using the connection-provided delimiter.
        def join(*name_segments)
          delimiter or raise ModeError,
            "hierarchy delimiter is unknown for this connection"
          name_segments.join(delimiter)
        end

        # Build a MigrationReport for +legacy_wire_names+ (modified UTF-7
        # wire bytes approved under the legacy encoding).  Nothing is sent
        # and the whitelist is not changed.
        def migration_report(legacy_wire_names)
          MigrationReport.build(legacy_wire_names)
        end

        # Commit a migration report: replaces the whitelist with the
        # migrated logical names.  Raises MigrationConflictError when the
        # report has unresolved conflicts; in that case the existing
        # approvals are left untouched.
        def apply_migration(report)
          names = report.commit!
          @approved.clear
          names.each { approve(_1) }
          names
        end

        private

        def key_for(logical_name)
          name = logical_name.encode(Encoding::UTF_8)
          (name.ascii_only? && name.casecmp?("INBOX")) ? "INBOX" : name
        end

        def encode_wire(logical_name, mode)
          case mode
          when :legacy
            Codec.encode_utf7(logical_name)
          when :utf8
            unless @utf8
              raise ModeError,
                    "server has not enabled UTF8=ACCEPT; " \
                    "refusing to send UTF-8 mailbox name " \
                    "#{logical_name.inspect}"
            end
            utf8 = logical_name.encode(Encoding::UTF_8)
            unless utf8.valid_encoding?
              raise MailboxNameError,
                    "mailbox name is not valid UTF-8: #{logical_name.inspect}"
            end
            utf8.b
          else
            raise ArgumentError, "unknown mailbox encoding mode: #{mode.inspect}"
          end
        end

        def decode_wire(wire_bytes, mode)
          case mode
          when :legacy
            Codec.decode_utf7(wire_bytes)
          when :utf8
            unless @utf8
              raise ModeError,
                    "server has not enabled UTF8=ACCEPT; " \
                    "refusing to interpret mailbox name as UTF-8"
            end
            utf8 = wire_bytes.b.dup.force_encoding(Encoding::UTF_8)
            unless utf8.valid_encoding?
              raise MailboxNameError,
                    "mailbox name is not valid UTF-8: #{wire_bytes.inspect}"
            end
            utf8
          else
            raise ArgumentError, "unknown mailbox encoding mode: #{mode.inspect}"
          end
        end
      end

      # Report on migrating approved legacy (modified UTF-7) wire names to
      # logical names that can be used in either encoding mode.
      #
      # Every entry that cannot be strictly decoded, every collision where
      # two distinct legacy names map to one identity, and every pair of
      # display-similar but distinct logical names is listed as a conflict
      # requiring manual confirmation.  #commit! refuses while any conflict
      # is unresolved, so a rejected migration sends nothing and changes no
      # existing authorization.
      class MigrationReport
        # One approved legacy wire name and its migration result.
        Entry = Data.define(:wire_bytes, :logical_name, :utf8_bytes, :error) do
          def ok? = error.nil?
        end

        # A conflict that requires manual confirmation.
        #
        # +kind+ is one of:
        # [:undecodable] legacy wire bytes that fail strict decoding.
        # [:collision]   distinct legacy names mapping to one identity.
        # [:confusable]  distinct logical names that normalize to the same
        #                display form (e.g. NFC vs NFD).
        Conflict = Data.define(:kind, :entries)

        attr_reader :entries, :conflicts

        def self.build(legacy_wire_names)
          entries = legacy_wire_names.map { build_entry(_1) }
          new(entries, find_conflicts(entries))
        end

        def self.build_entry(wire_bytes)
          wire = wire_bytes.b.freeze
          logical = Codec.decode_utf7(wire)
          Entry.new(wire_bytes: wire, logical_name: logical,
                    utf8_bytes: logical.b.freeze, error: nil)
        rescue MailboxNameError => error
          Entry.new(wire_bytes: wire, logical_name: nil, utf8_bytes: nil,
                    error: error)
        end

        def self.find_conflicts(entries)
          conflicts = []
          entries.reject(&:ok?).each do |entry|
            conflicts << Conflict.new(kind: :undecodable, entries: [entry])
          end
          valid = entries.select(&:ok?)
          valid.group_by { identity_key(_1.logical_name) }
            .each_value do |group|
            next unless group.map(&:wire_bytes).uniq.size > 1
            conflicts << Conflict.new(kind: :collision, entries: group)
          end
          valid.group_by { display_form(_1.logical_name) }
            .each_value do |group|
            next unless group.map(&:logical_name).uniq.size > 1
            conflicts << Conflict.new(kind: :confusable, entries: group)
          end
          conflicts
        end

        def self.identity_key(logical_name)
          (logical_name.ascii_only? && logical_name.casecmp?("INBOX")) \
            ? "INBOX" : logical_name
        end

        # Display similarity is used only to *flag* confusable names for
        # manual review—never to merge them.
        def self.display_form(logical_name)
          logical_name.unicode_normalize(:nfc)
        rescue StandardError
          logical_name
        end

        def initialize(entries, conflicts)
          @entries   = entries.freeze
          @conflicts = conflicts.freeze
          freeze
        end

        # True when no conflict requires manual confirmation.
        def ok? = conflicts.empty?

        # Human-readable report listing every conflict that requires
        # manual confirmation, one line per conflict.
        def summary
          lines = ["mailbox migration: %d approved name(s), %d conflict(s)" %
                   [entries.size, conflicts.size]]
          conflicts.each do |conflict|
            case conflict.kind
            when :undecodable
              conflict.entries.each do |entry|
                lines << "  undecodable: %p (%s)" %
                         [entry.wire_bytes, entry.error.message]
              end
            when :collision
              lines << "  collision: %s map to one mailbox identity" %
                       [conflict.entries.map { _1.wire_bytes.inspect }.join(", ")]
            when :confusable
              lines << "  confusable: %s look alike but are distinct" %
                       [conflict.entries.map { _1.logical_name.inspect }.join(", ")]
            end
          end
          lines.join("\n")
        end

        # The migrated logical names (deduplicated by identity key).
        # Raises MigrationConflictError when conflicts are unresolved.
        def commit!
          raise MigrationConflictError, self unless ok?
          entries.select(&:ok?).map(&:logical_name)
            .uniq { MigrationReport.identity_key(_1) }
        end
      end

    end
  end
end

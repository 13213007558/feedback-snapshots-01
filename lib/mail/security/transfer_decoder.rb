# encoding: utf-8
# frozen_string_literal: true

require 'base64'
require 'mail/security/issue'

module Mail
  module Security
    # Strict counterparts of Mail::Encodings that never silently repair or
    # discard bytes. Every decoder returns the decoded octets plus the list of
    # Issue objects describing bytes the encoding does not permit.
    #
    # Offsets always refer to the raw input string, byte for byte, so callers
    # can point back at the exact location in the original message body.
    module TransferDecoder
      module_function

      B64_ALPHABET = ('A'..'Z').to_a.concat(('a'..'z').to_a).concat(('0'..'9').to_a).concat(['+', '/']).freeze
      B64_CHARS = (B64_ALPHABET + ['=']).freeze
      HEX_CHARS = ('0'..'9').to_a.concat(('A'..'F').to_a).concat(('a'..'f').to_a).freeze

      def decode(transfer_encoding, raw_source)
        name = transfer_encoding.to_s.downcase
        case name
        when 'base64'
          decode_base64(raw_source)
        when 'quoted-printable'
          decode_quoted_printable(raw_source)
        when '7bit', '8bit', 'binary', '', 'identity'
          decode_identity(raw_source, name)
        else
          raise Mail::UnknownEncodingType, "Don't know how to strictly decode #{transfer_encoding.inspect}"
        end
      end

      # RFC 2045 section 6.8. Line breaks are the only whitespace permitted and
      # are ignored; everything outside the base64 alphabet is an error. Padding
      # must appear only at the end of a complete, correctly sized quantum.
      def decode_base64(raw_source)
        source = binary(raw_source)
        issues = []
        clean = String.new(encoding: Encoding::ASCII_8BIT)

        source.each_byte.with_index do |octet, index|
          char = octet.chr
          if char == "\r" || char == "\n"
            next
          elsif B64_CHARS.include?(char)
            clean << char
          else
            issues << Issue.new(stage: :transfer_encoding, reason: :illegal_base64_character,
                                offset: index, bytes: char,
                                message: "byte is not part of the base64 alphabet")
          end
        end

        unless clean.bytesize.modulo(4).zero?
          issues << Issue.new(stage: :transfer_encoding, reason: :truncated_base64_quantum,
                              offset: source.bytesize, bytes: String.new(encoding: Encoding::ASCII_8BIT),
                              message: "base64 stream ends with a #{clean.bytesize.modulo(4)}-byte partial quantum")
        end

        validate_base64_padding(clean, source, issues)

        decoded = begin
          Base64.strict_decode64(clean)
        rescue ArgumentError
          # Padding/quantum problems are already recorded above; fall back to
          # the tolerant unpack so a best-effort result is still available.
          clean.unpack1('m')
        end

        [decoded.dup.force_encoding(Encoding::ASCII_8BIT), issues]
      end

      # RFC 2045 section 6.7. A "=" is only legal as a soft line break or the
      # start of a valid hex escape. Malformed escapes are reported instead of
      # being passed through or dropped.
      def decode_quoted_printable(raw_source)
        source = binary(raw_source)
        issues = []
        decoded = String.new(encoding: Encoding::ASCII_8BIT)
        index = 0
        bytes = source.bytes

        while index < bytes.length
          octet = bytes[index]

          if octet == 0x3D # '='
            if source.byteslice(index, 3) == "=\r\n"
              index += 3
              next
            elsif source.byteslice(index, 2) == "=\n"
              issues << Issue.new(stage: :transfer_encoding, reason: :bare_line_break,
                                  offset: index + 1, bytes: "\n",
                                  message: 'soft line break uses bare LF instead of CRLF')
              index += 2
              next
            elsif (hex = source.byteslice(index + 1, 2)) && hex.bytesize == 2 && hex.each_char.all? { |c| HEX_CHARS.include?(c) }
              decoded << hex.to_i(16).chr
              index += 3
            else
              fragment = source.byteslice(index, [3, source.bytesize - index].min)
              issues << Issue.new(stage: :transfer_encoding, reason: :malformed_quoted_printable_escape,
                                  offset: index, bytes: fragment,
                                  message: 'quoted-printable "=" is not followed by two hex digits or CRLF')
              index += 1
            end
          elsif octet == 0x0D # CR
            if bytes[index + 1] == 0x0A
              decoded << "\r\n"
              index += 2
            else
              issues << Issue.new(stage: :transfer_encoding, reason: :bare_line_break,
                                  offset: index, bytes: "\r",
                                  message: 'bare CR is not a valid quoted-printable line break')
              decoded << "\r"
              index += 1
            end
          elsif octet == 0x0A
            issues << Issue.new(stage: :transfer_encoding, reason: :bare_line_break,
                                offset: index, bytes: "\n",
                                message: 'bare LF is not a valid quoted-printable line break')
            decoded << "\n"
            index += 1
          elsif octet <= 0x7E
            decoded << octet.chr
            index += 1
          else
            issues << Issue.new(stage: :transfer_encoding, reason: :non_ascii_quoted_printable_byte,
                                offset: index, bytes: octet.chr,
                                message: 'bytes above 0x7E must use a hex escape in quoted-printable')
            decoded << octet.chr
            index += 1
          end
        end

        [decoded, issues]
      end

      # Identity encodings do not transform octets. 7bit data must stay within
      # US-ASCII per RFC 2045; 8bit and binary pass any octet through untouched.
      def decode_identity(raw_source, name)
        source = binary(raw_source)
        issues = []
        if name == '7bit'
          source.each_byte.with_index do |octet, index|
            next if octet <= 0x7F

            issues << Issue.new(stage: :transfer_encoding, reason: :non_ascii_seven_bit_byte,
                                offset: index, bytes: octet.chr,
                                message: '7bit content must not contain octets above 0x7F')
          end
        end
        [source.dup, issues]
      end

      def validate_base64_padding(clean, source, issues)
        pad_index = clean.index('=')
        return if pad_index.nil?

        padding = clean[pad_index..]
        data = clean[0...pad_index]
        valid_padding = [padding.bytesize == 1, padding.bytesize == 2]
        unless padding.each_char.all? { |c| c == '=' } && valid_padding.any? && clean.bytesize.modulo(4).zero?
          issues << Issue.new(stage: :transfer_encoding, reason: :illegal_base64_padding,
                              offset: source.bytesize, bytes: padding,
                              message: 'base64 padding must be one or two "=" at the end of a complete quantum')
          return
        end

        if padding.bytesize == 2 && data.bytesize.modulo(4) != 2
          issues << Issue.new(stage: :transfer_encoding, reason: :illegal_base64_padding,
                              offset: source.bytesize, bytes: padding,
                              message: 'double padding requires a two-character final quantum')
        elsif padding.bytesize == 1 && data.bytesize.modulo(4) != 3
          issues << Issue.new(stage: :transfer_encoding, reason: :illegal_base64_padding,
                              offset: source.bytesize, bytes: padding,
                              message: 'single padding requires a three-character final quantum')
        end
      end

      def binary(string)
        string.to_s.dup.force_encoding(Encoding::ASCII_8BIT)
      end
      private_class_method :binary
    end
  end
end

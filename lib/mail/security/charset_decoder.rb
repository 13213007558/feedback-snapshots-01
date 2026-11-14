# encoding: utf-8
# frozen_string_literal: true

require 'mail/security/issue'

module Mail
  module Security
    # Validates transfer-decoded octets against the declared MIME charset
    # without ever substituting U+FFFD or "?" for unexplainable bytes.
    #
    # A complete result is only returned when every octet forms a legal
    # character. Invalid sequences, truncated multibyte sequences and
    # unconvertible characters are reported as Issue objects with offsets into
    # the transfer-decoded byte string.
    module CharsetDecoder
      module_function

      # Returns [utf8_string, issues]. When issues is empty the string is a
      # lossless UTF-8 transcoding of every input byte. Otherwise +nil+ is
      # returned in place of a string that would hide bytes behind replacement
      # characters.
      def decode(bytes, declared_charset)
        source = bytes.to_s.dup.force_encoding(Encoding::ASCII_8BIT)
        charset = resolve_charset(declared_charset)

        unless charset
          issue = Issue.new(stage: :charset, reason: :unknown_charset,
                            offset: 0, bytes: source,
                            message: "unknown or unsupported charset #{declared_charset.inspect}")
          return [nil, [issue]]
        end

        issues = scan(source, charset)
        return [transcode_lossless(source, charset), issues] if issues.empty?

        [nil, issues]
      end

      def resolve_charset(declared_charset)
        name = declared_charset.nil? || declared_charset.to_s.empty? ? 'US-ASCII' : declared_charset

        # Encoding.find recognizes genuine charset names/aliases and raises for
        # made-up declarations. Mail::Utilities.pick_encoding would otherwise
        # hide those by falling back to BINARY, which accepts every byte.
        begin
          Encoding.find(name)
        rescue ArgumentError
          return nil
        end

        picked = Mail::Utilities.pick_encoding(name)
        return nil if picked == Encoding::ASCII_8BIT && name.to_s.downcase != 'binary'

        Encoding.find(picked)
      rescue ArgumentError
        nil
      end

      # Walk the converter one error at a time. The converter leaves the bytes
      # it cannot consume at the front of +src+, which gives the exact byte
      # offset of each failure without re-scanning accepted input.
      def scan(source, charset)
        target = charset == Encoding::UTF_8 ? Encoding::UTF_16BE : Encoding::UTF_8
        issues = []
        offset = 0

        while offset < source.bytesize
          converter = Encoding::Converter.new(charset, target)
          src = source.byteslice(offset..).dup
          dst = String.new(encoding: Encoding::ASCII_8BIT)
          result = converter.primitive_convert(src, dst)
          info = converter.primitive_errinfo
          bad_offset = offset + (source.bytesize - offset - src.bytesize)

          case result
          when :finished
            break
          when :invalid_byte_sequence
            bad = info[3].to_s
            bad = source.byteslice(bad_offset, 1) if bad.empty?
            issues << Issue.new(stage: :charset, reason: :invalid_byte_sequence,
                                offset: bad_offset, bytes: bad,
                                message: "byte sequence is not valid #{charset}")
            offset = bad_offset + bad.bytesize
          when :undefined_conversion
            bad = info[3].to_s
            bad = source.byteslice(bad_offset, 1) if bad.empty?
            issues << Issue.new(stage: :charset, reason: :undefined_conversion,
                                offset: bad_offset, bytes: bad,
                                message: "character has no UTF-8 representation")
            offset = bad_offset + bad.bytesize
          when :incomplete_input
            trail = info[3].to_s
            start = source.bytesize - trail.bytesize
            issues << Issue.new(stage: :charset, reason: :truncated_multibyte_sequence,
                                offset: start, bytes: source.byteslice(start..),
                                message: "truncated multibyte sequence at end of #{charset} input")
            break
          else
            issues << Issue.new(stage: :charset, reason: :unexplainable_bytes,
                                offset: bad_offset, bytes: src,
                                message: "charset conversion stopped with #{result}")
            break
          end
        end

        issues
      end

      def transcode_lossless(source, charset)
        if charset == Encoding::UTF_8
          source.dup.force_encoding(Encoding::UTF_8)
        else
          source.encode(Encoding::UTF_8, charset)
        end
      end
    end
  end
end

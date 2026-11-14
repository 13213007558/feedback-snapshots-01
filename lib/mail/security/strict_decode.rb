# encoding: utf-8
# frozen_string_literal: true

require 'mail/security/issue'
require 'mail/security/transfer_decoder'
require 'mail/security/charset_decoder'
require 'mail/security/decode_result'

module Mail
  module Security
    # Security-oriented entry point for decoding a MIME body.
    #
    # Unlike Mail::Encodings / Mail::Message#decoded, which are tuned for
    # displaying something even for malformed input, this module keeps a strict
    # account of every byte. Callers learn separately whether the transfer
    # encoding stage and the charset stage were complete, and receive Issue
    # objects pointing at any raw byte neither stage could explain.
    module StrictDecode
      module_function

      # Decode a raw body string.
      #
      #   result = Mail::Security::StrictDecode.decode(raw_body,
      #                                               transfer_encoding: part.body.encoding,
      #                                               charset: part.charset)
      #   result.complete?          # => true only when no byte was lost
      #   result.transfer_encoding_complete?
      #   result.charset_complete?
      #   result.issues             # => [Mail::Security::Issue, ...]
      def decode(raw_source, transfer_encoding:, charset:, media_type: 'text')
        text_media = media_type.to_s.downcase == 'text'
        transfer_bytes, transfer_issues =
          begin
            TransferDecoder.decode(transfer_encoding, raw_source)
          rescue Mail::UnknownEncodingType => e
            issue = Issue.new(stage: :transfer_encoding, reason: :unknown_transfer_encoding,
                              offset: 0, bytes: raw_source.to_s, message: e.message)
            [binary(raw_source), [issue]]
          end

        strict_text, charset_issues =
          if transfer_issues.any?
            # The byte stream is already untrustworthy, so charset validation
            # could only produce misleading secondary errors. Record that the
            # stage never produced a complete result instead.
            [nil, [Issue.new(stage: :charset, reason: :stage_skipped_after_transfer_failure,
                             offset: 0, bytes: transfer_bytes,
                             message: 'charset stage skipped because transfer decoding was incomplete')]]
          elsif !text_media
            # RFC 2045 section 6.1: charset has no meaning for non-text media.
            [nil, []]
          else
            CharsetDecoder.decode(transfer_bytes, charset)
          end

        lenient_charset = text_media ? charset : nil
        lenient_text = tolerant_decode(raw_source, transfer_encoding, lenient_charset)

        DecodeResult.new(transfer_encoding: transfer_encoding.to_s,
                         charset: charset,
                         transfer_decoded_bytes: transfer_bytes,
                         transfer_issues: transfer_issues,
                         charset_issues: charset_issues,
                         strict_text: strict_text,
                         lenient_text: lenient_text,
                         charset_applicable: text_media)
      end

      # Decode a Mail::Part or Mail::Message leaf directly from its raw source.
      def decode_part(part)
        media_type = part.respond_to?(:main_type) ? part.main_type : 'text'
        decode(part.body.raw_source,
               transfer_encoding: part.body.encoding,
               charset: part.charset,
               media_type: media_type)
      end

      # Reproduces the gem's historical, display-oriented decoding so callers
      # can still render the message. Replacement characters may be present, so
      # this text must never be auto-marked as a completed scan.
      def tolerant_decode(raw_source, transfer_encoding, charset)
        encoding_class = Mail::Encodings.get_encoding(transfer_encoding.to_s.downcase)
        decoded =
          if encoding_class
            encoding_class.decode(raw_source.to_s)
          else
            raw_source.to_s.dup.force_encoding(Encoding::ASCII_8BIT)
          end

        return decoded unless charset

        Mail::Encodings.transcode_charset(decoded, charset, 'UTF-8')
      rescue StandardError
        decoded
      end

      def binary(string)
        string.to_s.dup.force_encoding(Encoding::ASCII_8BIT)
      end
    end
  end
end

# encoding: utf-8
# frozen_string_literal: true

require 'mail/constants'

module Mail
  module SMIME
    # Locates the signed MIME entity inside a multipart/signed message
    # without rewriting a single byte.
    #
    # RFC 2046 says the CRLF that precedes a boundary delimiter belongs to
    # the delimiter, not to the body part it follows. RFC 8551 requires the
    # first part of a multipart/signed body to be hashed exactly as it was
    # received, so this class slices the caller's raw octets instead of
    # serialising parsed parts through Mail::Message#encoded.
    class MimeEntity
      # Raised when the received message is not a verifiable
      # multipart/signed message.
      class ParseError < StandardError
        attr_reader :reason

        def initialize(reason, message = nil)
          @reason = reason
          super(message || reason.to_s)
        end
      end

      DEFAULT_PROTOCOL = 'application/pkcs7-signature'
      # OpenSSL's smime command and older clients emit the historical
      # x-pkcs7-signature alias. Both names identify CMS SignedData and are
      # treated as conforming; anything else is a protocol mismatch.
      CMS_PROTOCOLS = [
        'application/pkcs7-signature',
        'application/x-pkcs7-signature'
      ].freeze

      attr_reader :raw_source, :boundary, :protocol, :micalg

      # raw_source must be the exact octets received for the whole message.
      def initialize(raw_source)
        @raw_source = raw_source.to_s.dup.force_encoding(Encoding::BINARY)
        @protocol = nil
        @micalg = nil
      end

      # Returns the raw octets of the MIME entity that the signature covers.
      def signed_content
        extract!
        @signed_content
      end

      # Returns the raw octets of the application/pkcs7-signature part body.
      def signature_part_body
        extract!
        @signature_part_body
      end

      def signature_part_headers
        extract!
        @signature_part_headers
      end

      # True when the multipart/signed Content-Type carries a CMS signature
      # protocol (RFC 8551 name or the historical x-pkcs7 alias).
      def protocol_valid?
        extract!
        CMS_PROTOCOLS.include?(@protocol.to_s.downcase)
      end

      # Number of body parts in the multipart/signed body. A conforming
      # message has exactly two: the signed entity and the signature.
      def part_count
        extract!
        @parts.length
      end

      # True when the second body part carries a Content-Type header starting
      # with application/pkcs7-signature (or its historical x- alias).
      def signature_part_content_type
        extract!
        return nil if @signature_part_headers.to_s.empty?

        value = Mail::Header.new(@signature_part_headers)['content-type']
        value = value.value if value.respond_to?(:value)
        value.to_s
      end

      # Returns the message-level Content-Type parameters as parsed from the
      # raw header, preserving values such as "application/pkcs7-signature".
      def content_type_parameters
        extract!
        @content_type_parameters
      end

      def content_type_value
        extract!
        @content_type_value
      end

      private

      def extract!
        return if @extracted

        header_block, body = split_message
        parse_content_type(header_block)
        locate_boundary(body)
        @extracted = true
      end

      def split_message
        # Find the first empty line using the exact received octets. Accept
        # bare LF as well as CRLF, but never normalise the bytes we return.
        match = @raw_source.match(/\r?\n\r?\n/)
        unless match
          raise ParseError.new(:not_multipart_signed, 'message has no header/body separator')
        end

        header_block = @raw_source[0, match.begin(0)]
        body = @raw_source[(match.end(0))..-1] || ''.b
        [header_block, body]
      end

      def parse_content_type(header_block)
        value = Mail::Header.new(header_block)['content-type']
        value = value.value if value.respond_to?(:value)

        @content_type_value = value.to_s
        if @content_type_value.empty?
          raise ParseError.new(:not_multipart_signed, 'message has no Content-Type header')
        end

        unless %r{\Amultipart/signed\b}i.match?(@content_type_value.strip)
          raise ParseError.new(:not_multipart_signed, "message is #{@content_type_value.inspect}, not multipart/signed")
        end

        @content_type_parameters = Mail::ContentTypeField.new(@content_type_value).parameters
        @protocol = @content_type_parameters['protocol']
        @micalg = @content_type_parameters['micalg']
        @boundary = @content_type_parameters['boundary']
        raise ParseError.new(:missing_boundary, 'multipart/signed has no boundary parameter') if @boundary.to_s.empty?
      end

      def locate_boundary(body)
        delimiter = "--#{@boundary}".b
        unless body.include?(delimiter)
          raise ParseError.new(:missing_boundary, 'multipart/signed boundary not found in body')
        end

        segments = split_on_boundary(body, delimiter)

        unless segments
          raise ParseError.new(:missing_boundary, 'multipart/signed boundary not found in body')
        end

        open_segments = segments.reject { |s| s[:closing] }
        if open_segments.empty?
          raise ParseError.new(:missing_signature, 'multipart/signed has no body parts')
        end

        @signed_content = open_segments[0][:body]
        @parts = open_segments.map { |s| s[:body] }
        @signature_part_headers = ''.b
        @signature_part_body = ''.b
        return if open_segments.length < 2

        sig = open_segments[1]
        headers, signature_body = split_part(sig[:body])
        unless header_lines?(headers)
          signature_body = sig[:body]
          headers = ''.b
        end
        @signature_part_headers = headers
        @signature_part_body = signature_body || ''.b
      end

      # Splits a body on boundary delimiter lines. Returns an array of hashes
      # with :body (bytes between the delimiter line and the next delimiter)
      # and :closing. Returns nil if the boundary is absent.
      def split_on_boundary(body, delimiter)
        segments = []
        current = nil
        pos = 0
        length = body.bytesize
        found = false

        while pos <= length
          line_end = body.index("\n", pos)
          line_end = length - 1 if line_end.nil?
          line = body[pos..line_end] || ''.b
          content = line.sub(/\r?\n\z/, '')

          if content.start_with?(delimiter)
            rest = content[delimiter.bytesize..-1] || ''
            if rest.match?(/\A[ \t]*(?:--[ \t]*)?\z/)
              found = true
              current[:body] = current[:body].sub(/\r?\n\z/, '') if current
              closing = rest.strip.start_with?('--')
              segments << { body: ''.b, closing: closing }
              current = segments.last
            elsif current
              current[:body] << line
            end
          elsif current
            current[:body] << line
          end

          break if line_end >= length - 1
          pos = line_end + 1
        end

        found ? segments : nil
      end

      def split_part(part)
        match = part.match(/\r?\n\r?\n/)
        if match
          [part[0, match.begin(0)], part[(match.end(0))..-1] || ''.b]
        else
          [part.sub(/\r?\n\z/, ''), ''.b]
        end
      end

      def header_lines?(headers)
        return false if headers.to_s.empty?
        first = headers.split(/\r?\n/, 2).first
        first.to_s.match?(/\A[!#-9;-~]+:/)
      end
    end
  end
end

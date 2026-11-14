# frozen_string_literal: true

module Rack
  module MessageSignatures
    # A deliberately small and strict parser for the parts of RFC 8941
    # Structured Fields used by RFC 9421.  It does not attempt to infer the
    # type of arbitrary application fields; unsupported field types are
    # rejected by the verifier instead.
    module StructuredFields
      class ParseError < StandardError; end

      Item = Struct.new(:value, :parameters)
      InnerList = Struct.new(:items, :parameters)
      Bytes = Struct.new(:data)
      Token = Struct.new(:value)
      Decimal = Struct.new(:text)

      KEY_START = /\A[a-z*]\z/
      KEY_CHAR = /\A[a-z0-9_.*-]\z/
      TOKEN_START = /\A[A-Za-z*]\z/
      TOKEN_CHAR = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z:\/]\z/
      BASE64_CHAR = /\A[A-Za-z0-9+\/=]\z/
      INTEGER = /\A-?\d{1,15}\z/
      DECIMAL = /\A-?\d{1,12}\.\d{1,3}\z/

      module_function

      def parse_dictionary(value, strict_duplicates: false)
        Parser.new(value, strict_duplicates: strict_duplicates).parse_dictionary
      end

      def parse_item(value, strict_duplicates: false)
        Parser.new(value, strict_duplicates: strict_duplicates).parse_item
      end

      def serialize_item(item)
        serialize_bare(item.value) + serialize_parameters(item.parameters)
      end

      def serialize_inner_list(inner_list)
        "(" + inner_list.items.map { |item| serialize_item(item) }.join(" ") + ")" +
          serialize_parameters(inner_list.parameters)
      end

      def serialize_parameters(parameters)
        parameters.map do |key, value|
          if value.equal?(true)
            ";#{key}"
          else
            ";#{key}=#{serialize_bare(value)}"
          end
        end.join
      end

      def serialize_bare(value)
        case value
        when Item, InnerList
          raise ParseError, "nested item cannot be serialized as a bare item"
        when Bytes
          ":" + [value.data].pack("m0") + ":"
        when Token
          value.value
        when Decimal
          value.text
        when Integer
          value.to_s
        when String
          raise ParseError, "non-ASCII string" unless value.ascii_only?

          '"' + value.gsub(/["\\]/) { |character| "\\#{character}" } + '"'
        when true
          "?1"
        when false
          "?0"
        else
          raise ParseError, "unsupported structured field value"
        end
      end

      class Parser
        def initialize(value, strict_duplicates: false)
          unless value.is_a?(String)
            raise ParseError, "structured field value must be a String"
          end

          # RFC 8941 only defines an ASCII serialization.  In particular, a
          # newline in a Rack environment value would mean that the server had
          # already merged separate field lines in an unknown way, so it must
          # not be treated as an ordinary separator.
          unless value.ascii_only?
            raise ParseError, "structured field value is not ASCII"
          end
          if value.include?("\r") || value.include?("\n") || value.include?("\0")
            raise ParseError, "structured field value contains a line break"
          end

          @value = value
          @position = 0
          @strict_duplicates = strict_duplicates
        end

        def parse_dictionary
          skip_sp
          dictionary = {}

          until eof?
            key = parse_key

            member =
              if peek == "="
                advance
                parse_item_or_inner_list
              else
                Item.new(true, parse_parameters)
              end

            if dictionary.key?(key) && @strict_duplicates
              raise ParseError, "duplicate dictionary key"
            end
            dictionary[key] = member

            skip_ows
            break if eof?

            expect(",")
            skip_ows
            raise ParseError, "trailing comma in dictionary" if eof?
          end

          skip_ows
          raise ParseError, "trailing data after dictionary" unless eof?

          dictionary
        end

        def parse_item
          item = parse_item_or_inner_list
          unless item.is_a?(Item)
            raise ParseError, "expected an item"
          end

          skip_ows
          raise ParseError, "trailing data after item" unless eof?

          item
        end

        private

        def parse_item_or_inner_list
          if peek == "("
            parse_inner_list
          else
            Item.new(parse_bare_item, parse_parameters)
          end
        end

        def parse_inner_list
          expect("(")
          items = []

          loop do
            skip_sp

            if peek == ")"
              advance
              return InnerList.new(items, parse_parameters)
            end

            items << Item.new(parse_bare_item, parse_parameters)

            unless peek == " " || peek == ")"
              raise ParseError, "inner list members must be separated by spaces"
            end
          end
        end

        def parse_parameters
          parameters = {}

          while peek == ";"
            advance
            skip_sp
            key = parse_key

            value =
              if peek == "="
                advance
                parse_bare_item
              else
                true
              end

            if parameters.key?(key) && @strict_duplicates
              raise ParseError, "duplicate parameter key"
            end
            parameters[key] = value
          end

          parameters
        end

        def parse_key
          first = peek
          unless first && KEY_START.match?(first)
            raise ParseError, "invalid structured field key"
          end

          key = +""
          while (character = peek) && KEY_CHAR.match?(character)
            key << character
            advance
          end
          key
        end

        def parse_bare_item
          case peek
          when '"'
            parse_string
          when ":"
            parse_bytes
          when "?"
            parse_boolean
          when "-", /\d/
            parse_number
          when TOKEN_START
            parse_token
          else
            raise ParseError, "invalid structured field item"
          end
        end

        def parse_string
          expect('"')
          result = +""

          until eof?
            character = peek
            advance

            case character
            when '"'
              return result
            when "\\"
              escaped = peek
              unless escaped == '"' || escaped == "\\"
                raise ParseError, "invalid string escape"
              end
              result << escaped
              advance
            else
              unless character.ord >= 0x20 && character.ord <= 0x7e
                raise ParseError, "invalid character in string"
              end
              result << character
            end
          end

          raise ParseError, "unterminated string"
        end

        def parse_bytes
          expect(":")
          encoded = +""

          until eof?
            character = peek
            if character == ":"
              advance
              return Bytes.new(decode_base64(encoded))
            end

            unless BASE64_CHAR.match?(character)
              raise ParseError, "invalid character in byte sequence"
            end
            encoded << character
            advance
          end

          raise ParseError, "unterminated byte sequence"
        end

        def decode_base64(encoded)
          # RFC 8941 permits unpadded input and does not require rejection of
          # non-zero pad bits. Padding is synthesized before decoding.
          return "" if encoded.empty?

          unless encoded.match?(/\A[A-Za-z0-9+\/]*={0,2}\z/) &&
              encoded.length % 4 != 1
            raise ParseError, "invalid base64 in byte sequence"
          end

          padded = encoded.dup
          padding = (4 - padded.length % 4) % 4
          padded << ("=" * padding)

          begin
            padded.unpack1("m0")
          rescue ArgumentError
            raise ParseError, "invalid base64 in byte sequence"
          end
        end

        def parse_boolean
          expect("?")
          case peek
          when "0"
            advance
            false
          when "1"
            advance
            true
          else
            raise ParseError, "invalid boolean"
          end
        end

        def parse_number
          start = @position
          advance if peek == "-"

          digits = 0
          while (character = peek) && character.match?(/\d/)
            digits += 1
            advance
          end
          raise ParseError, "invalid number" if digits.zero?

          if peek == "."
            advance
            fraction = 0
            while (character = peek) && character.match?(/\d/)
              fraction += 1
              advance
            end
            raise ParseError, "invalid decimal" if fraction.zero? || fraction > 3

            text = @value[start...@position]
            raise ParseError, "invalid decimal" unless DECIMAL.match?(text)
            Decimal.new(text)
          else
            text = @value[start...@position]
            raise ParseError, "invalid integer" unless INTEGER.match?(text)
            text.to_i
          end
        end

        def parse_token
          first = peek
          unless first && TOKEN_START.match?(first)
            raise ParseError, "invalid token"
          end

          token = +""
          while (character = peek) && TOKEN_CHAR.match?(character)
            token << character
            advance
          end
          Token.new(token)
        end

        def skip_sp
          advance while peek == " "
        end

        def skip_ows
          advance while peek == " " || peek == "\t"
        end

        def expect(character)
          unless peek == character
            raise ParseError, "expected #{character.inspect}"
          end
          advance
        end

        def peek
          @value[@position]
        end

        def advance
          @position += 1
        end

        def eof?
          @position >= @value.length
        end
      end
    end
  end
end

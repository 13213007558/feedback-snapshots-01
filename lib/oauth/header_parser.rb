# frozen_string_literal: true

require "strscan"

require "oauth/errors"

module OAuth
  # A grammar-driven parser for the +Authorization+ and +WWW-Authenticate+
  # headers used by OAuth 1.0 (RFC 5849, section 3.5.1) and the HTTP
  # authentication framework (RFC 7235, section 2.1).
  #
  # Unlike a regular-expression +split+ on +,+, +-+ and +=+, this parser is
  # driven by the header grammar itself, so punctuation embedded inside a
  # quoted string cannot be mistaken for structural delimiters:
  #
  #   auth-scheme   = "OAuth"
  #   #auth-params  = auth-param *( OWS "," OWS auth-param )
  #   auth-param    = token "=" ( token / quoted-string )
  #   quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
  #   quoted-pair   = "\" ( HTAB / SP / VCHAR / obs-text )
  #
  # OAuth values are additionally percent-encoded (RFC 5849 section 3.6): a
  # literal +"+ must therefore be followed by exactly two hexadecimal digits.
  # Any deviation (a bare delimiter outside quotes, an unterminated string, an
  # illegal escape, a malformed +%+ sequence or a repeated parameter name)
  # raises OAuth::Problem instead of silently accepting or rewriting the
  # credential.
  class HeaderParser
    # RFC 5234 / RFC 7230 token characters: any VCHAR except separators.
    TOKEN_CHARS = /[!#$%&'*+\-.^_`|~0-9A-Za-z]+/.freeze
    HEX_DIGITS = /[0-9A-Fa-f]/.freeze

    def self.parse(header)
      new(header).parse
    end

    def initialize(header)
      raise OAuth::Problem, "Invalid authorization header" unless header.is_a?(String)

      @scanner = StringScanner.new(header)
      @params = {}
    end

    def parse
      consume_scheme
      parse_auth_params
      @params
    end

    private

    def consume_scheme
      @scanner.skip(/[ \t]*/)
      # The scheme token is matched literally and must end at a non-token
      # boundary; the request proxies only invoke the parser once the
      # "OAuth " prefix has already been observed. A bare "OAuth" with no
      # params at all is accepted and yields an empty hash.
      raise OAuth::Problem, "Invalid authorization header" unless @scanner.scan(/OAuth(?![!#$%&'*+\-.^_`|~0-9A-Za-z])/)

      @scanner.scan(/[ \t]+/)
    end

    def parse_auth_params
      loop do
        # An empty parameter list ("OAuth ") is accepted and yields {}.
        return if end_of_header?

        name = parse_name
        parse_equals
        value = parse_value
        register(name, value)

        return if end_of_header?

        parse_delimiter
      end
    end

    # Optional linear whitespace is permitted after the scheme token and after
    # every auth-param, including the final one before end of string.
    def end_of_header?
      @scanner.skip(/[ \t]*/)
      @scanner.eos?
    end

    def parse_name
      name = @scanner.scan(TOKEN_CHARS)
      raise OAuth::Problem, "Invalid authorization header" if name.nil? || name.empty?

      name
    end

    def parse_equals
      @scanner.skip(/[ \t]*/)
      raise OAuth::Problem, "Invalid authorization header" unless @scanner.scan(/=/)

      @scanner.skip(/[ \t]*/)
    end

    def parse_value
      if @scanner.peek(1) == '"'
        parse_quoted_string
      else
        parse_token_value
      end
    end

    def parse_token_value
      value = @scanner.scan(TOKEN_CHARS)
      raise OAuth::Problem, "Invalid authorization header" if value.nil? || value.empty?

      strict_percent_decode(value)
    end

    def parse_quoted_string
      @scanner.getch # consume opening DQUOTE
      raw = +""

      loop do
        char = @scanner.getch
        raise OAuth::Problem, "Invalid authorization header" if char.nil?

        case char
        when '"'
          return strict_percent_decode(raw)
        when "\\"
          escaped = @scanner.getch
          raise OAuth::Problem, "Invalid authorization header" if escaped.nil? || !quoted_pair_byte?(escaped.ord)

          raw << escaped
        else
          raise OAuth::Problem, "Invalid authorization header" unless qdtext_byte?(char.ord)

          raw << char
        end
      end
    end

    def parse_delimiter
      @scanner.skip(/[ \t]*/)
      raise OAuth::Problem, "Invalid authorization header" unless @scanner.scan(/,/)

      @scanner.skip(/[ \t]*/)
      # A dangling comma with no following auth-param is malformed.
      raise OAuth::Problem, "Invalid authorization header" if @scanner.eos?
    end

    def register(name, value)
      # Repeated parameter names are ambiguous: a Hash would silently keep one
      # of the values depending on insertion order, letting an attacker supply
      # an extra field that overrides the credential being verified.
      raise OAuth::Problem, "Invalid authorization header" if @params.key?(name)

      @params[name] = value
    end

    # qdtext: HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text (RFC 7230).
    def qdtext_byte?(byte)
      byte == 0x09 || byte == 0x20 || byte == 0x21 ||
        (byte >= 0x23 && byte <= 0x5B) || (byte >= 0x5D && byte <= 0x7E) ||
        byte >= 0x80
    end

    # quoted-pair second character: HTAB / SP / VCHAR / obs-text.
    def quoted_pair_byte?(byte)
      byte == 0x09 || byte == 0x20 || (byte >= 0x21 && byte <= 0x7E) || byte >= 0x80
    end

    # Decode RFC 3986 percent-escapes while rejecting malformed sequences. A
    # literal "%" that is not followed by exactly two hexadecimal digits is an
    # encoding error rather than data, so it must never reach the verifier.
    def strict_percent_decode(value)
      bytes = value.dup.force_encoding(Encoding::ASCII_8BIT)
      decoded = +""
      index = 0

      while index < bytes.bytesize
        byte = bytes.getbyte(index)

        if byte == 0x25 # "%"
          hex = bytes.byteslice(index + 1, 2)
          raise OAuth::Problem, "Invalid authorization header" if hex.nil? || hex.length != 2 || hex !~ /\A#{HEX_DIGITS}{2}\z/

          decoded << hex.to_i(16).chr
          index += 3
        else
          decoded << byte.chr
          index += 1
        end
      end

      decoded.force_encoding(Encoding::UTF_8)
    end
  end
end

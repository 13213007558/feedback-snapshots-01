# frozen_string_literal: true
require "secure_headers/utils/cookies_config"

module SecureHeaders
  class CookiesConfigError < StandardError; end
  class Cookie
    # RFC 6265 cookie-name: a token.
    COOKIE_NAME = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/
    # Bytes that would split or terminate the header field on the wire.
    INVALID_COOKIE_BYTES = /[\x00-\x08\x0A-\x1F\x7F]/n.freeze
    SAMESITE_VALUES = %w(none lax strict).freeze

    def self.validate_config!(config)
      CookiesConfig.new(config).validate!
    end

    attr_reader :raw_cookie, :config

    COOKIE_DEFAULTS = {
      httponly: true,
      secure: true,
      samesite: { lax: true },
    }.freeze

    def initialize(cookie, config)
      @raw_cookie = cookie
      unless config == OPT_OUT
        config ||= {}
        config = COOKIE_DEFAULTS.merge(config)
      end
      @config = config
      @attributes = {
        httponly: nil,
        secure: nil,
      }
      @cookie_name = nil
      @valid_cookie = false
      @invalid_samesite_segments = []
      @valid_samesite_value = nil
      @samesite_present = false

      parse(cookie)
    end

    def to_s
      return @raw_cookie if @raw_cookie.nil?
      return @raw_cookie.dup unless @valid_cookie
      return @raw_cookie.dup if config == OPT_OUT

      encoding = @raw_cookie.encoding
      output = @raw_cookie.b
      normalize_samesite!(output)
      output << "; secure" if secure?
      output << "; HttpOnly" if httponly?
      output << "; #{samesite_cookie}" if samesite?
      output.force_encoding(encoding)
    end

    def secure?
      flag_cookie?(:secure) && !already_flagged?(:secure)
    end

    def httponly?
      flag_cookie?(:httponly) && !already_flagged?(:httponly)
    end

    def samesite?
      flag_samesite? && !@samesite_present
    end

    private

    def already_flagged?(attribute)
      @attributes[attribute]
    end

    def flag_cookie?(attribute)
      return false if config == OPT_OUT
      case config[attribute]
      when TrueClass
        true
      when Hash
        conditionally_flag?(config[attribute])
      else
        false
      end
    end

    def conditionally_flag?(configuration)
      only = Array(configuration[:only])
      except = Array(configuration[:except])

      if only.any?
        only.include?(@cookie_name)
      elsif except.any?
        !except.include?(@cookie_name)
      else
        false
      end
    end

    def samesite_cookie
      if flag_samesite_lax?
        "SameSite=Lax"
      elsif flag_samesite_strict?
        "SameSite=Strict"
      elsif flag_samesite_none?
        "SameSite=None"
      end
    end

    def flag_samesite?
      return false if config == OPT_OUT || config[:samesite] == OPT_OUT
      flag_samesite_lax? || flag_samesite_strict? || flag_samesite_none?
    end

    def flag_samesite_lax?
      flag_samesite_enforcement?(:lax)
    end

    def flag_samesite_strict?
      flag_samesite_enforcement?(:strict)
    end

    def flag_samesite_none?
      flag_samesite_enforcement?(:none)
    end

    def flag_samesite_enforcement?(mode)
      return unless config[:samesite]

      if config[:samesite].is_a?(TrueClass) && mode == :lax
        return true
      end

      case config[:samesite][mode]
      when Hash
        conditionally_flag?(config[:samesite][mode])
      when TrueClass
        true
      else
        false
      end
    end

    # Parses a single Set-Cookie line. Only the first `;`-delimited segment is
    # the cookie-pair; every later segment is an attribute. Commas, percent
    # escapes, and names that merely resemble Secure/HttpOnly/SameSite are
    # never treated as those attributes.
    #
    # A line that is structurally unusable (no cookie-pair, a non-token name,
    # or control bytes that could split the field) is left untouched: flagging
    # it would risk rewriting a value we cannot delimit reliably.
    def parse(cookie)
      return unless cookie

      cookie = cookie.to_s.b
      return if INVALID_COOKIE_BYTES.match?(cookie)
      pair_end = cookie.index(";") || cookie.length
      name, separator, = cookie[0...pair_end].partition("=")
      return if separator.empty?
      name = name.sub(/\A[ \t]+/, "").sub(/[ \t]+\z/, "")
      return unless COOKIE_NAME.match?(name)

      @cookie_name = name
      @valid_cookie = true

      segment_start = pair_end
      while (separator_index = cookie.index(";", segment_start))
        segment_start = separator_index + 1
        segment_end = cookie.index(";", segment_start) || cookie.length
        parse_attribute(cookie, segment_start, segment_end)
        segment_start = segment_end
      end
    end

    def parse_attribute(cookie, segment_start, segment_end)
      segment = cookie[segment_start...segment_end]
      return if segment.nil?

      stripped = segment.sub(/\A[ \t]+/, "")
      name_start = segment_start + (segment.length - stripped.length)
      attribute, separator, attribute_value = stripped.partition("=")
      attribute = attribute.sub(/[ \t]+\z/, "")
      return if attribute.empty?

      case attribute.downcase
      when "secure"
        @attributes[:secure] = true
      when "httponly"
        @attributes[:httponly] = true
      when "samesite"
        @samesite_present = true
        value = if separator.empty?
          nil
        else
          attribute_value.sub(/\A[ \t]+/, "").sub(/[ \t]+\z/, "")
        end
        if SAMESITE_VALUES.include?(value&.downcase)
          @valid_samesite_value = value
        else
          value_end = name_start + stripped.sub(/[ \t]+\z/, "").length
          @invalid_samesite_segments << (name_start...value_end)
        end
      end
    end

    # Missing or unknown SameSite values provide no protection. Rewrite each
    # invalid value in place instead of appending a second SameSite attribute,
    # because parsers disagree about which duplicate wins. When a valid
    # SameSite value already exists, its value is reused so normalization does
    # not change the effective policy.
    def normalize_samesite!(cookie)
      return if @invalid_samesite_segments.empty?
      return unless flag_samesite?

      replacement = if @valid_samesite_value
        "SameSite=#{@valid_samesite_value}"
      else
        samesite_cookie
      end
      return unless replacement

      @invalid_samesite_segments.reverse_each do |range|
        cookie[range] = replacement
      end
    end
  end
end

# frozen_string_literal: true

module SecureHeaders
  module CspChangeChecker
    # Parses the *generated* Content-Security-Policy header value (the output of
    # SecureHeaders::ContentSecurityPolicy#value) into directive => token set.
    #
    # The parser deliberately models only the source grammar the checker can
    # reason about soundly. Anything outside that grammar is kept verbatim and
    # flagged as unsupported, so a caller can never receive a "provably
    # tightened" verdict based on syntax the checker does not understand.
    module EffectivePolicyParser
      module_function

      # Directives whose source lists the checker understands.
      SUPPORTED_FETCH_DIRECTIVES = PolicyManagement::FETCH_SOURCES - [
        PolicyManagement::TRUSTED_TYPES
      ]
      # Non-fetch source-list directives that are still allow-lists of URLs.
      SUPPORTED_NON_FETCH_DIRECTIVES = [
        PolicyManagement::BASE_URI,
        PolicyManagement::FORM_ACTION,
        PolicyManagement::FRAME_ANCESTORS
      ].freeze
      SUPPORTED_DIRECTIVES =
        (SUPPORTED_FETCH_DIRECTIVES + SUPPORTED_NON_FETCH_DIRECTIVES).freeze

      # Reporting plumbing never enforces an allow-list on page resources.
      REPORTING_DIRECTIVES = [PolicyManagement::REPORT_URI, PolicyManagement::REPORT_TO].freeze

      DISCRETE_KEYWORDS = [
        PolicyManagement::SELF,
        PolicyManagement::UNSAFE_INLINE,
        PolicyManagement::UNSAFE_EVAL
      ].freeze

      SCHEME_REGEXP = %r{\A([a-z][a-z0-9+.\-]*):\z}i
      HOST_REGEXP = %r{
        \A
        (?:(?<scheme>[a-z][a-z0-9+.\-]*)://)?
        (?<host>\*\.[a-z0-9.\-]+|[a-z0-9.\-]+)
        (?::(?<port>\*\*|\d+))?
        (?:/(?<path>\S*))?
        \z
      }xi
      NONCE_REGEXP = %r{\A'nonce-}i
      HASH_REGEXP = %r{\A'(sha256|sha384|sha512)-}i
      NONE = PolicyManagement::NONE

      ParsedPolicy = Struct.new(:directives, :unsupported, :ignored, keyword_init: true)
      UnsupportedToken = Struct.new(:directive, :token, :reason, keyword_init: true)

      def parse(header_value)
        directives = {}
        unsupported = []
        ignored = []

        header_value.to_s.split(";").each do |raw_directive|
          parts = raw_directive.strip.split(/\s+/)
          next if parts.empty?

          directive = parts.shift.tr("-", "_").to_sym
          tokens = parts

          if REPORTING_DIRECTIVES.include?(directive)
            ignored << directive
            next
          end

          unless SUPPORTED_DIRECTIVES.include?(directive)
            tokens.each do |token|
              unsupported << UnsupportedToken.new(
                directive: directive, token: token,
                reason: "directive #{directive} is outside the checker's supported set"
              )
            end
            # A directive we cannot model at all (sandbox, upgrade-insecure-requests,
            # trusted-types, ...) is recorded with an empty token set but flagged.
            directives[directive] = []
            next
          end

          parsed_tokens = tokens.map do |token|
            classify_token(directive, token, unsupported)
          end
          directives[directive] = parsed_tokens
        end

        ParsedPolicy.new(
          directives: directives,
          unsupported: unsupported,
          ignored: ignored.uniq
        )
      end

      def classify_token(directive, token, unsupported)
        if token == NONE
          { kind: :none, raw: token }
        elsif DISCRETE_KEYWORDS.include?(token)
          { kind: :keyword, raw: token, keyword: token }
        elsif token == PolicyManagement::STAR
          { kind: :star, raw: token }
        elsif token =~ NONCE_REGEXP
          unsupported << UnsupportedToken.new(
            directive: directive, token: token,
            reason: "nonce values are per-request and cannot be compared for tightening"
          )
          { kind: :unsupported, raw: token }
        elsif token =~ HASH_REGEXP
          unsupported << UnsupportedToken.new(
            directive: directive, token: token,
            reason: "hash-source interaction with inline fallback is not modelled"
          )
          { kind: :unsupported, raw: token }
        elsif (match = SCHEME_REGEXP.match(token))
          { kind: :scheme, raw: token, scheme: match[1].downcase }
        elsif (match = HOST_REGEXP.match(token))
          host_token(match, token, directive, unsupported)
        else
          unsupported << UnsupportedToken.new(
            directive: directive, token: token,
            reason: "source expression is outside the supported scheme/host/port grammar"
          )
          { kind: :unsupported, raw: token }
        end
      end

      def host_token(match, raw, directive, unsupported)
        host = match[:host].downcase
        port = match[:port]
        path = match[:path]

        if path && !path.empty?
          unsupported << UnsupportedToken.new(
            directive: directive, token: raw,
            reason: "path-scoped host sources are not modelled"
          )
          return { kind: :unsupported, raw: raw }
        end

        token = {
          kind: :host,
          raw: raw,
          scheme: match[:scheme]&.downcase,
          host: host,
          wildcard: host.start_with?("*."),
          port: port
        }
        token[:host] = host.sub(/\*\./, "") if token[:wildcard]
        token
      end
    end
  end
end

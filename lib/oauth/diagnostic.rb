# frozen_string_literal: true

require "openssl"
require "uri"
require "oauth/helper"
require "oauth/request_proxy"

module OAuth
  # DIAGNOSTIC USE ONLY.
  #
  # OAuth::Diagnostic produces a *signature explanation report* for a request so
  # that two parties debugging a `signature_invalid` failure can compare their
  # respective normalization pipelines (parameter sources, encoding steps,
  # normalized URI, HTTP method) without exchanging consumer secrets, token
  # secrets, or full business parameters.
  #
  # Sensitive values are never emitted. They are replaced by irreversible
  # correlation tags: HMAC-SHA256 keyed with a caller-supplied *ephemeral
  # diagnostic key*. Because the tags are keyed, low-entropy values cannot be
  # recovered by guessing (unlike a plain short hash of the value).
  #
  # Guarantees:
  # * It never signs the request, never generates a nonce or timestamp, and
  #   never writes to the request or its parameters.
  # * It never reads request body streams. If your proxy lazily parses a body
  #   (e.g. Rack POST), pass a pre-parsed Hash snapshot instead of the live
  #   request to be certain no input stream is consumed.
  # * The report is computed from *unverified* request parameters. It must not
  #   be treated as trusted input or used for authorization decisions.
  #
  # See docs/diagnostics.md for the diagnostic key usage scope.
  module Diagnostic
    REPORT_VERSION = "oauth-signature-explanation/1"

    # Parameters whose values are always replaced by correlation tags.
    DEFAULT_SENSITIVE_PARAMETERS = %w[
      oauth_signature
      oauth_token
      oauth_token_secret
      oauth_consumer_secret
      oauth_verifier
      code
    ].freeze

    MINIMUM_DIAGNOSTIC_KEY_BYTES = 16

    NOTICE = "DIAGNOSTIC USE ONLY: this report explains signature normalization " \
             "for debugging signature_invalid mismatches. It is not a signature " \
             "verification result."

    TRUST_NOTICE = "UNVERIFIED: the parameters summarized here come from an " \
                   "unauthenticated request and have NOT been verified. Do not " \
                   "treat them as trusted and do not base authorization " \
                   "decisions on this report."

    module_function

    # Build a signature explanation report for +request+.
    #
    # +request+ may be an OAuth::RequestProxy::Base, or anything
    # OAuth::RequestProxy.proxy accepts (e.g. a Hash snapshot, which is the
    # safest option because it never touches live input streams).
    #
    # Options:
    #   :diagnostic_key        - REQUIRED. Ephemeral, high-entropy key shared
    #                            out-of-band with the other party. Used only to
    #                            key the HMAC correlation tags.
    #   :sensitive_parameters  - Additional parameter names (beyond
    #                            DEFAULT_SENSITIVE_PARAMETERS) whose values must
    #                            be replaced by correlation tags, e.g. business
    #                            fields you may not disclose.
    #   :consumer_secret, :token_secret, :consumer, :token
    #                          - Optional. When provided, only their correlation
    #                            tags are reported so both sides can confirm they
    #                            hold the same secret without exchanging it.
    #   :proxy                 - Options passed to OAuth::RequestProxy.proxy
    #                            when +request+ is not already a proxy.
    def explain(request, options = {})
      diagnostic_key = options[:diagnostic_key]
      validate_diagnostic_key!(diagnostic_key)

      sensitive = DEFAULT_SENSITIVE_PARAMETERS |
                  Array(options[:sensitive_parameters]).map(&:to_s)

      proxy = OAuth::RequestProxy.proxy(request, options[:proxy] || {})

      entries = parameter_entries(proxy, sensitive, diagnostic_key)

      {
        "diagnostic" => REPORT_VERSION,
        "notice" => NOTICE,
        "trust" => TRUST_NOTICE,
        "method" => proxy.method.to_s,
        "normalized_uri" => proxy.normalized_uri,
        "parameters" => entries,
        "query_string_pairs" => query_string_pairs(proxy, sensitive, diagnostic_key),
        "normalized_parameters" => tagged_normalized_parameters(entries),
        "normalized_parameters_tag" => tag(diagnostic_key, "normalized-parameters", "", proxy.normalized_parameters),
        "signature_base_string_tag" => tag(diagnostic_key, "signature-base-string", "", proxy.signature_base_string),
        "provided_signature_tag" => provided_signature_tag(proxy, diagnostic_key),
        "secrets" => secret_tags(options, diagnostic_key)
      }
    end

    # Compare two reports and return an array of divergences, each a Hash with
    # "path", "a" and "b". Reports are compared structurally, in a deterministic
    # order, so the first divergence is the earliest point at which the two
    # normalization pipelines disagree.
    def diff(report_a, report_b)
      divergences = []
      walk(report_a, report_b, "$", divergences)
      divergences
    end

    # The first divergence between two reports, or nil if they are equivalent.
    def first_divergence(report_a, report_b)
      diff(report_a, report_b).first
    end

    # -- internals -----------------------------------------------------------

    def validate_diagnostic_key!(key)
      unless key.is_a?(String) && key.bytesize >= MINIMUM_DIAGNOSTIC_KEY_BYTES
        raise ArgumentError,
              "a :diagnostic_key of at least #{MINIMUM_DIAGNOSTIC_KEY_BYTES} bytes is required; " \
              "use a fresh random key per debugging session (see docs/diagnostics.md)"
      end
    end

    # Irreversible correlation tag: keyed HMAC, so low-entropy values cannot be
    # brute-forced without the ephemeral diagnostic key.
    def tag(key, context, name, value)
      OpenSSL::HMAC.hexdigest("SHA256", key, [REPORT_VERSION, context, name, value.to_s].join("\x00"))
    end

    def parameter_entries(proxy, sensitive, diagnostic_key)
      header_names = header_parameter_names(proxy)
      query_names = raw_query_pairs(proxy).map { |raw_name, _| OAuth::Helper.unescape(raw_name.to_s) }
      option_names = (proxy.options[:parameters] || {}).keys.map(&:to_s)

      entries = []
      proxy.parameters_for_signature.each do |name, values|
        (values.is_a?(Array) ? values : [values]).each do |value|
          entries << parameter_entry(name, value, sensitive, diagnostic_key,
                                     source_for(name.to_s, header_names, query_names, option_names))
        end
      end

      # Sort exactly like normalization does (by escaped name, then escaped
      # value) so the entry order itself is comparable. Sort keys use the real
      # values locally and are never emitted.
      entries.sort_by! { |entry| [entry["name_escaped"], entry.delete("_sort_key")] }
      entries
    end

    def parameter_entry(name, value, sensitive, diagnostic_key, source)
      name = name.to_s
      escaped_value = OAuth::Helper.escape(value.nil? ? "" : value)

      entry = {
        "name" => name,
        "name_escaped" => OAuth::Helper.escape(name),
        "source" => source,
        "_sort_key" => escaped_value
      }

      if sensitive.include?(name)
        entry["sensitive"] = true
        entry["value_tag"] = tag(diagnostic_key, "parameter-value", name, value)
        entry["value_escaped_tag"] = tag(diagnostic_key, "parameter-value-escaped", name, escaped_value)
      else
        entry["sensitive"] = false
        entry["value"] = value
        entry["value_escaped"] = escaped_value
      end

      entry
    end

    def source_for(name, header_names, query_names, option_names)
      return "authorization_header" if header_names.include?(name)
      return "query" if query_names.include?(name)
      return "option" if option_names.include?(name)

      "body_or_other"
    end

    def header_parameter_names(proxy)
      proxy.send(:header_params).keys.map(&:to_s)
    rescue StandardError
      []
    end

    def raw_query_pairs(proxy)
      query = URI.parse(proxy.uri).query
      return [] unless query

      query.split("&").map { |pair| pair.split("=", 2) }
    rescue URI::InvalidURIError
      []
    end

    # Raw, still-percent-encoded pairs from the URI query string. Encoding
    # differences between the two parties show up here first, so sensitive
    # values are tagged in their raw form as well.
    def query_string_pairs(proxy, sensitive, diagnostic_key)
      raw_query_pairs(proxy).map do |raw_name, raw_value|
        name = OAuth::Helper.unescape(raw_name.to_s)
        if sensitive.include?(name)
          {"name" => name, "raw_name" => raw_name, "sensitive" => true,
           "raw_value_tag" => tag(diagnostic_key, "raw-query-value", name, raw_value)}
        else
          {"name" => name, "raw_name" => raw_name, "sensitive" => false, "raw_value" => raw_value}
        end
      end
    end

    def tagged_normalized_parameters(entries)
      entries.map do |entry|
        value = if entry["sensitive"]
                  entry["value_escaped_tag"]
                else
                  entry["value_escaped"]
                end
        "#{entry["name_escaped"]}=#{value}"
      end.join("&")
    end

    def provided_signature_tag(proxy, diagnostic_key)
      signature = proxy.oauth_signature
      return nil if signature.nil? || signature == ""

      tag(diagnostic_key, "provided-signature", "oauth_signature", signature)
    rescue StandardError
      nil
    end

    def secret_tags(options, diagnostic_key)
      consumer_secret = options[:consumer_secret]
      consumer_secret ||= options[:consumer].secret if options[:consumer]
      token_secret = options[:token_secret]
      token_secret ||= options[:token].secret if options[:token]

      {
        "consumer_secret_tag" => consumer_secret && tag(diagnostic_key, "consumer-secret", "", consumer_secret),
        "token_secret_tag" => token_secret && tag(diagnostic_key, "token-secret", "", token_secret),
        "keying" => "HMAC-SHA256 keyed with the ephemeral diagnostic key; raw secrets are never reported"
      }
    end

    def walk(node_a, node_b, path, divergences)
      if node_a.is_a?(Hash) && node_b.is_a?(Hash)
        (node_a.keys | node_b.keys).each do |key|
          walk(node_a[key], node_b[key], "#{path}.#{key}", divergences)
        end
      elsif node_a.is_a?(Array) && node_b.is_a?(Array)
        [node_a.size, node_b.size].max.times do |index|
          walk(node_a[index], node_b[index], "#{path}[#{index}]", divergences)
        end
      elsif node_a != node_b
        divergences << {"path" => path, "a" => node_a, "b" => node_b}
      end
    end
  end
end

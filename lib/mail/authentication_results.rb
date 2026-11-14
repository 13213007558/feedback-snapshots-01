# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Trust-aware access to Authentication-Results (RFC 8601) header data.
  #
  # Threat model
  # ============
  # Any node on the delivery path — including the message's author — can
  # prepend arbitrary Authentication-Results headers to a message. A
  # "dkim=pass" found somewhere in the header block may have been written
  # by the attacker. The only results that may feed a security decision
  # are the ones your own receiving infrastructure added, and those are
  # exactly the first N Authentication-Results headers of the message
  # (receivers prepend), where N is the number your infrastructure adds.
  #
  # The caller therefore supplies both halves of the trust decision:
  #
  #  * +authserv_ids+ — the authserv-id(s) of your trusted receiving
  #    node(s), as they identify themselves in the headers they add.
  #  * +within+ — the header boundary: how many Authentication-Results
  #    headers, counted from the top of the message, your infrastructure
  #    could have added. Headers beyond this boundary are
  #    attacker-controlled and ignored.
  #
  # Only header instances inside the boundary whose authserv-id matches
  # are returned. Everything else — forged same-name headers deeper in
  # the header block, foreign authserv-ids, unparseable headers — is
  # excluded. Absence of a trusted result means "no trustworthy
  # information", never "pass".
  #
  # Example:
  #
  #  dkim = Mail::AuthenticationResults.trusted_result_for(mail, 'dkim',
  #           authserv_ids: 'mx.example.com', within: 1)
  #  if dkim && dkim.pass?
  #    # your own receiver verified the signature
  #  end
  module AuthenticationResults
    module_function

    # Returns the parsed Authentication-Results elements that are
    # eligible for security decisions, in header order (topmost first).
    def trusted(message, authserv_ids:, within: 1)
      ids = normalize_ids(authserv_ids)
      within = validate_within(within)

      authentication_results_fields(message).first(within).each_with_object([]) do |field, selected|
        element = parseable_element(field)
        if element && element.authserv_id && ids.include?(normalize_id(element.authserv_id))
          selected << element
        end
      end
    end

    # Returns the first trusted result entry recorded for +method+
    # (e.g. 'dkim', 'spf', 'dmarc'), or nil when no trusted receiving
    # node recorded one. nil is not a "pass".
    def trusted_result_for(message, method, authserv_ids:, within: 1)
      trusted(message, authserv_ids: authserv_ids, within: within).each do |element|
        if result = element.result_for(method)
          return result
        end
      end
      nil
    end

    # All Authentication-Results header fields of the message, in header
    # order (topmost first), regardless of trust. Receivers prepend
    # their own header, so the first entries are the ones closest to
    # your infrastructure.
    def authentication_results_fields(message)
      header = message.respond_to?(:header) ? message.header : message
      header.fields.select { |field| field.responsible_for?('Authentication-Results') }
    end

    def normalize_id(id) #:nodoc:
      id.to_s.strip.downcase
    end

    def normalize_ids(ids) #:nodoc:
      ids = Array(ids).map { |id| normalize_id(id) }.reject(&:empty?).uniq
      raise ArgumentError, 'at least one trusted authserv-id is required' if ids.empty?
      ids
    end

    def validate_within(within) #:nodoc:
      within = Integer(within)
      raise ArgumentError, 'header boundary (within:) must be >= 1' if within < 1
      within
    end

    # Parsed element for a header field, or nil when the field did not
    # parse as a valid Authentication-Results header. Unparseable
    # headers never participate in security decisions.
    def parseable_element(field) #:nodoc:
      inner = field.respond_to?(:field) ? field.field : field
      inner.element if inner.respond_to?(:element)
    rescue Mail::Field::ParseError
      nil
    end
  end
end

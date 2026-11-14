# encoding: utf-8
# frozen_string_literal: true

module Mail
  # = Identity Result
  #
  # IdentityResult is the strict counterpart to the lenient address
  # accessors (Mail::Message#from, Mail::CommonAddressField#addresses).
  #
  # The lenient accessors promise *displayability*: they always return
  # something renderable, falling back to the raw unparsed text when the
  # field does not conform to the structured address syntax. That is the
  # right behavior for showing a message to a human, but it is unsafe for
  # authorization decisions such as sender whitelists, because a
  # best-effort string can silently stand in for an identity that was
  # never verified.
  #
  # IdentityResult promises *verifiability*: it only reports an identity
  # when the field was parsed by the structured address parser and yielded
  # exactly one mailbox. Anything else - a parse failure, a fallback to
  # unstructured text, multiple mailboxes, or no mailbox at all - is
  # reported as an explicit, non-authorizable status. It never re-parses
  # the display string to pick out an email-looking fragment.
  #
  # == Contrast samples
  #
  #  sample = 'From: "Last, First" <user@example.com>'
  #  mail = Mail.new(sample)
  #  mail.from                    #=> ["user@example.com"]      (lenient: display)
  #  mail.from_identity.status    #=> :ok                       (strict: verified)
  #  mail.from_identity.address   #=> "user@example.com"
  #
  #  mail = Mail.new('From: a@example.com, b@example.com')
  #  mail.from                    #=> ["a@example.com", "b@example.com"]
  #  mail.from_identity.status    #=> :ambiguous   (not usable for authorization)
  #
  #  mail = Mail.new('From: not an address <<<>>>')
  #  mail.from                    #=> "not an address <<<>>>"   (raw text, displayable)
  #  mail.from_identity.status    #=> :unparseable (not usable for authorization)
  #  mail.from_identity.display   #=> "not an address <<<>>>"   (raw field kept)
  #
  #  mail = Mail.new('From: "attacker@evil.example" <real@example.com>')
  #  mail.from_identity.address   #=> "real@example.com"
  #  # The display name is never mined for an email-looking fragment.
  #
  # == Usage
  #
  #  result = mail.from_identity
  #  if result.usable_for_authorization?
  #    whitelist.include?(result.address)
  #  else
  #    reject(mail, result.status, result.reason)
  #  end
  class IdentityResult
    # The field parsed structurally and contains exactly one mailbox.
    # This is the only status that is usable for authorization.
    OK = :ok

    # No field was present at all.
    MISSING = :missing

    # Structured parsing failed and the field degraded to unstructured
    # plain text. The raw value is kept in #display for humans, but no
    # identity may be derived from it.
    UNPARSEABLE = :unparseable

    # The field parsed structurally but contains more than one mailbox,
    # so no single identity can be attributed.
    AMBIGUOUS = :ambiguous

    # The field parsed structurally but contains no mailbox at all
    # (for example an empty group such as "undisclosed-recipients:;").
    EMPTY = :empty

    STATUSES = [OK, MISSING, UNPARSEABLE, AMBIGUOUS, EMPTY].freeze

    # Builds an IdentityResult from a header field wrapper
    # (Mail::Field, e.g. the result of mail[:from]) or nil.
    #
    # Only the structured parse tree is consulted; the raw display string
    # is preserved as-is and never re-parsed.
    def self.extract(field)
      if field.nil?
        return new(status: MISSING, display: nil,
                   reason: 'no field present')
      end

      inner = field.field
      display = field.value.is_a?(String) ? field.value : field.value.to_s

      unless inner.is_a?(Mail::CommonAddressField)
        parse_error = inner.respond_to?(:errors) && inner.errors.map { |e| e[2] }.compact.first
        detail = parse_error ? ": #{parse_error.message}" : ''
        return new(status: UNPARSEABLE, display: display,
                   reason: "structured address parsing failed; field degraded to plain text#{detail}")
      end

      addresses = inner.addresses
      case addresses.length
      when 0
        new(status: EMPTY, display: display, addresses: [],
            reason: 'no mailbox found (e.g. empty group)')
      when 1
        new(status: OK, display: display, address: addresses.first,
            addresses: addresses)
      else
        new(status: AMBIGUOUS, display: display, addresses: addresses,
            reason: "#{addresses.length} mailboxes found; cannot attribute a single identity")
      end
    rescue Mail::Field::ParseError => e
      new(status: UNPARSEABLE, display: display,
          reason: "structured address parsing failed: #{e.message}")
    end

    # One of OK, MISSING, UNPARSEABLE, AMBIGUOUS or EMPTY.
    attr_reader :status

    # The single verified mailbox address. Only set when #status is OK.
    attr_reader :address

    # All structurally parsed mailbox addresses (diagnostics only; may be
    # empty or contain several entries when #status is not OK).
    attr_reader :addresses

    # The original, displayable field value, preserved untouched. Safe to
    # show to humans; never safe to authorize on.
    attr_reader :display

    # Human-readable explanation for non-OK statuses.
    attr_reader :reason

    def initialize(status:, display:, address: nil, addresses: [], reason: nil)
      @status = status
      @address = address
      @addresses = addresses
      @display = display
      @reason = reason
    end

    # True only when exactly one mailbox was verified by the structured
    # parser. This is the gate to use before any whitelist/authorization
    # decision.
    def ok?
      status == OK
    end
    alias usable_for_authorization? ok?

    def ==(other)
      other.kind_of?(IdentityResult) &&
        status == other.status && address == other.address
    end

    def inspect
      "#<#{self.class.name} status=#{status.inspect} address=#{address.inspect} display=#{display.inspect}>"
    end
  end
end

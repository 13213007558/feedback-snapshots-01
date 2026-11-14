# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Authentication-Results header field (RFC 8601).
  #
  #  field = Mail::AuthenticationResultsField.new('mx.example.com; dkim=pass header.d=example.com')
  #  field.authserv_id         # => 'mx.example.com'
  #  field.result_for('dkim')  # => #<Mail::AuthenticationResultsElement::MethodResult ...>
  #
  # A message can carry several Authentication-Results headers; each
  # receiving node prepends its own and anyone can forge one. Parsing
  # this field does NOT make its contents trustworthy — use
  # Mail::AuthenticationResults.trusted to select the header instances
  # your own receiving infrastructure added.
  class AuthenticationResultsField < NamedStructuredField #:nodoc:
    NAME = 'Authentication-Results'

    def element
      @element ||= Mail::AuthenticationResultsElement.new(value)
    end

    def authserv_id
      element.authserv_id
    end

    def results
      element.results
    end

    def result_for(method)
      element.result_for(method)
    end

    private
      def do_encode
        if Utilities.blank?(value)
          "#{name}: \r\n"
        else
          "#{name}: #{value}\r\n"
        end
      end

      def do_decode
        value.to_s
      end
  end
end

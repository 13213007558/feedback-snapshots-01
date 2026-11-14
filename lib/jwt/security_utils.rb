# frozen_string_literal: true

require 'openssl'

module JWT
  # Constant time string comparison helpers.
  #
  # @api private
  module SecurityUtils
    # rubocop:disable-next Naming/MethodParameterName, Style/StringLiterals, Style/NumericPredicate
    if defined?(OpenSSL.fixed_length_secure_compare)
      # Constant time comparison for strings of the same length.
      def fixed_length_secure_compare(a, b)
        OpenSSL.fixed_length_secure_compare(a, b)
      end
    else
      # :nocov:
      def fixed_length_secure_compare(a, b)
        raise ArgumentError, 'string length mismatch.' unless a.bytesize == b.bytesize

        l = a.unpack("C#{a.bytesize}")

        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res == 0
      end
      # :nocov:
    end
    module_function :fixed_length_secure_compare

    # Constant time comparison for strings of variable length.
    #
    # While a timing attack would not be able to discern the content of a
    # secret compared via secure_compare, it is possible to determine the
    # secret length. This should be considered when using secure_compare
    # to compare weak, short secrets.
    def secure_compare(a, b)
      a.bytesize == b.bytesize && fixed_length_secure_compare(a, b)
    end
    module_function :secure_compare
  end
end

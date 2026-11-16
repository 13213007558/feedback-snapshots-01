# frozen_string_literal: true

# Builds CBOR byte strings by hand so specs can exercise legal encodings the
# canonical CBOR encoder in the test suite would never produce, such as
# non-shortest integer headers and reordered map entries.
module CborEncodingHelpers
  module_function

  def int(value, wide: false)
    raise ArgumentError, "value #{value} needs a wide header" if !wide && value.abs >= 24

    if value >= 0
      wide ? [0x18, value].pack("CC") : [value].pack("C")
    else
      wide ? [0x38, -1 - value].pack("CC") : [0x20 | (-1 - value)].pack("C")
    end
  end

  def bytes(value, wide: false)
    header =
      if wide
        [0x59, value.bytesize].pack("Cn")
      elsif value.bytesize < 24
        [0x40 | value.bytesize].pack("C")
      else
        [0x58, value.bytesize].pack("CC")
      end

    header + value
  end

  def map(pairs, wide: false)
    header = wide ? [0xb8, pairs.size].pack("CC") : [0xa0 | pairs.size].pack("C")

    header + pairs.map { |key, value|
      int(key, wide: wide) + (value.is_a?(String) ? bytes(value, wide: wide) : int(value, wide: wide))
    }.join
  end

  def cose_key_pairs(cose_key)
    [[1, 2], [3, cose_key.alg], [-1, cose_key.crv], [-2, cose_key.x], [-3, cose_key.y]]
  end

  def encode_cose_key(cose_key, wide: false, reverse: false)
    pairs = cose_key_pairs(cose_key)
    pairs = pairs.reverse if reverse

    map(pairs, wide: wide)
  end
end

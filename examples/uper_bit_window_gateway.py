#!/usr/bin/env python
"""Gateway contract for multiple UPER messages packed into one byte buffer.

Two security messages whose lengths are not multiples of eight share a byte
buffer. The decoder is handed an authorized bit window per message, reports
the exact number of bits consumed, validates transport padding separately,
and refuses to borrow bits from the next message to finish a truncated value.

Run with: python examples/uper_bit_window_gateway.py

"""

import asn1tools
from asn1tools.codecs import DecodeError
from asn1tools.codecs import OutOfDataError


SPEC = """
SecurityGateway DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

-- 4 + 12 + 5 + 8 = 29 bits.
SecurityMessage ::= SEQUENCE {
  protocolVersion INTEGER (0..15),
  messageId       INTEGER (0..4095),
  permissions     BIT STRING (SIZE(5)),
  payload         OCTET STRING (SIZE(1))
}

-- 3 + 2 + 9 + 8 = 22 bits.
ShortSecurityMessage ::= SEQUENCE {
  version   INTEGER (0..7),
  severity  INTEGER (0..3),
  token     INTEGER (0..511),
  nonce     OCTET STRING (SIZE(1))
}

END
"""


def message_bits(encoded):
    return ''.join('{:08b}'.format(byte) for byte in encoded)


def pack(bit_string):
    bit_string += '0' * ((8 - len(bit_string) % 8) % 8)
    return bytes(int(bit_string[i:i + 8], 2)
                 for i in range(0, len(bit_string), 8))


def main():
    compiled = asn1tools.compile_string(SPEC, 'uper')
    security = compiled.types['SecurityMessage']
    short = compiled.types['ShortSecurityMessage']

    first = {
        'protocolVersion': 3,
        'messageId': 0x123,
        'permissions': (b'\xa8', 5),
        'payload': b'\x5a',
    }
    second = {
        'version': 5,
        'severity': 2,
        'token': 0x155,
        'nonce': b'\xa5',
    }

    first_bits = message_bits(security.encode(first))[:29]
    second_bits = message_bits(short.encode(second))[:22]

    # 29 + 22 = 51 message bits, packed into 7 bytes with 5 padding bits.
    stream = pack(first_bits + second_bits)
    print('buffer        :', stream.hex(), '({} bytes, {} message bits)'.format(
        len(stream), 51))

    one = security.decode_window(stream, bit_offset=0, limit_bits=29,
                                 final=False)
    print('message 1     : value={}, consumed={} bits, next offset={}'.format(
        one.value, one.consumed_bits, one.next_bit_offset))

    two = short.decode_window(stream, bit_offset=29, limit_bits=22, final=True)
    print('message 2     : value={}, consumed={} bits, padding={} bits, '
          'next offset={}'.format(two.value, two.consumed_bits,
                                  two.padding_bits, two.next_bit_offset))

    # A truncated first message must not borrow bit 29 from message two.
    cut = 28
    truncated = pack(first_bits[:cut] + second_bits)
    try:
        security.decode_window(truncated, bit_offset=0, limit_bits=cut,
                               final=False)
    except OutOfDataError as error:
        print('truncated     : rejected at consumed offset {} ({})'.format(
            error.offset, error))

    # Non-zero transport padding is rejected rather than silently dropped.
    bad_padding = pack(first_bits + '101')
    try:
        security.decode_window(bad_padding, bit_offset=0, limit_bits=32,
                               final=True)
    except DecodeError as error:
        print('bad padding   :', error)

    # A whole extra octet is reported instead of being rounded away.
    extra_octet = security.encode(first) + b'\x00'
    try:
        security.decode_window(extra_octet, bit_offset=0,
                               limit_bits=8 * len(extra_octet), final=True)
    except DecodeError as error:
        print('extra octet   :', error)


if __name__ == '__main__':
    main()

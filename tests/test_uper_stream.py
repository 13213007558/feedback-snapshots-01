#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Bit-window contract for multiple UPER security messages in one buffer.

These tests pin down the gateway decoding contract:

* the decoder reports exactly how many bits each message consumed;
* decoding is bounded by the caller-authorized bit window and can never
  borrow bits belonging to the following message to finish a value;
* in-message bits, zero transport padding in the final partial octet and
  spurious non-zero trailing bits are kept apart;
* the byte length is never rounded up in order to silently drop tail data.

"""

import unittest

import asn1tools
from asn1tools.codecs import DecodeError
from asn1tools.codecs import OutOfDataError


SPEC = """
SecurityGateway DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

-- 4 + 12 + 5 + 8 = 29 bits: not a multiple of eight.
SecurityMessage ::= SEQUENCE {
  protocolVersion INTEGER (0..15),
  messageId       INTEGER (0..4095),
  permissions     BIT STRING (SIZE(5)),
  payload         OCTET STRING (SIZE(1))
}

-- 3 + 2 + 9 + 8 = 22 bits: not a multiple of eight, different length.
ShortSecurityMessage ::= SEQUENCE {
  version   INTEGER (0..7),
  severity  INTEGER (0..3),
  token     INTEGER (0..511),
  nonce     OCTET STRING (SIZE(1))
}

END
"""

# Field widths in bits, in encoding order.
SECURITY_FIELDS = [
    ('protocolVersion', 4),
    ('messageId', 12),
    ('permissions', 5),
    ('payload', 8),
]
SECURITY_LENGTH_BITS = sum(width for _, width in SECURITY_FIELDS)

SHORT_FIELDS = [
    ('version', 3),
    ('severity', 2),
    ('token', 9),
    ('nonce', 8),
]
SHORT_LENGTH_BITS = sum(width for _, width in SHORT_FIELDS)


def bits_to_bytes(bit_string):
    """Pack an MSB-first bit string into bytes, zero-padding the last octet."""
    padded = bit_string + '0' * ((8 - len(bit_string) % 8) % 8)
    return bytes(
        int(padded[index:index + 8], 2)
        for index in range(0, len(padded), 8)
    )


def message_bits(encoded):
    return ''.join('{:08b}'.format(byte) for byte in encoded)


class Asn1ToolsUperStreamTest(unittest.TestCase):

    def setUp(self):
        self.compiled = asn1tools.compile_string(SPEC, 'uper')
        self.security_type = self.compiled.types['SecurityMessage']
        self.short_type = self.compiled.types['ShortSecurityMessage']

        self.first_message = {
            'protocolVersion': 3,
            'messageId': 0x123,
            'permissions': (b'\xa8', 5),
            'payload': b'\x5a',
        }
        self.third_message = {
            'protocolVersion': 9,
            'messageId': 0xabc,
            'permissions': (b'\x60', 5),
            'payload': b'\xa5',
        }
        self.short_message = {
            'version': 5,
            'severity': 2,
            'token': 0x155,
            'nonce': b'\xa5',
        }

        self.encoded_first = self.security_type.encode(self.first_message)
        self.encoded_third = self.security_type.encode(self.third_message)
        self.encoded_short = self.short_type.encode(self.short_message)

        self.first_bits = message_bits(self.encoded_first)[:SECURITY_LENGTH_BITS]
        self.third_bits = message_bits(self.encoded_third)[:SECURITY_LENGTH_BITS]
        self.short_bits = message_bits(self.encoded_short)[:SHORT_LENGTH_BITS]

        self.assertEqual(len(self.first_bits), 29)
        self.assertEqual(len(self.third_bits), 29)
        self.assertEqual(len(self.short_bits), 22)

    def test_encoded_messages_are_not_octet_aligned(self):
        # Both message types deliberately end in the middle of an octet.
        self.assertNotEqual(SECURITY_LENGTH_BITS % 8, 0)
        self.assertNotEqual(SHORT_LENGTH_BITS % 8, 0)
        self.assertEqual(SECURITY_LENGTH_BITS, 29)
        self.assertEqual(SHORT_LENGTH_BITS, 22)
        self.assertEqual(len(self.encoded_first), 4)
        self.assertEqual(len(self.encoded_short), 3)

    def test_single_message_reports_consumed_position_and_padding(self):
        result = self.security_type.decode_window(
            self.encoded_first, 0, 8 * len(self.encoded_first), final=True)

        self.assertEqual(result.value, self.first_message)
        self.assertEqual(result.bit_offset, 0)
        self.assertEqual(result.consumed_bits, 29)
        self.assertEqual(result.padding_bits, 3)
        self.assertEqual(result.next_bit_offset, 32)

    def test_two_homogeneous_messages_share_one_byte_buffer(self):
        # 29 + 29 = 58 message bits, padded to 64 bits = 8 bytes.
        stream = bits_to_bytes(self.first_bits + self.third_bits)
        self.assertEqual(len(stream), 8)

        results = self.security_type.decode_stream(stream, number_of_messages=2)
        first, second = results

        self.assertEqual(first.value, self.first_message)
        self.assertEqual(first.bit_offset, 0)
        self.assertEqual(first.consumed_bits, 29)
        self.assertEqual(first.next_bit_offset, 29)
        self.assertIsNone(first.padding_bits)

        self.assertEqual(second.value, self.third_message)
        self.assertEqual(second.bit_offset, 29)
        self.assertEqual(second.consumed_bits, 29)
        # 58 message bits plus 6 zero transport padding bits.
        self.assertEqual(second.padding_bits, 6)
        self.assertEqual(second.next_bit_offset, 64)

    def test_heterogeneous_messages_are_joined_at_bit_boundaries(self):
        # A 29-bit message followed by a 22-bit message: 51 bits in 7 bytes.
        stream = bits_to_bytes(self.first_bits + self.short_bits)
        self.assertEqual(len(stream), 7)

        first = self.security_type.decode_window(
            stream, bit_offset=0, limit_bits=29, final=False)
        self.assertEqual(first.value, self.first_message)
        self.assertEqual(first.consumed_bits, 29)
        self.assertEqual(first.next_bit_offset, 29)
        self.assertIsNone(first.padding_bits)

        second = self.short_type.decode_window(
            stream, bit_offset=29, limit_bits=22, final=True)
        self.assertEqual(second.value, self.short_message)
        self.assertEqual(second.consumed_bits, 22)
        self.assertEqual(second.padding_bits, 5)
        self.assertEqual(second.next_bit_offset, 56)

    def test_truncation_at_every_field_boundary_is_rejected(self):
        # For each field, authorize all bits up to the last bit of that field
        # (exclusive). The decoder must fail inside that field and report the
        # bits it managed to consume, never reaching the following message.
        consumed_before_field = 0
        boundary = 0

        for field_name, width in SECURITY_FIELDS:
            boundary += width
            authorized = boundary - 1

            with self.subTest(field=field_name, authorized_bits=authorized):
                with self.assertRaises(OutOfDataError) as context:
                    self.security_type.decode_window(
                        self.encoded_first,
                        bit_offset=0,
                        limit_bits=authorized,
                        final=False)

                # The read fails while inside this field; all earlier fields
                # were consumed and no bit was borrowed from later data.
                self.assertGreaterEqual(context.exception.offset,
                                        consumed_before_field)
                self.assertLess(context.exception.offset, boundary)

            consumed_before_field = boundary

    def test_truncated_message_cannot_borrow_the_next_messages_bits(self):
        # Keep the first 28 bits of message one (the 8-bit payload is cut to
        # two), then place the complete second message immediately afterwards.
        cut = SECURITY_LENGTH_BITS - 1
        stream_bits = self.first_bits[:cut] + self.third_bits
        stream = bits_to_bytes(stream_bits)

        # The gateway authorizes only the 28 bits attributed to message one.
        # After the 21 header/permission bits the payload read cannot be
        # satisfied inside the window, so OutOfDataError reports the start of
        # that failing read. It can never reach bit 28, which belongs to
        # message two.
        with self.assertRaises(OutOfDataError) as context:
            self.security_type.decode_window(
                stream, bit_offset=0, limit_bits=cut, final=False)

        self.assertEqual(context.exception.offset, 21)

        # An unsafe whole-buffer decoder would read across the boundary and
        # assemble a payload value using bits of message two. Show what that
        # borrowed value looks like and that it is not the genuine payload.
        borrowed_payload = self._naive_borrowed_payload(stream, cut)
        self.assertNotEqual(borrowed_payload, self.first_message['payload'])

        # The untouched second message still decodes from its real offset.
        second = self.security_type.decode_window(
            stream, bit_offset=cut, limit_bits=29, final=False)
        self.assertEqual(second.value, self.third_message)

    def _naive_borrowed_payload(self, stream, cut):
        """What an unsafe whole-buffer decode would read for the payload."""
        all_bits = message_bits(stream)
        payload_bits = all_bits[26:34]
        return bytes([int(payload_bits, 2)])

    def test_non_zero_transport_padding_is_rejected(self):
        # 29 message bits followed by three non-zero filler bits.
        bad = bytearray(bits_to_bytes(self.first_bits + '101'))
        with self.assertRaises(DecodeError):
            self.security_type.decode_window(bad, 0, 32, final=True)

    def test_extra_whole_octet_is_not_rounded_away(self):
        # A complete message plus a whole extra octet must not be swallowed by
        # rounding the length up to the next byte.
        padded = bytearray(self.encoded_first)
        padded.append(0x00)

        with self.assertRaises(DecodeError):
            self.security_type.decode_window(
                padded, 0, len(padded) * 8, final=True)

    def test_zero_transport_padding_in_partial_octet_is_accepted(self):
        result = self.security_type.decode_window(
            self.encoded_first, 0, 32, final=True)
        self.assertEqual(result.padding_bits, 3)

    def test_window_cannot_extend_past_the_buffer(self):
        with self.assertRaises(DecodeError):
            self.security_type.decode_window(
                self.encoded_first, 0, 8 * len(self.encoded_first) + 1)

    def test_stream_requires_a_positive_message_count(self):
        stream = bits_to_bytes(self.first_bits + self.third_bits)
        with self.assertRaises(DecodeError):
            self.security_type.decode_stream(stream, number_of_messages=0)

    def test_message_internal_zero_bits_are_not_confused_with_padding(self):
        # All-zero permission and payload bits are message content, not
        # transport padding; the decoder still consumes exactly 29 bits.
        message = {
            'protocolVersion': 0,
            'messageId': 0,
            'permissions': (b'\x00', 5),
            'payload': b'\x00',
        }
        encoded = self.security_type.encode(message)
        result = self.security_type.decode_window(encoded, 0, 32, final=True)

        self.assertEqual(result.value, message)
        self.assertEqual(result.consumed_bits, 29)
        self.assertEqual(result.padding_bits, 3)


if __name__ == '__main__':
    unittest.main()

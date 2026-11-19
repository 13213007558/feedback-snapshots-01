# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.6
# *
# * Copyright 2023. Benoit Michau. P1Sec.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : test/test_sms.py
# * Created : 2023-11-20
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii   import unhexlify
from timeit     import timeit

from pycrate_mobile.TS23040_SMS import *

# SMS 7 bit character together with UDH requires complex alignment and padding
# Here is a harness test to ensure everything gets encoded / decoded properly

def test_tpudh(I=28, J=8):
    for i in range(0, I):
        for j in range(0, J):
            txt = i*'A'
            enc = SMS_SUBMIT(val={
                'TP_UDHI': 1,
                'TP_DA'  : {'Num': '33123456'},
                'TP_DCS' : {'Group': 0, 'Charset': 0, 'Class': 0},
                'TP_UD'  : {
                    'UDH' : {'UDH': [{'T': 2, 'V': j*b'\0'}]},
                    'UD'  : txt
                }})
            buf = enc.to_bytes()
            dec = SMS_SUBMIT()
            dec.from_bytes(buf)
            assert( dec['TP_UD']['UD'].decode() in (txt, txt+'\r') )


# For more real-cases testing, here are some wireshark filters to collect such kind of SMS
# gsm_sms.tp-dcs == 0 and gsm_sms.dis_field_udh.user_data_header_length != 6 and gsm_sms.ie_identifier != 0x00
# gsm_sms.dis_field_udh.gsm.fill_bits == 0x0 and gsm_sms.ie_identifier != 0x00


#------------------------------------------------------------------------------#
# Byte-level regressions for SMS-DELIVER decoding
#------------------------------------------------------------------------------#
# Every TPDU below is a hand-built constant. The bit layout (TP-UDHI bit,
# TP-UDL, fill bits after the TP-UDH, septet packing) was computed independently
# of this library, so decoding is not checked against our own encoder.
#
# Common header of the SMS-DELIVER TPDUs:
#   00|40  first octet (TP-UDHI = 0|1, no other flag set)
#   0A 91 21 43 65 87 09  TP-OA, 10 digits, international, BCD 1234567890
#   00                    TP-PID
#   xx                    TP-DCS
#   62 11 91 21 43 65 00  TP-SCTS
#   xx                    TP-UDL
#   ...                   TP-UD (TP-UDH then text)

# Independent GSM 03.38 default alphabet, used only to build fixture bytes
_GSM7_LUT = (
    '@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?'
    '¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà'
    )
_GSM7_INV = {c: i for i, c in enumerate(_GSM7_LUT)}


def _pack_7bit(header, text):
    """pack TP-UDH bytes then septets, LSB first, and return (ud, udl, fill)

    This is a deliberately naive reference packer: plain bit lists, no use of
    pycrate. `fill' is the number of zero bits inserted after the header so
    that the first text septet starts on a septet boundary.
    """
    bits = []
    for byte in header:
        bits.extend((byte >> k) & 1 for k in range(8))
    fill = (-len(bits)) % 7
    bits.extend([0] * fill)
    for char in text:
        septet = _GSM7_INV[char]
        bits.extend((septet >> k) & 1 for k in range(7))
    udl = (len(bits) + 6) // 7
    bits.extend([0] * ((-len(bits)) % 8))
    body = bytes(sum(bits[i+j] << j for j in range(8))
                 for i in range(0, len(bits), 8))
    return body, udl, fill


def _deliver(dcs, udl, ud, udhi=False):
    return ('%02x' % (0x40 if udhi else 0x00)) + '0a91214365870900' + \
        ('%02x' % dcs) + '62119121436500' + ('%02x' % udl) + ud


def _report(tpdu_hex):
    msg = SMS_DELIVER()
    msg.from_bytes(unhexlify(tpdu_hex))
    return msg, msg['TP_UD']['UD'].decode_report()


def _check(tpdu_hex, charset, udl, header_octets, declared, effective,
           text, complete, pending=b'', pending_bits=0, padding=None):
    msg, rep = _report(tpdu_hex)
    assert rep['charset'] == charset, rep
    assert rep['udl'] == udl, rep
    assert rep['header_octets'] == header_octets, rep
    assert rep['declared_units'] == declared, rep
    assert rep['effective_units'] == effective, rep
    assert rep['text'] == text, rep
    assert rep['complete'] is complete, rep
    assert rep['pending'] == pending, rep
    assert rep['pending_bits'] == pending_bits, rep
    assert rep['padding'] == padding, rep
    # decoding must never rewrite the received bytes
    assert msg['TP_UD']['UD'].get_val() == rep['raw']
    assert msg.to_bytes() == unhexlify(tpdu_hex)
    return rep


def test_sms_deliver_no_udh():
    # ALERT -> septets 65 76 69 82 84, packed in 5 octets, no fill bit
    _check('000a912143658709000062119121436500054166514a05',
           'gsm-7bit', 5, 0, 5, 5, 'ALERT', True)
    # same TP-UD with TP-UDHI set and an empty TP-UDH: UDHL 0 is 1 octet, so
    # 6 fill bits are needed, and TP-UDL counts 1 + 5 septets
    _check('400a9121436587090000621191214365000700409059945201',
           'gsm-7bit', 7, 1, 5, 5, 'ALERT', True)


def test_sms_deliver_udh_fill_bits():
    # Same visible text, four different TP-UDH lengths. The 7-bit start offset
    # after the UDH is (-8*UDH_octets) % 7, i.e. 2, 1, 0 and 5 fill bits for the
    # 5, 6, 7 and 9 octet headers below, and TP-UDL counts the header septets.
    cases = (
        # TP-UDHL 4 (application port addressing 8 bit) -> 5 header septets
        ('400a9121436587090000621191214365000b04040216230499452915', 5, 2, 11),
        # TP-UDHL 5 (concatenation, 8 bit reference) -> 7 header septets
        ('400a9121436587090000621191214365000c0500032a020182cca2940a', 6, 1, 12),
        # TP-UDHL 6 -> 8 header septets, no fill bit
        ('400a9121436587090000621191214365000d067f04000000004166514a05', 7, 0, 13),
        # TP-UDHL 8 -> 11 header septets
        ('400a91214365870900006211912143650010087f0600000000000020c82c4aa9', 9, 5, 16),
    )
    for tpdu_hex, hdr_octets, fill, udl in cases:
        assert fill == (-8 * hdr_octets) % 7
        assert udl == ((hdr_octets * 8 + 6) // 7) + 5
        _check(tpdu_hex, 'gsm-7bit', udl, hdr_octets, 5, 5, 'ALERT', True)


def test_sms_deliver_udh_mismatch_keeps_text_aligned():
    # The raw TP-UD of the TP-UDHL 5 case (82 cc a2 94 0a) decoded from a bit
    # offset of 0 reads "$Theta ..." instead of ALERT. Verify the per-UDH offset
    # of 1 bit is what keeps the text aligned.
    _, rep_udh = _report('400a9121436587090000621191214365000c0500032a020182cca2940a')
    _, rep_noudh = _report('000a912143658709000062119121436500054166514a05')
    assert rep_udh['text'] == rep_noudh['text'] == 'ALERT'
    assert rep_udh['raw'] != rep_noudh['raw']
    # decoding the UDH-case raw body at offset 0 must not yield ALERT
    from pycrate_mobile.TS23038 import decode_7b
    assert decode_7b(rep_udh['raw'], 0) != 'ALERT'
    assert decode_7b(rep_udh['raw'], 1) == 'ALERT'


def test_sms_deliver_extended_escape():
    # A{€ -> septets 65, 27 40, 27 101 (5 septets). Escape chars occupy a full
    # septet and count in TP-UDL, hence 12 septets with the UDH and 5 here.
    _check('400a9121436587090000621191214365000c0500032a0201821bd4a60c',
           'gsm-7bit', 12, 6, 5, 5, 'A{€', True)
    # no UDH: [~]|^ -> 5 escape pairs, 10 septets, 9 octets
    _check('000a9121436587090000621191214365000a1bdea6b7f16d801b0a',
           'gsm-7bit', 10, 0, 10, 10, '[~]|^', True)


def test_sms_deliver_ucs2():
    # 预警€ -> BE UTF-16 9884 8b66 20ac, TP-UDL is the octet count
    _check('000a9121436587090008621191214365000698848b6620ac',
           'ucs2', 6, 0, 6, 6, '预警€', True)
    # same text, 6 header octets, 12 octets of payload: TP-UDL counts both
    _check('400a9121436587090008621191214365000c0500032a020198848b6620ac',
           'ucs2', 12, 6, 6, 6, '预警€', True)


def test_sms_deliver_dcs_only_counterexample():
    # Identical TP-UD 41 66 51 4a 05 and TP-UDL 5, only TP-DCS changes.
    # 0x00: GSM 7 bit -> ALERT (5 septets in 5 octets)
    _check('000a912143658709000062119121436500054166514a05',
           'gsm-7bit', 5, 0, 5, 5, 'ALERT', True)
    # 0x04: 8 bit data -> same octets returned raw, text is not ALERT
    _check('000a912143658709000462119121436500054166514a05',
           '8bit', 5, 0, 5, 5, b'AfQJ\x05', True)
    # 0x08: UCS2 -> 5 octets cannot hold 5 UCS2 units: 4 octets decode to one
    # character and the last octet stays pending
    _check('000a912143658709000862119121436500054166514a05',
           'ucs2', 5, 0, 5, 4, '䅦兊', False, pending=b'\x05')


def test_sms_deliver_truncated_7bit():
    # TP-UDL announces 5 septets (35 bits) but only 4 octets are present:
    # 4 septets decode, 4 bits and the raw 0x4a stay undecided
    _check('000a912143658709000062119121436500054166514a',
           'gsm-7bit', 5, 0, 5, 4, 'ALER', False,
           pending=b'\x4a', pending_bits=4)
    # 3 octets present: 3 septets, 3 pending bits
    _check('000a91214365870900006211912143650005416651',
           'gsm-7bit', 5, 0, 5, 3, 'ALE', False,
           pending=b'\x51', pending_bits=3)


def test_sms_deliver_truncated_ucs2():
    # TP-UDL 4 but 3 octets received: only one complete UCS2 character
    _check('000a91214365870900086211912143650004004100',
           'ucs2', 4, 0, 4, 2, 'A', False, pending=b'\x00')


def test_sms_deliver_truncated_udh():
    # TP-UDL 12, TP-UDHI set, but the buffer stops inside the TP-UDH
    # (UDHL 5 needs 6 octets, only 5 are present): the header/text boundary is
    # unknown so nothing is decoded and every octet stays pending.
    rep = _check('400a9121436587090000621191214365000c0500032a02',
                 'gsm-7bit', 12, 0, 12, 0, '', False,
                 pending=b'\x05\x00\x03\x2a\x02')
    assert rep['raw'] == unhexlify('0500032a02')


def test_sms_deliver_padding_vs_real_char():
    # A real trailing '@' (septet 0x00) must be kept: TP-UDL declares 6 septets
    _check('000a912143658709000062119121436500064166514a0500',
           'gsm-7bit', 6, 0, 6, 6, 'ALERT@', True)
    # ALERT12 is 7 septets; 7*7 = 49 bits leave 7 spare bits, which the
    # encoder fills with a CR septet. TP-UDL 8 then covers the CR as padding.
    _check('000a912143658709000062119121436500084166514a8dc91a',
           'gsm-7bit', 8, 0, 8, 7, 'ALERT12', True,
           pending=b'\x1a', padding=0x0D)
    # Without that padding the same text is 7 septets in 7 octets
    _check('000a912143658709000062119121436500074166514a8dc900',
           'gsm-7bit', 7, 0, 7, 7, 'ALERT12', True)


def test_sms_deliver_dangling_escape():
    # TP-UDL 2 with septets 0x41 then 0x1b (escape): the escape has no
    # following septet, so only 'A' is decoded and the raw pair is pending.
    _check('000a91214365870900006211912143650002c10d',
           'gsm-7bit', 2, 0, 2, 2, 'A', False, pending=b'\xc1\x0d')


def test_sms_deliver_8bit_with_udh():
    # 8 bit DCS: TP-UDL is the octet count including the header
    _check('400a9121436587090004621191214365000b0500032a02014142434445',
           '8bit', 11, 6, 5, 5, b'ABCDE', True)


def test_sms_deliver_known_vectors():
    # Widely published GSM 03.38 examples, packed independently of this library
    _check('000a9121436587090000621191214365000ae8329bfd4697d9ec37',
           'gsm-7bit', 10, 0, 10, 10, 'hellohello', True)
    # "How are you?" is exactly 12 septets (84 bits) in 11 octets; the last
    # 4 bits of the final octet are packing padding, not a character.
    _check('000a9121436587090000621191214365000cc8f71d14969741f977fd07',
           'gsm-7bit', 12, 0, 12, 12, 'How are you?', True)


def test_sms_deliver_udhl_sweep():
    # Every possible TP-UDH length from 0 to 12 octets, built from one IE
    # (T=0x7f, L=n, n payload octets) so the header is well-formed. A one-octet
    # TP-UDH cannot hold a complete IE, so it is not a well-formed fixture.
    for udhl in (0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
        if udhl == 0:
            header = b'\x00'
        else:
            header = bytes([udhl, 0x7f, udhl - 2]) + bytes(udhl - 2)
        ud, udl, fill = _pack_7bit(header, 'ALERT')
        tpdu = _deliver(0x00, udl, ud.hex(), bool(header))
        assert fill == (-8 * len(header)) % 7
        _check(tpdu, 'gsm-7bit', udl, len(header), 5, 5, 'ALERT', True)


def test_sms_deliver_udh_offset_sweep():
    # Same fixture family as above, but check that the decoded text does not
    # shift when the header grows: raw bodies differ, visible text does not.
    texts = set()
    for udhl in (0, 2, 3, 4, 5, 6, 8, 10):
        if udhl == 0:
            header = b'\x00'
        else:
            header = bytes([udhl, 0x7f, udhl - 2]) + bytes(udhl - 2)
        ud, udl, fill = _pack_7bit(header, 'ALERT')
        tpdu = _deliver(0x00, udl, ud.hex(), True)
        msg, rep = _report(tpdu)
        assert rep['text'] == 'ALERT', (udhl, rep)
        assert rep['header_octets'] == len(header)
        assert rep['declared_units'] == 5
        texts.add(rep['text'])
    assert texts == {'ALERT'}


def test_sms_deliver_never_replaces_bytes():
    # Whatever the outcome, the raw TP-UD must be preserved verbatim
    tpdu_hex = '000a912143658709000062119121436500054166514a'
    msg, rep = _report(tpdu_hex)
    assert msg['TP_UD']['UD'].get_val() == unhexlify('4166514a')
    assert rep['raw'] == unhexlify('4166514a')
    assert rep['pending'] == b'\x4a'
    assert msg.to_bytes() == unhexlify(tpdu_hex)


def test_sms_deliver_udhl_sweep_with_encoder():
    # Cross-check the independent fixtures against the library encoder. Septet
    # packing is unambiguous for these lengths; the only difference is the
    # TP-UDHL 0 case, where 7 spare bits may be filled with a CR septet (what
    # the encoder does) instead of left as 6 zero fill bits. Both are legal, so
    # that case is checked by decoding the encoder output rather than by byte
    # equality.
    for udhl in (0, 2, 4, 5, 6, 8, 10):
        header = b'\x00' if udhl == 0 else \
            bytes([udhl, 0x7f, udhl - 2]) + bytes(udhl - 2)
        ud, udl, fill = _pack_7bit(header, 'ALERT')
        ies = [] if udhl == 0 else [{'T': 0x7f, 'V': bytes(udhl - 2)}]
        submit = SMS_SUBMIT(val={
            'TP_UDHI': 1,
            'TP_DA'  : {'Num': '33123456'},
            'TP_DCS' : {'Group': 0, 'Charset': 0, 'Class': 0},
            'TP_UD'  : {'UDH': {'UDH': ies}, 'UD' : 'ALERT'}})
        enc = submit.to_bytes()
        assert submit['TP_UD']['UD'].decode() == 'ALERT'
        if udhl == 0:
            # encoder output must still decode as ALERT with the same UDL rules
            dec = SMS_SUBMIT()
            dec.from_bytes(enc)
            rep = dec['TP_UD']['UD'].decode_report()
            assert rep['text'] == 'ALERT', rep
            assert rep['header_octets'] == 1
            continue
        # TP-UD starts after the SMS-SUBMIT header; compare only the TP-UD part
        assert enc[-len(ud):] == ud, (udhl, enc.hex(), ud.hex())
        assert submit['TP_UD']['UDL']() == udl


def test_perf_sms():

    print('[+] SMS_SUBMIT encoding and decoding with GSM 7-bit and TP-UDH')
    Ta = timeit(test_tpudh, number=5)
    print('test_tpudh: {0:.4f}'.format(Ta))


if __name__ == '__main__':
    test_perf_sms()


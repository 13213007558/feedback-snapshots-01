# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
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
# *--------------------------------------------------------
# * File Name : test/test_gtpu_ext_hdr.py
# * Description : adversarial regression for the GTP-U extension header
# *               parser (TS 29.281 section 5.2)
# *--------------------------------------------------------
#*/

"""Adversarial regression tests for the GTP-U extension header parser.

Every case goes through the public `parse_GTPU' entry point with hand-built
frames.  Each successful parse reports the byte range actually covered by the
mandatory header, the optional header, every extension header and the payload,
so a malformed extension cannot silently be folded into the user payload (or
the reverse).

The tests are deterministic: a malformed frame is expected to be rejected by
the parser with the index / offset / type of the offending extension, never by
a timeout or by a stack overflow.
"""

from binascii import unhexlify

from pycrate_mobile.TS29281_GTPU import (
    parse_GTPU,
    gtpu_layers,
    GTPUType,
    ERR_GTPU_BUF_TOO_SHORT,
    ERR_GTPU_LEN_MISMATCH,
    ERR_GTPU_EXT_HDR,
    )


# extension types this module understands structurally; anything else must be
# preserved raw and never exposed as a decoded QFI container
KNOWN_EXT_TYPES = (3, 32, 64, 129, 130, 131, 132, 133, 192)


#------------------------------------------------------------------------------#
# frame builders
#------------------------------------------------------------------------------#

def build_frame(E=0, S=0, PN=0, nextext=0, typ=GTPUType.GPDU.value, teid=1,
                body=b'', lenval=None, version=1, pt=1, spare=0):
    """Assemble a GTP-U frame by hand.

    `body' is everything after the mandatory 8-byte header (optional header,
    extension headers, payload).  `lenval' overrides the declared length so
    truncation and trailing data can be exercised.
    """
    b0 = (version << 5) | (pt << 4) | (spare << 3) | (E << 2) | (S << 1) | PN
    if lenval is None:
        lenval = len(body)
    hdr = bytes([b0, typ, (lenval >> 8) & 0xFF, lenval & 0xFF])
    return hdr + (teid & 0xFFFFFFFF).to_bytes(4, 'big') + body


def opt_header(nextext, seq=1, npdu=0):
    return bytes([(seq >> 8) & 0xFF, seq & 0xFF, npdu, nextext])


def ext(typ, content, nextext=0, pad=b'', lenval=None):
    """One extension header, 4-octet aligned.

    `content' is the declared content; `pad' is appended after it when the
    declared length is larger than the known structure, so a caller can build
    a frame whose declared length does not match the meaningful bytes.
    """
    raw = content + pad
    if lenval is None:
        lenval = (2 + len(raw)) // 4
    return bytes([lenval]) + raw + bytes([nextext])


#------------------------------------------------------------------------------#
# assertion helpers
#------------------------------------------------------------------------------#

def expect_ok(buf):
    msg, code, lay = parse_GTPU(buf, with_diag=True)
    assert code == 0, 'valid frame rejected: %r' % (lay,)
    assert msg is not None
    # ranges must cover the whole declared message, contiguously
    assert lay['header'] == (0, 8), lay
    off = 8
    if lay['opt'] is not None:
        assert lay['opt'] == (off, off+4), lay
        off += 4
    for i, e in enumerate(lay['exts']):
        assert e['index'] == i, lay
        assert e['start'] == off, lay
        assert e['end'] == off + 4*e['len'], lay
        assert e['known'] == (e['type'] in KNOWN_EXT_TYPES), \
            'known/unknown classification wrong: %r' % (e,)
        off = e['end']
    assert lay['payload'] == (off, len(buf)), lay
    assert lay['trailing'] == 0, lay
    return msg, lay


def expect_fail(buf, err, ext_index=None, ext_type=None, offset=None):
    msg, code, diag = parse_GTPU(buf, with_diag=True)
    assert msg is None, 'malformed frame unexpectedly parsed: %r' % (diag,)
    assert code == err, 'wrong error code: %r' % (diag,)
    assert isinstance(diag, dict)
    if ext_index is not None:
        assert diag.get('ext_index') == ext_index, \
            'failure not located to the offending extension: %r' % (diag,)
    if ext_type is not None:
        assert diag.get('ext_type') == ext_type, \
            'offending extension type not reported: %r' % (diag,)
    if offset is not None:
        assert diag.get('offset') == offset, \
            'offending extension offset not reported: %r' % (diag,)
    return diag


#------------------------------------------------------------------------------#
# flags vs. layout, and the flag-only control
#------------------------------------------------------------------------------#

def test_flag_only_contrast():
    """Same bytes after the fixed header: only the E flag changes the split."""
    tail = opt_header(133) + ext(133, b'\x00\x01') + b'\xde\xad\xbe\xef'
    buf_e1 = build_frame(E=1, body=tail)
    buf_e0 = build_frame(E=0, body=tail)
    # the control: the two frames differ by exactly one bit, and nothing else
    assert buf_e1[0] ^ buf_e0[0] == 0x04
    assert buf_e1[1:] == buf_e0[1:]

    # with E set: four optional bytes, then extension header type 133
    msg, lay = expect_ok(buf_e1)
    assert lay['opt'] == (8, 12)
    assert [e['type'] for e in lay['exts']] == [133]
    assert lay['payload'] == (16, 20)

    # with E cleared, those same bytes are part of the payload
    msg, lay = expect_ok(buf_e0)
    assert lay['opt'] is None
    assert lay['exts'] == []
    assert lay['payload'] == (8, 20)
    assert msg['TPDU'].to_bytes() == buf_e0[8:]


def test_optional_header_flags():
    # S alone: optional header present, no extension
    buf = build_frame(S=1, nextext=0, body=opt_header(0) + b'\x01\x02\x03\x04')
    msg, lay = expect_ok(buf)
    assert lay['opt'] == (8, 12) and lay['exts'] == []
    assert lay['payload'] == (12, 16)

    # PN alone: same size optional header
    buf = build_frame(PN=1, nextext=0, body=opt_header(0) + b'\x01\x02\x03\x04')
    msg, lay = expect_ok(buf)
    assert lay['opt'] == (8, 12) and lay['exts'] == []
    assert lay['payload'] == (12, 16)

    # E implies the optional header even when S and PN are clear
    buf = build_frame(E=1, nextext=0, body=opt_header(0))
    msg, lay = expect_ok(buf)
    assert lay['opt'] == (8, 12)
    assert lay['payload'] == (12, 12)


#------------------------------------------------------------------------------#
# NextExt == 0 chain terminator
#------------------------------------------------------------------------------#

def test_chain_terminator_stops_at_next_zero():
    """A zero NextExt ends the chain: what follows is payload, not an ext."""
    buf = build_frame(E=1, body=opt_header(0) + b'\x01\x00\x01\x00')
    msg, lay = expect_ok(buf)
    assert lay['exts'] == []
    assert lay['payload'] == (12, 16)
    assert msg['TPDU'].to_bytes() == b'\x01\x00\x01\x00'


def test_chain_terminator_mid_buffer():
    """The terminator is honoured even when more extension-looking bytes follow."""
    buf = build_frame(E=1, body=opt_header(129)
                      + ext(129, b'\xaa\xbb', nextext=0)
                      + ext(133, b'\x00\x01', nextext=0)
                      + b'\xde\xad\xbe\xef')
    msg, lay = expect_ok(buf)
    assert [e['type'] for e in lay['exts']] == [129]
    assert lay['payload'] == (16, 24)
    assert msg['TPDU'].to_bytes() == b'\x01\x00\x01\x00\xde\xad\xbe\xef'


#------------------------------------------------------------------------------#
# zero-length extension
#------------------------------------------------------------------------------#

def test_zero_length_extension_rejected():
    # Len=0 is a 1-byte header: it cannot even carry its own NextExt byte
    buf = build_frame(E=1, body=opt_header(200) + b'\x00'
                      + b'\x85\x01\x00\x01\x00' + b'\xde\xad\xbe\xef')
    diag = expect_fail(buf, ERR_GTPU_EXT_HDR,
                       ext_index=0, ext_type=200, offset=12)
    assert 'zero length' in diag['error']


def test_zero_length_cannot_smuggle_a_chain():
    """A Len=0 extension must not let the following payload become ext #1."""
    body = opt_header(200) + b'\x00\x85' + ext(133, b'\x00\x01') \
           + b'\xde\xad\xbe\xef'
    buf = build_frame(E=1, body=body)
    expect_fail(buf, ERR_GTPU_EXT_HDR, ext_index=0, ext_type=200)


#------------------------------------------------------------------------------#
# unknown extension type
#------------------------------------------------------------------------------#

def test_unknown_extension_preserved_raw():
    buf = build_frame(E=1, body=opt_header(200) + ext(200, b'\xaa\xbb')
                      + b'\xde\xad\xbe\xef')
    msg, lay = expect_ok(buf)
    assert lay['exts'][0]['type'] == 200
    assert lay['exts'][0]['known'] is False
    cont = msg[0][10][0][1]
    assert getattr(cont, '_ExtKnown', None) is False
    assert getattr(cont, '_ID', None) == 200
    assert cont.to_bytes() == b'\xaa\xbb'
    # unknown content must not expose a decoded QFI (or any PDU session field)
    raised = False
    try:
        cont['QFI']
    except Exception:
        raised = True
    assert raised, 'unknown extension exposed a QFI field'
    assert msg.to_bytes() == buf


def test_unknown_extension_not_labelled_qfi():
    """Unknown content whose bytes parse as a valid QFI stays opaque."""
    # 0x0001 is a perfectly valid DL PDU session header (QFI == 1)
    buf = build_frame(E=1, body=opt_header(200) + ext(200, b'\x00\x01')
                      + b'\xde\xad\xbe\xef')
    msg, lay = expect_ok(buf)
    cont = msg[0][10][0][1]
    assert lay['exts'][0]['known'] is False
    assert cont._name == 'Content'
    assert not hasattr(cont, 'QFI')
    assert cont.to_bytes() == b'\x00\x01'


def test_known_qfi_still_decoded():
    """Control: a real type-133 extension is decoded as QFI."""
    buf = build_frame(E=1, body=opt_header(133) + ext(133, b'\x00\x01')
                      + b'\xde\xad\xbe\xef')
    msg, lay = expect_ok(buf)
    assert lay['exts'][0]['known'] is True
    cont = msg[0][10][0][1]
    assert cont._name == 'PDUSessionContainer'
    assert cont['Info']['QFI'].get_val() == 1


#------------------------------------------------------------------------------#
# truncated optional area / extension content
#------------------------------------------------------------------------------#

def test_truncated_optional_header():
    # E set, only two bytes of optional header available
    buf = build_frame(E=1, body=b'\x00\x01', lenval=2)
    msg, code, diag = parse_GTPU(buf, with_diag=True)
    assert msg is None and code != 0


def test_truncated_extension_content():
    # Len=1 means 2 content bytes, but the message ends after 1
    buf = build_frame(E=1, body=opt_header(133) + b'\x01\xaa', lenval=5)
    expect_fail(buf, ERR_GTPU_EXT_HDR, ext_index=0, ext_type=133, offset=12)


def test_truncated_next_ext_byte():
    # Len=1, 2 content bytes, but no room for the NextExt byte
    buf = build_frame(E=1, body=opt_header(133) + b'\x01\xaa\xbb', lenval=6)
    expect_fail(buf, ERR_GTPU_EXT_HDR, ext_index=0, ext_type=133, offset=12)


def test_truncation_in_second_extension():
    body = opt_header(200) + ext(200, b'\xaa\xbb', nextext=133) + b'\x01\xaa'
    buf = build_frame(E=1, body=body, lenval=len(body))
    expect_fail(buf, ERR_GTPU_EXT_HDR, ext_index=1, ext_type=133, offset=16)


#------------------------------------------------------------------------------#
# declared length vs. actual bytes
#------------------------------------------------------------------------------#

def test_declared_length_shorter_than_buffer():
    # one valid extension, then trailing bytes beyond the declared length
    body = opt_header(133) + ext(133, b'\x00\x01') + b'\xde\xad\xbe\xef'
    buf = build_frame(E=1, body=body, lenval=len(body)-4)
    msg, code, diag = parse_GTPU(buf, with_diag=True)
    assert msg is None
    assert code == ERR_GTPU_LEN_MISMATCH
    assert diag['declared_total'] == len(buf)-4


def test_declared_length_longer_than_buffer():
    body = opt_header(133) + ext(133, b'\x00\x01')
    buf = build_frame(E=1, body=body, lenval=len(body)+8)
    msg, code, diag = parse_GTPU(buf, with_diag=True)
    assert msg is None
    assert code == ERR_GTPU_BUF_TOO_SHORT


def test_extension_length_beyond_declared_message():
    """An extension must not read bytes past the declared message end."""
    # ext claims Len=2 (8 bytes) while the declared message leaves only 4
    body = opt_header(133) + ext(133, b'', pad=b'\x00'*6, lenval=2) \
           + b'\xde\xad\xbe\xef'
    buf = build_frame(E=1, body=body, lenval=8)
    expect_fail(buf, ERR_GTPU_EXT_HDR, ext_index=0, ext_type=133)


def test_extension_length_mismatch_known_type():
    """Declared Len must match the bytes the known structure consumes."""
    # type 32 (ServiceClassInd) has a 2-byte structure, so its Len is 1.
    # Len=2 leaves an extra 4-byte word that must not be silently dropped.
    body = opt_header(32) + bytes([2, 0x01, 0x02, 0x00]) + b'\x00\x00' \
           + b'\xde\xad\xbe\xef'
    buf = build_frame(E=1, body=body)
    msg, code, diag = parse_GTPU(buf, with_diag=True)
    if msg is None:
        assert code == ERR_GTPU_EXT_HDR
        assert diag['ext_index'] == 0
    else:
        lay = gtpu_layers(msg, len(buf))
        assert lay['exts'][0]['len'] == 2
        assert lay['payload'][0] == 20


#------------------------------------------------------------------------------#
# no aliasing between chain items
#------------------------------------------------------------------------------#

def test_extension_chain_items_are_distinct():
    body = opt_header(133) + ext(133, b'\x00\x01', nextext=129) \
           + ext(129, b'\xaa\xbb', nextext=0) + b'\xde\xad\xbe\xef'
    buf = build_frame(E=1, body=body)
    msg, lay = expect_ok(buf)
    exts = msg[0][10]
    assert exts.get_num() == 2
    assert exts._content[0] is not exts._content[1]
    assert exts[0][1].to_bytes() == b'\x00\x01'
    assert exts[1][1].to_bytes() == b'\xaa\xbb'
    assert exts[0][2].get_val() == 129
    assert exts[1][2].get_val() == 0
    assert msg.to_bytes() == buf


def test_roundtrip_preserves_chain():
    body = opt_header(200) + ext(200, b'\x11\x22', nextext=133) \
           + ext(133, b'\x00\x3f', nextext=0) + b'\xde\xad\xbe\xef'
    buf = build_frame(E=1, body=body)
    msg, lay = expect_ok(buf)
    val = msg.get_val()
    msg.reautomate()
    assert msg.get_val() == val
    msg.set_val(val)
    assert msg.to_bytes() == buf


#------------------------------------------------------------------------------#
# existing sample frames still parse
#------------------------------------------------------------------------------#

def test_real_sample_frames_still_parse():
    pdus = (
        '30ff003c04cec0bb4500003c22cb000080019bad0aa002ff481e268c0800995a0300b1016162636465666768696a6b6c6d6e6f7071727374757677616263646566676869',
        '361a00200000000000000040010868001004cec0bb85001022222222000000000000000000000002',
        '34ff0044008000350000008501100100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
        '34ff003c00000001000000850100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    )
    for pdu in pdus:
        buf = unhexlify(pdu)
        msg, code, lay = parse_GTPU(buf, with_diag=True)
        assert code == 0, 'regression on real frame %s: %r' % (pdu, lay)
        assert msg.to_bytes() == buf

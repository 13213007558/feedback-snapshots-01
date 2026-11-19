# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright 2026. pycrate contributors.
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
# * File Name : pycrate_crypto/AESCMAC.py
# * Created : 2026-11-19
# * Authors : pycrate contributors
# *--------------------------------------------------------
#*/

"""
Minimal AES-128 and AES-CMAC implementation.

It exists to let offline NAS transcript analysis verify 128-5G-IA2 / 128-EIA2
integrity protection without pulling an external crypto dependency (pycrate's
NAS modules delegate that to the optional CryptoMobile package).

Only what is needed for NAS integrity is provided:

* ``aes128_encrypt(key, block)``: single-block AES-128 encryption
* ``cmac(key, msg)``: AES-CMAC as specified in RFC 4493
* ``nas_mac(key, count, bearer, direction, msg)``: the 3GPP NAS MAC
  construction shared by 128-EIA2 (TS 33.401, annex B.2) and 128-5G-IA2
  (TS 33.501, annex D.2), truncated to the 32-bit NAS MAC

This is a verification helper for lab transcripts, not a hardened
cryptographic library: no side-channel hardening, no key schedule caching.
"""

__all__ = ['aes128_encrypt', 'cmac', 'nas_mac']


#------------------------------------------------------------------------------#
# AES-128
#------------------------------------------------------------------------------#

_SBOX = bytes((
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16))

_RCON = (0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36)


def _xtime(a):
    if a & 0x80:
        return ((a << 1) ^ 0x1b) & 0xff
    return (a << 1) & 0xff


def _expand_key(key):
    if len(key) != 16:
        raise ValueError('AES-128 key must be 16 bytes, got %i' % len(key))
    w = list(key)
    for i in range(4, 44):
        t = w[(i-1)*4:i*4]
        if i % 4 == 0:
            t = [ _SBOX[b] for b in (t[1:] + t[:1]) ]
            t[0] ^= _RCON[i//4 - 1]
        w += [ w[(i-4)*4 + j] ^ t[j] for j in range(4) ]
    return [ w[i*16:(i+1)*16] for i in range(11) ]


def aes128_encrypt(key, block):
    """AES-128 encryption of a single 16-byte block.

    Args:
        key: 16 bytes
        block: 16 bytes

    Returns:
        16 bytes
    """
    if len(block) != 16:
        raise ValueError('AES block must be 16 bytes, got %i' % len(block))
    rk = _expand_key(key)
    # state as 4 columns of 4 bytes (column-major, as in FIPS-197)
    s = [ [ block[r + 4*c] ^ rk[0][r + 4*c] for c in range(4) ] for r in range(4) ]
    for rnd in range(1, 11):
        s = [ [ _SBOX[s[r][c]] for c in range(4) ] for r in range(4) ]
        s = [ [ s[r][(c + r) % 4] for c in range(4) ] for r in range(4) ]
        if rnd != 10:
            for c in range(4):
                a0, a1, a2, a3 = ( s[r][c] for r in range(4) )
                s[0][c] = _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3
                s[1][c] = a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3
                s[2][c] = a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3
                s[3][c] = _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3)
        s = [ [ s[r][c] ^ rk[rnd][r + 4*c] for c in range(4) ] for r in range(4) ]
    return bytes( s[r][c] for c in range(4) for r in range(4) )


#------------------------------------------------------------------------------#
# AES-CMAC, RFC 4493
#------------------------------------------------------------------------------#

def _subkey(b):
    v = int.from_bytes(b, 'big') << 1
    if b[0] & 0x80:
        v ^= 0x87
    return ( v & ((1 << 128) - 1) ).to_bytes(16, 'big')


def cmac(key, msg):
    """AES-CMAC over `msg` with a 16-byte `key` (RFC 4493).

    Returns:
        16 bytes
    """
    if not isinstance(msg, (bytes, bytearray)):
        msg = bytes(msg)
    k1 = _subkey(aes128_encrypt(key, b'\0' * 16))
    k2 = _subkey(k1)
    n = (len(msg) + 15) // 16
    if n == 0:
        n = 1
        last = bytes((0x80,)) + b'\0' * 15
        k = k2
    elif len(msg) % 16 == 0:
        last = msg[-16:]
        k = k1
    else:
        rem = msg[(n-1)*16:]
        last = rem + bytes((0x80,)) + b'\0' * (15 - len(rem))
        k = k2
    x = b'\0' * 16
    for i in range(n - 1):
        x = aes128_encrypt(key, bytes(a ^ b for a, b in zip(x, msg[i*16:(i+1)*16])))
    return aes128_encrypt(key, bytes(a ^ b ^ c for a, b, c in zip(x, last, k)))


#------------------------------------------------------------------------------#
# 3GPP NAS integrity
# TS 33.401, annex B.2 (128-EIA2) and TS 33.501, annex D.2 (128-5G-IA2)
#------------------------------------------------------------------------------#

def nas_mac(key, count, bearer, direction, msg, length=4):
    """Compute the 3GPP NAS MAC for 128-EIA2 / 128-5G-IA2.

    The MAC is the first `length` bytes (4 for NAS) of::

        AES-CMAC(key, COUNT || BEARER || DIRECTION || 0x00000000 || MESSAGE)

    Args:
        key: 16 bytes, K_NASint
        count: 32-bit NAS COUNT
        bearer: 5 bits, 1 for NAS over 3GPP access, 2 for non-3GPP
        direction: 0 for uplink, 1 for downlink
        msg: NAS message bytes covered by the MAC
        length: number of MAC bytes to return, defaults to 4

    Returns:
        `length` bytes
    """
    if not 0 <= count <= 0xffffffff:
        raise ValueError('NAS COUNT out of range: %r' % count)
    if not 0 <= bearer <= 0x1f:
        raise ValueError('bearer out of range: %r' % bearer)
    if direction not in (0, 1):
        raise ValueError('direction must be 0 or 1, got %r' % direction)
    head = count.to_bytes(4, 'big') + bytes((bearer, direction)) + b'\0' * 4
    return cmac(key, head + bytes(msg))[:length]

# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2018. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/SCCP.py
# * Created : 2017-11-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import unhexlify
from collections.abc import Mapping

from pycrate_core.utils  import *
from pycrate_core.repr   import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.charpy import *

from .TS24008_IE import BufBCD


#------------------------------------------------------------------------------#
# ITU-T Q.713: Signalling connection control part formats and codes
# SCCP
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# SCCP general part
# ITU-T Q.713, section 2
#------------------------------------------------------------------------------#

_SCCPType_dict = {
    1 : 'CR',
    2 : 'CC',
    3 : 'CREF',
    4 : 'RLSD',
    5 : 'RLC',
    6 : 'DT1',
    7 : 'DT2',
    8 : 'AK',
    9 : 'UDT',
    10 : 'UDTS',
    11 : 'ED',
    12 : 'EA',
    13 : 'RSR',
    14 : 'RSC',
    15 : 'ERR',
    16 : 'IT',
    17 : 'XUDT',
    18 : 'XUDTS',
    19 : 'LUDT',
    20 : 'LUDTS'
    }


#------------------------------------------------------------------------------#
# SCCP parameters
# ITU-T Q.713, section 3
#------------------------------------------------------------------------------#

_SCCPParam_dict = {
    0 : 'End of optional parameters',
    1 : 'Destination local reference',
    2 : 'Source local reference',
    3 : 'Called Party address',
    4 : 'Calling party address',
    5 : 'Protocol class',
    6 : 'Segmenting/reassembling',
    7 : 'Receive sequence number',
    8 : 'Sequencint/segmenting',
    9 : 'Credit',
    10: 'Release cause',
    11: 'Return cause',
    12: 'Reset cause',
    13: 'Error cause',
    14: 'Refusal cause',
    15: 'Data',
    16: 'Segmentation',
    17: 'Hop counter',
    18: 'Importance',
    19: 'Long data'
    }

#------------------------------------------------------------------------------#
# End of optional parameters
# ITU-T Q.713, section 3.1
#------------------------------------------------------------------------------#

class EOO(Uint8):
    _val = 0
    _dic = _SCCPParam_dict


#------------------------------------------------------------------------------#
# Destination local reference
# ITU-T Q.713, section 3.2
#------------------------------------------------------------------------------#

class DstLocalRef(Uint24):
    pass


#------------------------------------------------------------------------------#
# Source local reference
# ITU-T Q.713, section 3.3
#------------------------------------------------------------------------------#

class SrcLocalRef(Uint24):
    pass


#------------------------------------------------------------------------------#
# Called Party Address / Calling Party Address
# ITU-T Q.713, section 3.4 / 3.5
#------------------------------------------------------------------------------#

class SCCPBufBCD(BufBCD):
    # as given in 3.4.2.3.1
    _chars  = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
               '_spare10_', '_code11_', '_code12_', '_spare13_', '_spare14_', '_ST_')
    # In Q.713 3.4.2.3.1, the high-order nibble of an odd number of address
    # signals is filled with 0000.  The ST code (1111) is an address signal
    # terminator, not padding, so get_route_identity() does not accept it as
    # filler for a GT number.
    _filler = 0x0

    def decode_parity(self, odd):
        """Decode address signals for display, according to the expected parity.

        Contrary to decode(), the last nibble of an odd address is removed as
        padding regardless of its value, so that both 0x0 filler and an ST code
        display the number without an extra trailing digit.  This is a display
        helper only: use get_route_identity() for a validated identity.
        """
        signals = []
        for octet in self.get_val():
            signals.append(octet & 0xF)
            signals.append((octet >> 4) & 0xF)
        if odd and signals:
            signals = signals[:-1]
        return ''.join(self._chars[s] for s in signals)


# GTInd 0001
# section 3.4.2.3.1

_GTNAI_dict = {
0 : 'unknown',
1 : 'subscriber number',
2 : 'reserved for national use',
3 : 'national significant number',
4 : 'international number'
}
_str_reserved_natuse = 'reserved for national use'
for i in range(0b1110000, 0b1111110):
    _GTNAI_dict[i] = _str_reserved_natuse


class _GlobalTitle0001(Envelope):
    _GEN = (
        Uint('OE', bl=1, dic={0:'even number of address signals', 1:'odd number of address signals'}),
        Uint('NAI', val=1, bl=7, dic=_GTNAI_dict),
        SCCPBufBCD('Addr', val=b'')
        )
    
    def get_addr(self):
        """return BCD-encoded Addr, properly decoded according to OE
        """
        return self[2].decode_parity(bool(self[0].get_val()))
    
    def set_addr(self, addr):
        """set the BCD-encoded Addr and OE
        """
        if len(addr) % 2:
            self[0].set_val(1)
        self[2].encode(addr)
    
    set_attr_bcd = set_addr


# GTInd 0010
# section 3.4.2.3.2

class _GlobalTitle0010(Envelope):
    _GEN = (
        Uint8('TranslationType'),
        Buf('Addr', val=b'', rep=REPR_HEX)
        )
    
    def get_addr(self):
        """return the hex-encoded Addr
        """
        return self[1].hex()
    
    def set_addr(self, addr):
        """set the hex-encoded Addr
        """
        self[1].set_val(unhexlify(addr))


# GTInd 0011
# section 3.4.2.3.3

_NumPlan_dict = {
    0 : 'unknown',
    1 : 'ISDN/telephony numbering plan (ITU-T E.163 and E.164)',
    2 : 'generic numbering plan',
    3 : 'data numbering plan (ITU-T X.121)',
    4 : 'telex numbering plan (ITU-T F.69)',
    5 : 'maritime mobile numbering plan (ITU-T E.210, E.211)',
    6 : 'land mobile numbering plan (ITU-T E.212)',
    7 : 'ISDN/mobile numbering plan (ITU-T E.214)',
    14 : 'private network or network-specific numbering plan'
    }

# kind reminder:
# from https://en.wikipedia.org/wiki/Global_title
# E.164 : MSISDN (CC + NDC + SN)
# E.212 : IMSI (MCC + MNC + MSIN)
# E.214 : MGT (CC + NDC + MSIN)

_EncScheme_dict = {
    0 : 'unknown',
    1 : 'BCD, odd number of digits',
    2 : 'BCD, even number of digits',
    3 : 'national specific'
    }

class _GlobalTitle0011(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('TranslationType'),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        Uint('EncodingScheme', val=1, bl=4, dic=_EncScheme_dict),
        Alt('Addr', GEN={
            1 : SCCPBufBCD('BCD', val=b''),
            2 : SCCPBufBCD('BCD', val=b'')},
            DEFAULT=Buf('Raw', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val())
        )

    def get_addr(self):
        """return the BCD- or hex-encoded Addr, properly decoded according to EncodingScheme
        """
        enc = self[2].get_val()
        if enc in (1, 2):
            return self[3].get_alt().decode_parity(enc == 1)
        else:
            return self[3].get_alt().hex()

    def set_addr_bcd(self, addr):
        """set the BCD-encoded Addr and EncodingScheme
        """
        if len(addr) % 2:
            self[2].set_val(1)
        else:
            self[2].set_val(2)
        self[3].get_alt().encode(addr)


# GTInd 0100
# section 3.4.2.3.4

_GTIntTransType_dict = {
    255: 'reserved for expansion'
    }
_str_int_serv = 'international services'
_str_nat_serv = 'national network specific'
for i in range(0b1, 0b111111):
    _GTIntTransType_dict[i] = _str_int_serv
for i in range(0b10000000, 0b11111110):
    _GTIntTransType_dict[i] = _str_nat_serv


class _GlobalTitle0100(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('TranslationType', val=1, dic=_GTIntTransType_dict),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        Uint('EncodingScheme', val=1, bl=4, dic=_EncScheme_dict),
        Uint('spare', bl=1),
        Uint('NAI', val=1, bl=7, dic=_GTNAI_dict),
        Alt('Addr', GEN={
            1 : SCCPBufBCD('BCD', val=b''),
            2 : SCCPBufBCD('BCD', val=b'')},
            DEFAULT=Buf('Raw', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val())
        )

    def get_addr(self):
        """return the BCD- or hex-encoded Addr, properly decoded according to EncodingScheme
        """
        enc = self[2].get_val()
        if enc in (1, 2):
            return self[5].get_alt().decode_parity(enc == 1)
        else:
            return self[5].get_alt().hex()
    
    def set_addr_bcd(self, addr):
        """set the BCD-encoded Addr and EncodingScheme
        """
        if len(addr) % 2:
            self[2].set_val(1)
        else:
            self[2].set_val(2)
        self[5].get_alt().encode(addr)


# SCCP called / calling party address

_RouteInd_dict = {
    0 : 'route on GT',
    1 : 'route on SSN'
    }

_GTInd_dict = {
    0 : 'no global title included',
    1 : 'global title includes nature of address indicator only',
    2 : 'global title includes translation type only',
    3 : 'global title includes translation type, numbering plan and encoding scheme',
    4 : 'global title includes translation type, numbering plan, '\
        'encoding scheme and nature of address indicator',
    }

_SSN_dict = {
    0 : 'SSN not known/not used',
    1 : 'SCCP management',
    2 : 'reserved for ITU-T allocation',
    3 : 'ISDN user part',
    4 : 'operation, maintenance and administration part (OMAP)',
    5 : 'mobile application part (MAP)',
    6 : 'home location register (HLR)',
    7 : 'visitor location register (VLR)',
    8 : 'mobile switching centre (MSC)',
    9 : 'equipment identifier register (EIR)',
    10 : 'authentication centre (AUC)',
    11 : 'ISDN supplementary services',
    12 : 'reserved for international use',
    13 : 'broadband ISDN edge-to-edge applications',
    14 : 'TC test responder',
    # from 3GPP TS 29.002 and 23.003
    142 : '3GPP RANAP',
    143 : '3GPP RNSAP',
    145 : '3GPP GMLC (MAP)',
    146 : '3GPP CAP',
    147 : '3GPP gsmSCF (MAP) or IM-SSF (MAP) or Presence Network Agent',
    148 : '3GPP SIWF (MAP)',
    149 : '3GPP SGSN (MAP)',
    150 : '3GPP GGSN (MAP)',
    248 : '3GPP CSS (MAP)',
    249 : '3GPP PCAP',
    250 : '3GPP BSC (BSSAP-LE)',
    251 : '3GPP MSC (BSSAP-LE)',
    252 : '3GPP SMLC (BSSAP-LE)',
    253 : '3GPP BSS O&M (A interface)',
    254 : '3GPP BSSAP (A interface)'
    }


class _SCCPAddr(Envelope):
    
    # this is to bypass the GT decoding process, and get a simple Buf() instead
    GT_DONT_DECODE = False
    
    ENV_SEL_TRANS = False
    _GEN = (
        Envelope('AddrInd', GEN=(
            Uint('res', bl=1),
            Uint('RoutingInd', val=0, bl=1, dic=_RouteInd_dict),
            Uint('GTInd', val=3, bl=4, dic=_GTInd_dict),
            Uint('SSNInd', val=0, bl=1),
            Uint('PCInd', val=0, bl=1)
            )),
        Uint16LE('PC'), # presence depends on PCInd
        Uint8('SSN', val=0, dic=_SSN_dict), # presence depends on SSNInd
        Alt('GT', GEN={
            1 : _GlobalTitle0001('GT_1'),
            2 : _GlobalTitle0010('GT_2'),
            3 : _GlobalTitle0011('GT_3'),
            4 : _GlobalTitle0100('GT_4')},
            DEFAULT=Buf('GT_unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0][2].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(lambda: False if self[0][4].get_val() != 0 else True)
        self[2].set_transauto(lambda: False if self[0][3].get_val() != 0 else True)
        self[3].set_transauto(lambda: False if self[0][2].get_val() != 0 else True)
    
    def _from_char(self, char):
        if not self.GT_DONT_DECODE:
            Envelope._from_char(self, char)
        else:
            self[0]._from_char(char)
            self[1]._from_char(char)
            self[2]._from_char(char)
            del self[3]
            gt = Buf('GT', rep=REPR_HEX)
            gt._from_char(char)
            self.append( gt )


class SCCPPartyAddr(Envelope):
    _GEN = (
        Uint8('Len'),
        _SCCPAddr('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)
    
    def get_gt(self):
        return self[1][3].get_alt()

    def get_route_identity(self, party=None):
        """Return the auditable exact routing identity for this party address.

        See pycrate_mobile.SCCP.get_route_identity().
        """
        return get_route_identity(self, party)


class CallingPartyAddr(SCCPPartyAddr):
    pass


class CalledPartyAddr(SCCPPartyAddr):
    pass


#------------------------------------------------------------------------------#
# SCCP routing identity and policy
# ITU-T Q.713, sections 3.4 and 3.5
#------------------------------------------------------------------------------#

# Exact fields which make up a routing identity, in deterministic order.  The
# decoded digits are represented too, but only for display and as one field
# among all the others: digits alone are never an identity.
_SCCPIdentityFields = (
    'address_indicator',
    'reserved',
    'routing_indicator',
    'gt_indicator',
    'ssn_indicator',
    'pc_indicator',
    'point_code',
    'ssn',
    'gt_present',
    'global_title_type',
    'translation_type',
    'numbering_plan',
    'nature_of_address',
    'encoding_scheme',
    'address_parity',
    'address_digits',
    'address_raw',
    'global_title_raw',
    'global_title_spare'
    )

_SCCPRouting_dict = {
    0 : 'route on GT',
    1 : 'route on SSN'
    }


def _sccp_elt_val(elt):
    """Return the numeric value of an SCCP element, or None."""
    try:
        return elt.get_val()
    except Exception:
        return None


def _sccp_elt_bytes(elt):
    """Return the raw bytes of an SCCP element, or b'' on error."""
    try:
        val = elt.to_bytes()
        if isinstance(val, bytes_types):
            return val
    except Exception:
        pass
    try:
        val = elt.get_val()
        if isinstance(val, bytes_types):
            return val
    except Exception:
        pass
    return b''


def _sccp_child(env, name):
    """Return a named child from an Envelope, or None."""
    try:
        if name in env._by_name:
            return env[name]
    except Exception:
        pass
    return None


def _sccp_addr_value(addr):
    """Return the _SCCPAddr value element from an address or message field."""
    if isinstance(addr, SCCPPartyAddr):
        return addr[1]
    if isinstance(addr, _SCCPAddr):
        return addr
    if isinstance(addr, Envelope) and 'AddrInd' in getattr(addr, '_by_name', ()):
        return addr
    raise(PycrateErr('SCCP routing identity: invalid address type {0}'\
          .format(type(addr).__name__)))


def _sccp_bcd_decode(raw, parity):
    """Strictly decode Q.713 BCD address signals.

    `parity` is "odd" or "even".  For an odd address, the last high-order
    nibble must be the 0000 filler defined in Q.713 3.4.2.3.1; for an even
    address, no filler is present.  Only decimal address signals 0..9 are
    accepted for the digits.

    Returns (digits, issues); digits is None when the address must be kept
    unknown.  Illegal filler and non-decimal signals are never trimmed or
    normalised into a shorter/wider valid number.
    """
    signals = []
    for octet in raw:
        # address signals are packed low nibble first, see Q.713 3.4.2.3.1
        signals.append(octet & 0xF)
        signals.append((octet >> 4) & 0xF)
    if parity not in ('odd', 'even'):
        return None, ['unknown address parity']
    if not signals:
        return None, ['empty address signals']
    if parity == 'odd':
        if signals[-1] != 0x0:
            return None, ['odd address has illegal filler 0x{0:x} (expected '
                          '0000)'.format(signals[-1])]
        signals = signals[:-1]
    if not signals:
        return None, ['no address signals after padding']
    bad = [s for s in signals if s > 9]
    if bad:
        return None, ['non-decimal address signal(s): {0}'\
                      .format(', '.join('0x{0:x}'.format(s) for s in bad))]
    return ''.join(str(s) for s in signals), []


def _sccp_gt_identity(gtind, gt_elt):
    """Extract global title fields from the `GT` alternative.

    Returns (gt_audit, canonical_fields, unknown, evidence).
    """
    evidence = []
    unknown = []
    canonical = {
        'global_title_type'  : gtind,
        'translation_type'   : None,
        'numbering_plan'     : None,
        'nature_of_address'  : None,
        'encoding_scheme'    : None,
        'address_parity'     : None,
        'address_digits'     : None,
        'address_raw'        : None,
        'global_title_raw'   : None,
        'global_title_spare' : None
        }
    if gt_elt is None:
        return None, canonical, ['GT indicator is non-zero but no GT is '\
                                 'present'], evidence
    # GT is a plain Buf when GT_DONT_DECODE was used or when the GT indicator
    # is not supported by this parser.
    if hasattr(gt_elt, 'get_alt'):
        try:
            actual = gt_elt.get_alt()
        except Exception:
            actual = None
    else:
        actual = gt_elt
    if actual is None or not isinstance(actual, Envelope) or \
    actual._name == 'GT_unk':
        raw = _sccp_elt_bytes(actual) if actual is not None else b''
        canonical['global_title_raw'] = raw.hex()
        unknown.append('global title is not decoded (raw only)')
        evidence.append({'source' : 'Value.GT',
                         'raw'    : '0x' + raw.hex(),
                         'field'  : 'global_title',
                         'value'  : None,
                         'status' : 'unknown'})
        audit = {'type'      : gtind,
                 'type_name' : _GTInd_dict.get(gtind, 'unsupported'),
                 'raw'       : raw.hex(),
                 'digits'    : None,
                 'parity'    : None,
                 'unknown'   : list(unknown)}
        return audit, canonical, unknown, evidence
    gt_raw = _sccp_elt_bytes(actual)
    canonical['global_title_raw'] = gt_raw.hex()
    audit = {'type'      : gtind,
             'type_name' : _GTInd_dict.get(gtind, 'unsupported'),
             'raw'       : gt_raw.hex(),
             'digits'    : None,
             'parity'    : None,
             'unknown'   : []}
    tt = _sccp_child(actual, 'TranslationType')
    np = _sccp_child(actual, 'NumberingPlan')
    es = _sccp_child(actual, 'EncodingScheme')
    nai = _sccp_child(actual, 'NAI')
    spare = _sccp_child(actual, 'spare')
    oe = _sccp_child(actual, 'OE')
    if tt is not None:
        tt_val = _sccp_elt_val(tt)
        canonical['translation_type'] = tt_val
        audit['translation_type'] = tt_val
        evidence.append({'source' : 'Value.GT.TranslationType',
                         'raw'    : '0x{0:02x}'.format(tt_val or 0),
                         'field'  : 'translation_type',
                         'value'  : tt_val})
    if np is not None:
        np_val = _sccp_elt_val(np)
        canonical['numbering_plan'] = np_val
        audit['numbering_plan'] = np_val
        audit['numbering_plan_name'] = _NumPlan_dict.get(np_val)
        evidence.append({'source' : 'Value.GT.NumberingPlan',
                         'raw'    : '0x{0:x}'.format(np_val or 0),
                         'field'  : 'numbering_plan',
                         'value'  : np_val,
                         'meaning': _NumPlan_dict.get(np_val)})
    if es is not None:
        es_val = _sccp_elt_val(es)
        canonical['encoding_scheme'] = es_val
        audit['encoding_scheme'] = es_val
        audit['encoding_scheme_name'] = _EncScheme_dict.get(es_val)
        evidence.append({'source' : 'Value.GT.EncodingScheme',
                         'raw'    : '0x{0:x}'.format(es_val or 0),
                         'field'  : 'encoding_scheme',
                         'value'  : es_val,
                         'meaning': _EncScheme_dict.get(es_val)})
    if nai is not None:
        nai_val = _sccp_elt_val(nai)
        canonical['nature_of_address'] = nai_val
        audit['nature_of_address'] = nai_val
        audit['nature_of_address_name'] = _GTNAI_dict.get(nai_val)
        evidence.append({'source' : 'Value.GT.NAI',
                         'raw'    : '0x{0:02x}'.format(nai_val or 0),
                         'field'  : 'nature_of_address',
                         'value'  : nai_val,
                         'meaning': _GTNAI_dict.get(nai_val)})
    if spare is not None:
        spare_val = _sccp_elt_val(spare)
        canonical['global_title_spare'] = spare_val
        audit['spare'] = spare_val
        evidence.append({'source' : 'Value.GT.spare',
                         'raw'    : str(spare_val),
                         'field'  : 'global_title_spare',
                         'value'  : spare_val})
    # parity comes from OE for GT type 1, from the encoding scheme otherwise
    parity = None
    if oe is not None:
        oe_val = _sccp_elt_val(oe)
        parity = 'odd' if oe_val else 'even'
        evidence.append({'source' : 'Value.GT.OE',
                         'raw'    : str(oe_val),
                         'field'  : 'address_parity',
                         'value'  : oe_val,
                         'meaning': parity})
    elif es is not None:
        es_val = _sccp_elt_val(es)
        if es_val == 1:
            parity = 'odd'
        elif es_val == 2:
            parity = 'even'
    canonical['address_parity'] = parity
    audit['parity'] = parity
    addr_elt = _sccp_child(actual, 'Addr')
    if addr_elt is None:
        unknown.append('GT address signals are absent')
        audit['unknown'] = list(unknown)
        return audit, canonical, unknown, evidence
    if hasattr(addr_elt, 'get_alt'):
        try:
            addr_alt = addr_elt.get_alt()
        except Exception:
            addr_alt = None
    else:
        addr_alt = addr_elt
    addr_raw = _sccp_elt_bytes(addr_alt) if addr_alt is not None else b''
    canonical['address_raw'] = addr_raw.hex()
    audit['address_signals_raw'] = addr_raw.hex()
    digits = None
    issues = []
    if gtind == 1:
        # GT 1: OE + NAI + BCD address signals, no numbering plan nor TT
        digits, issues = _sccp_bcd_decode(addr_raw, parity)
    elif gtind == 2:
        # GT 2 has no encoding scheme: never guess digits from its raw octets
        issues = ['GT type 2 has no BCD encoding scheme; address retained '\
                  'as raw only']
    elif gtind in (3, 4):
        es_val = _sccp_elt_val(es) if es is not None else None
        if es_val in (1, 2):
            digits, issues = _sccp_bcd_decode(addr_raw, parity)
        elif es_val == 3:
            issues = ['national specific encoding is not supported for '\
                      'routing identity']
        else:
            issues = ['unsupported/unknown encoding scheme {0!r}'\
                      .format(es_val)]
    else:
        issues = ['unsupported global title indicator {0}'.format(gtind)]
    canonical['address_digits'] = digits
    audit['digits'] = digits
    audit['unknown'] = list(issues)
    unknown.extend(issues)
    evidence.append({'source' : 'Value.GT.Addr',
                     'raw'    : '0x' + addr_raw.hex(),
                     'field'  : 'address_signals',
                     'parity' : parity,
                     'padding': '0x0' if parity == 'odd' else None,
                     'digits' : digits,
                     'status' : 'valid' if not issues else 'unknown',
                     'issues' : list(issues)})
    return audit, canonical, unknown, evidence


class SCCPRouteIdentity(Mapping):
    """Auditable SCCP routing identity.

    Behaves as a read-only mapping over its audit dictionary.  Equality and
    hashing use the complete canonical identity, never the displayed digits,
    so two addresses which display the same number but differ in numbering
    plan, nature of address, translation type, GT format or routing mode are
    distinct identities.
    """

    def __init__(self, audit, canonical):
        self._audit = audit
        self._canonical = canonical
        self._key = tuple(canonical[name] for name in _SCCPIdentityFields)

    # mapping interface
    def __getitem__(self, key):
        return self._audit[key]

    def __iter__(self):
        return iter(self._audit)

    def __len__(self):
        return len(self._audit)

    # attributes
    @property
    def canonical(self):
        return dict(self._canonical)

    @property
    def canonical_key(self):
        return self._key

    @property
    def unknown(self):
        return list(self._audit['unknown'])

    @property
    def valid(self):
        return bool(self._audit['valid'])

    @property
    def evidence(self):
        return list(self._audit['evidence'])

    @property
    def display(self):
        return self._audit['display']

    def to_dict(self):
        """Return a JSON-friendly audit dictionary."""
        audit = dict(self._audit)
        audit['canonical'] = dict(self._canonical)
        audit['identity_key'] = list(self._key)
        return audit

    def __eq__(self, other):
        if isinstance(other, SCCPRouteIdentity):
            return self._key == other._key
        if isinstance(other, Mapping):
            canonical = other.get('canonical')
            if isinstance(canonical, Mapping):
                other = canonical
            return dict(self._canonical) == dict(other)
        return NotImplemented

    def __ne__(self, other):
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return eq
        return not eq

    def __hash__(self):
        return hash(self._key)

    def __repr__(self):
        return '<SCCPRouteIdentity {0!r} valid={1}>'\
               .format(self._audit['display'], self.valid)


def get_route_identity(addr, party=None):
    """Build an auditable SCCP routing identity from a party address.

    Args:
        addr: SCCPPartyAddr / CalledPartyAddr / CallingPartyAddr, a bare
            _SCCPAddr, the bytes of a length-prefixed party address, or an
            SCCPRouteIdentity / audit dict produced earlier.
        party (str): optional role label stored in the audit output, e.g.
            "called" or "calling".

    Returns:
        SCCPRouteIdentity: mapping-like, JSON-friendly audit object.  It keeps
        the address indicator (including its reserved bit), routing indicator,
        GT indicator, numbering plan, nature of address, translation type,
        encoding scheme, BCD parity and raw address bytes.  GT is kept
        separate from point code and SSN.  Illegal BCD padding and unsupported
        encodings are retained as unknown: no alternative or truncated number
        is produced and nothing is normalised into a wider allowed number.
    """
    if isinstance(addr, SCCPRouteIdentity):
        return addr
    if isinstance(addr, Mapping):
        canonical = addr.get('canonical')
        if not isinstance(canonical, Mapping):
            raise(PycrateErr('SCCP routing identity: mapping has no '\
                             'canonical fields'))
        missing = [name for name in _SCCPIdentityFields
                   if name not in canonical]
        if missing:
            raise(PycrateErr('SCCP routing identity: mapping is missing '\
                             'canonical field(s) {0}'\
                             .format(', '.join(missing))))
        audit = dict(addr)
        audit.setdefault('party', None)
        audit.setdefault('unknown', [])
        audit.setdefault('valid', not audit['unknown'])
        audit.setdefault('evidence', [])
        if 'display' not in audit:
            digits = canonical.get('address_digits')
            raw = canonical.get('address_raw')
            audit['display'] = digits if digits is not None else \
                               ('raw:' + raw if raw else '<no address>')
        return SCCPRouteIdentity(audit, dict(canonical))
    if isinstance(addr, (bytes_types, bytearray)):
        paddr = SCCPPartyAddr()
        paddr.from_bytes(bytes(addr))
        addr = paddr
    if party is None:
        name = getattr(addr, '_name', None)
        if name == 'CalledPartyAddr':
            party = 'called'
        elif name == 'CallingPartyAddr':
            party = 'calling'
    value = _sccp_addr_value(addr)
    ai = _sccp_child(value, 'AddrInd')
    if ai is None:
        raise(PycrateErr('SCCP routing identity: address indicator is absent'))
    res = _sccp_elt_val(_sccp_child(ai, 'res')) or 0
    ri = _sccp_elt_val(_sccp_child(ai, 'RoutingInd'))
    gtind = _sccp_elt_val(_sccp_child(ai, 'GTInd'))
    ssnind = _sccp_elt_val(_sccp_child(ai, 'SSNInd')) or 0
    pcind = _sccp_elt_val(_sccp_child(ai, 'PCInd')) or 0
    if ri is None or gtind is None:
        raise(PycrateErr('SCCP routing identity: incomplete address indicator'))
    ai_raw = ((res & 1) << 7) | ((ri & 1) << 6) | ((gtind & 0xF) << 2) | \
             ((ssnind & 1) << 1) | (pcind & 1)
    bits = '{0:08b}'.format(ai_raw)
    evidence = [
        {'source' : 'Value.AddrInd',
         'raw'    : '0x{0:02x}'.format(ai_raw),
         'bits'   : bits,
         'field'  : 'reserved',
         'value'  : res},
        {'source' : 'Value.AddrInd',
         'raw'    : bits,
         'field'  : 'routing_indicator',
         'value'  : ri,
         'meaning': _SCCPRouting_dict.get(ri)},
        {'source' : 'Value.AddrInd',
         'raw'    : bits,
         'field'  : 'global_title_indicator',
         'value'  : gtind,
         'meaning': _GTInd_dict.get(gtind, 'unsupported')},
        {'source' : 'Value.AddrInd',
         'raw'    : bits,
         'field'  : 'ssn_indicator',
         'value'  : ssnind},
        {'source' : 'Value.AddrInd',
         'raw'    : bits,
         'field'  : 'point_code_indicator',
         'value'  : pcind}
        ]
    unknown = []
    pc = _sccp_elt_val(_sccp_child(value, 'PC')) if pcind else None
    ssn = _sccp_elt_val(_sccp_child(value, 'SSN')) if ssnind else None
    if pcind:
        pc_raw = _sccp_elt_bytes(_sccp_child(value, 'PC'))
        evidence.append({'source' : 'Value.PC',
                         'raw'    : '0x' + pc_raw.hex(),
                         'field'  : 'point_code',
                         'value'  : pc})
    if ssnind:
        evidence.append({'source' : 'Value.SSN',
                         'raw'    : '0x{0:02x}'.format(ssn or 0),
                         'field'  : 'ssn',
                         'value'  : ssn,
                         'meaning': _SSN_dict.get(ssn)})
    gt_elt = _sccp_child(value, 'GT')
    if ri == 0 and gtind == 0:
        unknown.append('routing indicator selects GT but GT indicator is 0')
    if ri == 1 and not (ssnind or pcind):
        unknown.append('routing indicator selects SSN but neither SSN nor '\
                       'point code is present')
    if ri == 1 and gtind != 0:
        # A global title in an address routed on SSN does not select the
        # destination by itself, but it remains part of the audited identity.
        evidence.append({'source' : 'Value.AddrInd',
                         'raw'    : bits,
                         'field'  : 'routing_conflict',
                         'value'  : 'GT present but routing indicator is SSN',
                         'meaning': 'GT retained separately from SSN route'})
    gt_audit = None
    gt_canonical = {
        'global_title_type'  : None,
        'translation_type'   : None,
        'numbering_plan'     : None,
        'nature_of_address'  : None,
        'encoding_scheme'    : None,
        'address_parity'     : None,
        'address_digits'     : None,
        'address_raw'        : None,
        'global_title_raw'   : None,
        'global_title_spare' : None
        }
    if gtind != 0:
        gt_audit, gt_canonical, gt_unknown, gt_evidence = \
            _sccp_gt_identity(gtind, gt_elt)
        unknown.extend(gt_unknown)
        evidence.extend(gt_evidence)
    else:
        evidence.append({'source' : 'Value.GT',
                         'raw'    : None,
                         'field'  : 'global_title',
                         'value'  : None,
                         'meaning': 'not present'})
    if gt_canonical['address_digits'] is not None:
        display = gt_canonical['address_digits']
    elif gt_canonical['address_raw']:
        display = 'raw:' + gt_canonical['address_raw']
    elif gt_canonical['global_title_raw']:
        display = 'raw:' + gt_canonical['global_title_raw']
    else:
        parts = []
        if pcind:
            parts.append('pc={0}'.format(pc))
        if ssnind:
            parts.append('ssn={0}'.format(ssn))
        display = ' '.join(parts) if parts else '<no address>'
    canonical = {
        'address_indicator' : ai_raw,
        'reserved'          : res,
        'routing_indicator' : ri,
        'gt_indicator'      : gtind,
        'ssn_indicator'     : ssnind,
        'pc_indicator'      : pcind,
        'point_code'        : pc,
        'ssn'               : ssn,
        'gt_present'        : gtind != 0
        }
    canonical.update(gt_canonical)
    audit = {
        'party' : party,
        'address' : {
            'indicator'         : ai_raw,
            'reserved'          : res,
            'routing_indicator' : ri,
            'routing'           : _SCCPRouting_dict.get(ri),
            'gt_indicator'      : gtind,
            'gt_type'           : _GTInd_dict.get(gtind, 'unsupported'),
            'ssn_indicator'     : ssnind,
            'pc_indicator'      : pcind,
            'point_code'        : pc,
            'ssn'               : ssn
            },
        'global_title' : gt_audit,
        'display'      : display,
        'display_note' : 'display is for review only; it is not a route '
                         'identity and must not be used for policy',
        'canonical'    : dict(canonical),
        'unknown'      : list(dict.fromkeys(unknown)),
        'valid'        : not unknown,
        'evidence'     : evidence
        }
    return SCCPRouteIdentity(audit, canonical)


# convenient aliases
route_identity = get_route_identity
routing_identity = get_route_identity


def get_message_route_identities(msg):
    """Return the routing identities carried by an SCCP message.

    Args:
        msg: a parsed SCCPMessage (or any Envelope containing
            CalledPartyAddr / CallingPartyAddr fields, including optional
            parameters).

    Returns:
        list of SCCPRouteIdentity, in field order.  Messages without party
        addresses (e.g. RLC) return an empty list.
    """
    idents = []
    _sccp_collect_party_addrs(msg, idents)
    return idents


def _sccp_collect_party_addrs(elt, idents):
    if isinstance(elt, SCCPPartyAddr):
        name = getattr(elt, '_name', None)
        if name == 'CalledPartyAddr':
            party = 'called'
        elif name == 'CallingPartyAddr':
            party = 'calling'
        else:
            # unwrap the option wrapper around the party address, if any
            party = None
            for child in getattr(elt, '_content', ()):
                if isinstance(child, SCCPPartyAddr):
                    party = 'called' if child._name == 'CalledPartyAddr' \
                            else 'calling'
                    elt = child
                    break
        idents.append(get_route_identity(elt, party))
        return
    for child in getattr(elt, '_content', ()):
        if isinstance(child, Element):
            _sccp_collect_party_addrs(child, idents)


def _sccp_identity(addr, party=None):
    """Coerce an address, identity or audit dict into an identity."""
    return get_route_identity(addr, party)


def _sccp_compare(rule, ident):
    """Compare every canonical field of two identities."""
    checks = []
    for name in _SCCPIdentityFields:
        expected = rule._canonical[name]
        observed = ident._canonical[name]
        checks.append({'field'    : name,
                       'expected' : expected,
                       'observed' : observed,
                       'match'    : expected == observed})
    return checks


class SCCPRoutePolicy:
    """Exact-match allow policy for SCCP routing identities.

    A rule is a complete SCCPRouteIdentity.  There is deliberately no
    digits-only, prefix or wildcard matching: the same displayed number on a
    different numbering plan, nature of address, translation type, GT type or
    routing mode is a different route.  Identities containing unknown or
    illegal fields can never be added as trusted rules and are always denied
    by check(), instead of being normalised into a wider allowed number.
    """

    def __init__(self, allowed=None, name=None):
        self._name = name
        self._rules = []
        if allowed:
            for rule in allowed:
                self.add_allowed(rule)

    @property
    def rules(self):
        return list(self._rules)

    def add_allowed(self, addr, party=None):
        """Add one complete identity or party address to the allow list."""
        ident = _sccp_identity(addr, party)
        if not ident.valid:
            raise(PycrateErr('SCCP routing policy: refusing unknown identity '
                             'as trusted rule: {0}'\
                             .format(', '.join(ident.unknown))))
        self._rules.append(ident)
        return ident

    # aliases for readability at call sites
    allow = add_allowed
    allow_addr = add_allowed

    def clear(self):
        self._rules = []

    def is_allowed(self, addr, party=None):
        return self.check(addr, party)['allowed']

    def check(self, addr, party=None):
        """Return a decision with raw-field evidence and exact-match checks."""
        try:
            ident = _sccp_identity(addr, party)
        except Exception as exc:
            return {'allowed'  : False,
                    'reason'   : 'unparseable_address',
                    'error'    : str(exc),
                    'checks'   : [],
                    'identity' : None}
        if not ident.valid:
            return {'allowed'  : False,
                    'reason'   : 'unknown_identity',
                    'unknown'  : ident.unknown,
                    'checks'   : [],
                    'identity' : ident.to_dict()}
        decision = {'allowed'       : False,
                    'reason'        : 'no_matching_rule',
                    'checks'        : [],
                    'nearest_rules' : [],
                    'identity'      : ident.to_dict()}
        for ind, rule in enumerate(self._rules):
            checks = _sccp_compare(rule, ident)
            if all(check['match'] for check in checks):
                decision['allowed'] = True
                decision['reason'] = 'allowed'
                decision['matched_rule'] = ind
                decision['checks'] = checks
                return decision
            decision['nearest_rules'].append(
                {'rule_index' : ind,
                 'mismatches' : [check for check in checks
                                 if not check['match']]})
        # keep the closest rules for the audit trail, best match first
        decision['nearest_rules'].sort(key=lambda r: len(r['mismatches']))
        decision['nearest_rules'] = decision['nearest_rules'][:3]
        if decision['nearest_rules']:
            decision['checks'] = decision['nearest_rules'][0]['mismatches']
        if not self._rules:
            decision['reason'] = 'no_rules_configured'
        return decision


#------------------------------------------------------------------------------#
# Protocol Class
# ITU-T Q.713, section 3.6
#------------------------------------------------------------------------------#

_ProtClass_dict = {
    0 : 'Class 0 (connection-less)',
    1 : 'Class 1 (connection-less)',
    2 : 'Class 2 (connection-oriented)',
    3 : 'Class 3 (connection-oriented)'
    }

_ProtCon_dict = {i: 'spare' for i in range(16)}
_ProtConLess_dict = {i: 'spare' for i in range(16)}
_ProtConLess_dict[0] = 'no special options'
_ProtConLess_dict[8] = 'return message on error'


class ProtocolClass(Envelope):
    _GEN = (
        Uint('Handling', bl=4),
        Uint('Class', bl=4, dic=_ProtClass_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_dicauto(lambda: _ProtConLess_dict if self[1].get_val() < 2 else _ProtCon_dict)


#------------------------------------------------------------------------------#
# Segmenting/reassembling
# ITU-T Q.713, section 3.7
#------------------------------------------------------------------------------#

class SegmentReassemb(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('M', val=0, bl=1, dic={0:'no more data', 1:'more data'})
        )


#------------------------------------------------------------------------------#
# Receive sequence number
# ITU-T Q.713, section 3.8
#------------------------------------------------------------------------------#

class RecvSeqn(Envelope):
    _GEN = (
        Uint('PR', val=0, bl=7),
        Uint('spare', bl=1)
        )


#------------------------------------------------------------------------------#
# Sequencing/segmenting
# ITU-T Q.713, section 3.9
#------------------------------------------------------------------------------#

class SeqSegment(Envelope):
    _GEN = (
        Uint('PS', val=0, bl=7),
        Uint('spare', bl=1),
        Uint('PR', val=0, bl=7),
        Uint('M', val=0, bl=1, dic={0:'no more data', 1:'more data'})
        )


#------------------------------------------------------------------------------#
# Credit
# ITU-T Q.713, section 3.10
#------------------------------------------------------------------------------#

class Credit(Uint8):
    pass


#------------------------------------------------------------------------------#
# Release Cause
# ITU-T Q.713, section 3.11
#------------------------------------------------------------------------------#

_RelCause_dict = {
    0 : 'end user originated',
    1 : 'end user congestion',
    2 : 'end user failure',
    3 : 'SCCP user originated',
    4 : 'remote procedure error',
    5 : 'inconsistent connection data',
    6 : 'access failure',
    7 : 'access congestion',
    8 : 'subsystem failure',
    9 : 'subsystem congestion',
    10 : 'MTP failure',
    11 : 'network congestion',
    12 : 'expiration of reset timer',
    13 : 'expiration of receive inactivity timer',
    14 : 'reserved',
    15 : 'unqualified',
    16 : 'SCCP failure'
    }

class RelCause(Uint8):
    _dic = _RelCause_dict


#------------------------------------------------------------------------------#
# Return Cause
# ITU-T Q.713, section 3.12
#------------------------------------------------------------------------------#

_RetCause_dict = {
    0 : 'no translation for an address of such nature',
    1 : 'no translation for this specific address',
    2 : 'subsystem congestion',
    3 : 'subsystem failure',
    4 : 'unequipped user',
    5 : 'MTP failure',
    6 : 'network congestion',
    7 : 'unqualified',
    8 : 'error in message transport (Note)',
    9 : 'error in local processing (Note)',
    10 : 'destination cannot perform reassembly (Note)',
    11 : 'SCCP failure',
    12 : 'hop counter violation',
    13 : 'segmentation not supported',
    14 : 'segmentation failure'
    }

class RetCause(Uint8):
    _dic = _RetCause_dict


#------------------------------------------------------------------------------#
# Reset Cause
# ITU-T Q.713, section 3.13
#------------------------------------------------------------------------------#

_ResCause_dict = {
    0 : 'end user originated',
    1 : 'SCCP user originated',
    2 : 'message out of order – incorrect P(S)',
    3 : 'message out of order – incorrect P(R)',
    4 : 'remote procedure error – message out of window',
    5 : 'remote procedure error – incorrect P(S) after (re)initialization',
    6 : 'remote procedure error – general',
    7 : 'remote end user operational',
    8 : 'network operational',
    9 : 'access operational',
    10 : 'network congestion',
    11 : 'reserved',
    12 : 'unqualified'
    }

class ResCause(Uint8):
    _dic = _ResCause_dict


#------------------------------------------------------------------------------#
# Error Cause
# ITU-T Q.713, section 3.14
#------------------------------------------------------------------------------#

_ErrCause_dict = {
    0 : 'local reference number (LRN) mismatch – unassigned destination LRN',
    1 : 'local reference number (LRN) mismatch – inconsistent source LRN',
    2 : 'point code mismatch',
    3 : 'service class mismatch',
    4 : 'unqualified'
    }

class ErrCause(Uint8):
    _dic = _ErrCause_dict


#------------------------------------------------------------------------------#
# Refusal Cause
# ITU-T Q.713, section 3.15
#------------------------------------------------------------------------------#

_RefCause_dict = {
    0 : 'end user originated',
    1 : 'end user congestion',
    2 : 'end user failure',
    3 : 'SCCP user originated',
    4 : 'destination address unknown',
    5 : 'destination inaccessible',
    6 : 'network resource – QoS not available/non-transient',
    7 : 'network resource – QoS not available/transient',
    8 : 'access failure',
    9 : 'access congestion',
    10 : 'subsystem failure',
    11 : 'subsystem congestion',
    12 : 'expiration of the connection establishment timer',
    13 : 'incompatible user data',
    14 : 'reserved',
    15 : 'unqualified',
    16 : 'hop counter violation',
    17 : 'SCCP failure',
    18 : 'no translation for an address of such nature',
    19 : 'unequipped user'
    }

class RefCause(Uint8):
    _dic = _RefCause_dict


#------------------------------------------------------------------------------#
# Data
# ITU-T Q.713, section 3.16
#------------------------------------------------------------------------------#

class Data(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Value', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


#------------------------------------------------------------------------------#
# Segmentation
# ITU-T Q.713, section 3.17
#------------------------------------------------------------------------------#

class Segmentation(Envelope):
    _GEN = (
        Uint('F', val=1, bl=1, dic={1:'first segment'}),
        Uint('C', bl=1, dic={0:'class 0 selected', 1:'class 1 selected'}),
        Uint('spare', bl=2),
        Uint('RemainingSeg', val=0, bl=4, dic={0:'last segment'}),
        Uint24('SegmentLocalRef')
        )


#------------------------------------------------------------------------------#
# Hop counter
# ITU-T Q.713, section 3.18
#------------------------------------------------------------------------------#

class HopCounter(Uint8):
    pass


#------------------------------------------------------------------------------#
# Importance
# ITU-T Q.713, section 3.19
#------------------------------------------------------------------------------#

class Importance(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('Value', val=0, bl=3, dic={0:'least important', 7:'more important'})
        )


#------------------------------------------------------------------------------#
# Long data
# ITU-T Q.713, section 3.20
#------------------------------------------------------------------------------#

class LongData(Envelope):
    _GEN = (
        # WNG: Q.713 does not say if it is in BE or LE, we guess LE similarly to Ptr16
        Uint16LE('Len'),
        Buf('Value', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


#------------------------------------------------------------------------------#
# SCCP messages and codes
# ITU-T Q.713, section 4
#------------------------------------------------------------------------------#

class _Ptr(UintLE):
    """Special SCCP pointer element, which sets its value automatically to the
    given field name
    """
    _field = None
    
    def __init__(self, *args, **kwargs):
        if 'field' in kwargs:
            self._field = kwargs['field']
            del kwargs['field']
        UintLE.__init__(self, *args, **kwargs)
        self._max = (1<<self._bl)-1
    
    def clone(self):
        c = UintLE.clone(self)
        if self._field:
            c._field = self._field
        return c
    
    def _make_val(self):
        if self._env is None or self._env._env is None:
            return 0
        else:
            val = 0
            # in case of pointer to optional part and no options, set to 0
            if self._field == 'Opt' and all([o.get_trans() for o in self._env._env['Opt']._content]):
                return val
            #
            # get the length of the following pointers (including self) within the Pointers envelope
            ind = self._env._content.index(self)
            for ptr in self._env._content[ind:]:
                val += ptr._bl//8
            if self._bl == 16:
                # see Q.713, section 2.3:
                # pointer value is between the MSB (LE) of the pointer and the parameter
                # hence removing 1 bytes for Ptr16
                val -= 1
            #
            # get the length of the fields after the Pointers field, up to self._field
            ind = 1 + self._env._env._content.index(self._env)
            for field in self._env._env._content[ind:]:
                if field._name == self._field:
                    break
                else:
                    val += field.get_len()
            #
            return min(self._max, val)
    
    _valauto = _make_val


class Ptr8(_Ptr):
    _bl = 8


class Ptr16(_Ptr):
    _bl = 16


# constructor for an optional parameter wrapper
def Optional(param, name):
    """prefix the parameter element `param' with an uint8 as name, and eventually
    an uint8 as len, and make it transparent by default
    """
    if param._name == 'EOO':
        w = Envelope(param._name, GEN=(param, ), trans=True)
    elif param.CLASS == 'Envelope' and param[0]._name == 'Len':
        # length prefix already present
        w = Envelope(param._name, GEN=(
                Uint8('Name', val=name, dic=_SCCPParam_dict),
                param), trans=True)
    else:
        # length prefix to be added
        class Option(Envelope):
            _GEN = (
                Uint8('Name', val=name, dic=_SCCPParam_dict),
                Uint8('Len'),
                param
                )
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
                self[1].set_valauto(lambda: self[2].get_len())
                if not hasattr(param, '_bl') or param._bl is None:
                    self[2].set_blauto(lambda: self[1].get_val()<<3)
                self.set_trans(True)
        w = Option(param._name)
    return w


# parent class for SCCP messages
class SCCPMessage(Envelope):
    """Parent class for all SCCP message, handling the parsing of variable-length
    fields specifically 
    """
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # parse the fixed content up the the pointers
        start = 0
        for e in self._content:
            e._from_char(char)
            if e._name == 'Pointers':
                # e: envelope containing all Ptr8 or Ptr16 values
                start = 1 + self.index(e)
                break
        if not start:
            return
        # parse the variable-length and optional content according to the pointers
        # this is done non-sequentially
        ccur, numptr = char._cur, len(e._content)
        # ccur: cursor at the end of the Pointers field
        # numptr: number of pointers
        for ind, ptr in enumerate(e._content):
            if ptr._field == 'Opt' and ptr._val == 0:
                break
            # update the charpy cursor
            char._cur = ccur + (8 * ptr.get_val()) - ((numptr-ind) * ptr._bl)
            if ptr._bl == 16:
                # see Q.713, section 2.3:
                # pointer value is between the MSB (LE) of the pointer and the parameter
                # hence removing 1 bytes for Ptr16
                char._cur += 8
            # select the corresponding field
            field = self._content[start+ind]
            field._from_char(char)
    
    def is_valid(self):
        """Ensures an SCCP message has a valid layout,
        i.e. its mandatory parameters with variable length (those with pointers) 
        do not overlap
        
        Args:
            None
        
        Returns:
            result: bool
        """
        if 'Pointers' in self._by_name:
            ptrs_ind = self._by_name.index('Pointers')
            ptrs  = self._content[ptrs_ind].get_val()
            prms  = self._content[1+ptrs_ind:]
            areas, len_ptrs = [], len(ptrs)
            for i in range(len_ptrs):
                prm = prms[i]
                if prm._name == 'Opt':
                    # Options have no global length prefix, but are always the last parameter
                    # moreover, if their pointer is null, the parameter is not present
                    ptr = ptrs[i]
                    if ptr != 0:
                        areas.append( (ptr-(len_ptrs-i), None) )
                else:
                    areas.append( (ptrs[i]-(len_ptrs-i), 1+prm._content[0].get_val()) )
            areas.sort(key=lambda x: x[0])
            # areas: list of (prm_offset, prm_length), sorted by prm_offset
            off = 0
            for prm in areas:
                if prm[0] < off:
                    return False
                else:
                    if prm[1] is not None:
                        off += prm[1]
        return True


# parent class for SCCP messages options
class SCCPOpt(Envelope):
    """Class for handling the set of SCCP optional fields in a given message
    """
    ENV_SEL_TRANS = False
    _opts = {}
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # build a dict of name : optional field
        self._opts = {e[0]._val: e for e in self._content}
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # parse the different options in the given order
        ind = 0
        while char.len_bit() >= 8:
            name = char.get_uint(8)
            if name not in self._opts:
                #raise(PycrateErr('SCCP option: invalid identifier %i' % name))
                # unknown option
                opt = Optional(Buf('_unk_%i' % name, rep=REPR_HEX), name)
                unk = True
            else:
                opt = self._opts[name]
                unk = False
            opt.set_trans(False)
            opt[0].set_val(name)
            # parse the rest of the option
            for e in opt._content[1:]:
                e._from_char(char)
            if unk:
                # insert unknown optional field
                self.insert(ind, opt)
            elif self.index(opt) != ind:
                # reorder optional field
                self.remove(opt)
                self.insert(ind, opt)
            ind += 1
            if name == 0:
                # end of options
                break


#------------------------------------------------------------------------------#
# Connection Request (CR)
# ITU-T Q.713, section 4.2
#------------------------------------------------------------------------------#

class SCCPConnectionRequest(SCCPMessage):
    _GEN = (
        Uint8('Type', val=1, dic=_SCCPType_dict),
        SrcLocalRef(),
        ProtocolClass(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='Opt')
            )),
        CalledPartyAddr(),
        SCCPOpt('Opt', GEN=(
            Optional(Credit(), 9),
            Optional(CallingPartyAddr(), 4),
            Optional(Data(), 15),
            Optional(HopCounter(), 17),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Connection Confirm (CC)
# ITU-T Q.713, section 4.3
#------------------------------------------------------------------------------#

class SCCPConnectionConfirm(SCCPMessage):
    _GEN = (
        Uint8('Type', val=2, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        ProtocolClass(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(Credit(), 9),
            Optional(CalledPartyAddr(), 4),
            Optional(Data(), 15),
            Optional(HopCounter(), 17),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Connection Refused (CREF)
# ITU-T Q.713, section 4.4
#------------------------------------------------------------------------------#

class SCCPConnectionRefused(SCCPMessage):
    _GEN = (
        Uint8('Type', val=3, dic=_SCCPType_dict),
        DstLocalRef(),
        RefCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(CalledPartyAddr(), 4),
            Optional(Data(), 15),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Released (RLSD)
# ITU-T Q.713, section 4.5
#------------------------------------------------------------------------------#

class SCCPReleased(SCCPMessage):
    _GEN = (
        Uint8('Type', val=4, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        RelCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(Data(), 15),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Release complete (RLC)
# ITU-T Q.713, section 4.6
#------------------------------------------------------------------------------#

class SCCPReleaseComplete(SCCPMessage):
    _GEN = (
        Uint8('Type', val=5, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef()
        )


#------------------------------------------------------------------------------#
# Data form 1 (DT1)
# ITU-T Q.713, section 4.7
#------------------------------------------------------------------------------#

class SCCPDataForm1(SCCPMessage):
    _GEN = (
        Uint8('Type', val=6, dic=_SCCPType_dict),
        DstLocalRef(),
        SegmentReassemb(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Data'),
            )),
        Data()
        )


#------------------------------------------------------------------------------#
# Data form 2 (DT2)
# ITU-T Q.713, section 4.8
#------------------------------------------------------------------------------#

class SCCPDataForm2(SCCPMessage):
    _GEN = (
        Uint8('Type', val=7, dic=_SCCPType_dict),
        DstLocalRef(),
        SeqSegment(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Data'),
            )),
        Data()
        )


#------------------------------------------------------------------------------#
# Data acknowledgement (AK)
# ITU-T Q.713, section 4.9
#------------------------------------------------------------------------------#

class SCCPDataAck(SCCPMessage):
    _GEN = (
        Uint8('Type', val=8, dic=_SCCPType_dict),
        DstLocalRef(),
        RecvSeqn(),
        Credit()
        )


#------------------------------------------------------------------------------#
# Unit Data (UDT)
# ITU-T Q.713, section 4.10
#------------------------------------------------------------------------------#

class SCCPUnitData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=9, dic=_SCCPType_dict),
        ProtocolClass(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data()
        )


#------------------------------------------------------------------------------#
# Unit Data Service (UDTS)
# ITU-T Q.713, section 4.11
#------------------------------------------------------------------------------#

class SCCPUnitDataService(SCCPMessage):
    _GEN = (
        Uint8('Type', val=10, dic=_SCCPType_dict),
        RetCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data()
        )


#------------------------------------------------------------------------------#
# Expedited data (ED)
# ITU-T Q.713, section 4.12
#------------------------------------------------------------------------------#

class SCCPExpeditedData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=11, dic=_SCCPType_dict),
        DstLocalRef(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Data'),
            )),
        Data()
        )


#------------------------------------------------------------------------------#
# Expedited data acknowledgement (EA)
# ITU-T Q.713, section 4.13
#------------------------------------------------------------------------------#

class SCCPExpeditedDataAck(SCCPMessage):
    _GEN = (
        Uint8('Type', val=12, dic=_SCCPType_dict),
        DstLocalRef()
        )


#------------------------------------------------------------------------------#
# Reset request (RSR)
# ITU-T Q.713, section 4.14
#------------------------------------------------------------------------------#

class SCCPResetRequest(SCCPMessage):
    _GEN = (
        Uint8('Type', val=13, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        ResCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(EOO(), 0),
            ))
        )


#------------------------------------------------------------------------------#
# Reset confirmation (RSC)
# ITU-T Q.713, section 4.15
#------------------------------------------------------------------------------#

class SCCPResetConf(SCCPMessage):
    _GEN = (
        Uint8('Type', val=14, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef()
        )


#------------------------------------------------------------------------------#
# Protocol data unit error (ERR)
# ITU-T Q.713, section 4.16
#------------------------------------------------------------------------------#

class SCCPError(SCCPMessage):
    _GEN = (
        Uint8('Type', val=15, dic=_SCCPType_dict),
        DstLocalRef(),
        ErrCause,
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(EOO(), 0),
            ))
        )


#------------------------------------------------------------------------------#
# Inactivity test (IT)
# ITU-T Q.713, section 4.17
#------------------------------------------------------------------------------#

class SCCPInactivityTest(SCCPMessage):
    _GEN = (
        Uint8('Type', val=16, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        ProtocolClass(),
        SeqSegment(),
        Credit()
        )


#------------------------------------------------------------------------------#
# Extended unitdata (XUDT)
# ITU-T Q.713, section 4.18
#------------------------------------------------------------------------------#

class SCCPExtUnitData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=17, dic=_SCCPType_dict),
        ProtocolClass(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data'),
            Ptr8('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
        

#------------------------------------------------------------------------------#
# Extended unitdata service (XUDTS)
# ITU-T Q.713, section 4.19
#------------------------------------------------------------------------------#

class SCCPExtUnitDataService(SCCPMessage):
    _GEN = (
        Uint8('Type', val=18, dic=_SCCPType_dict),
        RetCause(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data'),
            Ptr8('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
        

#------------------------------------------------------------------------------#
# Long unitdata (LUDT)
# ITU-T Q.713, section 4.20
#------------------------------------------------------------------------------#

class SCCPLongUnitData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=19, dic=_SCCPType_dict),
        ProtocolClass(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr16('Ptr0', field='CalledPartyAddr'),
            Ptr16('Ptr1', field='CallingPartyAddr'),
            Ptr16('Ptr2', field='LongData'),
            Ptr16('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        LongData(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
    
    def is_valid(self):
        """Ensures an SCCP message has a valid layout,
        i.e. its mandatory parameters with variable length (those with pointers) 
        do not overlap
        
        Args:
            None
        
        Returns:
            result: bool
        """
        # for LUDT / LUDTS, pointer and length prefix are 2 bytes long
        ptrs = self._content[3].get_val()
        prms = self._content[4:]
        areas = []
        for i in range(4):
            prm = prms[i]
            if prm._name == 'Opt':
                # Options have no global length prefix, but are always the last parameter
                # moreover, if their pointer is null, the parameter is not present
                ptr = ptrs[i]
                if ptr != 0:
                    areas.append( (ptr-2*(4-i), None) )
            else:
                areas.append( (ptrs[i]-2*(4-i), 2+prm._content[0].get_val()) )
        areas.sort(key=lambda x: x[0])
        # areas: list of (prm_offset, prm_length), sorted by prm_offset
        off = 0
        for prm in areas:
            if prm[0] < off:
                return False
            else:
                if prm[1] is not None:
                    off += prm[1]
        return True


#------------------------------------------------------------------------------#
# Long unitdata service (LUDTS)
# ITU-T Q.713, section 4.21
#------------------------------------------------------------------------------#

class SCCPLongUnitDataService(SCCPMessage):
    _GEN = (
        Uint8('Type', val=20, dic=_SCCPType_dict),
        RetCause(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr16('Ptr0', field='CalledPartyAddr'),
            Ptr16('Ptr1', field='CallingPartyAddr'),
            Ptr16('Ptr2', field='LongData'),
            Ptr16('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        LongData(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
    
    def is_valid(self):
        """Ensures an SCCP message has a valid layout,
        i.e. its mandatory parameters with variable length (those with pointers) 
        do not overlap
        
        Args:
            None
        
        Returns:
            result: bool
        """
        # for LUDT / LUDTS, pointer and length prefix are 2 bytes long
        ptrs = self._content[3].get_val()
        prms = self._content[4:]
        areas = []
        for i in range(4):
            prm = prms[i]
            if prm._name == 'Opt':
                # Options have no global length prefix, but are always the last parameter
                # moreover, if their pointer is null, the parameter is not present
                ptr = ptrs[i]
                if ptr != 0:
                    areas.append( (ptr-2*(4-i), None) )
            else:
                areas.append( (ptrs[i]-2*(4-i), 2+prm._content[0].get_val()) )
        areas.sort(key=lambda x: x[0])
        # areas: list of (prm_offset, prm_length), sorted by prm_offset
        off = 0
        for prm in areas:
            if prm[0] < off:
                return False
            elif prm[1] is None:
                return False
            else:
                off = prm[1]
        return True


#------------------------------------------------------------------------------#
# SCCP Message dispatcher
#------------------------------------------------------------------------------#

SCCPTypeClasses = {
    1 : SCCPConnectionRequest,
    2 : SCCPConnectionConfirm,
    3 : SCCPConnectionRefused,
    4 : SCCPReleased,
    5 : SCCPReleaseComplete,
    6 : SCCPDataForm1,
    7 : SCCPDataForm2,
    8 : SCCPDataAck,
    9 : SCCPUnitData,
    10 : SCCPUnitDataService,
    11 : SCCPExpeditedData,
    12 : SCCPExpeditedDataAck,
    13 : SCCPResetRequest,
    14 : SCCPResetConf,
    15 : SCCPError,
    16 : SCCPInactivityTest,
    17 : SCCPExtUnitData,
    18 : SCCPExtUnitDataService,
    19 : SCCPLongUnitData,
    20 : SCCPLongUnitDataService,
    }

def get_sccp_msg_instances():
    return {k: SCCPTypeClasses[k]() for k in SCCPTypeClasses}


#------------------------------------------------------------------------------#
# SCCP Management messages and codes
# ITU-T Q.713, section 5
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# SCMG message parameters
# ITU-T Q.713, section 5.2
#------------------------------------------------------------------------------#

_SCMGType_dict = {
    1 : 'SSA subsystem-allowed',
    2 : 'SSP subsystem-prohibited',
    3 : 'SST subsystem-status-test',
    4 : 'SOR subsystem-out-of-service-request',
    5 : 'SOG subsystem-out-of-service-grant',
    6 : 'SSC SCCP/subsystem-congested'
    }


_SMI_dict = {
    0 : 'affected subsystem multiplicity unknown',
    2 : 'reserved for national use',
    3 : 'reserved for national use'
    }

class SubsysMultInd(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('Value', val=0, bl=2, dic=_SMI_dict)
        )


class CongestLevel(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', val=1, bl=4, dic={1:'least congested', 8:'most congested'})
        )


#------------------------------------------------------------------------------#
# SCCP Messages
# ITU-T Q.713, section 5.3
#------------------------------------------------------------------------------#

class SCMGSubsysAllowed(Envelope):
    _GEN = (
        Uint8('Type', val=1, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysProhibited(Envelope):
    _GEN = (
        Uint8('Type', val=2, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysStatTest(Envelope):
    _GEN = (
        Uint8('Type', val=3, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysOutOfServRequest(Envelope):
    _GEN = (
        Uint8('Type', val=4, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysOutOfServGrant(Envelope):
    _GEN = (
        Uint8('Type', val=5, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )

class SCMGSubsysCongested(Envelope):
    _GEN = (
        Uint8('Type', val=6, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd(),
        CongestLevel()
        )

#------------------------------------------------------------------------------#
# SCMG Message dispatcher
#------------------------------------------------------------------------------#

SCMGTypeClasses = {
    1 : SCMGSubsysAllowed,
    2 : SCMGSubsysProhibited,
    3 : SCMGSubsysStatTest,
    4 : SCMGSubsysOutOfServRequest,
    5 : SCMGSubsysOutOfServGrant,
    6 : SCMGSubsysCongested
    }

def get_scmg_msg_instances():
    return {k: SCMGTypeClasses[k]() for k in SCMGTypeClasses}


#------------------------------------------------------------------------------#
# SCPP Message parser
#------------------------------------------------------------------------------#

def parse_SCCP(buf, w_scmg=True):
    """Parses an SCCP message bytes' buffer
    
    Args:
        buf: SCCP message bytes' buffer
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null
            err: 0 no error, 1 invalid message type, 2 message parsing failed
    """
    if not buf:
        return None, 1
    try:
        Msg = SCCPTypeClasses[buf[0]]()
    except:
        return None, 1
    try:
        Msg.from_bytes(buf)
    except:
        return None, 2
    #
    # if SCMG, parses it further (UDT/XUDT/LUDT, ProtocolClass 0, both addresses on SSN 1)
    if w_scmg:
        try:
            if Msg[0].get_val() in (9, 17, 19) and Msg[1][1].get_val() == 0 and \
            Msg[3][1][0]['RoutingInd'].get_val() == 1 and  Msg[3][1][0]['SSNInd'].get_val() == 1 and Msg[3][1]['SSN'].get_val() == 1 and \
            Msg[4][1][0]['RoutingInd'].get_val() == 1 and  Msg[4][1][0]['SSNInd'].get_val() == 1 and Msg[4][1]['SSN'].get_val() == 1:
                data = Msg[5]
                dataval = data[1]
                scmg, err = parse_SCMG(dataval.get_val())
                if err == 0:
                    data.replace(dataval, scmg)
        except:
            pass
    #
    return Msg, 0


def parse_SCMG(buf):
    """Parses an SCMG message bytes' buffer
    
    Args:
        buf: SCMG message bytes' buffer
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null
            err: 0 no error, 1 invalid message type, 2 message parsing failed
    """
    if not buf:
        return None, 1
    try:
        Msg = SCMGTypeClasses[buf[0]]()
    except:
        return None, 1
    try:
        Msg.from_bytes(buf)
    except:
        return None, 2
    return Msg, 0



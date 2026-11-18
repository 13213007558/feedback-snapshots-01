# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# *
# * Structured redaction / export for 5G NAS messages.
# *
# * The redaction policy is driven by the real 3GPP field types and their
# * nesting path (TS 24.501 5GS mobile identity, section 9.11.3.4), not by
# * field names: an element is only redacted when it is a known identity
# * information element. Allowed routing / scheme metadata of a SUCI is kept
# * analytically usable, while clear-text permanent identifiers, protected
# * identifier material and temporary identifiers are replaced with distinct,
# * non-trust-equivalent keyed aliases.
# *
# * Neither the input bytes nor the parsed pycrate objects are ever modified.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# */

import hmac

from hashlib    import sha256
from enum       import IntEnum

from pycrate_core.elt        import Atom, Envelope, Sequence, Alt, Array, Element
from pycrate_core.base       import Buf
from pycrate_mobile.TS24007  import IE
from pycrate_mobile.TS24501_IE import (
    FGSID,
    FGSIDTYPE,
    FGSIDFMT,
    _NAI_PREF,
    _NAI_NULL,
    _NAI_ECC,
    _NAI_PROP,
    _NAI_REA,
    )


#------------------------------------------------------------------------------#
# Trust domains
# Each kind of identifier has a distinct exposure surface. Aliases are derived
# with domain-separated HMAC labels so that an alias can never be promoted from
# one subject class to another (e.g. a cipher-text SUCI is not a clear-text
# SUPI, and a 5G-TMSI temporary identity is not a permanent identity).
#------------------------------------------------------------------------------#

class SubjectClass(IntEnum):
    """Trust class of a redacted identifier (TS 24.501 5GS identity type)."""
    PERMANENT_PLAIN = 1   # clear-text SUPI / IMSI / null-scheme SUCI / NAI userid
    PERMANENT_PROT  = 2   # protected SUCI material (ECIES / proprietary output)
    TEMPORARY       = 3   # 5G-GUTI / 5G-S-TMSI (5G-TMSI part)
    DEVICE          = 4   # IMEI / IMEISV (PEI)
    LINKLAYER       = 5   # MAC address / EUI-64


# HMAC domain labels, one per trust class
_DOMAIN_LABEL = {
    SubjectClass.PERMANENT_PLAIN: b'nas5g-redact:permanent-plain:v1',
    SubjectClass.PERMANENT_PROT:  b'nas5g-redact:permanent-protected:v1',
    SubjectClass.TEMPORARY:       b'nas5g-redact:temporary:v1',
    SubjectClass.DEVICE:          b'nas5g-redact:device:v1',
    SubjectClass.LINKLAYER:       b'nas5g-redact:linklayer:v1',
    }

# human-readable tag kept in the export, alongside the trust class
_SUBJECT_TAG = {
    SubjectClass.PERMANENT_PLAIN: 'permanent_plain',
    SubjectClass.PERMANENT_PROT:  'permanent_protected',
    SubjectClass.TEMPORARY:       'temporary',
    SubjectClass.DEVICE:          'device',
    SubjectClass.LINKLAYER:       'linklayer',
    }

# names of the IE wrappers that embed a 5GS mobile identity (used to catch an
# identity which failed to be decoded and is still present as raw bytes)
_IDENTITY_IE_NAMES = frozenset(('5GSID', 'AddGUTI', 'GUTI', 'IMEISV', 'PEI'))

_ALIAS_LEN = 16   # bytes of HMAC output exposed in the alias


#------------------------------------------------------------------------------#
# Keyed alias derivation
#------------------------------------------------------------------------------#

class RedactionKeyError(ValueError):
    """Raised when the caller-supplied redaction key is invalid."""
    pass


def _check_key(key):
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise RedactionKeyError(
            'redaction key must be a bytes-like object of at least 16 bytes')
    return bytes(key)


def _alias(key, subject_class, canonical):
    """Derive a deterministic, domain-separated pseudonym for an identifier.

    The same canonical identifier with the same key always yields the same
    alias (correlation within an export is preserved), while different trust
    classes use distinct HMAC labels so aliases never collide across domains.
    """
    mac = hmac.new(key, _DOMAIN_LABEL[subject_class] + b'|' + canonical,
                   sha256)
    return 'alias-%s-%s' % (
        _SUBJECT_TAG[subject_class],
        mac.hexdigest()[:2 * _ALIAS_LEN])


def _redacted(key, subject_class, canonical, path, name='5GSID'):
    """Build a redaction record replacing a sensitive identifier."""
    return {
        'element': name,
        'path': list(path),
        'redacted': True,
        'subject_class': int(subject_class),
        'subject_tag': _SUBJECT_TAG[subject_class],
        'alias': _alias(key, subject_class, canonical),
        }


#------------------------------------------------------------------------------#
# NAI parsing (TS 23.003 section 28.7.3), reused for _SUCI_NAI values
#------------------------------------------------------------------------------#

def _parse_nai(value):
    """Parse a SUPI/SUCI NAI string into structural components.

    Returns a dict with the allowed routing/scheme fields and the protected or
    clear-text identity material, or None if the NAI does not match the
    3GPP syntax.
    """
    if not isinstance(value, str):
        return None
    m = _NAI_PREF.match(value)
    if not m:
        return None
    fmt = int(m.group(1))
    routing_ind = m.group(2)
    scheme = int(m.group(3))
    rest = value[m.end():]
    info = {
        'fmt': fmt,
        'routing_ind': routing_ind,
        'scheme': scheme,
        'hnpk_id': None,
        'realm': '',
        }
    if scheme == 0:
        m2 = _NAI_NULL.match(rest)
        if not m2:
            return None
        info['user_id'] = m2.group(1)
        rest = rest[m2.end():]
    elif scheme in (1, 2):
        m2 = _NAI_ECC.match(rest)
        if not m2:
            return None
        info['hnpk_id'] = int(m2.group(1))
        info['ecc_ephem_pk'] = m2.group(2)
        info['cipher_text'] = m2.group(3)
        info['mac'] = m2.group(4)
        rest = rest[m2.end():]
    else:
        m2 = _NAI_PROP.match(rest)
        if not m2:
            return None
        info['hnpk_id'] = int(m2.group(1))
        info['output'] = m2.group(2)
        rest = rest[m2.end():]
    m3 = _NAI_REA.match(rest)
    info['realm'] = m3.group(1) if m3 else rest
    return info


#------------------------------------------------------------------------------#
# Generic, non-mutating serialization
#------------------------------------------------------------------------------#

def _atom_value(elt):
    """JSON-safe representation of an Atom value."""
    val = elt.get_val()
    if isinstance(val, bytes):
        return {'hex': val.hex(), 'len': len(val)}
    if isinstance(val, IntEnum):
        return int(val)
    return val


def _walk(elt, path, key, redactions):
    """Recursively export a pycrate element, redacting known identity IEs."""
    # 5GS mobile identity: policy decided on the real identity type
    if isinstance(elt, FGSID):
        return _export_fgsid(elt, path, key, redactions)

    # identity IE wrapper whose inner 5GSID failed to decode: the raw buffer
    # must not be exported as-is
    if isinstance(elt, IE) and elt._name in _IDENTITY_IE_NAMES \
            and len(elt._content) and elt._content[-1]._name == 'V' \
            and isinstance(elt._content[-1], Buf):
        raw = elt._content[-1].get_val()
        rec = _redacted(key=key,
                        subject_class=SubjectClass.PERMANENT_PROT,
                        canonical=b'opaque-identity:' + raw,
                        path=path + [elt._name], name=elt._name)
        rec['reason'] = 'undecoded identity IE'
        rec['wire_len'] = len(raw)
        redactions.append(rec)
        return rec

    if isinstance(elt, Atom):
        node = {
            'element': elt._name,
            'type': type(elt).__name__,
            'path': list(path),
            'value': _atom_value(elt),
            }
        return node

    if isinstance(elt, Alt):
        return _walk(elt.get_alt(), path, key, redactions)

    # Envelope / Sequence / Array: recurse over the non-transparent content
    if isinstance(elt, (Envelope, Sequence, Array)):
        children = []
        for sub in elt:
            children.append(
                _walk(sub, path + [elt._name], key, redactions))
        node = {
            'element': elt._name,
            'type': type(elt).__name__,
            'path': list(path),
            'content': children,
            }
        return node

    # fallback for any other element kind: expose only a type marker, never an
    # opaque raw value
    return {
        'element': getattr(elt, '_name', type(elt).__name__),
        'type': type(elt).__name__,
        'path': list(path),
        'value': None,
        }


#------------------------------------------------------------------------------#
# 5GS mobile identity redaction (TS 24.501, 9.11.3.4)
#------------------------------------------------------------------------------#

def _bcd(elt):
    """Decode a BCD element defensively (falls back to raw hex)."""
    try:
        return elt.decode()
    except Exception:
        return elt.get_val().hex()


def _redaction_record(fgsid, path, key, subject_class, canonical):
    rec = _redacted(key=key, subject_class=subject_class, canonical=canonical,
                    path=path + [fgsid._name], name=fgsid._name)
    rec['identity_type'] = int(fgsid['Type'].get_val())
    return rec


def _export_suci_imsi(suci, path, key, redactions):
    """SUCI / SUPI in IMSI format: keep routing metadata, redact the output."""
    plmn = suci['PLMN'].decode()
    routing = _bcd(suci['RoutingInd'])
    scheme = int(suci['ProtSchemeID'].get_val())
    hnpk_id = int(suci['HNPKID'].get_val())
    out = suci['Output'].get_alt()

    node = {
        'element': '5GSID',
        'type': 'FGSID',
        'path': list(path),
        'identity_type': int(FGSIDTYPE.SUPI),
        'format': int(FGSIDFMT.IMSI),
        'allowed': {
            'PLMN': plmn,
            'RoutingInd': routing,
            'ProtSchemeID': scheme,
            'HNPKID': hnpk_id,
            },
        }

    if scheme == 0:
        # null protection: the MSIN is a clear-text permanent identity
        msin = out.decode()
        canonical = ('imsi:%s%s' % (plmn, msin)).encode('utf-8')
        rec = _redacted(key=key, subject_class=SubjectClass.PERMANENT_PLAIN,
                        canonical=canonical, path=path + ['Output', 'MSIN'])
        rec['identity_type'] = int(FGSIDTYPE.SUPI)
        rec['field'] = 'MSIN'
        redactions.append(rec)
        node['output'] = rec
        node['output']['clear_text'] = True
    elif scheme in (1, 2):
        # ECIES protected SUCI: keep no key/cipher/mac material, only lengths
        wire = out.to_bytes()
        rec = _redacted(key=key, subject_class=SubjectClass.PERMANENT_PROT,
                        canonical=b'suci-imsi-ecies:' + wire,
                        path=path + ['Output'])
        rec['identity_type'] = int(FGSIDTYPE.SUPI)
        rec['field'] = 'ECIESOutput'
        rec['wire_len'] = len(wire)
        redactions.append(rec)
        node['output'] = rec
        node['output']['protected'] = True
        node['output']['components'] = {
            'ECCEphemPK': {'len': len(out['ECCEphemPK'].get_val())},
            'CipherText': {'len': len(out['CipherText'].get_val())},
            'MAC': {'len': len(out['MAC'].get_val())},
            }
    else:
        # proprietary / unknown protection scheme
        raw = out.get_val()
        if not isinstance(raw, bytes):
            raw = out.to_bytes()
        rec = _redacted(key=key, subject_class=SubjectClass.PERMANENT_PROT,
                        canonical=b'suci-imsi-proprietary:' + raw,
                        path=path + ['Output'])
        rec['identity_type'] = int(FGSIDTYPE.SUPI)
        rec['field'] = 'ProtectedOutput'
        rec['wire_len'] = len(raw)
        redactions.append(rec)
        node['output'] = rec
        node['output']['protected'] = True
    return node


def _export_suci_nai(alt, fmt, path, key, redactions):
    """SUPI / SUCI in NAI formats (NSI / GCI / GLI)."""
    value = alt.get_val()
    parsed = _parse_nai(value if isinstance(value, str) else '')
    node = {
        'element': '5GSID',
        'type': 'FGSID',
        'path': list(path),
        'identity_type': int(FGSIDTYPE.SUPI),
        'format': fmt,
        }
    if parsed is None:
        # unparseable NAI: treat the whole string as protected material
        raw = value.encode('utf-8') if isinstance(value, str) else b''
        rec = _redacted(key=key, subject_class=SubjectClass.PERMANENT_PROT,
                        canonical=b'suci-nai-opaque:' + raw,
                        path=path + ['NAI'])
        rec['identity_type'] = int(FGSIDTYPE.SUPI)
        rec['field'] = 'NAI'
        redactions.append(rec)
        node['output'] = rec
        return node

    allowed = {
        'NAIFmt': parsed['fmt'],
        'RoutingInd': parsed['routing_ind'],
        'ProtSchemeID': parsed['scheme'],
        'Realm': parsed['realm'],
        }
    if parsed['hnpk_id'] is not None:
        allowed['HNPKID'] = parsed['hnpk_id']
    node['allowed'] = allowed

    if parsed['scheme'] == 0:
        canonical = ('nai-null:%s:%s' % (parsed['realm'],
                                         parsed['user_id'])).encode('utf-8')
        rec = _redacted(key=key, subject_class=SubjectClass.PERMANENT_PLAIN,
                        canonical=canonical, path=path + ['UserID'])
        rec['identity_type'] = int(FGSIDTYPE.SUPI)
        rec['field'] = 'UserID'
        redactions.append(rec)
        node['output'] = rec
        node['output']['clear_text'] = True
    else:
        if 'cipher_text' in parsed:
            material = (parsed['ecc_ephem_pk'] + parsed['cipher_text']
                        + parsed['mac'])
            field = 'ECIESOutput'
        else:
            material = parsed['output']
            field = 'ProtectedOutput'
        rec = _redacted(key=key, subject_class=SubjectClass.PERMANENT_PROT,
                        canonical=b'suci-nai-protected:' + material.encode('ascii'),
                        path=path + ['Output'])
        rec['identity_type'] = int(FGSIDTYPE.SUPI)
        rec['field'] = field
        rec['wire_len'] = len(material)
        redactions.append(rec)
        node['output'] = rec
        node['output']['protected'] = True
    return node


def _export_fgsid(fgsid, path, key, redactions):
    """Apply the type-driven policy to a decoded 5GS mobile identity IE."""
    ident_type = int(fgsid['Type'].get_val())

    # SUPI / SUCI: dispatch on the IMSI vs NAI format, then on scheme
    if ident_type == FGSIDTYPE.SUPI:
        fmt = int(fgsid['Fmt'].get_val())
        alt = fgsid['Value'].get_alt()
        if fmt == FGSIDFMT.IMSI:
            return _export_suci_imsi(alt, path + [fgsid._name], key,
                                     redactions)
        return _export_suci_nai(alt, fmt, path + [fgsid._name], key,
                                redactions)

    # 5G-GUTI: routing/AMF locator is kept, only the 5G-TMSI is a temporary
    # subject and gets aliased
    if ident_type == FGSIDTYPE.GUTI:
        tmsi = fgsid['5GTMSI'].get_val()
        canonical = ('guti:%s:%02x:%03x:%02x:%08x' % (
            fgsid['PLMN'].decode(),
            int(fgsid['AMFRegionID'].get_val()),
            int(fgsid['AMFSetID'].get_val()),
            int(fgsid['AMFPtr'].get_val()),
            tmsi)).encode('ascii')
        rec = _redaction_record(fgsid, path, key, SubjectClass.TEMPORARY,
                                canonical)
        rec['field'] = '5GTMSI'
        redactions.append(rec)
        return {
            'element': '5GSID',
            'type': 'FGSID',
            'path': list(path),
            'identity_type': ident_type,
            'allowed': {
                'PLMN': fgsid['PLMN'].decode(),
                'AMFRegionID': int(fgsid['AMFRegionID'].get_val()),
                'AMFSetID': int(fgsid['AMFSetID'].get_val()),
                'AMFPtr': int(fgsid['AMFPtr'].get_val()),
                },
            'output': rec,
            }

    # 5G-S-TMSI: AMF pointer locator kept, 5G-TMSI aliased
    if ident_type == FGSIDTYPE.STMSI:
        tmsi = fgsid['5GTMSI'].get_val()
        canonical = ('stmsi:%03x:%02x:%08x' % (
            int(fgsid['AMFSetID'].get_val()),
            int(fgsid['AMFPtr'].get_val()),
            tmsi)).encode('ascii')
        rec = _redaction_record(fgsid, path, key, SubjectClass.TEMPORARY,
                                canonical)
        rec['field'] = '5GTMSI'
        redactions.append(rec)
        return {
            'element': '5GSID',
            'type': 'FGSID',
            'path': list(path),
            'identity_type': ident_type,
            'allowed': {
                'AMFSetID': int(fgsid['AMFSetID'].get_val()),
                'AMFPtr': int(fgsid['AMFPtr'].get_val()),
                },
            'output': rec,
            }

    # IMEI / IMEISV: device permanent identity
    if ident_type in (FGSIDTYPE.IMEI, FGSIDTYPE.IMEISV):
        digits = fgsid.decode()[1]
        label = 'imei' if ident_type == FGSIDTYPE.IMEI else 'imeisv'
        rec = _redaction_record(
            fgsid, path, key, SubjectClass.DEVICE,
            ('%s:%s' % (label, digits)).encode('ascii'))
        rec['field'] = 'Digits'
        redactions.append(rec)
        return {
            'element': '5GSID',
            'type': 'FGSID',
            'path': list(path),
            'identity_type': ident_type,
            'output': rec,
            }

    # MAC address
    if ident_type == FGSIDTYPE.MAC:
        raw = fgsid['MAC'].get_val()
        rec = _redaction_record(
            fgsid, path, key, SubjectClass.LINKLAYER,
            b'mac:' + raw)
        rec['field'] = 'MAC'
        redactions.append(rec)
        return {
            'element': '5GSID',
            'type': 'FGSID',
            'path': list(path),
            'identity_type': ident_type,
            'allowed': {'MAURI': int(fgsid['MAURI'].get_val())},
            'output': rec,
            }

    # EUI-64
    if ident_type == FGSIDTYPE.EUI64:
        raw = fgsid['EUI64'].get_val()
        rec = _redaction_record(
            fgsid, path, key, SubjectClass.LINKLAYER,
            b'eui64:' + raw)
        rec['field'] = 'EUI64'
        redactions.append(rec)
        return {
            'element': '5GSID',
            'type': 'FGSID',
            'path': list(path),
            'identity_type': ident_type,
            'output': rec,
            }

    # No identity / unknown type: generic structural export
    return _walk_generic(fgsid, path, key, redactions)


def _walk_generic(elt, path, key, redactions):
    """Structural export for non-identity FGSID variants (e.g. No identity)."""
    children = []
    for sub in elt:
        if isinstance(sub, Alt):
            children.append(_walk(sub.get_alt(), path + [elt._name], key,
                                  redactions))
        else:
            children.append(_walk(sub, path + [elt._name], key, redactions))
    return {
        'element': elt._name,
        'type': type(elt).__name__,
        'path': list(path),
        'content': children,
        }


#------------------------------------------------------------------------------#
# Public API
#------------------------------------------------------------------------------#

def redact_message(msg, key):
    """Export a parsed 5G NAS message into a redacted, JSON-safe structure.

    Args:
        msg: a pycrate 5G NAS Element (e.g. returned by `parse_NAS5G`), or a
            raw 5G NAS bytes buffer.
        key: caller-supplied bytes-like secret of at least 16 bytes. Aliases
            for correlated identifiers are derived from it; the same key must
            be reused across a shared analysis export to keep correlations.

    Returns:
        dict with:
            - message: class name of the root element
            - tree: redacted structural export (paths, types, allowed fields)
            - redactions: list of every redacted identifier, with its trust
              class, nesting path and keyed alias

    The parsed object and any input buffer are left unchanged.
    """
    from pycrate_mobile.NAS5G import parse_NAS5G

    key = _check_key(key)
    if isinstance(msg, (bytes, bytearray)):
        parsed, err = parse_NAS5G(bytes(msg))
        if parsed is None:
            raise ValueError('unable to parse 5G NAS message, error %i' % err)
        msg = parsed
    elif not isinstance(msg, Element):
        raise TypeError('msg must be a pycrate Element or a bytes buffer')

    redactions = []
    tree = _walk(msg, [], key, redactions)
    return {
        'message': type(msg).__name__,
        'tree': tree,
        'redactions': redactions,
        }

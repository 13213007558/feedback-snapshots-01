'''Layered checksum verification for UEFI firmware volumes.

Three unrelated checksums protect different byte ranges, and this module
reports each one separately:

``volume_header``
    16-bit sum over the volume header and its block map, ``[0, hdrlen)``,
    stored at offset 0x32. It covers the header, the block map and the
    ExtHeaderOffset field, but none of the volume body.

``ffs_header``
    8-bit sum over one FFS file header, stored at offset 0x10. The two
    checksum bytes (0x10 and 0x11) and the State byte (0x17) are zero while
    summing. A large file's 64-bit ExtendedSize is part of its 32-byte
    header and is therefore covered.

``file_data``
    8-bit sum over the bytes after the file header, ``[header_size, size)``,
    stored at offset 0x11. It exists only when the file's attribute 0x40
    (data checksum) is set. Without that attribute, byte 0x11 is a fixed
    filler (0xAA in FFS2, 0x5A in FFS1) and the file data is unprotected.

There is deliberately no aggregate "image is valid" result: one layer can
pass while another fails, and a passing layer says nothing about the bytes
outside its range. Free space, file alignment padding after a file's
declared size, and the contents of a volume extended header are not covered
by any of these checksums.

Checksums are not signatures. They use no key, identify no publisher, and
an editor can recompute them after changing any content. A recomputed
8-bit sum also collides trivially, so even a matching checksum does not
prove the bytes are the ones the vendor shipped.
'''

from dataclasses import dataclass
import struct
import uuid

from .structs.uefi_structs import FIRMWARE_VOLUME_GUIDS

VOLUME_HEADER = 'volume_header'
FFS_HEADER = 'ffs_header'
FILE_DATA = 'file_data'
EXTENDED_HEADER = 'extended_header'

VALID = 'valid'
INVALID = 'invalid'
NOT_PRESENT = 'not_present'
NOT_COVERED = 'not_covered'

_FFS_ATTRIB_LARGE_FILE = 0x01
_FFS_TYPE_PAD = 0xF0
_FFS_ATTRIB_CHECKSUM = 0x40
_FFS_HEADER_SIZE = 24
_FFS_LARGE_HEADER_SIZE = 32
_VOLUME_HEADER_SIZE = 56
_EXT_HEADER_SIZE = 0x14

_FFS_GUIDS = {
    uuid.UUID(FIRMWARE_VOLUME_GUIDS[name]).bytes_le
    for name in ('FFS1', 'FFS2', 'FFS3')
}


@dataclass(frozen=True)
class LayerResult(object):
    '''The result of one checksum layer.

    Attributes:
        layer: One of the layer constants.
        status: VALID, INVALID, NOT_PRESENT or NOT_COVERED.
        checksum_offset: Raw offset of the stored checksum, or None.
        checksum_size: Width of the stored checksum in bytes, or 0.
        covered_start: First raw byte offset the layer accounts for.
        covered_end: Offset just past the last byte the layer accounts for.
        detail: Human-readable scope or mismatch information.
    '''
    layer: str
    status: str
    checksum_offset: int = None
    checksum_size: int = 0
    covered_start: int = 0
    covered_end: int = 0
    detail: str = ''

    @property
    def failed(self):
        return self.status == INVALID

    @property
    def protects_bytes(self):
        '''Whether a checksum value covers this range at all.

        A mismatch still protects the range in the sense that it was
        supposed to match, so INVALID counts as protected too.
        '''
        return self.status in (VALID, INVALID)


def _checksum8(data):
    '''Return the byte that makes the 8-bit sum of data and it zero.'''
    return -sum(data) & 0xFF


def _checksum16(data):
    '''Return the word that makes the 16-bit sum of data and it zero.'''
    if len(data) % 2:
        data = data + b'\x00'
    return -sum(word for word, in struct.iter_unpack('<H', data)) & 0xFFFF


def _u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def _u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def _ffs_layout(data, offset):
    '''Return (size, header_size, large) for the file at offset, or None.'''
    if offset + _FFS_HEADER_SIZE > len(data):
        return None
    attributes = data[offset + 0x13]
    size = int.from_bytes(data[offset + 0x14:offset + 0x17], 'little')
    large = (attributes & _FFS_ATTRIB_LARGE_FILE) and size == 0 and \
        offset + _FFS_LARGE_HEADER_SIZE <= len(data)
    if large:
        return _u64(data, offset + 0x18), _FFS_LARGE_HEADER_SIZE, True
    return size, _FFS_HEADER_SIZE, False


def verify_volume_header(data):
    '''Check the 16-bit volume header checksum over [0, hdrlen).'''
    if len(data) < _VOLUME_HEADER_SIZE or data[0x28:0x2C] != b'_FVH':
        return LayerResult(
            VOLUME_HEADER, NOT_PRESENT,
            covered_end=min(len(data), _VOLUME_HEADER_SIZE),
            detail='no _FVH signature')

    hdrlen = _u16(data, 0x30)
    if hdrlen < _VOLUME_HEADER_SIZE or hdrlen > len(data):
        return LayerResult(
            VOLUME_HEADER, NOT_PRESENT,
            checksum_offset=0x32, checksum_size=2,
            covered_end=min(len(data), hdrlen),
            detail='header length 0x%x is outside the data' % hdrlen)

    covered = bytearray(data[:hdrlen])
    stored = _u16(covered, 0x32)
    covered[0x32:0x34] = b'\x00\x00'
    expected = _checksum16(bytes(covered))
    status = VALID if stored == expected else INVALID
    return LayerResult(
        VOLUME_HEADER, status,
        checksum_offset=0x32, checksum_size=2,
        covered_start=0, covered_end=hdrlen,
        detail='stored 0x%04x, expected 0x%04x (16-bit sum over the '
               'header and block map, [0x0, 0x%x))' % (
                   stored, expected, hdrlen))


def verify_ffs_header(data, offset=0):
    '''Check the 8-bit file header checksum of the file at offset.'''
    layout = _ffs_layout(data, offset)
    if layout is None:
        return LayerResult(
            FFS_HEADER, NOT_PRESENT, covered_start=offset,
            covered_end=min(len(data), offset + _FFS_HEADER_SIZE),
            detail='no complete FFS file header')

    size, header_size, large = layout
    if offset + header_size > len(data):
        return LayerResult(
            FFS_HEADER, NOT_PRESENT, covered_start=offset,
            covered_end=min(len(data), offset + header_size),
            detail='no complete FFS file header')
    if size < header_size:
        return LayerResult(
            FFS_HEADER, NOT_PRESENT, checksum_offset=offset + 0x10,
            checksum_size=1, covered_start=offset,
            covered_end=offset + header_size,
            detail='file size 0x%x is smaller than its header' % size)

    header = bytearray(data[offset:offset + header_size])
    stored = header[0x10]
    header[0x10] = 0
    header[0x11] = 0
    header[0x17] = 0
    expected = _checksum8(bytes(header))
    status = VALID if stored == expected else INVALID
    detail = 'stored 0x%02x, expected 0x%02x (8-bit sum over the %d-byte ' \
        'header; bytes 0x10, 0x11 and 0x17 treated as zero)' % (
            stored, expected, header_size)
    if large:
        detail += '; large file ExtendedSize at 0x18..0x20 is covered'
    return LayerResult(
        FFS_HEADER, status,
        checksum_offset=offset + 0x10, checksum_size=1,
        covered_start=offset, covered_end=offset + header_size,
        detail=detail)


def verify_file_data(data, offset=0):
    '''Check the 8-bit file data checksum of the file at offset.'''
    layout = _ffs_layout(data, offset)
    if layout is None:
        return LayerResult(
            FILE_DATA, NOT_PRESENT, covered_start=offset,
            covered_end=min(len(data), offset + _FFS_HEADER_SIZE),
            detail='no complete FFS file header')

    size, header_size, _large = layout
    body_start = offset + header_size
    body_end = offset + size
    if size < header_size:
        return LayerResult(
            FILE_DATA, NOT_PRESENT, checksum_offset=offset + 0x11,
            checksum_size=1, covered_start=body_start,
            covered_end=min(len(data), body_end),
            detail='file size 0x%x is smaller than its header' % size)

    attributes = data[offset + 0x13]
    if not attributes & _FFS_ATTRIB_CHECKSUM:
        return LayerResult(
            FILE_DATA, NOT_COVERED,
            checksum_offset=offset + 0x11, checksum_size=1,
            covered_start=body_start,
            covered_end=min(len(data), body_end),
            detail='attribute 0x40 is clear, so byte 0x%x is a fixed '
                   'filler (0xAA in FFS2, 0x5A in FFS1) and not a data '
                   'checksum' % (offset + 0x11))

    if body_end > len(data):
        return LayerResult(
            FILE_DATA, NOT_PRESENT, checksum_offset=offset + 0x11,
            checksum_size=1, covered_start=body_start,
            covered_end=len(data),
            detail='file claims 0x%x bytes but only 0x%x remain' % (
                body_end - offset, len(data) - offset))

    body = data[body_start:body_end]
    stored = data[offset + 0x11]
    expected = _checksum8(body)
    status = VALID if stored == expected else INVALID
    return LayerResult(
        FILE_DATA, status,
        checksum_offset=offset + 0x11, checksum_size=1,
        covered_start=body_start, covered_end=body_end,
        detail='stored 0x%02x, expected 0x%02x (8-bit sum over the file '
               'data [0x%x, 0x%x))' % (
                   stored, expected, body_start, body_end))


def verify_extended_header(data):
    '''Report the volume extended header, which no checksum covers.

    Only the ExtHeaderOffset field in the volume header is checksummed. The
    extended header the field points at holds FvName and ExtHeaderSize in
    the volume body, outside that range.
    '''
    if len(data) < _VOLUME_HEADER_SIZE or data[0x28:0x2C] != b'_FVH':
        return None
    offset = _u16(data, 0x34)
    if offset == 0:
        return None
    end = offset + _EXT_HEADER_SIZE
    status = NOT_COVERED if end <= len(data) else NOT_PRESENT
    return LayerResult(
        EXTENDED_HEADER, status,
        covered_start=offset, covered_end=min(end, len(data)),
        detail='only the ExtHeaderOffset field at 0x34 is inside the '
               'volume header checksum; FvName and ExtHeaderSize are not '
               'covered')


def verify_volume(data):
    '''Return one result per checksum layer in a firmware volume.

    Results appear in raw order: the volume header, the extended header
    note, then each FFS file's header and data. There is no aggregate
    verdict; callers must keep the layers separate.
    '''
    results = [verify_volume_header(data)]
    if results[0].status == NOT_PRESENT:
        return results

    extended_header = verify_extended_header(data)
    if extended_header is not None:
        results.append(extended_header)

    if data[0x10:0x20] not in _FFS_GUIDS:
        return results

    hdrlen = _u16(data, 0x30)
    size = _u64(data, 0x20)
    limit = min(size, len(data))
    offset = hdrlen
    while offset + _FFS_HEADER_SIZE <= limit and \
            data[offset:offset + _FFS_HEADER_SIZE] != b'\xff' * 24:
        layout = _ffs_layout(data, offset)
        if layout is None:
            break
        file_size, header_size, _large = layout
        if file_size < header_size or file_size > limit - offset:
            # A stub, an erased gap with a stray byte, or a header larger
            # than the volume: no complete file to check here.
            break
        if data[offset + 0x12] == _FFS_TYPE_PAD:
            # A padding file holds the volume extended header or fills a
            # gap; the parser does not treat it as a file.
            offset += (file_size + 7) & ~7
            continue
        results.append(verify_ffs_header(data, offset))
        results.append(verify_file_data(data, offset))
        step = (file_size + 7) & ~7
        if step <= 0:
            break
        offset += step
    return results


def verify_ffs_file(data, offset=0):
    '''Return the header and data results for one FFS file.'''
    return [verify_ffs_header(data, offset), verify_file_data(data, offset)]


def invalid_layers(results):
    '''Return the names of the layers whose checksum does not match.'''
    return [result.layer for result in results if result.failed]


def first_invalid(results):
    '''Return the first failing result, or None.'''
    for result in results:
        if result.failed:
            return result
    return None


def protected_ranges(results):
    '''Return [(start, end, layer)] for the byte ranges checksummed.'''
    return [
        (result.covered_start, result.covered_end, result.layer)
        for result in results if result.protects_bytes
    ]


def format_report(results):
    '''Return one line per layer, naming failures and raw byte offsets.'''
    lines = []
    for result in results:
        if result.status == INVALID:
            line = '%s: invalid checksum at 0x%x, covers 0x%x..0x%x' % (
                result.layer, result.checksum_offset,
                result.covered_start, result.covered_end)
        elif result.status == VALID:
            line = '%s: valid checksum at 0x%x, covers 0x%x..0x%x' % (
                result.layer, result.checksum_offset,
                result.covered_start, result.covered_end)
        elif result.status == NOT_COVERED:
            line = '%s: not covered (0x%x..0x%x)' % (
                result.layer, result.covered_start, result.covered_end)
        else:
            line = '%s: not present (0x%x..0x%x)' % (
                result.layer, result.covered_start, result.covered_end)
        if result.detail:
            line += ' - %s' % result.detail
        lines.append(line)
    return '\n'.join(lines)

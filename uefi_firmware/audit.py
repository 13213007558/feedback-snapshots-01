'''Compare the bytes a firmware object was parsed from with its rebuild.

The parser's rebuild path is used as a review tool: ``build()`` without
``generate_checksum`` must give back the parsed bytes of an object nobody
changed, including padding, unrecognised blobs and stale checksums. Only
``build(generate_checksum=True)`` may recompute sizes, checksums and block
maps, and it must never mark a signed section as trusted again.

This module does not modify the object it inspects. It records which byte
ranges changed, what each range is, and whether the change follows from the
requested mode or from content the caller replaced.
'''

import argparse
import contextlib
import dataclasses
import io
import sys

from .base import AutoRawObject, PaddingObject, RawObject
from . import uefi as uefi_module
from .pfs import PFSFile, PFSSection
from .uefi import (
    CompressedSection, EfiSection, FirmwareFile, FirmwareFileSystem,
    FirmwareFileSystemSection, FirmwareVolume, GuidDefinedSection,
    NVARVariableStore)


# Region kinds, grouped by what a rebuild is allowed to do with them.
CHECKSUM_KINDS = {
    'volume-checksum', 'file-header-checksum', 'guided-crc', 'pfs-checksum',
}
SIZE_KINDS = {
    'volume-size', 'file-size', 'file-extended-size', 'section-size',
    'pfs-size', 'capsule-size',
}
META_KINDS = CHECKSUM_KINDS | SIZE_KINDS | {
    'volume-block-map', 'compressed-stream', 'guided-preamble',
}
CONTENT_KINDS = {
    'section-payload', 'section-unknown-payload', 'unknown-blob',
    'volume-body', 'file-body', 'nvar-variable',
}
PADDING_KINDS = {
    'volume-padding', 'file-padding', 'file-alignment', 'section-padding',
    'file-system-padding', 'nvar-free-space',
}
# A header or body range that specific fields sit inside. When a change also
# touches a specific field, only that field names the change.
CONTAINER_KINDS = {
    'volume-header', 'file-header', 'section-header', 'volume-body',
    'file-body', 'section-payload',
}


@dataclasses.dataclass
class Region:
    start: int
    end: int
    kind: str
    label: str


@dataclasses.dataclass
class Signature:
    label: str
    path: str
    span: tuple
    signed_span: tuple
    attributes: int


@dataclasses.dataclass
class ByteChange:
    start: int
    end: int
    original: bytes
    rebuilt: bytes
    kinds: tuple
    labels: tuple
    status: str

    def describe(self):
        if self.original == b'' and self.rebuilt != b'':
            detail = 'added %d bytes' % len(self.rebuilt)
        elif self.rebuilt == b'' and self.original != b'':
            detail = 'removed %d bytes' % len(self.original)
        else:
            detail = '%d bytes differ' % max(len(self.original), len(self.rebuilt))
        names = ', '.join(self.labels) if self.labels else 'unclassified bytes'
        return '0x%x-0x%x %s: %s' % (self.start, self.end, names, detail)


@dataclasses.dataclass
class AuditReport:
    mode: str
    original_size: int
    rebuilt_size: int
    changes: list
    signatures: list
    notes: list
    # Warnings build() printed, such as a resized file.
    output: str = ''

    @property
    def identical(self):
        return (self.original_size == self.rebuilt_size and
                not self.changes)

    @property
    def unexpected(self):
        return [change for change in self.changes
                if change.status == 'unexpected']

    @property
    def invalidated_signatures(self):
        return [sig for sig in self.signatures if sig.get('invalidated')]

    def render(self):
        lines = []
        if self.mode == 'preserve':
            mode_text = ('preserve (build(generate_checksum=False)): bytes '
                         'must match the original')
        else:
            mode_text = ('recompute (build(generate_checksum=True)): sizes, '
                         'checksums and block maps may be regenerated')
        lines.append(mode_text)
        lines.append('%d parsed bytes, %d rebuilt bytes' % (
            self.original_size, self.rebuilt_size))
        if self.identical:
            lines.append('unchanged: every byte matches')
        else:
            lines.append('%d byte range(s) changed:' % len(self.changes))
            for change in self.changes:
                lines.append('  %s [%s]' % (change.describe(), change.status))
        for note in self.notes:
            lines.append('note: %s' % note)
        if self.signatures:
            lines.append('signatures:')
            for sig in self.signatures:
                if sig.get('invalidated'):
                    lines.append(
                        '  %s INVALIDATED by a change in 0x%x-0x%x; auth '
                        'status left at 0x%x, re-sign and re-verify' % (
                            sig['path'], sig['overlap'][0], sig['overlap'][1],
                            sig['attributes']))
                else:
                    lines.append('  %s unchanged; auth status left at 0x%x' % (
                        sig['path'], sig['attributes']))
        else:
            lines.append('signatures: none found')
        return '\n'.join(lines)


def _overlap(start, end, span):
    return start < span[1] and end > span[0]


def _add(regions, start, end, kind, label, limit=None):
    if end <= start:
        return
    if limit is not None:
        end = min(end, limit)
        start = min(start, limit)
        if end <= start:
            return
    regions.append(Region(start, end, kind, label))


def _as_bytes(value):
    if value is None:
        return b''
    return bytes(value)


def _collect_volume(volume, base, path, regions, signatures):
    if not getattr(volume, 'valid_header', False):
        return
    header_size = volume.hdrlen
    _add(regions, base, base + 0x38, 'volume-header',
         path + ' volume header')
    _add(regions, base + 0x20, base + 0x28, 'volume-size', path + ' volume size')
    _add(regions, base + 0x32, base + 0x34, 'volume-checksum',
         path + ' volume header checksum')
    _add(regions, base + 0x38, base + header_size, 'volume-block-map',
         path + ' volume block map')
    if getattr(volume, 'exthdroff', 0):
        ext_size = max(getattr(volume, 'exthdrsize', 0),
                       FirmwareVolume._EXT_HEADER_SIZE)
        _add(regions, base + volume.exthdroff,
             base + volume.exthdroff + ext_size, 'volume-ext-header',
             path + ' volume extended header')
    body = _as_bytes(getattr(volume, 'data', b''))
    _add(regions, base + header_size, base + header_size + len(body),
         'volume-body', path + ' volume body')

    for index, filesystem in enumerate(volume.firmware_filesystems):
        _collect_filesystem(filesystem, base + header_size,
                            '%s/ffs[%d]' % (path, index), regions, signatures)
    for index, raw in enumerate(volume.raw_objects):
        span = base + header_size
        if isinstance(raw, bytes):
            _add(regions, span, span + len(raw), 'volume-body',
                 '%s/raw[%d]' % (path, index))
            continue
        if isinstance(raw, NVARVariableStore):
            _collect_nvar(raw, span, '%s/nvar[%d]' % (path, index),
                          regions, signatures)
        elif isinstance(raw, FirmwareVolume):
            _collect_volume(raw, span, '%s/volume[%d]' % (path, index),
                            regions, signatures)


def _collect_filesystem(filesystem, base, path, regions, signatures):
    cursor = 0
    data_size = len(getattr(filesystem, '_data', b''))
    for index, firmware_file in enumerate(filesystem.files):
        start, parsed_size = getattr(
            firmware_file, 'parsed_extent', (cursor, firmware_file.size))
        if start > cursor:
            _add(regions, base + cursor, base + start, 'file-alignment',
                 path + ' alignment before file %d' % index)
        _add(regions, base + start, base + start + parsed_size, 'file-body',
             path + '/file[%d]' % index)
        _collect_file(firmware_file, base + start,
                      '%s/file[%d]' % (path, index), regions, signatures)
        cursor = max(cursor, start + ((parsed_size + 7) & ~7))
    if cursor < data_size:
        _add(regions, base + cursor, base + data_size, 'file-system-padding',
             path + ' free space')


def _collect_file(firmware_file, base, path, regions, signatures):
    data = _as_bytes(getattr(firmware_file, '_data', b''))
    header_size = firmware_file.header_size
    _add(regions, base, base + header_size, 'file-header', path + ' header')
    _add(regions, base + 0x10, base + 0x12, 'file-header-checksum',
         path + ' header checksum')
    _add(regions, base + 0x17, base + 0x18, 'file-state', path + ' state byte')
    if firmware_file.large_file:
        _add(regions, base + 0x14, base + 0x18, 'file-size',
             path + ' 24-bit size (zero)')
        _add(regions, base + 0x18, base + 0x20, 'file-extended-size',
             path + ' extended size')
    else:
        _add(regions, base + 0x14, base + 0x17, 'file-size', path + ' file size')
    body_start = base + header_size
    _add(regions, body_start, base + len(data), 'file-body', path + ' body')

    sections_end = 0
    for index, section in enumerate(firmware_file.sections):
        start, parsed_size = getattr(section, 'parsed_extent', (None, None))
        if start is None:
            continue
        _collect_section(section, body_start + start,
                         '%s/section[%d]' % (path, index), regions, signatures)
        sections_end = max(sections_end, start + parsed_size)
    if firmware_file.sections and sections_end < len(data) - header_size:
        # Alignment after the last section is kept as it was, too.
        _add(regions, body_start + sections_end, base + len(data),
             'file-alignment', path + ' alignment after the last section')
    if firmware_file.raw_blobs:
        # The parser records the offset of a discovered volume as its name.
        for index, blob in enumerate(firmware_file.raw_blobs):
            name = getattr(blob, 'name', None)
            if isinstance(blob, FirmwareVolume) and isinstance(name, int):
                _collect_volume(blob, body_start + name,
                                '%s/volume[%d]' % (path, index),
                                regions, signatures)


def _collect_section(section, base, path, regions, signatures):
    header_size = 8 if section.large_header else 4
    _add(regions, base, base + header_size, 'section-header',
         path + ' header')
    if section.large_header:
        _add(regions, base, base + 3, 'section-size',
             path + ' large size marker')
        _add(regions, base + 4, base + 8, 'section-size',
             path + ' extended size')
    else:
        _add(regions, base, base + 3, 'section-size', path + ' section size')
    prefix = _as_bytes(getattr(section, '_parsed_prefix', b''))
    if prefix:
        _add(regions, base + header_size, base + header_size + len(prefix),
             'section-header', path + ' nested object prefix')
    body = base + header_size + len(prefix)
    parsed = section.parsed_object

    if section.type == 0x02 and isinstance(parsed, GuidDefinedSection):
        _collect_guided(parsed, body, path, regions, signatures)
    elif section.type == 0x01 and isinstance(parsed, CompressedSection):
        _collect_compressed(parsed, body, path, regions, signatures)
    elif section.type == 0x19 and not isinstance(parsed, RawObject):
        _collect_nested(parsed, body, base + len(section._data), path,
                        regions, signatures)
    elif isinstance(parsed, (RawObject, AutoRawObject, PaddingObject)):
        _add(regions, body, base + len(section._data),
             'section-unknown-payload', path + ' raw payload')
    elif parsed is not None:
        _collect_nested(parsed, body, base + len(section._data), path,
                        regions, signatures)
    else:
        # An unparsed body is not rewritten by either build mode, whether it
        # is a raw section or a type the parser does not understand.
        kind = 'section-payload' if section.type == 0x19 else \
            'section-unknown-payload'
        _add(regions, body, base + len(section._data),
             kind, path + ' unchanged body')
    return


def _collect_nested(parsed, body, body_end, path, regions, signatures):
    extent = getattr(parsed, '_nested_extent', None)
    if isinstance(parsed, FirmwareVolume):
        _collect_volume(parsed, body, path + '/volume', regions, signatures)
        if extent is not None:
            start, size = extent
            # Vendor bytes after the volume are kept by build().
            _add(regions, body + start + size, body_end,
                 'section-unknown-payload', path + ' bytes after volume')
        return
    if isinstance(parsed, (RawObject, AutoRawObject, PaddingObject)):
        _add(regions, body, body + len(_as_bytes(parsed.data)),
             'section-unknown-payload', path + ' blob')
        return
    if isinstance(parsed, EfiSection):
        _add(regions, body, body + len(_as_bytes(parsed.data)),
             'section-payload', path + ' nested section')
        return
    _add(regions, body, body + len(_as_bytes(getattr(parsed, 'data', b''))),
         'section-payload', path + ' parsed object')


def _collect_guided(guided, body, path, regions, signatures):
    _add(regions, body, body + 20, 'section-header', path + ' guided header')
    preamble_len = len(_as_bytes(guided.preamble))
    data_start = 20 + preamble_len
    attrs = guided.attrs.get('attrs', 0)
    signed = attrs & (GuidDefinedSection.ATTR_AUTH_STATUS_VALID |
                      GuidDefinedSection.ATTR_PROCESSING_REQUIRED)
    if signed:
        _add(regions, body + 20, body + data_start,
             'guided-preamble-signature', path + ' signature preamble')
        # The signature covers the body as stored, compressed or not.
        signed_end = body + len(_as_bytes(guided._body)) \
            if hasattr(guided, 'subtype') \
            else body + data_start + len(_as_bytes(guided.data))
        signature = Signature(
            label=path,
            path=path,
            span=(body + 20, body + data_start),
            signed_span=(body + data_start, signed_end),
            attributes=attrs,
        )
        signatures.append(dataclasses.asdict(signature))
        if hasattr(guided, 'subtype'):
            # The signed body is a compressed stream, which is kept as it is
            # unless its content changed.
            _add(regions, body + data_start, signed_end,
                 'compressed-stream', path + ' signed compressed body')
            return
        cursor = 0
        for index, subsection in enumerate(guided.subsections):
            start = getattr(subsection, 'parsed_extent', (None, None))[0]
            if start is None:
                start = cursor
            cursor = start + ((subsection.size + 3) & ~3)
            _collect_section(
                subsection, body + data_start + start,
                '%s/subsection[%d]' % (path, index), regions, signatures)
        return
    if preamble_len == 4:
        _add(regions, body + 20, body + data_start, 'guided-crc',
             path + ' CRC32 preamble')
    else:
        _add(regions, body + 20, body + data_start, 'guided-preamble',
             path + ' preamble')
    if hasattr(guided, 'subtype'):
        # Compressed bodies are kept byte-for-byte unless they change.
        _add(regions, body + data_start,
             body + len(_as_bytes(guided._body)),
             'compressed-stream', path + ' compressed body')
        return
    _add(regions, body + data_start,
         body + data_start + len(_as_bytes(guided.data)),
         'section-payload', path + ' payload')


def _collect_compressed(compressed, body, path, regions, signatures):
    _add(regions, body, body + 5, 'section-header', path + ' compression header')
    # The decompressed size is written again when the content changes.
    _add(regions, body, body + 4, 'section-size',
         path + ' decompressed size')
    _add(regions, body + 5,
         body + len(_as_bytes(getattr(compressed, '_body', b''))),
         'compressed-stream', path + ' compressed stream')


def _collect_nvar(store, base, path, regions, signatures):
    data = _as_bytes(getattr(store, 'data', b''))
    free = _as_bytes(getattr(store, 'free_space', b''))
    _add(regions, base, base + len(data), 'nvar-variable', path + ' variables')
    _add(regions, base + len(data), base + len(data) + len(free),
         'nvar-free-space', path + ' free space')


def _collect_pfs(pfs_file, regions, signatures):
    body_size = len(pfs_file.data) - 0x20
    _add(regions, 0, 0x10, 'pfs-header', 'pfs header')
    _add(regions, 0x0C, 0x10, 'pfs-size', 'pfs body size')
    _add(regions, 0x10, 0x10 + body_size, 'pfs-body', 'pfs body')
    _add(regions, 0x10 + body_size, 0x20 + body_size, 'pfs-footer',
         'pfs footer')
    if body_size + 0x18 <= len(pfs_file.data):
        _add(regions, 0x14 + body_size, 0x18 + body_size, 'pfs-checksum',
             'pfs footer checksum')
    offset = 0x10
    for index, section in enumerate(pfs_file.sections):
        _collect_pfs_section(section, offset,
                             'pfs/section[%d]' % index, regions, signatures)
        offset += section.section_size


def _collect_pfs_section(section, base, path, regions, signatures):
    header_size = PFSSection.HEADER_SIZE
    _add(regions, base, base + header_size, 'pfs-header', path + ' header')
    _add(regions, base + 0x28, base + 0x2C, 'pfs-size',
         path + ' section data size')
    if len(section.header) > 0x44:
        _add(regions, base + 0x40, base + 0x44, 'pfs-checksum',
             path + ' section data checksum')
    section_data = _as_bytes(section.section_data)
    data_start = base + header_size
    _add(regions, data_start, data_start + len(section_data), 'pfs-body',
         path + ' data')
    cursor = header_size + len(section_data)
    for name in ('rsa1', 'pmim', 'rsa2'):
        chunk = getattr(section, name, None)
        if chunk is None:
            continue
        chunk_data = _as_bytes(getattr(chunk, 'data', b''))
        if chunk_data:
            _add(regions, base + cursor, base + cursor + len(chunk_data),
                 'pfs-signature', '%s %s' % (path, name))
        cursor += len(chunk_data)

    if isinstance(section, PFSSection):
        cursor = 0
        for index, child in enumerate(section.section_objects):
            size = len(_as_bytes(getattr(child, '_data',
                                         getattr(child, 'data', b''))))
            if isinstance(child, FirmwareVolume):
                _collect_volume(child, data_start + cursor,
                                '%s/volume[%d]' % (path, index),
                                regions, signatures)
            else:
                _add(regions, data_start + cursor,
                     data_start + cursor + size, 'pfs-body',
                     '%s/object[%d]' % (path, index))
            cursor += size


def _collect_capsule(capsule, regions, signatures):
    data_size = len(getattr(capsule, '_data', b''))
    header_size = getattr(capsule, 'header_size', 0)
    _add(regions, 0, 16, 'capsule-header', 'capsule guid')
    _add(regions, 0x10, 0x14, 'capsule-size', 'capsule header size')
    _add(regions, 0x18, 0x1C, 'capsule-size', 'capsule image size')
    preamble = _as_bytes(getattr(capsule, 'preamble', b''))
    _add(regions, header_size, header_size + len(preamble),
         'capsule-header', 'capsule body preamble')
    _add(regions, header_size + len(preamble), data_size, 'capsule-body',
         'capsule body')
    body = getattr(capsule, 'capsule_body', None)
    if isinstance(body, uefi_module.FirmwareVolume):
        _collect_volume(body, header_size + len(preamble), 'capsule/volume',
                        regions, signatures)


def collect_regions(firmware_object):
    '''Return the labelled byte ranges of a parsed object, and its signatures.'''
    regions = []
    signatures = []
    if isinstance(firmware_object, FirmwareVolume):
        _collect_volume(firmware_object, 0, 'volume', regions, signatures)
    elif isinstance(firmware_object, FirmwareFileSystem):
        _collect_filesystem(firmware_object, 0, 'ffs', regions, signatures)
    elif isinstance(firmware_object, FirmwareFile):
        _collect_file(firmware_object, 0, 'file', regions, signatures)
    elif isinstance(firmware_object, FirmwareFileSystemSection):
        _collect_section(firmware_object, 0, 'section', regions, signatures)
    elif isinstance(firmware_object, PFSFile):
        _collect_pfs(firmware_object, regions, signatures)
    elif isinstance(firmware_object, uefi_module.FirmwareCapsule):
        _collect_capsule(firmware_object, regions, signatures)
    return sorted(regions, key=lambda region: (region.start, region.end)), \
        signatures


def original_bytes(firmware_object):
    '''Return the bytes an object was parsed from, when it kept them.'''
    for attribute in ('_data', 'data'):
        data = getattr(firmware_object, attribute, None)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
    raise ValueError('%s did not keep its parsed bytes' % (
        type(firmware_object).__name__,))


def _build(firmware_object, recompute_checksums):
    built = firmware_object.build(generate_checksum=recompute_checksums)
    if isinstance(built, tuple):
        built = built[1]
    return bytes(built)


def _status_for(kinds, mode):
    if not kinds:
        return 'unexpected'
    if mode == 'preserve':
        if any(kind in CONTENT_KINDS for kind in kinds):
            return 'content'
        if any(kind in META_KINDS | PADDING_KINDS for kind in kinds):
            # A size change moves padding and alignment with it.
            return 'derived'
        return 'unexpected'
    if all(kind in CHECKSUM_KINDS | SIZE_KINDS | {'volume-block-map'}
           for kind in kinds):
        return 'allowed'
    if all(kind in META_KINDS | CONTENT_KINDS for kind in kinds):
        return 'derived'
    return 'unexpected'


def _diff(original, rebuilt, regions, mode, rebuilt_regions=()):
    changes = []
    common = min(len(original), len(rebuilt))
    index = 0
    while index < common:
        if original[index] == rebuilt[index]:
            index += 1
            continue
        start = index
        while index < common and original[index] != rebuilt[index]:
            index += 1
        changes.append(_change(original, rebuilt, start, index, regions, mode,
                               rebuilt_regions))
    if len(original) != len(rebuilt):
        changes.append(_change(original, rebuilt, common,
                               max(len(original), len(rebuilt)), regions, mode,
                               rebuilt_regions))
    return changes


def _change(original, rebuilt, start, end, regions, mode, rebuilt_regions=()):
    overlapping = [region for region in regions
                   if _overlap(start, end, (region.start, region.end))]
    # A rebuilt image that grew shifted its later bytes, so a range can fall
    # inside a different structure there. Label it with the rebuilt one too.
    overlapping += [region for region in rebuilt_regions
                    if _overlap(start, end, (region.start, region.end))]
    specific = [region for region in overlapping
                if region.kind not in CONTAINER_KINDS]
    if specific:
        overlapping = specific
    kinds = []
    labels = []
    for region in overlapping:
        if region.kind not in kinds:
            kinds.append(region.kind)
        if region.label not in labels:
            labels.append(region.label)
    return ByteChange(
        start=start,
        end=end,
        original=original[start:end],
        rebuilt=rebuilt[start:end],
        kinds=tuple(kinds),
        labels=tuple(labels),
        status=_status_for(kinds, mode),
    )


def _reparse_like(firmware_object, data):
    '''Parse rebuilt bytes as the same kind of object, for region labels.'''
    for cls in (FirmwareVolume, FirmwareFileSystem, FirmwareFile, PFSFile,
                uefi_module.FirmwareCapsule):
        if isinstance(firmware_object, cls):
            try:
                reparsed = cls(data)
                if getattr(reparsed, 'valid_header', True) and \
                        quietly_process(reparsed):
                    return reparsed
            except Exception:
                return None
            return None
    return None


def quietly_process(firmware_object):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return firmware_object.process()


def _snapshot(firmware_object):
    '''Save fields a recomputing build updates, so the audit leaves the
    object as it found it.'''
    saved = []
    seen = set()

    def walk(obj):
        if obj is None or id(obj) in seen:
            return
        seen.add(id(obj))
        fields = {}
        for name in ('size', 'checksum'):
            value = getattr(obj, name, None)
            if isinstance(value, int) and isinstance(
                    getattr(type(obj), name, None), property):
                # A computed size cannot be set back; it is not stored.
                continue
            if isinstance(value, int):
                fields[name] = value
        if fields:
            saved.append((obj, fields))
        for child in getattr(obj, 'objects', None) or []:
            walk(child)

    walk(firmware_object)
    return saved


def audit_rebuild(firmware_object, recompute_checksums=False):
    '''Compare a parsed object with its rebuild, without changing the object.

    Args:
        firmware_object: A parsed object whose ``build`` returns bytes, such
            as a ``FirmwareVolume``, ``FirmwareFileSystem`` or ``PFSFile``.
        recompute_checksums: Audit ``build(generate_checksum=True)`` instead
            of the byte-preserving build.

    Return:
        AuditReport: The changed ranges, their labels and the signatures a
        change invalidates.
    '''
    original = original_bytes(firmware_object)
    regions, signatures = collect_regions(firmware_object)
    saved = _snapshot(firmware_object)
    printed = io.StringIO()
    try:
        with contextlib.redirect_stdout(printed), \
                contextlib.redirect_stderr(printed):
            rebuilt = _build(firmware_object, recompute_checksums)
    finally:
        for obj, fields in saved:
            for name, value in fields.items():
                setattr(obj, name, value)

    mode = 'recompute' if recompute_checksums else 'preserve'
    rebuilt_regions = []
    try:
        reparsed = _reparse_like(firmware_object, rebuilt)
        if reparsed is not None:
            rebuilt_regions = collect_regions(reparsed)[0]
    except Exception:
        rebuilt_regions = []
    changes = _diff(original, rebuilt, regions, mode, rebuilt_regions)
    for signature in signatures:
        overlap = None
        for change in changes:
            spans = [signature['span'], signature['signed_span']]
            hits = [span for span in spans
                    if _overlap(change.start, change.end, span)]
            if hits:
                overlap = (max(change.start, hits[0][0]),
                           min(change.end, hits[0][1]))
                break
        signature['invalidated'] = overlap is not None
        if overlap is not None:
            signature['overlap'] = overlap

    notes = []
    if mode == 'preserve':
        notes.append('preserve mode refuses to rewrite padding, unknown '
                     'sections, blobs, extended headers or checksum bytes')
    else:
        notes.append('recompute mode may rewrite sizes, checksum bytes and '
                     'the block map only; padding and unknown data stay')
    if any(sig.get('invalidated') for sig in signatures):
        notes.append('an invalidated signature is reported, never re-marked '
                     'as trusted')
    output = printed.getvalue()
    if output:
        # build() names the GUIDs and offsets it adjusted; keep that as a
        # note rather than letting it leak to the caller's stdout.
        notes.append('build output: %s' % ' '.join(output.split()))
    return AuditReport(
        mode=mode,
        original_size=len(original),
        rebuilt_size=len(rebuilt),
        changes=changes,
        signatures=signatures,
        notes=notes,
        output=output,
    )


def main(argv=None):
    from . import AutoParser

    parser = argparse.ArgumentParser(
        description='Audit a firmware rebuild against the parsed bytes.')
    parser.add_argument('file', help='Firmware image to parse and audit')
    parser.add_argument(
        '--recompute-checksums', action='store_true',
        help='Audit build(generate_checksum=True) instead of preserving bytes')
    args = parser.parse_args(argv)

    with open(args.file, 'rb') as handle:
        data = handle.read()
    firmware = AutoParser(data).parse()
    if firmware is None:
        print('Error: could not parse %s' % args.file, file=sys.stderr)
        return 1
    if not hasattr(firmware, 'build'):
        print('Error: %s cannot be rebuilt' % type(firmware).__name__,
              file=sys.stderr)
        return 1
    try:
        original_bytes(firmware)
    except ValueError as error:
        print('Error: %s' % error, file=sys.stderr)
        return 1

    report = audit_rebuild(firmware, args.recompute_checksums)
    print(report.render())
    return 0 if not report.unexpected else 2


if __name__ == '__main__':
    raise SystemExit(main())

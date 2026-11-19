import hashlib
import json
import struct
import os
import re
import zlib

from .base import FirmwareObject, RawObject, BaseObject, AutoRawObject
from .uefi import FirmwareVolume
from .utils import print_error, dump_data, sguid, green, blue, \
    limit_nesting, zlib_decompress


def _checksum(data):
    '''PFS stores each checksum as the CRC32 with its bits inverted.'''
    return zlib.crc32(data) ^ 0xFFFFFFFF


def _object_data(obj):
    '''Return the bytes an object was parsed from.'''
    if isinstance(obj, FirmwareVolume):
        return obj._data
    return obj.data


PFS_GUIDS = {
    "FIRMWARE_VOLUMES": "7ec6c2b0-3fe3-42a0-a316-22dd0517c1e8",
    "INTEL_ME":         "7439ed9e-70d3-4b65-9e33-1963a7ad3c37",
    "BIOS_ROMS_1":      "08e56a30-62ed-41c6-9240-b7455ee653d7",
    "BIOS_ROMS_2":      "492261e4-0659-424c-82b6-73274389e7a7"
}


def _discover_volumes(data):
    # Assume a series of firmware volumes
    volumes = []
    view = memoryview(data)
    fv_offset = 0
    while fv_offset < len(data):
        fv = FirmwareVolume(view[fv_offset:], hex(fv_offset))
        if not fv.valid_header:
            break
        if not fv.process():
            return False
        volumes.append(fv)
        fv_offset += fv.size
    return volumes


class PFRegion(FirmwareObject):
    def __init__(self, header, data):
        self.offset, self.size, self.address, self.name_offset = struct.unpack(
            '<IIQI', header[:20])
        self.header = header
        # data may be a memoryview of the remaining images; copy this one.
        self.data = bytes(data[:self.size])

    @property
    def objects(self):
        return [self.obj]

    def process(self):
        # Regions dump to the same folder, so name their volumes by offset.
        self.obj = AutoRawObject(self.data, offset=self.offset)
        if not self.obj.process():
            self.obj = RawObject(self.data)
        else:
            self.obj = self.obj.object
        return True

    def showinfo(self, ts='', index=0):
        print('%s%s size= 0x%x offset= 0x%x address= 0x%x name= 0x%x' % (
            ts, blue("PHRegionEntry:"),
            self.size, self.offset, self.address, self.name_offset
        ))
        self.obj.showinfo('%s  ' % (ts), index)

    def dump(self, parent='', index=None):
        if self.obj is not None:
            self.obj.dump(parent, index=index)


class PFHeader(FirmwareObject, BaseObject):
    '''A PFHeader: gh://skochinsky/181e6e338d90bb7f2693098dc43c6d54


    struct PFRegionEntry
    {
      UINT32 FileOffset;
      UINT32 Size;
      UINT64 FlashAddress;
      UINT32 NameOffset; //absolute offset
    };

    struct PFHeader
    {
      /* 00 */char Signature[4]; //$PFH
      /* 04 */UINT32 dwVersion;
      /* 08 */UINT32 dwHeaderSize;
      /* 0C */UINT16 wHeaderChecksum;
      /* 0E */UINT32 dwTotalImageSize;
      /* 12 */UINT16 wTotalImageChecksum;
      /* 04 */UINT32 dwNumberOfImages;
      /* 18 */UINT32 imagetableOffset;
      /* 1C */UINT32 unknown[48];
      /* DC */PFImageEntry rgtable[1];
    };
    '''

    def __init__(self, data):
        self.valid_header = False
        self.data = data
        self.size = len(data)

        if self.size < 32:
            return
        if self.data[:4] == b'$PFH':
            self.valid_header = True
        version, hdr_size, checksum, image_size, image_checksum, image_count, \
            image_offset = struct.unpack('<IIHIHII', self.data[4:28])
        self.hdr_size = hdr_size
        self.image_count = image_count
        self.image_offset = image_offset

    @property
    def objects(self):
        return self.objs

    def process(self):
        if not self.valid_header:
            return False

        self.objs = []
        view = memoryview(self.data)
        data_offset = self.hdr_size
        for i in range(self.image_count):
            region_offset = 0xDC + (i * 20)
            if region_offset + 20 > len(self.data):
                # image_count is larger than the region table.
                break
            entry = PFRegion(self.data[region_offset:region_offset + 20],
                view[data_offset:])
            data_offset += entry.size
            if entry.process():
                self.objs.append(entry)
        return True

    def showinfo(self, ts='', index=None):
        print('%s%s header size 0x%x images= %d offset= %s' % (
            ts, blue("PFHeader:"),
            self.hdr_size,  self.image_count, self.image_offset
        ))
        for i in range(len(self.objs)):
            self.objs[i].showinfo('%s  ' % (ts), index=i)
            pass

    def dump(self, parent='', index=None):
        path = os.path.join(parent, "pfheader.pfh")
        dump_data("%s" % path, self.data)
        images = os.path.join(parent, "pfheader")
        for i in range(len(self.objs)):
            self.objs[i].dump(images, i)


def _merge_ranges(ranges):
    '''Return the sorted, non-overlapping union of (start, end) ranges.'''
    merged = []
    for start, end in sorted(ranges):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _subtract_ranges(ranges, start, end):
    '''The parts of [start, end) not covered by ranges.'''
    missing = []
    position = start
    for range_start, range_end in _merge_ranges(ranges):
        if range_end <= position:
            continue
        if range_start > position:
            missing.append((position, min(range_start, end)))
        position = max(position, range_end)
        if position >= end:
            break
    if position < end:
        missing.append((position, end))
    return [list(pair) for pair in missing if pair[1] > pair[0]]


def _declared_version(header):
    '''Read a section header's declared spec and version.

    The values are copied from the image and are not authenticated: they
    must not be used to identify a chunk or to decide that two chunks are
    the same.
    '''
    spec, version_type = struct.unpack("<I4s", header[0x10:0x18])
    version = ""
    for i in range(4):
        group_offset = 0x18 + (i * 2)
        if version_type[i:i + 1] == b'A':
            version += "%X" % struct.unpack(
                "<h", header[group_offset:group_offset + 2])[0]
        elif version_type[i:i + 1] == b'N':
            version += ".%d" % struct.unpack(
                "<h", header[group_offset:group_offset + 2])[0]
    return spec, version_type, version


def _scan_volume_region(data):
    '''Scan consecutive firmware volumes, keeping declared and held extents.

    A volume header may claim more bytes than the caller holds. The volume is
    still parsed from the bytes present, but its declared end is reported so
    the caller can separate parsed content from a declared but absent tail.

    Returns:
        dict: "volumes" (each with offset, declared size, bytes held, whether
            it processed, and the object), "failure" (None, "no_header",
            "process" or "zero") and "failure_offset" (where parsing stopped).
    '''
    volumes = []
    failure = None
    failure_offset = len(data)
    view = memoryview(data)
    offset = 0
    while offset < len(data):
        volume = FirmwareVolume(view[offset:], hex(offset))
        if not volume.valid_header:
            failure = "no_header"
            failure_offset = offset
            break
        size = volume.size
        available = len(getattr(volume, "_data", b""))
        parsed = volume.process()
        volumes.append({
            "offset": offset,
            "size": size,
            "available": available,
            "parsed": bool(parsed),
            "object": volume,
        })
        if size <= 0:
            failure = "zero"
            failure_offset = offset
            break
        if not parsed:
            failure = "process"
            failure_offset = offset
            break
        offset += size
    return {
        "volumes": volumes,
        "failure": failure,
        "failure_offset": failure_offset,
    }


class PFSPartitionedSection(FirmwareObject, BaseObject):
    '''A PFSSection whose content is split across nested chunk records.

    A partitioned section is a PFS.HDR. envelope followed by one or more
    chunks and a PFS.FTR. trailer. Each chunk is a 0x48-byte header, 0x248
    bytes of variables, its payload, then up to three signature blobs. The
    payloads belong to one logical stream, but the container does not store a
    chunk number: order comes from the physical record sequence.

    This object keeps a table of every chunk with its container range, its
    payload range and its reassembled range, so a caller can trace any
    reassembled byte back to the record that supplied it. Each record has two
    independent states: how far its own framing extends (complete, truncated,
    signatures absent, invalid) and whether its reassembled position is
    supported (confirmed, unconfirmed, duplicate, tail). It never edits the
    input. Missing bytes, duplicate payloads, length conflicts and trailing
    bytes are reported separately, each with the coordinate space its ranges
    refer to; "complete" is only true when the records account for the whole
    body and the nested firmware volumes are wholly present.

    Section names, specs and versions are declarations copied from the image.
    They are not used as identities and do not authenticate a chunk.
    '''

    HEADER_SIZE = 0x48
    DATA_OFFSET = 0x248

    def __init__(self, data):
        self.data = data
        self.size = len(data)
        self.section_objects = []
        self.partitions = 0
        self.section_data = b""
        # The class documented a "uuid" here, but bytes 0..8 are the
        # PFS.HDR. magic, so this is not an RFC 4122 GUID. Keep it as the
        # opaque body prefix rather than a binary GUID.
        self.header_prefix = data[0x0:0x10]
        self.chunks = []
        self.missing = []
        self.duplicates = []
        self.length_conflicts = []
        self.tail = []
        self.container_errors = []
        self.coverage = {}
        self.complete = False

    def _add_length_conflict(self, where, declared, actual):
        self.length_conflicts.append({
            "where": where,
            "declared": declared,
            "actual": actual,
        })

    def _add_missing(self, reason, ranges, space="reassembly", **extra):
        entry = {
            "reason": reason,
            "space": space,
            "ranges": ranges,
        }
        entry.update(extra)
        self.missing.append(entry)

    def _add_tail(self, reason, ranges, space="container", **extra):
        entry = {
            "reason": reason,
            "space": space,
            "ranges": ranges,
        }
        entry.update(extra)
        self.tail.append(entry)

    def _parse_envelope(self):
        # The first 0x10 bytes start with the PFS.HDR. magic. The remaining
        # eight were called a UUID by the original parser and are kept
        # opaque here: they are not a body size and must not decide framing.
        # The last 0x10 bytes are a trailer. Images put its magic either at
        # the end (like a PFSFile footer, which also holds a body size) or at
        # the start (as the partitioned-chunk fixture does), so both layouts
        # are recognised. Only the physical extent bounds the chunk scan.
        header = bytes(self.data[:0x10])
        magic, opaque = header[:8], header[8:0x10]
        self.header_magic = magic
        self.envelope = {
            "magic": magic.decode("latin-1"),
            "opaque": opaque.hex(),
        }

        trailer_layout = None
        footer_size = None
        footer_checksum = None
        if self.size >= 0x20:
            trailer = bytes(self.data[-0x10:])
            if trailer[8:] == PFSFile.PFS_FOOTER:
                trailer_layout = "size_then_magic"
                footer_size, footer_checksum = struct.unpack(
                    "<II", trailer[:8])
            elif trailer[:8] == PFSFile.PFS_FOOTER:
                trailer_layout = "magic_first"

        if trailer_layout is None:
            self.container_errors.append({
                "where": "footer.magic",
                "detail": "missing PFS.FTR. trailer",
            })
            physical_body_end = self.size
        else:
            physical_body_end = self.size - 0x10

        body_size = physical_body_end - 0x10
        self.envelope.update({
            "trailer": trailer_layout,
            "footer_body_size": footer_size,
            "footer_checksum": footer_checksum,
            "body": [0x10, physical_body_end],
            "physical_body_size": body_size,
        })

        if footer_size is not None and footer_size != body_size:
            # The trailer's own size claim disagrees with the bytes present.
            self._add_length_conflict(
                "envelope.footer_body_size", footer_size, body_size)
        return physical_body_end

    def _parse_chunks(self, scan_end):
        step = 0x10
        chunk_limit = max(0, scan_end)
        while step + self.HEADER_SIZE <= chunk_limit:
            order = len(self.chunks)
            header = bytes(self.data[step:step + self.HEADER_SIZE])
            declared_size = struct.unpack("<I", header[0x28:0x2C])[0]
            sig1_size, sig2_size, sig3_size = struct.unpack(
                "<III", header[0x2C:0x38])

            spec, version_type, version = _declared_version(header)
            payload_start = step + self.HEADER_SIZE + self.DATA_OFFSET
            payload_end = step + self.HEADER_SIZE + declared_size
            record_end = step + self.HEADER_SIZE + declared_size + \
                sig1_size + sig2_size + sig3_size

            def entry_for(payload, status):
                return {
                    "order": order,
                    "header": [step, step + self.HEADER_SIZE],
                    "record": [step, min(record_end, chunk_limit)],
                    "declared_record_end": record_end,
                    "declared_size": declared_size,
                    "payload": [payload_start,
                                payload_start + len(payload)],
                    "declared_payload": [payload_start, payload_end],
                    "signatures": {
                        "rsa1": [payload_end, payload_end + sig1_size],
                        "pmim": [payload_end + sig1_size,
                                 payload_end + sig1_size + sig2_size],
                        "rsa2": [payload_end + sig1_size + sig2_size,
                                 payload_end + sig1_size + sig2_size +
                                 sig3_size],
                    },
                    "declared": {
                        "spec": spec,
                        "version_type": version_type.hex(),
                        "version": version,
                    },
                    "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                    "payload_length": len(payload),
                    "duplicate_of": None,
                    "placement": "unconfirmed",
                    "status": status,
                }

            if declared_size < self.DATA_OFFSET or \
                    payload_start > chunk_limit:
                # The header does not describe a payload that can be sourced.
                # Keep the header in the table, but do not invent a payload
                # range and do not try to frame later records.
                self.chunks.append(entry_for(b"", "invalid"))
                self.partitions += 1
                self._add_length_conflict(
                    "chunk[%d].payload_range" % order,
                    [payload_start, payload_end], chunk_limit)
                self._add_tail(
                    "framing_lost", [[step, chunk_limit]],
                    space="container")
                return

            available_end = max(payload_start,
                                min(payload_end, chunk_limit))
            payload = bytes(self.data[payload_start:available_end])

            if payload_end > chunk_limit:
                self.chunks.append(entry_for(payload, "truncated"))
                self.partitions += 1
                # The record claims data past the bytes present. Report the
                # absent part and stop: later framing cannot be trusted.
                self._add_length_conflict(
                    "chunk[%d].payload_end" % order,
                    payload_end, chunk_limit)
                self._add_missing(
                    "chunk_payload_absent",
                    [[available_end, payload_end]],
                    space="container", chunk=order)
                return

            if record_end > chunk_limit:
                self.chunks.append(entry_for(payload, "signatures_absent"))
                self.partitions += 1
                # The payload is present but the declared signatures or
                # stride are not. The record's end is reported as absent; no
                # later record is expected to be framed after it.
                self._add_length_conflict(
                    "chunk[%d].record_end" % order,
                    record_end, chunk_limit)
                self._add_missing(
                    "chunk_record_absent",
                    [[chunk_limit, record_end]],
                    space="container", chunk=order)
                return

            if record_end <= step:
                self.chunks.append(entry_for(payload, "invalid"))
                self.partitions += 1
                self._add_length_conflict(
                    "chunk[%d].stride" % order, record_end, step)
                return

            self.chunks.append(entry_for(payload, "complete"))
            self.partitions += 1
            step = record_end

        if step < chunk_limit:
            # Too few bytes for another chunk header. They are trailing data
            # inside the body, not a chunk.
            self._add_tail(
                "chunk_framing_leftover", [[step, chunk_limit]],
                space="container")

    def _mark_duplicates(self):
        '''Record chunks whose payload repeats one already seen.

        The container has no chunk identifier, so equal bytes are the only
        duplicate evidence available. A repeated payload is reported but is
        not used to extend the confirmed range.
        '''
        first_seen = {}
        for entry in self.chunks:
            if entry["payload_length"] == 0:
                continue
            digest = entry["digest"]
            if digest in first_seen:
                entry["duplicate_of"] = first_seen[digest]
                self.duplicates.append({
                    "order": entry["order"],
                    "duplicate_of": first_seen[digest],
                    "ranges": [entry["payload"]],
                    "space": "container",
                })
            else:
                first_seen[digest] = entry["order"]

    def _reassemble(self):
        payloads = []
        reassembly_offset = 0
        for entry in self.chunks:
            payload = bytes(self.data[entry["payload"][0]:entry["payload"][1]])
            reassembly_start = reassembly_offset
            reassembly_offset += len(payload)
            entry["reassembly"] = [reassembly_start, reassembly_offset]
            payloads.append(payload)
        self.section_data = b"".join(payloads)

    def _parse_volumes(self):
        scan = _scan_volume_region(self.section_data)
        self.volumes = []
        for index, volume in enumerate(scan["volumes"]):
            declared_end = volume["offset"] + volume["size"]
            complete = volume["size"] <= volume["available"] and \
                volume["parsed"]
            self.volumes.append({
                "index": index,
                "offset": volume["offset"],
                "size": volume["size"],
                "available": volume["available"],
                "declared_end": declared_end,
                "complete": complete,
            })
            self.section_objects.append(volume["object"])
            if volume["size"] > volume["available"]:
                # The volume claims bytes the reassembled stream does not
                # hold. Their position inside the volume is not known: a
                # missing chunk could be at the end or between chunks.
                self._add_missing(
                    "volume_declares_more",
                    [[volume["offset"] + volume["available"], declared_end]],
                    volume=index, declared=volume["size"],
                    available=volume["available"])
        if scan["failure"] in ("process", "zero"):
            self._add_missing(
                "volume_unparsed",
                [[scan["failure_offset"], len(self.section_data)]],
                volume=scan["failure_offset"])
        elif scan["failure"] == "no_header":
            failure_offset = scan["failure_offset"]
            if failure_offset < len(self.section_data):
                if self.volumes:
                    self._add_tail(
                        "after_volumes",
                        [[failure_offset, len(self.section_data)]],
                        space="reassembly")
                else:
                    # A partitioned section's stream should begin with a
                    # firmware volume. Without one, the record that held the
                    # start is absent or unrecognised; the bytes are not
                    # simply trailing data after parsed content.
                    self._add_missing(
                        "volume_header_absent",
                        [[0, len(self.section_data)]],
                        space="reassembly")
        self.volume_scan = scan

    def _label_chunks(self):
        '''Mark whether a chunk's reassembled position is supported.

        A chunk inside a complete volume is confirmed. A chunk that starts an
        incomplete volume is confirmed only if it also ends within the bytes
        that volume holds: the container anchors its first chunk, but chunks
        after a possible gap could have shifted. A duplicate payload is never
        counted as confirmation.
        '''
        for entry in self.chunks:
            start, end = entry.get("reassembly", [0, 0])
            if entry["duplicate_of"] is not None:
                entry["placement"] = "duplicate"
                continue
            if end == start:
                # No payload bytes were sourced from this record, so it
                # cannot anchor or extend the reassembled stream. Its framing
                # status still says whether the record itself was located.
                entry["placement"] = "unparsed"
                continue
            overlapping = [
                volume for volume in self.volumes
                if volume["offset"] < end and start < volume["declared_end"]
            ]
            if not overlapping:
                entry["placement"] = "tail"
                continue
            if all(volume["complete"] for volume in overlapping):
                entry["placement"] = "confirmed"
                continue
            first = overlapping[0]
            if start == first["offset"] and \
                    end <= first["offset"] + first["available"]:
                entry["placement"] = "confirmed"
            else:
                entry["placement"] = "unconfirmed"

    def _summarize_coverage(self):
        total = len(self.section_data)
        declared_ends = [volume["declared_end"] for volume in self.volumes]
        coverage_end = max([total] + declared_ends)
        confirmed = [
            tuple(entry["reassembly"]) for entry in self.chunks
            if entry["placement"] == "confirmed"
        ]
        sourced = [tuple(entry["reassembly"]) for entry in self.chunks
                   if entry["payload_length"] > 0]
        self.coverage = {
            "reassembled_size": total,
            "coverage_end": coverage_end,
            "sourced_ranges": [list(pair) for pair in _merge_ranges(sourced)],
            "confirmed_ranges": [
                list(pair) for pair in _merge_ranges(confirmed)],
            "unknown_ranges": _subtract_ranges(confirmed, 0, coverage_end),
        }
        for entry in self.chunks:
            self.coverage.setdefault("chunks", []).append({
                "order": entry["order"],
                "original": entry["payload"],
                "reassembly": entry["reassembly"],
                "placement": entry["placement"],
            })

    def process(self):
        if len(self.data) < 0x10 or self.data[:8] != PFSFile.PFS_HEADER:
            return False
        scan_end = self._parse_envelope()
        self._parse_chunks(scan_end)
        self._mark_duplicates()
        self._reassemble()
        self._parse_volumes()
        self._label_chunks()
        self._summarize_coverage()

        # Each check answers a different question, and all of them must hold
        # before the reassembly can be called complete. Chunk records must
        # account for the body, every payload must be sourced and placed, no
        # byte may be missing or extra, and the nested volumes must be wholly
        # present rather than merely parseable up to a cut.
        body_start, body_end = self.envelope["body"]
        framed = [tuple(chunk["record"]) for chunk in self.chunks]
        unframed = _subtract_ranges(framed, body_start, body_end)
        self.coverage["unframed_ranges"] = unframed
        self.complete = bool(
            self.chunks and
            not self.container_errors and
            not self.length_conflicts and
            not self.missing and
            not self.duplicates and
            not self.tail and
            not unframed and
            all(entry["placement"] == "confirmed" for entry in self.chunks) and
            self.volumes and
            all(volume["complete"] for volume in self.volumes)
        )
        return True

    @property
    def objects(self):
        return self.section_objects

    def build(self, generate_checksum=False, debug=False):
        body = b"".join(
            volume.build(generate_checksum) for volume in self.section_objects)
        if body != self.section_data[:len(body)]:
            # The volumes are split across the partitions' chunks.
            print_error("Error: cannot rebuild a changed partitioned section.")
        return self.data

    def to_dict(self):
        return {
            'partitions': self.partitions,
            'size': len(self.section_data),
            'complete': self.complete,
            'envelope': dict(self.envelope),
            'chunks': [dict(entry) for entry in self.chunks],
            'missing': list(self.missing),
            'duplicates': list(self.duplicates),
            'length_conflicts': list(self.length_conflicts),
            'tail': list(self.tail),
            'container_errors': list(self.container_errors),
            'coverage': dict(self.coverage),
            'objects': [volume.to_dict() for volume in self.section_objects],
        }

    def _range_text(self, ranges):
        return ", ".join("0x%x-0x%x" % (start, end)
                         for start, end in ranges) or "-"

    def showinfo(self, ts='', index=None):
        print("%s%s partitions %d, reassembled 0x%x (%d bytes), "
              "complete %s" % (
                  ts, blue("Dell PFSPartitionedSection:"), self.partitions,
                  len(self.section_data), len(self.section_data),
                  "yes" if self.complete else "no"))
        for entry in self.chunks:
            duplicate = ""
            if entry["duplicate_of"] is not None:
                duplicate = " duplicate-of %d" % entry["duplicate_of"]
            print("%s  chunk %d: original 0x%x-0x%x reassembled 0x%x-0x%x "
                  "framing %s, placement %s%s" % (
                      ts, entry["order"], entry["payload"][0],
                      entry["payload"][1], entry["reassembly"][0],
                      entry["reassembly"][1], entry["status"],
                      entry["placement"], duplicate))
        for item in self.missing:
            print("%s  missing %s: %s %s" % (
                ts, item.get("space", "reassembly"), item["reason"],
                self._range_text(item["ranges"])))
        for item in self.tail:
            print("%s  tail %s: %s %s" % (
                ts, item.get("space", "container"), item["reason"],
                self._range_text(item["ranges"])))
        for item in self.length_conflicts:
            print("%s  length conflict: %s declared %s actual %s" % (
                ts, item["where"], item["declared"], item["actual"]))
        if self.coverage.get("confirmed_ranges"):
            print("%s  confirmed: %s" % (
                ts, self._range_text(self.coverage["confirmed_ranges"])))
        if self.coverage.get("unknown_ranges"):
            print("%s  unknown: %s" % (
                ts, self._range_text(self.coverage["unknown_ranges"])))
        for sub_object in self.section_objects:
            sub_object.showinfo("%s  " % ts)

    def dump(self, parent="", index=None):
        # The partitioned body has no GUID of its own (its head is the
        # PFS.HDR. magic), so name the files by their serial position.
        name = "partitioned"
        if index is not None:
            name += "-%d" % index
        path = os.path.join(parent, name)
        dump_data("%s.data" % path, self.section_data)

        # The manifest makes the reassembly traceable after extraction. It
        # describes the original container; no original bytes are rewritten.
        manifest = {
            "complete": self.complete,
            "envelope": self.envelope,
            "chunks": self.chunks,
            "missing": self.missing,
            "duplicates": self.duplicates,
            "length_conflicts": self.length_conflicts,
            "tail": self.tail,
            "coverage": self.coverage,
            "section_sha256": hashlib.sha256(self.section_data).hexdigest(),
        }
        dump_data(
            "%s.provenance.json" % path,
            json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))

        path = os.path.join(parent, "section-%s" % name)
        for sub_object in self.section_objects:
            sub_object.dump(path)
        pass


class PFSSection(FirmwareObject, BaseObject):
    HEADER_SIZE = 0x48

    def __init__(self, data):
        self.data = data
        self.size = -1

        # Store parsed objects (if any)
        self.section_objects = []

    def process(self):
        # self.data may be a memoryview of the remaining sections, so copy
        # each part kept from it.
        hdr = bytes(self.data[:self.HEADER_SIZE])
        self.uuid = hdr[:0x10]
        self.header = hdr

        # Spec seems to be a consistent 1, what I thought was a timestamp is not.
        # Version is static except for the first section in a PFS
        ##spec, ts, ctype, version, _u1 = struct.unpack("<I4shh4s", hdr[0x10:0x20])
        spec, version_type = struct.unpack("<I4s", hdr[0x10:0x10 + 0x08])
        self.spec = spec
        self.version = ""
        self.type = 0
        self.ts = 0
        for i in range(4):
            group_offset = 0x18 + (i * 2)
            if version_type[i:i+1] == b'A':
                self.version += "%X" % struct.unpack("<h", hdr[group_offset:group_offset + 2])
            elif version_type[i:i+1] == b'N':
                self.version += ".%d" % struct.unpack("<h", hdr[group_offset:group_offset + 2])

        # U1, U2 might be flag containers
        _u2, section_size, rsa1_size, pmim_size, rsa2_size = struct.unpack(
            "<8sIIII", hdr[0x20:0x20 + 0x18])

        # This seems to be a set of 8byte CRCs for each chunk (4 total)
        self.crcs = hdr[0x20 + 0x18:self.HEADER_SIZE]
        self.section_data = bytes(self.data[
            self.HEADER_SIZE:self.HEADER_SIZE + section_size])

        rsa1_offset = self.HEADER_SIZE + section_size
        self.rsa1 = RawObject(
            bytes(self.data[rsa1_offset:rsa1_offset + rsa1_size]))
        pmim_offset = rsa1_offset + rsa1_size
        self.pmim = RawObject(
            bytes(self.data[pmim_offset:pmim_offset + pmim_size]))
        rsa2_offset = pmim_offset + pmim_size
        self.rsa2 = RawObject(
            bytes(self.data[rsa2_offset:rsa2_offset + rsa2_size]))

        # Unknown 8byte variable
        # _u3 = self.data[64+total_chunk_size:64+total_chunk_size+8]
        self.unknowns = [_u2]

        # Size of header, data, and footer
        total_size = section_size + rsa1_size + pmim_size + rsa2_size
        self.section_size = self.HEADER_SIZE + total_size
        self.data = None

        if self.section_data[:0x08] == b"PFS.HDR.":
            # Partitioned ROM
            rom = PFSPartitionedSection(self.section_data)
            if not rom.process():
                return False
            self.section_objects.append(rom)
        elif sguid(self.uuid) == PFS_GUIDS["FIRMWARE_VOLUMES"]:
            volumes = _discover_volumes(self.section_data)
            if volumes is False:
                return False
            self.section_objects += volumes
        else:
            raw = AutoRawObject(self.section_data)
            raw.process()
            self.section_objects.append(raw)

    @property
    def objects(self):
        return self.section_objects + [self.rsa1, self.pmim, self.rsa2]

    def info(self, include_content=False):
        return {
            "_self": self,
            "guid": sguid(self.uuid),
            "type": "PFSSection",
            "content": self.section_data if include_content else "",
            "attrs": {
                "size": self.section_size,
                "crcs": self.crcs,
                "unknowns": [u for u in self.unknowns],
                "version": self.version
            },
            "chunks": [self.rsa1, self.pmim, self.rsa2] if include_content else []
        }
        pass

    def build(self, generate_checksum=False, debug=False):
        body = b""
        parsed = 0
        for sub_object in self.section_objects:
            body += sub_object.build(generate_checksum, debug=debug)
            parsed += len(_object_data(sub_object))
        # Keep any data after the last volume found in the section.
        body += self.section_data[parsed:]

        header = self.header
        if body != self.section_data:
            # Update the data size and its checksum, the third of four.
            header = bytearray(header)
            struct.pack_into("<I", header, 0x28, len(body))
            struct.pack_into("<I", header, 0x40, _checksum(body))
            header = bytes(header)
        return header + body + \
            self.rsa1.build(generate_checksum) + \
            self.pmim.build(generate_checksum) + \
            self.rsa2.build(generate_checksum)

    def to_dict(self):
        return {
            'guid': sguid(self.uuid),
            'version': self.version,
            'size': self.section_size,
            'objects': [obj.to_dict() for obj in self.section_objects],
        }

    def showinfo(self, ts=0, index=None):
        print("%s%s %s spec 0x%02x ts 0x%02x type 0x%02x version %s size 0x%x (%d bytes)" % (
            ts, blue("Dell PFSSection:"), green(sguid(self.uuid)),
            self.spec, self.ts, self.type, self.version,
            self.section_size, self.section_size
        ))

        for sub_object in self.section_objects:
            sub_object.showinfo("%s  " % ts)
        pass

    def dump(self, parent="", index=None, duplicate=0):
        name = sguid(self.uuid)
        if duplicate > 0:
            # Keep each section that repeats an earlier section's GUID.
            name += "-%d" % duplicate
        path = os.path.join(parent, name)
        dump_data("%s.data" % path, self.section_data)

        # Instead of calling dump on each chunk RawObject, dump with a better
        # name.
        if len(self.rsa1.data) > 0:
            dump_data("%s.rsa1" % path, self.rsa1.data)
        if len(self.pmim.data) > 0:
            dump_data("%s.pmim" % path, self.pmim.data)
        if len(self.rsa2.data) > 0:
            dump_data("%s.rsa2" % path, self.rsa2.data)

        path = os.path.join(parent, "section-%s" % name)
        for sub_object in self.section_objects:
            sub_object.dump(path)
        pass


class PFSFile(FirmwareObject):
    PFS_HEADER = b"PFS.HDR."
    PFS_FOOTER = b"PFS.FTR."

    def __init__(self, data):
        self.sections = []
        self.data = data
        self.valid_header = False
        if self.check_header():
            self.valid_header = True

    def check_header(self):
        if len(self.data) < 32:
            print_error("Data does not contain a header.")
            return False

        header = self.data[:0x10]
        magic, spec, body_size = struct.unpack("<8sII", header)

        self.spec = spec
        self.body_size = body_size
        # The header and footer are 0x10 bytes each.
        self.size = body_size + 0x20

        if magic != self.PFS_HEADER:
            print_error(
                "Data does not contain the header magic (%s)." % self.PFS_HEADER)
            return False

        footer_offset = self.body_size + 0x10
        footer = self.data[footer_offset:footer_offset + 0x10]
        if len(footer) < 0x10:
            print_error("Data is too short for the footer at 0x%x." % (
                footer_offset))
            return False
        # Footer size is a repeated body size.
        footer_size, _u2, footer_magic = struct.unpack("<II8s", footer)
        if footer_magic != self.PFS_FOOTER:
            print_error(
                "Data does not container the footer magic (%s)." % self.PFS_FOOTER)
            return False

        # Keep only this PFS, the caller parses any data that follows.
        self.data = self.data[:self.size]
        return True

    def process(self):
        '''Chunks are assumed to contain a chunk header.'''
        if not self.valid_header:
            return False
        data = self.data[0x10:0x10 + self.body_size]

        view = memoryview(data)
        chunk_num = 0
        offset = 0
        while len(data) - offset >= PFSSection.HEADER_SIZE:
            section = PFSSection(view[offset:])
            section.process()
            self.sections.append(section)

            chunk_num += 1
            offset += section.section_size
        return True

    @property
    def objects(self):
        return self.sections

    def build(self, generate_checksum=False, debug=False):
        original = self.data[0x10:-0x10]
        body = b""
        parsed = 0
        for section in self.sections:
            body += section.build(generate_checksum, debug=debug)
            parsed += section.section_size
        # Keep the bytes after the last section, too few for a header.
        body += original[parsed:]
        header = self.data[:0x10]
        footer = self.data[-0x10:]
        if body != original:
            # The header and footer hold the body size, and the footer its
            # checksum.
            header = header[:0x0C] + struct.pack("<I", len(body))
            footer = struct.pack("<II", len(body), _checksum(body)) + \
                footer[0x08:]
        return header + body + footer

    def to_dict(self):
        return {
            'spec': self.spec,
            'size': self.body_size,
            'sections': [section.to_dict() for section in self.sections],
        }

    def showinfo(self, ts='', index=None):
        print("%s%s spec 0x%x size 0x%x (%d bytes)" % (
            ts, blue("DellPFS:"),
            self.spec, self.body_size, self.body_size
        ))
        for section in self.sections:
            section.showinfo("%s  " % ts)

    def dump(self, parent='', index=None):
        name = "pfsobject"
        if index:
            # Another PFS may come first in the same file.
            name += "-%d" % index
        dump_data(os.path.join(parent, "%s.pfs" % name), self.data)

        path = os.path.join(parent, name)
        seen = {}
        for section in self.sections:
            guid = sguid(section.uuid)
            section.dump(path, duplicate=seen.get(guid, 0))
            seen[guid] = seen.get(guid, 0) + 1


class DellUpdateBinary(FirmwareObject):
    '''A Dell BIOS update program (PE) with an embedded, compressed PFS.

    The PFS follows a 16-byte header: its little-endian compressed size, a
    static marker, and one unknown byte. The marker appears several times in
    the program, so the zlib header (0x789C) is matched to find the right one.

    See https://forums.mydigitallife.net/threads/i-present-you-a-tool-to-decompress-dell-uefi-bios.44785/
    '''
    HDR_PATTERN = re.compile(
        b'.{4}\xAA\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C',
        re.DOTALL)
    HDR_SIZE = 0x10

    def __init__(self, data):
        self.data = data
        self.size = len(data)
        self.pfs = None
        self.pfs_offset = None
        self.valid_header = False
        if data[:2] == b"MZ":
            match = self.HDR_PATTERN.search(data)
            if match is not None:
                self.pfs_offset = match.start()
                self.valid_header = True

    @limit_nesting(False)
    def process(self):
        if not self.valid_header:
            return False
        compressed_size, = struct.unpack(
            "<I", self.data[self.pfs_offset:self.pfs_offset + 4])
        compressed_offset = self.pfs_offset + self.HDR_SIZE
        try:
            pfs_data = zlib_decompress(
                self.data[compressed_offset:compressed_offset + compressed_size])
        except zlib.error as err:
            print_error("Cannot decompress Dell PFS: %s" % str(err))
            return False
        self.pfs = PFSFile(pfs_data)
        return self.pfs.process()

    @property
    def objects(self):
        return [self.pfs]

    def to_dict(self):
        return {
            'size': self.size,
            'pfsOffset': self.pfs_offset,
            'pfs': self.pfs.to_dict(),
        }

    def showinfo(self, ts='', index=None):
        print("%s%s size 0x%x (%d bytes) PFS offset 0x%x" % (
            ts, blue("DellUpdateBinary:"),
            self.size, self.size, self.pfs_offset
        ))
        self.pfs.showinfo("%s  " % ts)

    def dump(self, parent='', index=None):
        self.pfs.dump(parent)

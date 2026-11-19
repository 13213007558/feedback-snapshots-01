'''Machine-readable parse coverage summaries.

``process()`` returns a boolean for each object, and a parent often keeps
going when a child fails. That boolean does not say how much of the input was
actually explained. This module walks the parsed object tree and records what
happened to each byte:

  parsed     structure was interpreted
  preserved  bytes were kept as evidence but not interpreted
  unknown    bytes could not be identified
  failed     parsing was attempted and failed
  padding    alignment or erased flash, excluded from coverage

Bytes read from an object and bytes produced by decompressing it belong to
different coordinate spaces, so their sizes and ratios are never added
together. Each transformation records the input and output sizes. Erased
bytes and alignment padding are reported separately and are removed from the
denominator, so they cannot make a nearly empty parse look complete.
'''

PARSED = "parsed"
PRESERVED = "preserved"
UNKNOWN = "unknown"
FAILED = "failed"
PADDING = "padding"

_KINDS = (PARSED, PRESERVED, UNKNOWN, FAILED, PADDING)
_BAD = (UNKNOWN, FAILED)


def _region(offset, size, kind, path, reason=None, transform=None,
            header=False, retained=0, located=True):
    return {
        "path": path,
        "offset": offset,
        "size": size,
        "kind": kind,
        "reason": reason,
        "transform": transform,
        "header": bool(header),
        "retained": retained,
        "located": located,
    }


class _Space(object):
    '''One coordinate space, such as the input or one decompressed stream.'''

    def __init__(self, key, size, parent=None, transform=None,
                 declared_size=None):
        self.key = key
        self.size = max(int(size or 0), 0)
        self.parent = parent
        self.transform = transform
        self.declared_size = declared_size
        self.regions = []

    def add(self, start, end, kind, path, reason=None, transform=None,
            header=False, retained=0):
        '''Place a region after clipping it to this space.'''
        start = max(int(start), 0)
        end = min(int(end), self.size)
        if end <= start:
            return
        self.regions.append(_region(
            start, end - start, kind, path, reason, transform, header,
            retained))

    def fill(self, start, end, kind, path, reason=None, transform=None,
             retained=0):
        '''Mark only the parts of [start, end) not already claimed.'''
        for gap_start, gap_end in self.unclaimed(start, end):
            self.add(gap_start, gap_end, kind, path, reason, transform,
                     retained=retained)

    def unclaimed(self, start, end):
        '''Return the sub-ranges of [start, end) no region has claimed.'''
        start = max(int(start), 0)
        end = min(int(end), self.size)
        if end <= start:
            return []
        covered = sorted((r["offset"], r["offset"] + r["size"])
                         for r in self.regions)
        gaps = []
        cursor = start
        for covered_start, covered_end in covered:
            if covered_end <= cursor:
                continue
            if covered_start >= end:
                break
            if covered_start > cursor:
                gaps.append((cursor, min(covered_start, end)))
            cursor = max(cursor, covered_end)
            if cursor >= end:
                break
        if cursor < end:
            gaps.append((cursor, end))
        return gaps

    def finalize(self):
        '''Order regions and mark unclaimed bytes as unknown.'''
        self.regions.sort(key=lambda region: region["offset"])
        placed = []
        cursor = 0
        for region in self.regions:
            start = region["offset"]
            end = start + region["size"]
            if start > cursor:
                placed.append(_region(
                    cursor, start - cursor, UNKNOWN, self.key,
                    "bytes not claimed by the parse"))
            if end <= cursor:
                continue
            if start < cursor:
                region["offset"] = cursor
                region["size"] = end - cursor
            placed.append(region)
            cursor = max(cursor, region["offset"] + region["size"])
        if cursor < self.size:
            placed.append(_region(
                cursor, self.size - cursor, UNKNOWN, self.key,
                "bytes not claimed by the parse"))
        self.regions = placed
        return placed

    def counts(self):
        counts = {kind: 0 for kind in _KINDS}
        headers = 0
        for region in self.regions:
            counts[region["kind"]] += region["size"]
            if region["header"]:
                headers += region["size"]
        denominator = max(self.size - counts[PADDING], 0)
        parsed = counts[PARSED]
        body = max(parsed - headers, 0)
        unexplained = counts[UNKNOWN] + counts[FAILED]
        counts.update({
            "total": self.size,
            "header": headers,
            "bodyParsed": body,
            "unexplained": unexplained,
            "denominator": denominator,
            # Structure bytes are excluded, so a header-only parse has a low
            # body ratio even though it recognized every header.
            "parsedRatio":
                (parsed / denominator) if denominator else None,
            "bodyParsedRatio":
                (body / denominator) if denominator else None,
            "unexplainedRatio":
                (unexplained / denominator) if denominator else None,
            "preservedRatio":
                (counts[PRESERVED] / denominator) if denominator else None,
        })
        return counts

    def as_dict(self):
        return {
            "parent": self.parent,
            "transform": self.transform,
            "declaredSize": self.declared_size,
            "sizeMismatch": self.declared_size is not None and
                self.declared_size != self.size,
            "counts": self.counts(),
            "regions": self.regions,
        }


class _Walker(object):
    def __init__(self):
        self.spaces = {}
        self.order = []
        self.transformations = []
        self.warnings = []
        self.seen = set()

    def space(self, key, size, parent=None, transform=None,
              declared_size=None):
        if key not in self.spaces:
            self.spaces[key] = _Space(
                key, size, parent, transform, declared_size)
            self.order.append(key)
        else:
            existing = self.spaces[key]
            existing.size = max(existing.size, int(size or 0))
        return self.spaces[key]

    def walk(self, obj, space, base, path, role=PRESERVED, depth=0):
        if obj is None or depth > 96:
            return
        identity = id(obj)
        if identity in self.seen:
            return
        self.seen.add(identity)

        from .base import RawObject, PaddingObject, AutoRawObject
        from . import uefi, flash, pfs, me
        from . import MultiObject

        if isinstance(obj, PaddingObject):
            self._walk_padding(obj, space, base, path)
        elif isinstance(obj, RawObject):
            self._walk_raw(obj, space, base, path, role)
        elif isinstance(obj, AutoRawObject):
            self._walk_auto_raw(obj, space, base, path, role, depth)
        elif isinstance(obj, uefi.FirmwareVolume):
            self._walk_volume(obj, space, base, path, depth)
        elif isinstance(obj, uefi.FirmwareFileSystem):
            self._walk_ffs(obj, space, base, path, depth)
        elif isinstance(obj, uefi.FirmwareFile):
            self._walk_file(obj, space, base, path, depth)
        elif isinstance(obj, uefi.FirmwareFileSystemSection):
            self._walk_section(obj, space, base, path, depth)
        elif isinstance(obj, uefi.CompressedSection):
            self._walk_compressed(obj, space, base, path, depth)
        elif isinstance(obj, uefi.GuidDefinedSection):
            self._walk_guid_defined(obj, space, base, path, depth)
        elif isinstance(obj, uefi.NVARVariableStore):
            self._walk_nvar_store(obj, space, base, path, depth)
        elif isinstance(obj, uefi.NVARVariable):
            size = getattr(obj, "size", 0) or 0
            space.add(base, base + size, PARSED, path, "NVRAM variable")
        elif isinstance(obj, pfs.PFSFile):
            self._walk_pfs(obj, space, base, path, depth)
        elif isinstance(obj, pfs.PFSSection):
            self._walk_pfs_section(obj, space, base, path, depth)
        elif isinstance(obj, pfs.PFSPartitionedSection):
            self._walk_pfs_partitioned(obj, space, base, path, depth)
        elif isinstance(obj, me.MeContainer):
            self._walk_me_container(obj, space, base, path, depth)
        elif isinstance(obj, me.PartitionEntry):
            self._walk_me_partition(obj, space, base, path, depth)
        elif isinstance(obj, me.MeManifestHeader):
            self._walk_me_manifest(obj, space, base, path, depth)
        elif isinstance(obj, me.CPDManifestHeader):
            self._walk_me_cpd(obj, space, base, path, depth)
        elif isinstance(obj, uefi.FirmwareCapsule):
            self._walk_capsule(obj, space, base, path, depth)
        elif isinstance(obj, MultiObject):
            self._walk_stacked(obj.objects, space, base, path, depth)
        elif isinstance(obj, uefi.MultiVolumeContainer):
            self._walk_stacked(obj.objs, space, base, path, depth)
        elif isinstance(obj, flash.FlashDescriptor):
            self._walk_flash_descriptor(obj, space, base, path, depth)
        elif isinstance(obj, flash.FlashRegion):
            self._walk_stacked(obj.sections, space, base, path, depth)
        elif isinstance(obj, uefi.FirmwareVariableStore):
            self._walk_stacked(obj.objects, space, base, path, depth)
        else:
            self._walk_generic(obj, space, base, path)

    # -- leaves and wrappers ----------------------------------------------

    def _walk_padding(self, obj, space, base, path):
        data = obj.data if obj.data is not None else b""
        if not data:
            return
        if getattr(obj, "erased", False):
            space.add(base, base + len(data), PADDING, path, "erased bytes")
        else:
            space.add(base, base + len(data), UNKNOWN, path,
                      "padding holds data that was not parsed")

    def _walk_raw(self, obj, space, base, path, role):
        from .utils import is_erased
        data = obj.data if obj.data is not None else b""
        if not data:
            return
        if is_erased(data):
            space.add(base, base + len(data), PADDING, path, "erased bytes")
        elif role == PADDING:
            space.add(base, base + len(data), PADDING, path,
                      "alignment bytes")
        elif role == UNKNOWN:
            space.add(base, base + len(data), UNKNOWN, path,
                      "bytes were not interpreted")
        else:
            space.add(base, base + len(data), PRESERVED, path,
                      "raw bytes kept as evidence")

    def _walk_auto_raw(self, obj, space, base, path, role, depth):
        data = obj.data if obj.data is not None else b""
        if obj.object is None:
            if getattr(obj, "failed_end", 0):
                space.add(base, base + len(data), FAILED, path,
                          "a nested object failed to parse",
                          retained=len(data))
            else:
                space.add(base, base + len(data), UNKNOWN, path,
                          "no known object could be identified",
                          retained=len(data))
            return
        self.walk(obj.object, space, base, path + "/auto", role, depth + 1)

    def _walk_stacked(self, objects, space, base, path, depth):
        '''Walk children laid out one after another in the same space.'''
        from .base import RawObject, PaddingObject
        cursor = base
        for index, child in enumerate(objects):
            if child is None:
                continue
            size = object_size(child)
            # A raw object is bytes the parser did not recognize. It is
            # reported as unknown unless it is erased, in which case the
            # leaf walk treats it as padding.
            role = UNKNOWN if isinstance(child, RawObject) else PRESERVED
            self.walk(child, space, cursor, path + "/" + label(child, index),
                      role, depth + 1)
            cursor += size

    # -- UEFI containers ---------------------------------------------------

    def _walk_volume(self, obj, space, base, path, depth):
        size = object_size(obj)
        if size == 0:
            return
        hdrlen = getattr(obj, "hdrlen", 0) or 0
        hdrlen = min(hdrlen, size)
        space.add(base, base + hdrlen, PARSED, path,
                  "firmware volume header", header=True)
        body = base + hdrlen
        end = base + size
        data = getattr(obj, "_data", b"") or b""

        filesystems = list(getattr(obj, "firmware_filesystems", []) or [])
        raw_objects = list(getattr(obj, "raw_objects", []) or [])

        if filesystems:
            for index, ffs in enumerate(filesystems):
                self.walk(ffs, space, body, path + "/ffs%d" % index,
                          PRESERVED, depth + 1)
        elif raw_objects:
            cursor = body
            for index, child in enumerate(raw_objects):
                if isinstance(child, (bytes, bytearray)):
                    kind = PADDING if _is_erased(child) else PRESERVED
                    reason = "volume body is not a file system"
                    space.add(body, end, kind, path + "/body", reason,
                              retained=len(child))
                    cursor = end
                    continue
                self.walk(child, space, cursor,
                          path + "/" + label(child, index), PRESERVED,
                          depth + 1)
                cursor += object_size(child)
            if cursor < end:
                self._gap(space, data, cursor - body, size - hdrlen, path,
                          "volume body was not parsed", base=body)
        elif not getattr(obj, "valid_header", False):
            space.add(body, end, FAILED, path,
                      "firmware volume header is not valid")
        else:
            self._gap(space, data, 0, size - hdrlen, path,
                      "firmware volume body was not parsed", base=body)

        if getattr(obj, "process_status", True) is False:
            # The volume failed, but everything its children explained is
            # kept. Only the bytes they left are counted as failed.
            for gap_start, gap_end in space.unclaimed(body, end):
                if _is_erased(data[gap_start - base:gap_end - base]):
                    kind, reason = PADDING, "erased bytes"
                else:
                    kind, reason = FAILED, \
                        "firmware volume processing returned false"
                space.add(gap_start, gap_end, kind, path, reason)

    def _walk_ffs(self, obj, space, base, path, depth):
        data = getattr(obj, "_data", b"") or b""
        size = len(data)
        cursor = 0
        for index, firmware_file in enumerate(getattr(obj, "files", []) or []):
            extent = getattr(firmware_file, "parsed_extent", None)
            if extent is None:
                self.walk(firmware_file, space, base + cursor,
                          path + "/" + _index_label(firmware_file, index),
                          PRESERVED, depth + 1)
                cursor += object_size(firmware_file)
                continue
            start, length = extent
            if start > cursor:
                self._gap(space, data, cursor, start, path,
                          "file alignment", base=base)
            self.walk(firmware_file, space, base + start,
                      path + "/" + _index_label(firmware_file, index),
                      PRESERVED, depth + 1)
            cursor = max(cursor, start + length)

        overflow = getattr(obj, "overflow_data", b"") or b""
        start = size - len(overflow) if overflow else cursor
        if start < size:
            self._gap(space, data, start, size, path,
                      "free space was not parsed", base=base)

    def _walk_file(self, obj, space, base, path, depth):
        data = getattr(obj, "_data", b"") or b""
        size = len(data)
        if size == 0:
            return
        header_size = getattr(obj, "header_size", 0x18) or 0x18
        header_size = min(header_size, size)

        if getattr(obj, "type", None) == 0xf0:
            # A pad file is alignment by definition. Its header is padding;
            # a body that is not erased is vendor data and is reported as
            # unexplained rather than counted as explained bytes.
            space.add(base, base + header_size, PADDING, path,
                      "FFS padding file header")
            body = data[header_size:]
            if body:
                if _is_erased(body):
                    space.add(base + header_size, base + size, PADDING, path,
                              "erased padding file body")
                else:
                    space.add(base + header_size, base + size, UNKNOWN, path,
                              "padding file body holds data that was not "
                              "parsed")
            return

        space.add(base, base + header_size, PARSED, path,
                  "firmware file header", header=True)
        body = base + header_size
        end = base + size
        body_size = max(size - header_size, 0)

        sections = list(getattr(obj, "sections", []) or [])
        blobs = list(getattr(obj, "raw_blobs", []) or [])

        if sections:
            cursor = 0
            for index, section in enumerate(sections):
                extent = getattr(section, "parsed_extent", None)
                if extent is None:
                    self.walk(section, space, body + cursor,
                              path + "/" + _index_label(section, index),
                              PRESERVED, depth + 1)
                    cursor += object_size(section)
                    continue
                start, length = extent
                if start > cursor:
                    self._gap(space, data, header_size + cursor,
                              header_size + start, path, "section alignment",
                              base=base, alignment=4)
                self.walk(section, space, body + start,
                          path + "/" + _index_label(section, index),
                          PRESERVED, depth + 1)
                cursor = max(cursor, start + length)
            if cursor < body_size:
                self._gap(space, data, header_size + cursor, size, path,
                          "bytes after the last section were not parsed",
                          base=base, alignment=4)
        elif blobs:
            cursor = body
            for index, blob in enumerate(blobs):
                self.walk(blob, space, cursor,
                          path + "/" + _index_label(blob, index), PRESERVED,
                          depth + 1)
                cursor += object_size(blob)
            if cursor < end:
                self._gap(space, data, cursor - base, size, path,
                          "bytes after the last raw object were not parsed",
                          base=base)
        elif body_size:
            if getattr(obj, "process_status", True) is False:
                space.add(body, end, FAILED, path,
                          "firmware file could not be parsed",
                          retained=body_size)
            else:
                kind = PADDING if _is_erased(data[header_size:]) else \
                    PRESERVED
                reason = "file body is not structured"
                space.add(body, end, kind, path, reason)

    def _walk_section(self, obj, space, base, path, depth):
        if not getattr(obj, "valid_header", True):
            size = len(getattr(obj, "_data", b"")) or 0
            if size:
                space.add(base, base + size, FAILED, path,
                          "section header is not valid")
            return

        data = getattr(obj, "_data", b"") or b""
        size = len(data)
        if size == 0:
            return
        header_size = 8 if getattr(obj, "large_header", False) else 4
        header_size = min(header_size, size)
        space.add(base, base + header_size, PARSED, path,
                  "section header", header=True)
        body = base + header_size
        end = base + size
        section_type = getattr(obj, "type", None)
        parsed = getattr(obj, "parsed_object", None)
        failed = getattr(obj, "failed_object", None)

        if section_type == 0x01:  # compression
            if parsed is None:
                space.add(body, end, FAILED, path,
                          "compression section could not be parsed")
                return
            self._walk_compressed(parsed, space, body, path, depth)
            return

        if section_type == 0x02:  # GUID-defined
            if parsed is None and failed is not None:
                self._walk_guid_failed(failed, space, body, end, path)
                return
            if parsed is None:
                space.add(body, end, UNKNOWN, path,
                          "GUID-defined section was not parsed")
                return
            self._walk_guid_defined(parsed, space, body, path, depth)
            return

        if section_type == 0x17:  # firmware volume image
            if parsed is not None and getattr(parsed, "valid_header", False):
                volume_size = object_size(parsed)
                start = end - volume_size
                start = max(start, body)
                self.walk(parsed, space, start, path + "/volume",
                          PRESERVED, depth + 1)
                return
            space.add(body, end, FAILED, path,
                      "firmware volume image could not be parsed")
            return

        if section_type == 0x19:  # raw
            if parsed is not None:
                self.walk(parsed, space, body, path + "/raw", PRESERVED,
                          depth + 1)
            else:
                space.add(body, end, PRESERVED, path,
                          "raw section bytes kept unparsed")
            return

        if section_type == 0x18:  # free-form GUID
            space.add(body, end, PARSED, path, "free-form GUID section")
            return

        if section_type in (0x13, 0x1b, 0x1c, 0x14, 0x15):
            space.add(body, end, PARSED, path, "section body")
            return

        if section_type in (0x03, 0x10, 0x11, 0x12, 0x16):
            space.add(body, end, PRESERVED, path,
                      "known section type that is not parsed")
            return

        space.add(body, end, UNKNOWN, path,
                  "unknown section type 0x%02x" % (section_type or 0))

    def _walk_compressed(self, obj, space, body, path, depth):
        '''Walk a CompressedSection whose body starts at body.'''
        raw = getattr(obj, "_body", b"") or b""
        compressed = getattr(obj, "compressed_data", b"") or b""
        size = len(raw)
        if size == 0:
            return
        header_size = min(5, size)
        compression_type = getattr(obj, "type", 0)
        decompressed = getattr(obj, "data", None)

        if compression_type == 0x00:
            # No compression: the subsections share this coordinate space.
            space.add(body, body + header_size, PARSED, path,
                      "compression header", header=True)
            start = body + header_size
            self._walk_substream(
                obj, space, start, path + "/subsections",
                "compression-none", depth)
            return

        if decompressed is None:
            reason = "compressed data could not be decompressed"
            space.add(body, body + size, FAILED, path, reason,
                      transform="compression",
                      retained=len(compressed))
            return

        space.add(body, body + size, PARSED, path,
                  "compressed stream, decoded into another space",
                  transform="compression")
        child = self.space(
            path + "/decompressed", len(decompressed), parent=space.key,
            transform="compression:%d" % compression_type,
            declared_size=getattr(obj, "decompressed_size", None))
        self.transformations.append({
            "path": path,
            "from": space.key,
            "to": child.key,
            "kind": "compression:%d" % compression_type,
            "inputOffset": body,
            "inputSize": size,
            "outputSize": len(decompressed),
            "declaredOutputSize": getattr(obj, "decompressed_size", None),
        })
        self._walk_substream(obj, child, 0, child.key,
                             "compression:%d" % compression_type, depth)

    def _walk_substream(self, owner, target, base, path, transform, depth):
        '''Walk owner.subsections, laid out from base in target.

        The subsections cover owner.data, so any bytes of that stream that
        no subsection claimed are classified here.
        '''
        stream = getattr(owner, "data", b"") or b""
        subsections = list(getattr(owner, "subsections", []) or [])
        cursor = 0
        for index, section in enumerate(subsections):
            extent = getattr(section, "parsed_extent", None)
            if extent is None:
                self.walk(section, target, base + cursor,
                          path + "/" + _index_label(section, index),
                          PRESERVED, depth + 1)
                cursor += object_size(section)
                continue
            start, length = extent
            if start > cursor:
                self._gap(target, stream, cursor, start, path,
                          "subsection alignment", base=base, alignment=4)
            self.walk(section, target, base + start,
                      path + "/" + _index_label(section, index),
                      PRESERVED, depth + 1)
            cursor = max(cursor, start + length)

        if cursor < len(stream):
            self._gap(target, stream, cursor, len(stream), path,
                      "bytes after the last subsection were not parsed",
                      base=base, alignment=4)

    def _walk_guid_defined(self, obj, space, body, path, depth):
        '''Walk a GuidDefinedSection's body, which starts at body.'''
        from .structs.uefi_structs import FIRMWARE_GUIDED_GUIDS
        from .utils import sguid
        guid = sguid(getattr(obj, "guid", b""))
        raw = getattr(obj, "_body", b"") or b""
        size = len(raw)
        if size == 0:
            return
        data = getattr(obj, "data", b"") or b""
        data_offset = len(raw) - len(data)
        data_start = body + max(data_offset, 0)
        subsections = list(getattr(obj, "subsections", []) or [])
        failure_reason = getattr(obj, "failure_reason", None)

        compressed = guid in (
            FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED"],
            FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED_HP"],
            FIRMWARE_GUIDED_GUIDS["TIANO_COMPRESSED"],
            FIRMWARE_GUIDED_GUIDS["ZLIB_COMPRESSED_AMD"],
            FIRMWARE_GUIDED_GUIDS["GZIP_COMPRESSED_QC"])
        known = set(FIRMWARE_GUIDED_GUIDS.values())

        if compressed:
            if not data:
                space.add(body, body + size, FAILED, path,
                          failure_reason or
                          "GUID-defined compressed data could not be "
                          "decompressed", transform="guid-defined",
                          retained=size)
                return
            space.add(body, body + size, PARSED, path,
                      "GUID-defined compressed stream, decoded into another "
                      "space", transform="guid-defined")
            child = self.space(
                path + "/decompressed", len(data), parent=space.key,
                transform="guid-defined:%s" % guid)
            self.transformations.append({
                "path": path,
                "from": space.key,
                "to": child.key,
                "kind": "guid-defined:%s" % guid,
                "inputOffset": body,
                "inputSize": size,
                "outputSize": len(data),
                "declaredOutputSize": getattr(obj, "decompressed_size", None),
            })
            self._walk_substream(obj, child, 0, child.key,
                                 "guid-defined:%s" % guid, depth)
            return

        # Header and preamble are interpreted in this space.
        space.add(body, min(data_start, body + size), PARSED, path,
                  "GUID-defined header", header=True)

        if subsections:
            # The section's GUID is not one this parser knows. The content
            # was parsed with a heuristic (usually as a volume), so it is
            # evidence rather than verified structure: report the whole
            # body as unverified even when the heuristic succeeded.
            if guid not in known:
                self.warnings.append({
                    "path": path,
                    "kind": "heuristic-parse",
                    "size": size,
                    "reason": "unrecognized GUID-defined section %s; its "
                              "content was parsed heuristically" %
                              (guid or "?"),
                })
                space.add(body, body + size, PRESERVED, path,
                          "unrecognized GUID-defined section %s; content "
                          "parsed heuristically" % (guid or "?"),
                          transform="guid-defined", retained=size)
                for index, section in enumerate(subsections):
                    extent = getattr(section, "parsed_extent", None)
                    start = data_start + (extent[0] if extent else 0)
                    self.walk(section, space, start,
                              path + "/" + _index_label(section, index),
                              PRESERVED, depth + 1)
                return
            cursor = data_start
            for index, section in enumerate(subsections):
                extent = getattr(section, "parsed_extent", None)
                start = data_start + (extent[0] if extent else 0)
                self.walk(section, space, start,
                          path + "/" + _index_label(section, index),
                          PRESERVED, depth + 1)
                cursor = start + (extent[1] if extent else object_size(
                    section))
            if cursor < body + size:
                self._gap(space, raw, cursor - body, size, path,
                          "bytes after the GUID-defined content were not "
                          "parsed", base=body, alignment=4)
            return

        if guid in known:
            space.add(body, body + size, FAILED, path,
                      failure_reason or
                      "known GUID-defined section produced no content",
                      transform="guid-defined", retained=size)
            return

        reason = "unrecognized GUID-defined section %s" % (guid or "?")
        space.add(body, body + size, UNKNOWN, path, reason,
                  transform="guid-defined", retained=size)

    def _walk_guid_failed(self, obj, space, body, end, path):
        '''A GUID-defined section whose process failed but was kept.'''
        reason = getattr(obj, "failure_reason", None) or \
            "GUID-defined section could not be parsed"
        raw = getattr(obj, "_body", b"") or b""
        subsections = list(getattr(obj, "subsections", []) or [])
        if subsections and raw:
            data = getattr(obj, "data", b"") or b""
            data_offset = max(len(raw) - len(data), 0)
            start = body + data_offset
            space.add(body, min(start, end), PARSED, path,
                      "GUID-defined header", header=True)
            for index, section in enumerate(subsections):
                extent = getattr(section, "parsed_extent", None)
                location = start + (extent[0] if extent else 0)
                self.walk(section, space, location,
                          path + "/" + _index_label(section, index),
                          PRESERVED, depth + 1)
            for gap_start, gap_end in space.unclaimed(start, end):
                space.add(gap_start, gap_end, FAILED, path, reason)
            return
        space.add(body, end, FAILED, path, reason, transform="guid-defined",
                  retained=end - body)

    def _walk_nvar_store(self, obj, space, base, path, depth):
        data = getattr(obj, "data", b"") or b""
        cursor = 0
        for index, variable in enumerate(getattr(obj, "variables", []) or []):
            size = getattr(variable, "size", 0) or object_size(variable)
            self.walk(variable, space, base + cursor,
                      path + "/variable%d" % index, PRESERVED, depth + 1)
            cursor += size
        free_space = getattr(obj, "free_space", b"") or b""
        if free_space:
            kind = PADDING if _is_erased(free_space) else UNKNOWN
            reason = None if kind == PADDING else \
                "NVRAM free space holds data that was not parsed"
            space.add(base + cursor, base + cursor + len(free_space), kind,
                      path, reason)

    # -- other formats -----------------------------------------------------

    def _walk_capsule(self, obj, space, base, path, depth):
        size = object_size(obj)
        data = getattr(obj, "_data", b"") or b""
        size = min(size, len(data)) if data else size
        if size == 0:
            return
        header_size = min(getattr(obj, "header_size", 0) or 0, size)
        space.add(base, base + header_size, PARSED, path,
                  "capsule header", header=True)
        body = getattr(obj, "capsule_body", None)
        if body is None:
            if getattr(obj, "process_status", True) is False:
                space.add(base + header_size, base + size, FAILED, path,
                          "capsule body could not be parsed")
            else:
                space.add(base + header_size, base + size, PRESERVED, path,
                          "capsule body kept as evidence")
            return
        body_offset = getattr(obj, "body_offset", None)
        if body_offset is None:
            body_offset = header_size + (getattr(obj, "offsets", {}) or {}).get(
                "capsule_body", 0)
        body_offset = min(max(body_offset, header_size), size)
        self.walk(body, space, base + body_offset, path + "/body",
                  PRESERVED, depth + 1)

    # -- Intel ME ----------------------------------------------------------

    def _walk_me_container(self, obj, space, base, path, depth):
        '''An ME/CSME partition table and the partitions it points to.

        Partition offsets are absolute in the container, which is the same
        coordinate space as the input here.
        '''
        from . import me
        data = getattr(obj, "data", b"") or b""
        size = len(data)
        if size == 0:
            return
        table = min(0x30 + me.PartitionEntry.size *
                    getattr(obj.structure, "Entries", 0), size)
        space.add(base, base + table, PARSED, path, "ME partition table",
                  header=True)
        for index, partition in enumerate(
                getattr(obj, "partitions", []) or []):
            offset = getattr(partition.structure, "Offset", None)
            if offset is None or offset >= size:
                self._walk_generic(
                    partition, space, base + table,
                    path + "/" + _index_label(partition, index))
                continue
            self.walk(partition, space, base + offset,
                      path + "/" + _index_label(partition, index),
                      PRESERVED, depth + 1)
        # Any container bytes no partition claimed are unaccounted for.
        self._gap(space, data, 0, size, path,
                  "ME container bytes were not claimed by a partition",
                  base=base)

    def _walk_me_partition(self, obj, space, base, path, depth):
        from . import me
        data = getattr(obj, "data", b"") or b""
        size = len(data)
        if size == 0:
            return
        if not getattr(obj, "has_content", False):
            space.add(base, base + size, UNKNOWN, path,
                      "ME partition entry has no valid content",
                      retained=size)
            return
        manifest = getattr(obj, "manifest", None)
        if manifest is None:
            space.add(base, base + size, PRESERVED, path,
                      "ME partition data kept as evidence", retained=size)
            return
        self.walk(manifest, space, base,
                  path + "/" + _index_label(manifest, 0), PRESERVED,
                  depth + 1)

    def _walk_me_manifest(self, obj, space, base, path, depth):
        '''An ME module manifest: header, modules, optional huffman table.

        MeManifestHeader.data holds only the module stream; the header is
        the difference between the object's size and that stream.
        '''
        stream = getattr(obj, "data", b"") or b""
        total = getattr(obj, "size", 0) or len(stream)
        header = max(total - len(stream), 0)
        if total == 0:
            return
        if not getattr(obj, "valid_header", True):
            space.add(base, base + total, FAILED, path,
                      "ME manifest header is not valid", retained=total)
            return
        space.add(base, base + header, PARSED, path, "ME manifest header",
                  header=True)
        cursor = 0
        for group in ("modules", "variable_modules"):
            for index, module in enumerate(getattr(obj, group, []) or []):
                module_size = object_size(module)
                if module_size <= 0 or cursor + module_size > len(stream):
                    break
                self._walk_me_module(module, space, base + header + cursor,
                                     path + "/" + _index_label(module, index),
                                     depth + 1)
                cursor += module_size
        llut = getattr(obj, "huffman_llut", None)
        if llut is not None and cursor < len(stream):
            size = object_size(llut)
            self.walk(llut, space, base + header + cursor,
                      path + "/" + _index_label(llut, 0), PRESERVED,
                      depth + 1)
            cursor += size
        if cursor < len(stream):
            self._gap(space, stream, cursor, len(stream), path,
                      "ME manifest bytes after the last module were not "
                      "parsed", base=base + header)

    def _walk_me_module(self, obj, space, base, path, depth, header_size=None):
        '''An ME module: its header, and either its body or a new space.'''
        from . import me
        size = object_size(obj)
        if size <= 0:
            return
        if header_size is None:
            header_size = getattr(obj, "HEADER_SIZE", 0) or 0
        header_size = min(header_size, size)
        if header_size:
            space.add(base, base + header_size, PARSED, path,
                      "ME module header", header=True)
        body = base + header_size
        end = base + size
        decompressed = getattr(obj, "decompressed", None)
        compression = getattr(obj, "compression", None)
        if compression == me.COMP_TYPE_LZMA:
            body_bytes = getattr(obj, "data", b"") or b""
            if decompressed is None:
                space.add(body, end, FAILED, path,
                          "ME LZMA module could not be decompressed",
                          transform="me-lzma", retained=len(body_bytes))
                return
            space.add(body, end, PARSED, path,
                      "ME LZMA stream, decoded into another space",
                      transform="me-lzma")
            child = self.space(
                path + "/decompressed", len(decompressed), parent=space.key,
                transform="me-lzma")
            self.transformations.append({
                "path": path,
                "from": space.key,
                "to": child.key,
                "kind": "me-lzma",
                "inputOffset": body,
                "inputSize": end - body,
                "outputSize": len(decompressed),
            })
            child.add(0, len(decompressed), PRESERVED, child.key,
                      "decompressed ME module kept as evidence",
                      retained=len(decompressed))
            return
        if compression == me.COMP_TYPE_HUFFMAN:
            space.add(body, end, PRESERVED, path,
                      "Huffman-compressed ME module kept as evidence",
                      retained=end - body)
            return
        space.add(body, end, PRESERVED, path,
                  "ME module body kept as evidence", retained=end - body)

    def _walk_me_cpd(self, obj, space, base, path, depth):
        '''An ME CPD manifest with entries pointing at modules.'''
        from . import me
        data = getattr(obj, "data", b"") or b""
        size = len(data)
        if size == 0:
            return
        header_length = max((getattr(obj.structure, "Flags", 0) >> 16) & 0xFF,
                            me.MeCpdHeaderType.size)
        table = min(header_length + me.MeCpdEntryType.size *
                    getattr(obj.structure, "NumModules", 0), size)
        space.add(base, base + table, PARSED, path, "ME CPD header and "
                  "entry table", header=True)
        for index, entry in enumerate(getattr(obj, "modules", []) or []):
            offset = getattr(entry, "offset", None)
            if offset is None or offset >= size:
                continue
            self._walk_me_module(
                entry, space, base + offset,
                path + "/" + _index_label(entry, index), depth + 1,
                header_size=0)
        self._gap(space, data, table, size, path,
                  "ME CPD bytes were not claimed by an entry", base=base)

    # -- Dell PFS ----------------------------------------------------------

    def _walk_pfs(self, obj, space, base, path, depth):
        '''A PFS file: a 0x10-byte header, its sections, a 0x10-byte footer.'''
        size = object_size(obj)
        if size == 0:
            return
        header = min(0x10, size)
        footer = min(0x10, max(size - header, 0))
        space.add(base, base + header, PARSED, path, "PFS header",
                  header=True)
        if footer:
            space.add(base + size - footer, base + size, PARSED, path,
                      "PFS footer", header=True)
        body_start = base + header
        body_size = max(size - header - footer, 0)
        cursor = 0
        for index, section in enumerate(getattr(obj, "sections", []) or []):
            length = getattr(section, "section_size", 0) or object_size(section)
            if cursor >= body_size:
                break
            self.walk(section, space, body_start + cursor,
                      path + "/" + _index_label(section, index), PRESERVED,
                      depth + 1)
            cursor += length
        if cursor < body_size:
            self._gap(space, getattr(obj, "data", b"") or b"",
                      header + cursor, size - footer, path,
                      "PFS body bytes after the last section were not parsed",
                      base=base)

    def _walk_pfs_section(self, obj, space, base, path, depth):
        '''A PFS section: a 0x48-byte header, data, then signed blobs.'''
        from . import pfs
        size = getattr(obj, "section_size", 0) or object_size(obj)
        if size <= 0:
            return
        header = min(pfs.PFSSection.HEADER_SIZE, size)
        data = getattr(obj, "section_data", None)
        section_data = data if isinstance(data, (bytes, bytearray)) else b""
        data_size = len(section_data)
        space.add(base, base + header, PARSED, path, "PFS section header",
                  header=True)
        data_start = base + header
        data_end = min(data_start + data_size, base + size)
        if data_end > data_start:
            content = list(getattr(obj, "section_objects", []) or [])
            if content:
                cursor = data_start
                for index, child in enumerate(content):
                    self.walk(child, space, cursor,
                              path + "/" + _index_label(child, index),
                              PRESERVED, depth + 1)
                    cursor += object_size(child)
                if cursor < data_end:
                    self._gap(space, section_data,
                              cursor - data_start, data_size, path,
                              "PFS section content after the last object "
                              "was not parsed", base=data_start)
            else:
                space.add(data_start, data_end, PRESERVED, path,
                          "PFS section data kept as evidence",
                          retained=data_size)
        blobs_start = data_start + data_size
        if blobs_start < base + size:
            space.add(blobs_start, base + size, PRESERVED, path,
                      "PFS signatures kept as evidence")

    def _walk_pfs_partitioned(self, obj, space, base, path, depth):
        '''A partitioned PFS section whose chunks rebuild several volumes.'''
        size = object_size(obj)
        if size == 0:
            return
        reconstructed = getattr(obj, "section_data", b"") or b""
        space.add(base, base + size, PRESERVED, path,
                  "partitioned PFS chunks kept as evidence",
                  retained=size)
        if not reconstructed:
            return
        child = self.space(
            path + "/reconstructed", len(reconstructed), parent=space.key,
            transform="pfs-partitions")
        self.transformations.append({
            "path": path,
            "from": space.key,
            "to": child.key,
            "kind": "pfs-partitions",
            "inputOffset": base,
            "inputSize": size,
            "outputSize": len(reconstructed),
            "declaredOutputSize": None,
        })
        cursor = 0
        for index, volume in enumerate(
                getattr(obj, "section_objects", []) or []):
            self.walk(volume, child, cursor,
                      child.key + "/" + _index_label(volume, index),
                      PRESERVED, depth + 1)
            cursor += object_size(volume)
        if cursor < len(reconstructed):
            self._gap(child, reconstructed, cursor, len(reconstructed),
                      child.key, "reconstructed PFS bytes after the last "
                      "volume were not parsed", base=0)

    def _walk_flash_descriptor(self, obj, space, base, path, depth):
        '''Walk the descriptor and the flash regions it defines.

        Regions are subranges of the same input, so each is a child space.
        A region may overlap the descriptor or another region, in which case
        its bytes stay in its own space instead of being merged into the
        input. The descriptor header is interpreted; region bodies are then
        summarized from their parsed sections.
        '''
        from .flash import DescriptorMap, RegionSection, MasterSection
        data = getattr(obj, "data", b"") or b""
        size = len(data)
        if size == 0:
            return
        descriptor_size = min(
            20 + DescriptorMap.size + RegionSection.size +
            MasterSection.size, size)
        space.add(base, base + descriptor_size, PARSED, path,
                  "flash descriptor header", header=True)
        if descriptor_size < size:
            space.add(base + descriptor_size, base + size, PRESERVED, path,
                      "flash image bytes outside the descriptor")

        for index, region in enumerate(getattr(obj, "regions", []) or []):
            region_data = getattr(region, "data", b"") or b""
            if not region_data:
                continue
            name = getattr(region, "name", None) or str(index)
            offset = getattr(region, "base", None)
            child = self.space(
                path + "/region-%s" % name, len(region_data),
                parent=space.key, transform="flash-region:%s" % name)
            self.transformations.append({
                "path": path,
                "from": space.key,
                "to": child.key,
                "kind": "flash-region:%s" % name,
                "inputOffset": offset,
                "inputSize": len(region_data),
                "outputSize": len(region_data),
            })
            self._walk_stacked(
                getattr(region, "sections", []) or [], child, 0,
                child.key, depth + 1)

    def _walk_generic(self, obj, space, base, path):
        '''A format this summary does not model.

        Its bytes are recorded as retained evidence, never as parsed, so a
        container the walker does not understand cannot make the result
        look complete.
        '''
        size = object_size(obj)
        if not size:
            return
        if getattr(obj, "process_status", None) is False:
            space.add(base, base + size, FAILED, path,
                      "%s could not be parsed" % type(obj).__name__,
                      retained=size)
        else:
            space.add(base, base + size, PRESERVED, path,
                      "%s content was not examined by the coverage summary"
                      % type(obj).__name__, retained=size)

    # -- helpers -----------------------------------------------------------

    def _gap(self, space, data, start, end, path, reason, base=0,
             alignment=4):
        '''Classify bytes that no region claimed.

        start and end are relative to data, whose first byte sits at base in
        space. Erased bytes and gaps shorter than one aligned structure are
        padding; anything else is unexplained.
        '''
        if not data:
            return
        start = max(int(start), 0)
        end = min(int(end), len(data))
        if end <= start:
            return
        for gap_start, gap_end in space.unclaimed(base + start, base + end):
            first = gap_start - base
            last = gap_end - base
            chunk = bytes(data[first:last])
            if _is_erased(chunk):
                kind, label = PADDING, "erased bytes"
            elif last - first < alignment:
                kind, label = PADDING, "alignment bytes"
            else:
                kind, label = UNKNOWN, reason
            space.add(gap_start, gap_end, kind, path, label)


def _is_erased(data):
    from .utils import is_erased
    return is_erased(data)


def object_size(obj):
    '''Return the number of input bytes an object covers.

    Some containers overclaim in their header (a truncated volume), while
    some (a capsule followed by another object) hold more data than they
    own, so the specific classes are handled first.
    '''
    from .base import RawObject
    from . import uefi
    from . import MultiObject

    if isinstance(obj, uefi.FirmwareVolume):
        return len(getattr(obj, "_data", b"") or b"")
    if isinstance(obj, uefi.FirmwareCapsule):
        data = getattr(obj, "_data", b"") or b""
        size = getattr(obj, "size", None)
        return min(size, len(data)) if isinstance(size, int) and data else \
            (len(data) or (size or 0))
    if isinstance(obj, MultiObject):
        return sum(object_size(child) for child in obj.objects)
    if isinstance(obj, uefi.MultiVolumeContainer):
        return getattr(obj, "size", 0) or 0
    data = getattr(obj, "_data", None)
    if data is not None and hasattr(data, "__len__"):
        return len(data)
    size = getattr(obj, "size", None)
    if isinstance(size, int):
        return size
    data = getattr(obj, "data", None)
    if data is not None and hasattr(data, "__len__"):
        return len(data)
    return 0


def _root_size(obj):
    size = object_size(obj)
    if size:
        return size
    return sum(object_size(child) for child in
               (getattr(obj, "objects", []) or []))


def _index_label(obj, index):
    from .base import PaddingObject
    if isinstance(obj, PaddingObject):
        return "padding-%d" % index
    name = getattr(obj, "name", None)
    if isinstance(name, str) and name:
        return "%s-%s" % (type(obj).__name__.lower(), name)
    guid = getattr(obj, "guid", None)
    if guid:
        from .utils import sguid
        text = sguid(guid)
        if text:
            return "%s-%s" % (type(obj).__name__.lower(), text)
    return "%s-%d" % (type(obj).__name__.lower(), index)


label = _index_label


def build_coverage(root):
    '''Walk root and return a JSON-ready coverage summary.'''
    walker = _Walker()
    input_space = walker.space("input", _root_size(root))
    walker.walk(root, input_space, 0, "root")

    spaces = {}
    unresolved = []
    unverified = []
    preserved_regions = 0
    for key in walker.order:
        space = walker.spaces[key]
        space.finalize()
        spaces[key] = space.as_dict()
        for region in space.regions:
            item = dict(region, space=key)
            if region["kind"] in _BAD:
                unresolved.append(item)
            elif region["kind"] == PRESERVED:
                unverified.append(item)
                preserved_regions += 1

    # Counts stay per space; these only decide the categorical status.
    body_parsed = sum(entry["counts"]["bodyParsed"]
                      for entry in spaces.values())

    # complete: every non-padding byte was verified, with no region kept
    # verbatim. partial: something is still unknown, failed or preserved,
    # but at least one byte of body content was interpreted. header-only:
    # the same, but nothing beyond headers was interpreted. A parent whose
    # process() returned True is never enough on its own for "complete".
    if not unresolved and not preserved_regions:
        status = "complete"
    elif body_parsed > 0:
        status = "partial"
    else:
        status = "header-only"

    return {
        "status": status,
        "complete": status == "complete",
        "root": "input",
        "spaces": spaces,
        "spaceOrder": walker.order,
        "transformations": walker.transformations,
        "unresolved": unresolved,
        "unverified": unverified,
        "warnings": walker.warnings,
        "counts": {
            "spaces": len(spaces),
            "transformations": len(walker.transformations),
            "unresolved": len(unresolved),
            "unverified": len(unverified),
        },
    }

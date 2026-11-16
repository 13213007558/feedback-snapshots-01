import math
import os
from collections.abc import Iterable
from struct import calcsize, pack, unpack
from typing import BinaryIO, ClassVar, cast

from pdfminer.pdfexceptions import PDFValueError

# segment structure base
SEG_STRUCT = [
    (">L", "number"),
    (">B", "flags"),
    (">B", "retention_flags"),
    (">B", "page_assoc"),
    (">L", "data_length"),
]

# segment header literals
HEADER_FLAG_DEFERRED = 0b10000000
HEADER_FLAG_PAGE_ASSOC_LONG = 0b01000000

SEG_TYPE_MASK = 0b00111111

REF_COUNT_SHORT_MASK = 0b11100000
REF_COUNT_LONG_MASK = 0x1FFFFFFF
REF_COUNT_LONG = 7

DATA_LEN_UNKNOWN = 0xFFFFFFFF

# segment types
SEG_TYPE_IMMEDIATE_GEN_REGION = 38
SEG_TYPE_END_OF_PAGE = 49
SEG_TYPE_END_OF_FILE = 51

# file literals
FILE_HEADER_ID = b"\x97\x4a\x42\x32\x0d\x0a\x1a\x0a"
FILE_HEAD_FLAG_SEQUENTIAL = 0b00000001


def bit_set(bit_pos: int, value: int) -> bool:
    return bool((value >> bit_pos) & 1)


def check_flag(flag: int, value: int) -> bool:
    return bool(flag & value)


def masked_value(mask: int, value: int) -> int:
    for bit_pos in range(31):
        if bit_set(bit_pos, mask):
            return (value & mask) >> bit_pos

    raise PDFValueError("Invalid mask or value")


def mask_value(mask: int, value: int) -> int:
    for bit_pos in range(31):
        if bit_set(bit_pos, mask):
            return (value & (mask >> bit_pos)) << bit_pos

    raise PDFValueError("Invalid mask or value")


def unpack_int(format: str, buffer: bytes) -> int:
    assert format in {">B", ">H", ">I", ">L"}
    [result] = cast(tuple[int], unpack(format, buffer))
    return result


JBIG2SegmentFlags = dict[str, int | bool]
JBIG2RetentionFlags = dict[str, int | list[int] | list[bool]]
JBIG2Segment = dict[
    str,
    bool | int | bytes | JBIG2SegmentFlags | JBIG2RetentionFlags,
]


class JBIG2StreamReader:
    """Read segments from a JBIG2 byte stream"""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    def get_segments(self) -> list[JBIG2Segment]:
        segments: list[JBIG2Segment] = []
        seen_numbers: set[int] = set()
        while not self.is_eof():
            segment: JBIG2Segment = {}
            for field_format, name in SEG_STRUCT:
                field_len = calcsize(field_format)
                field = self.stream.read(field_len)
                if len(field) < field_len:
                    seg_num = segment.get("number", "unknown")
                    if not isinstance(seg_num, int):
                        seg_num = "unknown"
                    raise PDFValueError(
                        f"Truncated JBIG2 segment header: expected {field_len}"
                        f" bytes for field {name!r} of segment {seg_num},"
                        f" got {len(field)}",
                    )
                value = unpack_int(field_format, field)
                parser = getattr(self, f"parse_{name}", None)
                if callable(parser):
                    value = parser(segment, value, field)
                segment[name] = value

            seg_num = cast(int, segment["number"])
            if seg_num in seen_numbers:
                raise PDFValueError(f"Duplicate JBIG2 segment number {seg_num}")
            seen_numbers.add(seg_num)
            segments.append(segment)
        return segments

    def is_eof(self) -> bool:
        if self.stream.read(1) == b"":
            return True
        else:
            self.stream.seek(-1, os.SEEK_CUR)
            return False

    def parse_flags(
        self,
        segment: JBIG2Segment,
        flags: int,
        field: bytes,
    ) -> JBIG2SegmentFlags:
        return {
            "deferred": check_flag(HEADER_FLAG_DEFERRED, flags),
            "page_assoc_long": check_flag(HEADER_FLAG_PAGE_ASSOC_LONG, flags),
            "type": masked_value(SEG_TYPE_MASK, flags),
        }

    def parse_retention_flags(
        self,
        segment: JBIG2Segment,
        flags: int,
        field: bytes,
    ) -> JBIG2RetentionFlags:
        ref_count = masked_value(REF_COUNT_SHORT_MASK, flags)
        retain_segments = []
        ref_segments = []

        if ref_count < REF_COUNT_LONG:
            for bit_pos in range(5):
                retain_segments.append(bit_set(bit_pos, flags))
        else:
            field += self.read_exact(3, segment, "referred-to segment count")
            ref_count = unpack_int(">L", field)
            ref_count = masked_value(REF_COUNT_LONG_MASK, ref_count)
            ret_bytes_count = math.ceil((ref_count + 1) / 8)
            for _ret_byte_index in range(ret_bytes_count):
                ret_byte = unpack_int(
                    ">B",
                    self.read_exact(1, segment, "retention flags"),
                )
                for bit_pos in range(8):
                    retain_segments.append(bit_set(bit_pos, ret_byte))

        seg_num = segment["number"]
        assert isinstance(seg_num, int)
        if seg_num <= 256:
            ref_format = ">B"
        elif seg_num <= 65536:
            ref_format = ">H"
        else:
            ref_format = ">L"

        ref_size = calcsize(ref_format)

        for _ref_index in range(ref_count):
            ref_data = self.read_exact(ref_size, segment, "referred-to segment table")
            ref = unpack_int(ref_format, ref_data)
            ref_segments.append(ref)

        return {
            "ref_count": ref_count,
            "retain_segments": retain_segments,
            "ref_segments": ref_segments,
        }

    def read_exact(
        self,
        size: int,
        segment: JBIG2Segment,
        field_name: str,
    ) -> bytes:
        data = self.stream.read(size)
        if len(data) < size:
            seg_num = segment.get("number", "unknown")
            if not isinstance(seg_num, int):
                seg_num = "unknown"
            raise PDFValueError(
                f"Truncated JBIG2 segment {seg_num}: expected {size} bytes"
                f" for {field_name}, got {len(data)}",
            )
        return data

    def parse_page_assoc(self, segment: JBIG2Segment, page: int, field: bytes) -> int:
        if cast(JBIG2SegmentFlags, segment["flags"])["page_assoc_long"]:
            field += self.read_exact(3, segment, "page association")
            page = unpack_int(">L", field)
        return page

    def parse_data_length(
        self,
        segment: JBIG2Segment,
        length: int,
        field: bytes,
    ) -> int:
        if length:
            if (
                cast(JBIG2SegmentFlags, segment["flags"])["type"]
                == SEG_TYPE_IMMEDIATE_GEN_REGION
            ) and (length == DATA_LEN_UNKNOWN):
                raise NotImplementedError(
                    "Working with unknown segment length is not implemented yet",
                )
            else:
                segment["raw_data"] = self.read_exact(
                    length,
                    segment,
                    "segment data",
                )

        return length


class JBIG2StreamWriter:
    """Write JBIG2 segments to a file in JBIG2 format"""

    EMPTY_RETENTION_FLAGS: ClassVar[JBIG2RetentionFlags] = {
        "ref_count": 0,
        "ref_segments": cast(list[int], []),
        "retain_segments": cast(list[bool], []),
    }

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    def write_segments(
        self,
        segments: Iterable[JBIG2Segment],
        fix_last_page: bool = True,
    ) -> int:
        segments = list(segments)
        self.check_segment_dependencies(segments)

        data_len = 0
        current_page: int | None = None
        seg_num: int | None = None

        for segment in segments:
            data = self.encode_segment(segment)
            self.stream.write(data)
            data_len += len(data)

            seg_num = cast(int | None, segment["number"])

            if fix_last_page:
                seg_page = cast(int, segment.get("page_assoc"))

                if (
                    cast(JBIG2SegmentFlags, segment["flags"])["type"]
                    == SEG_TYPE_END_OF_PAGE
                ):
                    current_page = None
                elif seg_page:
                    current_page = seg_page

        if fix_last_page and current_page and (seg_num is not None):
            segment = self.get_eop_segment(seg_num + 1, current_page)
            data = self.encode_segment(segment)
            self.stream.write(data)
            data_len += len(data)

        return data_len

    def write_file(
        self,
        segments: Iterable[JBIG2Segment],
        fix_last_page: bool = True,
    ) -> int:
        header = FILE_HEADER_ID
        header_flags = FILE_HEAD_FLAG_SEQUENTIAL
        header += pack(">B", header_flags)
        # The embedded JBIG2 files in a PDF always
        # only have one page
        number_of_pages = pack(">L", 1)
        header += number_of_pages
        self.stream.write(header)
        data_len = len(header)

        data_len += self.write_segments(segments, fix_last_page)

        seg_num = 0
        for segment in segments:
            seg_num = cast(int, segment["number"])

        seg_num_offset = 2 if fix_last_page else 1
        eof_segment = self.get_eof_segment(seg_num + seg_num_offset)
        data = self.encode_segment(eof_segment)

        self.stream.write(data)
        data_len += len(data)

        return data_len

    def check_segment_dependencies(self, segments: list[JBIG2Segment]) -> None:
        """Ensure the segment list can be exported as a self-contained file.

        Every referred-to segment must be present and segment numbers must be
        unique, otherwise independent readers would silently render an
        incomplete image.
        """
        known_numbers: set[int] = set()
        for segment in segments:
            seg_num = cast(int, segment["number"])
            if seg_num in known_numbers:
                raise PDFValueError(f"Duplicate JBIG2 segment number {seg_num}")
            known_numbers.add(seg_num)

        for segment in segments:
            seg_num = cast(int, segment["number"])
            retention_flags = cast(
                JBIG2RetentionFlags,
                segment.get("retention_flags") or {},
            )
            ref_segments = cast(list[int], retention_flags.get("ref_segments") or [])
            for ref in ref_segments:
                if ref not in known_numbers:
                    raise PDFValueError(
                        f"JBIG2 segment {seg_num} refers to missing segment {ref}",
                    )

    def encode_segment(self, segment: JBIG2Segment) -> bytes:
        data = b""
        for field_format, name in SEG_STRUCT:
            value = segment.get(name)
            encoder = getattr(self, f"encode_{name}", None)
            if callable(encoder):
                field = encoder(value, segment)
            else:
                field = pack(field_format, value)
            data += field
        return data

    def encode_flags(self, value: JBIG2SegmentFlags, segment: JBIG2Segment) -> bytes:
        flags = 0
        if value.get("deferred"):
            flags |= HEADER_FLAG_DEFERRED

        if "page_assoc_long" in value:
            flags |= HEADER_FLAG_PAGE_ASSOC_LONG if value["page_assoc_long"] else flags
        else:
            flags |= (
                HEADER_FLAG_PAGE_ASSOC_LONG
                if cast(int, segment.get("page", 0)) > 255
                else flags
            )

        flags |= mask_value(SEG_TYPE_MASK, value["type"])

        return pack(">B", flags)

    def encode_retention_flags(
        self,
        value: JBIG2RetentionFlags,
        segment: JBIG2Segment,
    ) -> bytes:
        flags = []
        flags_format = ">B"
        ref_count = value["ref_count"]
        assert isinstance(ref_count, int)
        retain_segments = cast(list[bool], value.get("retain_segments", []))

        if ref_count <= 4:
            flags_byte = mask_value(REF_COUNT_SHORT_MASK, ref_count)
            for ref_index, ref_retain in enumerate(retain_segments):
                if ref_retain:
                    flags_byte |= 1 << ref_index
            flags.append(flags_byte)
        else:
            bytes_count = math.ceil((ref_count + 1) / 8)
            flags_format = ">L" + ("B" * bytes_count)
            flags_dword = (
                mask_value(REF_COUNT_SHORT_MASK, REF_COUNT_LONG) << 24
            ) | ref_count
            flags.append(flags_dword)

            for byte_index in range(bytes_count):
                ret_byte = 0
                ret_part = retain_segments[byte_index * 8 : byte_index * 8 + 8]
                for bit_pos, ret_seg in enumerate(ret_part):
                    ret_byte |= 1 << bit_pos if ret_seg else ret_byte

                flags.append(ret_byte)

        ref_segments = cast(list[int], value.get("ref_segments", []))

        seg_num = cast(int, segment["number"])
        if seg_num <= 256:
            ref_format = "B"
        elif seg_num <= 65536:
            ref_format = "H"
        else:
            ref_format = "L"

        for ref in ref_segments:
            flags_format += ref_format
            flags.append(ref)

        return pack(flags_format, *flags)

    def encode_data_length(self, value: int, segment: JBIG2Segment) -> bytes:
        data = pack(">L", value)
        data += cast(bytes, segment["raw_data"])
        return data

    def get_eop_segment(self, seg_number: int, page_number: int) -> JBIG2Segment:
        return {
            "data_length": 0,
            "flags": {"deferred": False, "type": SEG_TYPE_END_OF_PAGE},
            "number": seg_number,
            "page_assoc": page_number,
            "raw_data": b"",
            "retention_flags": JBIG2StreamWriter.EMPTY_RETENTION_FLAGS,
        }

    def get_eof_segment(self, seg_number: int) -> JBIG2Segment:
        return {
            "data_length": 0,
            "flags": {"deferred": False, "type": SEG_TYPE_END_OF_FILE},
            "number": seg_number,
            "page_assoc": 0,
            "raw_data": b"",
            "retention_flags": JBIG2StreamWriter.EMPTY_RETENTION_FLAGS,
        }

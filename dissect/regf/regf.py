from __future__ import annotations

import logging
import os
import struct
from bisect import bisect_right
from dataclasses import dataclass
from enum import IntFlag, auto
from functools import cached_property, lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO, TypeAlias

from dissect.util.ts import wintimestamp

from dissect.regf.c_regf import (
    KEY,
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_EXPAND_SZ,
    REG_FULL_RESOURCE_DESCRIPTOR,
    REG_MULTI_SZ,
    REG_NONE,
    REG_QWORD,
    REG_RESOURCE_REQUIREMENTS_LIST,
    REG_SZ,
    VALUE,
    c_regf,
)
from dissect.regf.exceptions import (
    Error,
    HiveIntegrityError,
    HiveStructureError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_REGF", "CRITICAL"))


CellType: TypeAlias = "IndexLeaf | FastLeaf | HashLeaf | IndexRoot | KeyNode | KeyValue"

STABLE = 0
VOLATILE = 1

REGISTRY_FILE_SIGNATURE = 0x66676572  # "regf"
HBIN_SIGNATURE = 0x6E696268  # "hbin"
HBIN_ALIGNMENT = 0x1000


class HiveState(IntFlag):
    """Independent integrity conditions that may be present at the same time.

    These flags are not mutually exclusive: a hive can be dirty, mid-transaction
    and structurally out of bounds at the same time. ``HiveState.OK`` is only
    present when no other flag is set.
    """

    OK = 0
    CHECKSUM_MISMATCH = auto()
    IN_TRANSACTION = auto()
    STRUCTURE_OUT_OF_BOUNDS = auto()


@dataclass(frozen=True)
class HiveIntegrity:
    """Detailed result of the integrity checks performed when opening a hive."""

    filename: str
    state: HiveState
    checksum_expected: int
    checksum_actual: int
    sequence1: int
    sequence2: int
    hbin_ranges: tuple[tuple[int, int], ...]
    structure_errors: tuple[str, ...]

    @property
    def checksum_ok(self) -> bool:
        return self.checksum_expected == self.checksum_actual

    @property
    def sequences_match(self) -> bool:
        return self.sequence1 == self.sequence2

    @property
    def structure_ok(self) -> bool:
        return not self.structure_errors

    @property
    def ok(self) -> bool:
        return self.state == HiveState.OK

    def summary(self) -> str:
        """Return a stable, log-friendly description of every condition present."""
        if self.ok:
            return "integrity OK (checksum matches, sequences match, structure in bounds)"

        reasons = []
        if self.state & HiveState.CHECKSUM_MISMATCH:
            reasons.append(
                f"checksum mismatch (stored 0x{self.checksum_expected:08x}, computed 0x{self.checksum_actual:08x})"
            )
        if self.state & HiveState.IN_TRANSACTION:
            reasons.append(f"transaction in progress (Sequence1 {self.sequence1} != Sequence2 {self.sequence2})")
        if self.state & HiveState.STRUCTURE_OUT_OF_BOUNDS:
            reasons.append("structure out of bounds (" + "; ".join(self.structure_errors) + ")")

        return ", ".join(reasons)


class RegistryHive:
    def __init__(self, fh: BinaryIO, strict: bool = False):
        """Open a registry hive.

        By default the hive is opened leniently: checksum, sequence and structure
        problems are recorded in :attr:`integrity` (and logged individually) but
        do not prevent reading. With ``strict=True`` any failed check raises
        :class:`~dissect.regf.exceptions.HiveIntegrityError` before any cells are
        parsed.
        """
        self.fh = fh
        self.strict = strict

        self.fh.seek(0, os.SEEK_END)
        self._file_size = self.fh.tell()
        self.fh.seek(0)
        data = self.fh.read(len(c_regf._HBASE_BLOCK))
        if len(data) < len(c_regf._HBASE_BLOCK):
            raise Error(f"Hive header truncated: expected {len(c_regf._HBASE_BLOCK)} bytes, got {len(data)}")

        self.header = c_regf._HBASE_BLOCK(data)
        self.version = self.header.Minor
        self.filename = self.header.FileName.rstrip("\x00")

        self._hbin_offset = len(c_regf._HBASE_BLOCK)
        self._hbin_ranges, self._hbin_errors = self._scan_hbins()
        self._hbin_starts = [bin_offset for bin_offset, _ in self._hbin_ranges]
        self.integrity = self._check_integrity(data)
        self.state = self.integrity.state

        self._log_integrity()

        if strict and not self.integrity.ok:
            raise HiveIntegrityError(self.integrity)

        root_error = self._cell_bounds_error(self.header.RootCell)
        if root_error is not None:
            self._root = None
            log.error("Hive %r root cell 0x%x cannot be read: %s", self.filename, self.header.RootCell, root_error)
        else:
            self._root = self.cell(self.header.RootCell)

        self.cell = lru_cache(4096)(self.cell)

    @property
    def dirty(self) -> bool:
        """Whether the header checksum failed (kept for backwards compatibility)."""
        return bool(self.state & HiveState.CHECKSUM_MISMATCH)

    @property
    def in_transaction(self) -> bool:
        """Whether Sequence1 and Sequence2 disagree (kept for backwards compatibility)."""
        return bool(self.state & HiveState.IN_TRANSACTION)

    def _log_integrity(self) -> None:
        if self.integrity.checksum_ok:
            log.debug("Hive %r checksum OK", self.filename)
        else:
            log.warning(
                "Hive %r header checksum mismatch: stored 0x%08x, computed 0x%08x, may not be able to read "
                "keys and values properly",
                self.filename,
                self.integrity.checksum_expected,
                self.integrity.checksum_actual,
            )

        if self.integrity.sequences_match:
            log.debug("Hive %r is not undergoing any transactions", self.filename)
        else:
            log.warning(
                "Hive %r has an unfinished transaction: Sequence1 %d != Sequence2 %d, may not be able to read "
                "keys and values properly",
                self.filename,
                self.integrity.sequence1,
                self.integrity.sequence2,
            )

        for error in self.integrity.structure_errors:
            log.warning("Hive %r structure out of bounds: %s", self.filename, error)

        if self.integrity.ok:
            log.debug("Hive %r integrity OK", self.filename)
        else:
            log.info("Hive %r integrity state: %s", self.filename, self.integrity.summary())

    def _scan_hbins(self) -> tuple[list[tuple[int, int]], list[str]]:
        """Walk the hbin chain bounded by the header Length and the file size.

        Returns the accepted ``(offset, size)`` ranges and a list of structural
        errors encountered while walking the chain.
        """
        ranges = []
        errors = []

        declared_end = self._hbin_offset + self.header.Length
        end = min(declared_end, self._file_size)
        offset = self._hbin_offset

        while offset + len(c_regf._HBIN) <= end:
            self.fh.seek(offset)
            header = c_regf._HBIN(self.fh)
            if header.Signature != HBIN_SIGNATURE:
                errors.append(f"hbin at 0x{offset:x} has invalid signature 0x{header.Signature:08x}")
                break
            if header.Size == 0:
                errors.append(f"hbin at 0x{offset:x} has size zero")
                break
            if header.Size % HBIN_ALIGNMENT:
                errors.append(f"hbin at 0x{offset:x} has unaligned size 0x{header.Size:x}")
                break
            if offset + header.Size > end:
                errors.append(
                    f"hbin at 0x{offset:x} extends to 0x{offset + header.Size:x}, "
                    f"beyond the declared hive end 0x{declared_end:x}"
                )
                ranges.append((offset, header.Size))
                break

            ranges.append((offset, header.Size))
            offset += header.Size

        return ranges, errors

    def _check_integrity(self, data: bytes) -> HiveIntegrity:
        checksum_actual = xor32_crc(data[:508])
        structure_errors = list(self._hbin_errors)

        expected_end = self._hbin_offset + self.header.Length
        if self.header.Signature != REGISTRY_FILE_SIGNATURE:
            structure_errors.append(
                f"header signature is 0x{self.header.Signature:08x}, expected 0x{REGISTRY_FILE_SIGNATURE:08x}"
            )
        if self.header.Length == 0:
            structure_errors.append("header Length is zero")
        elif self.header.Length % HBIN_ALIGNMENT:
            structure_errors.append(f"header Length 0x{self.header.Length:x} is not aligned to 0x{HBIN_ALIGNMENT:x}")
        if expected_end > self._file_size:
            structure_errors.append(f"header Length ends at 0x{expected_end:x}, beyond file size 0x{self._file_size:x}")
        if expected_end < self._file_size and self.header.Length and not self.header.Length % HBIN_ALIGNMENT:
            # Slack beyond the declared hive length is normal (cluster alignment).
            log.debug(
                "Hive %r is followed by 0x%x bytes outside the declared hive length",
                self.filename,
                self._file_size - expected_end,
            )

        if not self._hbin_ranges:
            if not self._hbin_errors:
                structure_errors.append(f"no hbin found at 0x{self._hbin_offset:x}")
        else:
            offset = self._hbin_offset
            for bin_offset, bin_size in self._hbin_ranges:
                if bin_offset != offset:
                    structure_errors.append(f"hbin at 0x{offset:x} missing; next hbin found at 0x{bin_offset:x}")
                    break
                offset += bin_size

            last_offset, last_size = self._hbin_ranges[-1]
            if last_offset + last_size != expected_end and not self._hbin_errors:
                structure_errors.append(
                    f"hbin chain ends at 0x{last_offset + last_size:x}, header Length ends at 0x{expected_end:x}"
                )

        if (root_error := self._cell_bounds_error(self.header.RootCell)) is not None:
            structure_errors.append(f"root cell 0x{self.header.RootCell:x}: {root_error}")

        state = HiveState.OK
        if checksum_actual != self.header.CheckSum:
            state |= HiveState.CHECKSUM_MISMATCH
        if self.header.Sequence1 != self.header.Sequence2:
            state |= HiveState.IN_TRANSACTION
        if structure_errors:
            state |= HiveState.STRUCTURE_OUT_OF_BOUNDS

        return HiveIntegrity(
            filename=self.filename,
            state=state,
            checksum_expected=self.header.CheckSum,
            checksum_actual=checksum_actual,
            sequence1=self.header.Sequence1,
            sequence2=self.header.Sequence2,
            hbin_ranges=tuple(self._hbin_ranges),
            structure_errors=tuple(structure_errors),
        )

    def _cell_bounds_error(self, offset: int) -> str | None:
        """Return why ``offset`` does not address a complete cell inside a known hbin."""
        if offset < 0 or offset >= self.header.Length:
            return "offset outside the declared hive length"

        absolute = self._hbin_offset + offset
        idx = bisect_right(self._hbin_starts, absolute) - 1
        if idx < 0:
            return "offset before the first hbin"

        bin_offset, bin_size = self._hbin_ranges[idx]
        bin_end = min(bin_offset + bin_size, self._file_size)
        if absolute + 4 > bin_end:
            return f"offset is outside hbin 0x{bin_offset - self._hbin_offset:x}+0x{bin_size:x}"
        if absolute < bin_offset + len(c_regf._HBIN):
            return "offset inside the hbin header"

        self.fh.seek(absolute)
        raw_size = self.fh.read(4)
        if len(raw_size) < 4:
            return "cell size unreadable"

        size = struct.unpack("<i", raw_size)[0]
        size = -size if size < 0 else size
        if size < 4:
            return f"invalid cell size {size}"
        if absolute + size > bin_end:
            return (
                f"cell of size 0x{size:x} at 0x{offset:x} crosses the end of hbin "
                f"0x{bin_offset - self._hbin_offset:x}+0x{bin_size:x}"
            )

        return None

    def _check_cell_offset(self, offset: int) -> bool:
        """Validate a cell offset, raising in strict mode and logging otherwise."""
        error = self._cell_bounds_error(offset)
        if error is None:
            return True

        if self.strict:
            raise HiveStructureError(f"Cell at 0x{offset:x} is out of bounds: {error}")

        log.warning("Hive %r cell at 0x%x is out of bounds: %s", self.filename, offset, error)
        return False

    def root(self) -> KeyNode:
        if self._root is None:
            raise HiveStructureError(
                f"Root cell 0x{self.header.RootCell:x} of hive {self.filename!r} is out of bounds: "
                + (self._cell_bounds_error(self.header.RootCell) or "unknown")
            )
        return self._root

    def cell(self, offset: int) -> CellType:
        data = self.cell_data(offset)
        if not data:
            raise HiveStructureError(
                f"Cell at 0x{offset:x} of hive {self.filename!r} could not be read: "
                + (self._cell_bounds_error(offset) or "empty cell")
            )
        return self.parse_cell_data(data)

    def _cell_data(self, offset: int, *, validate: bool = True, limit: int | None = None) -> tuple[bool, bytes]:
        if validate and not self._check_cell_offset(offset):
            return False, b""

        absolute = self._hbin_offset + offset
        self.fh.seek(absolute)

        allocated = False
        raw_size = self.fh.read(4)
        if len(raw_size) < 4:
            return allocated, b""

        size = struct.unpack("<i", raw_size)[0]
        if size < 0:
            size = -size
            allocated = True

        if size < 4:
            return allocated, b""

        end = self._file_size if limit is None else min(limit, self._file_size)
        size = min(size, max(end - absolute, 4))
        return allocated, self.fh.read(size - 4)

    def cell_data(self, offset: int) -> bytes:
        _, data = self._cell_data(offset)
        return data

    def parse_cell_data(self, data: bytes) -> CellType:
        sig = data[:2]

        if cls := _CELL_CLASSES.get(sig):
            return cls(self, data)

        raise NotImplementedError(repr(sig))

    def open(self, path: str) -> CellType:
        path = path.strip("\\")
        parts = path.split("\\") if path else []

        realpath = []
        node = self._root
        for part in parts:
            subkey = node.subkey(part)
            realpath.append(subkey.name)

            node = subkey

        return node

    def walk(self) -> Iterator[tuple[int, bool, CellType | bytes]]:
        """Iterate over all cells in the hive, following the validated hbin chain.

        Iteration stops at the end of the declared hive length or when a hbin
        cannot be advanced over, so a corrupt size can never loop forever.
        """
        for bin_offset, bin_size in self._hbin_ranges:
            bin_end = min(bin_offset + bin_size, self._file_size)
            offset = bin_offset + len(c_regf._HBIN)

            while offset < bin_end:
                allocated, data = self._cell_data(offset - self._hbin_offset, validate=False, limit=bin_end)
                if not data:
                    log.warning(
                        "Hive %r cell at 0x%x is truncated, stopping walk of this hbin",
                        self.filename,
                        offset,
                    )
                    break

                cell = _CELL_CLASSES.get(data[:2], lambda hive, buf: buf)(self, data)

                yield offset, allocated, cell
                offset += 4 + len(data)


class Cell:
    __signature__ = b""
    __struct__ = None

    def __init__(self, hive: RegistryHive, data: bytes, strict: bool = True):
        self.hive = hive

        if data[:2] != self.__signature__:
            raise Error(f"Invalid {self.__class__.__name__} signature {data[:2]!r}, expected {self.__signature__!r}")

        self.cell = self.__struct__(data)


class KeyNode(Cell):
    __signature__ = b"nk"
    __struct__ = c_regf._CM_KEY_NODE

    def __init__(self, hive: RegistryHive, data: bytes):
        super().__init__(hive, data)
        self._cache = {}

        self.class_name = None
        if (class_idx := self.cell.Class) != 0xFFFFFFFF:
            self.class_name = self.hive.cell_data(class_idx)[: self.cell.ClassLength].decode("utf-16-le")

        name_length = self.cell.NameLength
        name_blob = data[len(self.__struct__) :][:name_length]
        self.name = decode_name(name_blob, name_length, KEY.COMP_NAME in self.cell.Flags)

    def __repr__(self) -> str:
        return f"<KeyNode {self.name}>"

    @cached_property
    def timestamp(self) -> datetime:
        return wintimestamp(self.cell.LastWriteTime)

    @property
    def path(self) -> str:
        # As long as we are not the ROOT key, we add our name to the stack.
        #
        # The path is relative to the hive of this key. Adding a name for the
        # ROOT key will lead to issues when this hive is mapped on a subkey of
        # another hive. The full path to this key is constructed using both the
        # path of the subkey in the other hive and this key's path.
        #
        # If ROOT would be part of that path, that part (and thus the whole
        # path) would not be accesible, nor is the presence of the ROOT part in
        # the path expected by the user (it is never visible in e.g. regedit).
        parts = []

        current = self
        parent = self.hive.cell(current.cell.Parent) if KEY.HIVE_ENTRY not in current.cell.Flags else None
        while parent is not None:
            parts.append(current.name)
            current = parent
            parent = self.hive.cell(current.cell.Parent) if KEY.HIVE_ENTRY not in current.cell.Flags else None

        return "\\".join(list(reversed(parts)))

    @cached_property
    def _subkey_list(self) -> IndexLeaf | FastLeaf | HashLeaf | IndexRoot | None:
        num_sk = self.cell.SubKeyCounts[STABLE]
        if not num_sk:
            return None

        subkey_list: KeyIndex = self.hive.cell(self.cell.SubKeyLists[STABLE])
        if num_sk != subkey_list.count:
            log.debug(
                "KeyNode %s has %d subkeys, while the %s has %d elements",
                self.name,
                num_sk,
                subkey_list.__class__.__name__,
                subkey_list.count,
            )

        return subkey_list

    def subkeys(self) -> Iterator[KeyNode]:
        if self._subkey_list:
            yield from self._subkey_list

    def subkey(self, name: str) -> KeyNode:
        lname = name.lower()

        try:
            return self._cache[lname]
        except KeyError:
            pass

        if self._subkey_list and (sk := self._subkey_list.subkey(name)):
            self._cache[lname] = sk
            return sk

        raise RegistryKeyNotFoundError(name)

    def values(self) -> Iterator[KeyValue]:
        if num_values := self.cell.ValueList.Count:
            data = self.hive.cell_data(self.cell.ValueList.List)

            # Possible slack values
            if len(data) // 4 < num_values:
                num_values = len(data) // 4
                bytes_short = num_values * 4 - len(data)
                if bytes_short:
                    log.debug(
                        "Value list of key %r is %d bytes short reading %d values instead of %d, "
                        "the difference could be due to slack values",
                        self.name,
                        bytes_short,
                        num_values,
                        num_values,
                    )

            yield from ValueList(self.hive, data, num_values)

    def value(self, name: str) -> KeyValue:
        for value in self.values():
            if value.name.lower() == name.lower():
                return value

        raise RegistryValueNotFoundError(name)


class ValueList:
    def __init__(self, hive: RegistryHive, data: bytes, count: int):
        self.hive = hive
        self._values = c_regf.int32[count](data)

    def __iter__(self) -> Iterator[KeyValue]:
        for entry in self._values:
            if entry <= 2:
                continue

            data = self.hive.cell_data(entry)
            if data[:2] != KeyValue.__signature__:
                log.warning("Invalid cell signature %r at offset 0x%x", data[:2], entry)
                continue

            yield KeyValue(self.hive, data)


class KeyValue(Cell):
    __signature__ = b"vk"
    __struct__ = c_regf._CM_KEY_VALUE

    def __init__(self, hive: RegistryHive, data: bytes):
        super().__init__(hive, data)

        if (name_length := self.cell.NameLength) == 0:
            self.name = "(Default)"
        else:
            name_blob = data[len(self.__struct__) :][:name_length]
            self.name = decode_name(name_blob, name_length, VALUE.COMP_NAME in self.cell.Flags)

    def __repr__(self) -> str:
        return f"<KeyValue {self.name}={self.value!r}>"

    @cached_property
    def type(self) -> int:
        return self.cell.Type

    @cached_property
    def size(self) -> int:
        return self.cell.DataLength & ~0x80000000

    @cached_property
    def is_big_value(self) -> bool:
        # HSYS_WHISTLER_BETA1, CM_KEY_VALUE_SPECIAL_SIZE, CM_KEY_VALUE_BIG
        return self.hive.version > 4 and self.cell.DataLength < 0x80000000 and self.cell.DataLength > 0x3FD8

    @cached_property
    def data(self) -> bytes:
        data_size = self.size
        if self.cell.DataLength & 0x80000000:
            return struct.pack("<I", self.cell.Data)[:data_size]

        if self.is_big_value:
            bd = self.hive.cell(self.cell.Data)
            if not isinstance(bd, BigData):
                raise Error(f"Expected BigData, got {bd.__class__.__name__}")

            return bd.data[:data_size]

        return self.hive.cell_data(self.cell.Data)[:data_size]

    @cached_property
    def value(self) -> int | str | list[str] | bytes:
        return parse_value(self.type, self.data)


class KeyIndex(Cell):
    def __len__(self) -> int:
        raise NotImplementedError

    def __iter__(self) -> Iterator[KeyNode]:
        raise NotImplementedError

    @cached_property
    def count(self) -> int:
        raise NotImplementedError

    def subkey(self, name: str) -> KeyNode | None:
        raise NotImplementedError


class IndexRoot(KeyIndex):
    __signature__ = b"ri"
    __struct__ = c_regf._CM_KEY_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield from self.hive.cell(entry)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        for entry in self.cell.List:
            if sk := self.hive.cell(entry).subkey(name):
                return sk
        return None


class IndexLeaf(KeyIndex):
    __signature__ = b"li"
    __struct__ = c_regf._CM_KEY_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield self.hive.cell(entry)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        for entry in self.cell.List:
            if (sk := self.hive.cell(entry)).name == name:
                return sk
        return None


class HashLeaf(KeyIndex):
    __signature__ = b"lh"
    __struct__ = c_regf._CM_KEY_HASH_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield self.hive.cell(entry.Cell)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        name_hash = hashname(name)
        name = name.lower()

        for entry in self.cell.List:
            if name_hash == entry.HashKey and (sk := self.hive.cell(entry.Cell)).name.lower() == name:
                return sk

        return None


class FastLeaf(KeyIndex):
    __signature__ = b"lf"
    __struct__ = c_regf._CM_KEY_FAST_INDEX

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[KeyNode]:
        for entry in self.cell.List:
            yield self.hive.cell(entry.Cell)

    @cached_property
    def count(self) -> int:
        return self.cell.Count

    def subkey(self, name: str) -> KeyNode | None:
        name = name.lower()
        name_hint = name[:4]

        for entry in self.cell.List:
            # If names are < 4 characters, the name hint is padded with
            # 0-bytes, the characters are stored from the lowest byte number
            # up.
            # Note that names of keys are only supposed to contain "printable
            # characters except the `\' character", which probably is the
            # printable subset of ascii (MS documentation is inconclusive on
            # this).
            # For non-ASCII names name hint is filled with zeroes, for these cases
            # we need to fall back to regular name comparison
            hint = entry.NameHint.rstrip(b"\x00").decode("ascii").lower()
            if not hint or name_hint == hint:
                sk = self.hive.cell(entry.Cell)
                if sk.name.lower() == name:
                    return sk

        return None


class KeySecurity(Cell):
    __signature__ = b"sk"
    __struct__ = c_regf._CM_KEY_SECURITY


class BigData(Cell):
    __signature__ = b"db"
    __struct__ = c_regf._CM_BIG_DATA

    @property
    def data(self) -> bytes:
        parts = []
        segment_list = self.hive.cell_data(self.cell.List)
        for segment in c_regf.int32[self.cell.Count](segment_list):
            part = self.hive.cell_data(segment)
            parts.append(part[:16344])  # CM_KEY_VALUE_BIG

        return b"".join(parts)


_CELL_CLASSES = {
    KeyNode.__signature__: KeyNode,
    KeyValue.__signature__: KeyValue,
    IndexRoot.__signature__: IndexRoot,
    IndexLeaf.__signature__: IndexLeaf,
    FastLeaf.__signature__: FastLeaf,
    HashLeaf.__signature__: HashLeaf,
    KeySecurity.__signature__: KeySecurity,
    BigData.__signature__: BigData,
}


def decode_name(blob: bytes, size: int, is_comp_name: bool) -> str:
    if is_comp_name:
        try:
            return blob.decode()
        except UnicodeDecodeError:
            pass

        try:
            return blob.decode("latin1")
        except UnicodeDecodeError:
            pass
    else:
        try:
            return c_regf.wchar[size // 2](blob)
        except UnicodeDecodeError:
            pass

    return repr(blob)


def try_decode_sz(data: bytes) -> str:
    if not len(data):
        return ""

    try:
        if (data.isascii() or data.endswith(b"\x00")) and data[1:2] != b"\x00":
            # This will return the string latin1 decoded up until the first
            # NULL byte.
            return data.split(b"\x00")[0].decode("latin1")

        if len(data) % 2 != 0:
            data = data.ljust(len(data) + 1, b"\x00")

        # This will return the string utf-16-le decoded up until the first
        # double NULL byte.
        # A naive split on two NULL bytes will not work as the possibility
        # exists that the first NULL byte is the high byte of the first
        # character and the second NULL byte the low byte of the second
        # character. So the first NULL byte should start at an even index in
        # the data.
        idx = -1
        while (idx := data.find(b"\x00\x00", idx + 1)) & 1:
            if idx == -1:
                idx = len(data)
                break
        return data[:idx].decode("utf-16-le")

    except UnicodeDecodeError:
        # Last ditch effort, decode the whole bytestring as if it were utf-16,
        # any decoding errors, which incase of utf-16 will be invalid utf-16
        # surrogates, will be ignored.
        return data.decode("utf-16-le", "ignore").strip("\x00")


def parse_value(data_type: int, data: bytes) -> int | str | list[str] | bytes:
    if data_type in (REG_DWORD, REG_DWORD_BIG_ENDIAN):
        if len(data) == 0:
            return 0

        if data_type == REG_DWORD:
            return c_regf.uint32(data[:4])

        if data_type == REG_DWORD_BIG_ENDIAN:
            return struct.unpack(">I", data[:4])[0]

    if data_type == REG_QWORD:
        return c_regf.uint64(data) if len(data) else 0

    if data_type in (REG_SZ, REG_EXPAND_SZ):
        return try_decode_sz(data)

    if data_type in (REG_BINARY, REG_NONE):
        return data

    if data_type == REG_MULTI_SZ:
        data_len = len(data)
        data = BytesIO(data)

        multi_string = []
        while data.tell() < data_len:
            string = read_null_terminated_wstring(data)
            if string == "":
                break

            multi_string.append(string)

        return multi_string

    if data_type == REG_FULL_RESOURCE_DESCRIPTOR:
        log.warning("Unimplemented REG_FULL_RESOURCE_DESCRIPTOR")
        return data

    if data_type == REG_RESOURCE_REQUIREMENTS_LIST:
        log.warning("Unimplemented REG_RESOURCE_REQUIREMENTS_LIST")
        return data

    log.warning("Data type 0x%x not supported", data_type)
    return data


def read_null_terminated_wstring(stream: BinaryIO, encoding: str = "utf-16-le") -> str:
    """Adapted function to read null terminated wide strings.

    The cstruct way raises EOFError when the end of the stream is reached.
    This is fine, but not what we want for this particular implementation.
    """
    wide_string = b""
    while True:
        wide_char = stream.read(2)

        if len(wide_char) != 2 or wide_char == b"\x00\x00":
            break

        wide_string += wide_char

    return wide_string.decode(encoding)


def hashname(name: str) -> int:
    # Note that `name' is a python str(), which means the ord() used to
    # calculate name_hash works (it wouldn't for byte()).
    # Also note that names of keys are only supposed to contain "printable
    # characters except the `\' character", which probably is the printable
    # subset of ascii (MS documentation is inconclusive on this).
    name_hash = 0
    for char in name.upper():
        name_hash = (name_hash * 37 + ord(char)) & 0xFFFFFFFF

    return name_hash


def xor32_crc(data: bytes) -> int:
    crc = 0
    for ii in c_regf.uint32[len(data) // 4](data):
        crc ^= ii

    return crc

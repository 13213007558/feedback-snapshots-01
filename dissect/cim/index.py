from __future__ import annotations

import hashlib
import string
from functools import lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.cim.c_cim import (
    INDEX_PAGE_INVALID,
    INDEX_PAGE_INVALID2,
    INDEX_PAGE_SIZE,
    c_cim,
)
from dissect.cim.exceptions import ReferenceNotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.cim.cim import CIM
    from dissect.cim.mappings import Mapping

MAX_KEY_CHAR = chr(0x10FFFF)


class KeyPart(NamedTuple):
    """A single typed component of an index key."""

    tag: str
    value: str | None
    data: tuple[int, int, int] | None = None


@lru_cache(8192)
def parse_key(key: str) -> tuple[KeyPart, ...] | None:
    """Split an index key into its typed components.

    A key consists of one or more ``TAG_VALUE`` components separated by ``/``. A query may omit the value of its last
    component to denote a range (e.g. ``NS_.../CD`` for all class definitions in a namespace). The last component of a
    key may carry a data reference suffix (``.page.id.length``).
    """
    components = key.split("/")
    parts = []
    for idx, component in enumerate(components):
        tag, separator, value = component.partition("_")
        if not tag or not tag.isascii() or not tag.isalpha() or not tag.isupper():
            return None

        if not separator:
            parts.append(KeyPart(tag, None))
            continue

        if not value:
            return None

        data = None
        if "." in value:
            # A data reference suffix is only valid on the final component and consists of three uint32 fields.
            if idx != len(components) - 1:
                return None

            digest, _, suffix = value.partition(".")
            fields = suffix.split(".")
            if len(fields) != 3 or not all(field.isascii() and field.isdigit() for field in fields):
                return None
            if any(int(field) > 0xFFFFFFFF for field in fields):
                return None
            if not digest:
                return None

            value = digest
            data = tuple(int(field) for field in fields)

        parts.append(KeyPart(tag, value, data))

    return tuple(parts) if parts else None


def key_prefix(query: tuple[KeyPart, ...]) -> str:
    """Render the typed components of a query without its data reference suffix."""
    parts = [part.tag if part.value is None else f"{part.tag}_{part.value}" for part in query]
    return "/".join(parts)


class Index:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.store = Store(cim, fh, mapping)

        self._lookup = lru_cache(1024)(self._lookup)

    def lookup(self, key: Key) -> list[Key]:
        return self._lookup(str(key), self.store.root_page)

    def _lookup(self, key: str, page: IndexPage) -> list[Key]:
        query = parse_key(key)
        if query is None:
            return []

        # A complete data reference is an exact lookup, a namespace or class query is a range lookup. The range only
        # contains keys that are covered by the typed query components, so keys that merely share a textual prefix
        # (e.g. ``CI_AB`` vs ``CI_ABC``) or live in another namespace can never leak into the results.
        exact = query[-1].data is not None
        prefix = key_prefix(query)
        lower = key if exact else prefix
        upper = lower if exact else f"{prefix}{MAX_KEY_CHAR}"

        matches = []
        seen = set()
        for match in self._lookup_range(query, lower, upper, page):
            match_str = str(match)
            if match_str not in seen:
                seen.add(match_str)
                matches.append(match)

        return matches

    def _lookup_range(self, query: tuple[KeyPart, ...], lower: str, upper: str, page: IndexPage) -> Iterator[Key]:
        keys = [str(page.key(i)) for i in range(page.count)]

        for i in range(page.count + 1):
            # Child ``i`` holds the keys between separator ``i - 1`` and separator ``i``. The bounds are inclusive,
            # because a separator may be a copy of a key that is also present in the adjacent child. Anything outside
            # the requested range is rejected by ``_key_matches`` before it is returned.
            if i > 0 and keys[i - 1] > upper:
                break

            if (i == 0 or keys[i - 1] <= upper) and (i == page.count or keys[i] >= lower):
                child_idx = page.child(i)
                if child_idx not in (INDEX_PAGE_INVALID, INDEX_PAGE_INVALID2):
                    yield from self._lookup_range(query, lower, upper, self.store.page(child_idx))

            if i < page.count and lower <= keys[i] <= upper and _key_matches(query, keys[i]):
                yield page.key(i)


def _key_matches(query: tuple[KeyPart, ...], key: str) -> bool:
    """Check if ``key`` is covered by ``query``.

    Only complete, typed key components are compared, so a query for ``CI_AB`` never matches ``CI_ABC`` or a record
    in a different namespace that happens to contain ``CI_AB`` somewhere in its key.
    """
    key_parts = parse_key(key)
    if key_parts is None or len(key_parts) < len(query):
        return False

    for query_part, key_part in zip(query, key_parts):
        if query_part.tag != key_part.tag:
            return False
        if query_part.value is not None and query_part.value != key_part.value:
            return False

    if len(key_parts) == len(query):
        if query[-1].data is not None:
            # Exact data reference query, the suffix has to match as well.
            return key_parts[-1].data == query[-1].data

        return True

    # The key has additional components below the query. This is only valid if the query does not pin a data suffix.
    return query[-1].data is None


class Store:
    def __init__(self, cim: CIM, fh: BinaryIO, mapping: Mapping):
        self.cim = cim
        self.fh = fh
        self.map = mapping

        root_page_num = self.map.get_entry(0).used_space
        if root_page_num is None:
            root_page_num = self.page(0).page.root_page

        self.root_page = self.page(root_page_num)

    def page(self, logical_num: int) -> IndexPage:
        page_num = self.map.get_entry(logical_num).page_number
        buf = self.read_page(page_num)
        return IndexPage(self, buf, logical_num, page_num)

    def read_page(self, page_num: int) -> BytesIO:
        self.fh.seek(INDEX_PAGE_SIZE * page_num)
        return BytesIO(self.fh.read(INDEX_PAGE_SIZE))


class IndexPage:
    def __init__(self, store: Store, fh: BinaryIO, logical_num: int, page_num: int):
        self.store = store
        self.fh = fh
        self.logical_num = logical_num
        self.page_num = page_num

        start = fh.tell()
        self.page = c_cim.index_page(fh)
        self.data = fh.read(INDEX_PAGE_SIZE - (fh.tell() - start))

        self.count = self.page.record_count

        self.key = lru_cache(256)(self.key)

    def _string_part(self, idx: int) -> str:
        offset = self.page.string_table[idx]
        return self.data[offset : self.data.find(b"\x00", offset)].decode("utf8")

    def string(self, idx: int) -> str:
        parts = []
        part_count = self.page.string_definition_table[idx]

        for i in range(part_count):
            part_idx = self.page.string_definition_table[idx + 1 + i]
            parts.append(self._string_part(part_idx))

        return "/".join(parts)

    def key(self, idx: int) -> Key:
        str_idx = self.page.keys[idx]
        key_idx = self.string(str_idx)
        return Key(self.store.cim, key_idx)

    def keys(self) -> Iterator[Key]:
        for i in range(self.count):
            yield self.key(i)

    def child(self, idx: int) -> int:
        return self.page.children[idx]

    def children(self) -> list[int]:
        return self.page.children


class Key:
    def __init__(self, cim: CIM, *parts: str):
        self.cim = cim
        self.key = "/".join(parts).strip("/")

    def __repr__(self) -> str:
        return f"<Key {self.key}>"

    def __str__(self) -> str:
        return self.key

    def __getitem__(self, item: int) -> str:
        return self.parts()[item]

    def _hash(self, s: bytes) -> str:
        hash_object = hashlib.md5(s) if self.cim.type_xp else hashlib.sha256(s)
        return hash_object.hexdigest().upper()

    def _path(self, prefix: str, name: str | None = None) -> Key:
        if name is None:
            return Key(self.cim, self.key, prefix)

        if name.isupper() and all(c in string.hexdigits for c in name):
            digest = name
        else:
            digest = self._hash(name.upper().encode("utf-16-le"))

        return Key(self.cim, self.key, f"{prefix}_{digest}")

    def _data_part(self, idx: int) -> str:
        if not self.is_data_reference:
            raise ValueError(f"Key is not a data reference: {self}")

        return self.key.split(".")[idx]

    def parts(self) -> dict[str, str]:
        obj = {}
        for p in self.key.split("/"):
            prefix, digest = p.split("_")
            obj[prefix] = digest
        return obj

    def reference(self) -> Key | None:
        refs = self.references()
        if refs and len(refs) > 1:
            raise ValueError("Key returned more than one reference")
        return refs[0] if refs else None

    def references(self) -> list[Key]:
        return self.cim.index.lookup(self)

    def object(self) -> BytesIO:
        ref = self.reference()
        if not ref:
            raise ReferenceNotFoundError("Reference not found")
        return self.cim.objects.get(ref)

    def objects(self) -> Iterator[tuple[Key, BytesIO]]:
        for ref in self.references():
            yield ref, self.cim.objects.get(ref)

    @property
    def is_data_reference(self) -> bool:
        return "." in self.key

    @property
    def data_page(self) -> int:
        return int(self._data_part(1))

    @property
    def data_id(self) -> int:
        return int(self._data_part(2))

    @property
    def data_length(self) -> int:
        return int(self._data_part(3))

    def NS(self, name: str | None = None) -> Key:
        return self._path("NS", name)

    def CD(self, name: str | None = None) -> Key:
        return self._path("CD", name)

    def CI(self, name: str | None = None) -> Key:
        return self._path("CI", name)

    def IL(self, name: str | None = None) -> Key:
        return self._path("IL", name)

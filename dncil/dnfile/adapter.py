# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Optional

from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.clr.evidence import TokenResolver, TokenResolution
from dncil.clr.token import MetadataTable

if TYPE_CHECKING:
    from dnfile import dnPE
    from dnfile.mdtable import MethodDefRow


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    """read a managed method body from a dnfile PE image"""

    def __init__(self, pe: dnPE, row: MethodDefRow):
        self.pe: dnPE = pe
        self.offset: int = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        """get bytes from the PE image"""
        data: bytes = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += len(data)
        return data

    def tell(self) -> int:
        """get current file offset"""
        return self.offset

    def seek(self, offset: int) -> int:
        """seek to a file offset"""
        self.offset = offset
        return self.offset


def read_method_body(pe: dnPE, row: MethodDefRow) -> CilMethodBody:
    """read a managed method body for a MethodDef row"""
    return CilMethodBody(DnfileMethodBodyReader(pe, row))


class DnfileTokenProvider(TokenResolver):
    """resolve dncil token requests against dnfile metadata

    Only metadata that dnfile has already parsed is used; no assembly is loaded
    or executed. Unknown tables, absent rows, and undecodable user strings are
    returned as structured unresolved results rather than exceptions.
    """

    def __init__(self, pe: dnPE):
        super(DnfileTokenProvider, self).__init__()
        self.pe: dnPE = pe

    @property
    def metadata(self) -> Any:
        """get parsed CLR metadata, or None"""
        return getattr(self.pe, "net", None)

    @property
    def tables(self) -> Any:
        """get the parsed metadata table container, or None"""
        metadata: Any = self.metadata
        if metadata is None:
            return None
        return getattr(metadata, "mdtables", None)

    def _table(self, table: MetadataTable) -> Any:
        container: Any = self.tables
        if container is None:
            return None

        tables: Any = getattr(container, "tables", None)
        if isinstance(tables, dict):
            return tables.get(int(table))

        # older dnfile releases expose tables only as named attributes
        return getattr(container, table.name, None)

    def has_table(self, table: MetadataTable) -> bool:
        """check if a metadata table has rows available"""
        table_obj: Any = self._table(table)
        if table_obj is None:
            return False
        rows: Any = getattr(table_obj, "rows", None)
        return rows is not None and len(rows) > 0

    def table_row_count(self, table: MetadataTable) -> Optional[int]:
        """get the row count that dnfile parsed for a table"""
        table_obj: Any = self._table(table)
        if table_obj is None:
            return None
        rows: Any = getattr(table_obj, "rows", None)
        return len(rows) if rows is not None else None

    def get_table_row(self, table: MetadataTable, rid: int) -> Any:
        """get a 1-based metadata table row"""
        table_obj: Any = self._table(table)
        if table_obj is None:
            return None
        return table_obj.get_with_row_index(rid)

    def get_user_string(self, rid: int) -> Optional[str]:
        """get a #US heap entry, or None when absent or not decodable"""
        metadata: Any = self.metadata
        if metadata is None:
            return None
        heap: Any = getattr(metadata, "user_strings", None)
        if heap is None:
            return None
        item: Any = heap.get(rid)
        if item is None:
            return None
        return getattr(item, "value", None)


def resolve_method_body(provider: DnfileTokenProvider, body: CilMethodBody) -> List[TokenResolution]:
    """resolve every token request in a method body, including the local signature

    Results preserve the original token, instruction/header offset, and expected
    kind. Unresolved requests are returned next to successful ones.
    """
    return provider.resolve_all(body.get_token_requests())


def _name(value: Any) -> str:
    name: Any = getattr(value, "Name", None)
    return str(name) if name is not None else str(value)


def format_resolved_value(value: Any) -> str:
    """format a resolved dnfile value for display

    This is intentionally shallow: it shows the identity dnfile parsed and does
    not follow references into other assemblies.
    """
    if isinstance(value, str):
        return '"%s"' % value

    class_name: Any = getattr(value, "TypeName", None)
    if class_name is not None:
        namespace: Any = getattr(value, "TypeNamespace", None)
        return "%s.%s" % (namespace, class_name) if namespace else str(class_name)

    member_class: Any = getattr(value, "Class", None)
    if member_class is not None:
        parent_row: Any = getattr(member_class, "row", None)
        if parent_row is not None:
            parent: str = format_resolved_value(parent_row)
            return "%s::%s" % (parent, _name(value))
        return _name(value)

    method: Any = getattr(value, "Method", None)
    if method is not None and getattr(value, "Instantiation", None) is not None:
        target: Any = getattr(method, "row", None)
        target_name: str = format_resolved_value(target) if target is not None else "token(0x%08X)" % getattr(
            method, "row_index", 0
        )
        return "generic instance of %s" % target_name

    signature: Any = getattr(value, "Signature", None)
    if signature is not None and getattr(value, "Name", None) is None:
        raw: Any = getattr(signature, "value", b"")
        return "signature(0x%X bytes)" % len(raw)

    return _name(value)

# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""dnfile metadata adapter for the bounded reachability reviewer.

dnfile is imported lazily so the core ``dncil.analysis`` package keeps its
single dependency. this module reads metadata and method bodies only; it never
loads or executes the assembly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Set, Dict, List, Optional, Sequence

from dncil.clr.token import Token
from dncil.analysis.metadata import MetadataView, MethodRecord, MetadataError, ReferenceKind, MethodReference

if TYPE_CHECKING:
    from dnfile import dnPE
    from dnfile.mdtable import MethodDefRow


class DnfileMethodBodyReader:
    """minimal reader over a dnfile PE, matching dncil's reader protocol."""

    def __init__(self, pe: "dnPE", offset: int):
        self.pe = pe
        self.offset = offset

    def read(self, n: int) -> bytes:
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int) -> int:
        self.offset = offset
        return self.offset


class DnfileMetadataView(MetadataView):
    """read-only metadata view backed by ``dnfile.dnPE``.

    tokens are resolved by table and RID. anything that cannot be resolved
    exactly raises ``MetadataError``; the reviewer turns that into an
    unresolved call site instead of guessing.
    """

    def __init__(self, pe: "dnPE"):
        try:
            import dnfile  # noqa: F401
        except ImportError as error:  # pragma: no cover - exercised by import guard test
            raise MetadataError("dnfile is required for the dnfile adapter") from error

        if getattr(pe, "net", None) is None:
            raise MetadataError("PE has no CLR metadata")

        self.pe = pe
        self.tables = pe.net.mdtables
        self._methods: List[MethodRecord] = []
        self._rows_by_rid: Dict[int, Any] = {}
        self._rid_by_row_id: Dict[int, int] = {}
        self._declaring_type: Dict[int, str] = {}
        self._pinvoke_module: Dict[int, str] = {}
        self._pinvoke_import_name: Dict[int, str] = {}
        self._generic_methods: Set[int] = set()
        self._build_index()

    def _build_index(self) -> None:
        method_rows = list(getattr(self.tables, "MethodDef", None) or [])
        for index, row in enumerate(method_rows, start=1):
            self._rows_by_rid[index] = row
            self._rid_by_row_id[id(row)] = index

        self._index_declaring_types()
        self._index_pinvoke()
        self._index_generic_methods()

        for rid, row in self._rows_by_rid.items():
            flags = row.Flags
            impl = row.ImplFlags
            has_body = bool(row.Rva and impl.miIL and not flags.mdAbstract and not flags.mdPinvokeImpl)
            self._methods.append(
                MethodRecord(
                    token=Token((0x06 << Token.TABLE_SHIFT) | rid),
                    name=_text(row.Name),
                    declaring_type=self._declaring_type.get(rid, "<unknown>"),
                    rva=int(row.Rva),
                    has_body=has_body,
                    is_pinvoke=bool(flags.mdPinvokeImpl),
                    is_virtual=bool(flags.mdVirtual),
                    is_abstract=bool(flags.mdAbstract),
                    is_generic=rid in self._generic_methods,
                    pinvoke_module=self._pinvoke_module.get(rid),
                    pinvoke_name=self._pinvoke_import_name.get(rid, _text(row.Name)),
                )
            )

    def _index_declaring_types(self) -> None:
        for type_row in getattr(self.tables, "TypeDef", None) or []:
            name = _type_name(type_row)
            for item in getattr(type_row, "MethodList", []) or []:
                rid = getattr(item, "row_index", None)
                if rid:
                    self._declaring_type[rid] = name

    def _index_pinvoke(self) -> None:
        for row in getattr(self.tables, "ImplMap", None) or []:
            forwarded = row.MemberForwarded.row
            if forwarded is None:
                continue
            rid = self._rid_by_row_id.get(id(forwarded))
            if rid is None:
                continue
            scope = row.ImportScope.row
            module = _text(scope.Name) if scope is not None else None
            if module:
                self._pinvoke_module[rid] = module
                self._pinvoke_import_name[rid] = _text(row.ImportName)

    def _index_generic_methods(self) -> None:
        for row in getattr(self.tables, "GenericParam", None) or []:
            owner = row.Owner.row
            rid = self._rid_by_row_id.get(id(owner))
            if rid is not None:
                self._generic_methods.add(rid)

        for row in getattr(self.tables, "MethodSpec", None) or []:
            target = row.Method.row
            rid = self._rid_by_row_id.get(id(target))
            if rid is not None:
                self._generic_methods.add(rid)

    def methods(self) -> Sequence[MethodRecord]:
        return list(self._methods)

    def method_body(self, method: MethodRecord) -> bytes:
        row = self._rows_by_rid.get(method.token.rid)
        if row is None or not row.Rva:
            raise MetadataError(f"no method body RVA for {method.display}")

        from dncil.cil.body import CilMethodBody
        from dncil.cil.body.reader import CilMethodBodyReaderBase

        class _Reader(CilMethodBodyReaderBase):
            def __init__(self, pe: "dnPE", offset: int):
                self._reader = DnfileMethodBodyReader(pe, offset)

            def read(self, n: int) -> bytes:
                return self._reader.read(n)

            def tell(self) -> int:
                return self._reader.tell()

            def seek(self, offset: int) -> int:
                return self._reader.seek(offset)

        try:
            offset = self.pe.get_offset_from_rva(row.Rva)
        except Exception as error:
            raise MetadataError(f"cannot map RVA 0x{row.Rva:X}: {error}") from error
        return bytes(CilMethodBody(_Reader(self.pe, offset)).get_bytes())

    def entry_point(self) -> Optional[MethodRecord]:
        struct = getattr(self.pe.net, "struct", None)
        if struct is None:
            return None
        if getattr(self.pe.net.Flags, "CLR_NATIVE_ENTRYPOINT", False):
            raise MetadataError("entry point is native, not managed")

        token_value = int(struct.EntryPointTokenOrRva)
        if token_value == 0:
            return None
        token = Token(token_value)
        if token.table != 0x06:
            raise MetadataError(f"entry point token 0x{token_value:08X} is not a MethodDef token")
        for method in self._methods:
            if method.token.rid == token.rid:
                return method
        raise MetadataError(f"entry point token 0x{token_value:08X} does not name a MethodDef row")

    def resolve(self, token: Token) -> MethodReference:
        if token.table == 0x06:
            return self._resolve_method_def(token)
        if token.table == 0x0A:
            return self._resolve_member_ref(token)
        if token.table == 0x2B:
            return self._resolve_method_spec(token)
        raise MetadataError(f"token 0x{token.value:08X} is not a method token")

    def _resolve_method_def(self, token: Token) -> MethodReference:
        row = self._rows_by_rid.get(token.rid)
        if row is None:
            raise MetadataError(f"unresolved MethodDef token 0x{token.value:08X}")
        return MethodReference(
            token=token,
            kind=ReferenceKind.METHOD_DEF,
            name=_text(row.Name),
            declaring_type=self._declaring_type.get(token.rid, "<unknown>"),
            method_def_token=token,
            generic=token.rid in self._generic_methods,
        )

    def _resolve_member_ref(self, token: Token) -> MethodReference:
        rows = getattr(self.tables, "MemberRef", None)
        if rows is None or token.rid < 1 or token.rid > len(rows.rows):
            raise MetadataError(f"unresolved MemberRef token 0x{token.value:08X}")

        row = rows.rows[token.rid - 1]
        parent = row.Class.row
        name = _text(row.Name)

        if parent is None:
            raise MetadataError(f"MemberRef token 0x{token.value:08X} has no parent")

        from dnfile import mdtable

        if isinstance(parent, mdtable.ModuleRefRow):
            return MethodReference(
                token=token,
                kind=ReferenceKind.MEMBER_REF,
                name=name,
                module=_text(parent.Name),
            )

        if isinstance(parent, mdtable.MethodDefRow):
            # vararg call site: the parent names the method definition.
            rid = self._rid_by_row_id.get(id(parent))
            method_token = Token((0x06 << Token.TABLE_SHIFT) | rid) if rid else None
            return MethodReference(
                token=token,
                kind=ReferenceKind.MEMBER_REF,
                name=name,
                declaring_type=self._declaring_type.get(rid or -1, "<unknown>"),
                method_def_token=method_token,
            )

        if isinstance(parent, mdtable.TypeRefRow):
            return MethodReference(
                token=token,
                kind=ReferenceKind.MEMBER_REF,
                name=name,
                declaring_type=_type_name(parent),
                method_def_token=None,
            )

        if isinstance(parent, mdtable.TypeDefRow):
            # a same-module MemberRef is signature dependent (vararg or a
            # generic declaring type). matching by name alone would let
            # overloads collapse into one row, so it stays unresolved.
            return MethodReference(
                token=token,
                kind=ReferenceKind.MEMBER_REF,
                name=name,
                declaring_type=_type_name(parent),
                method_def_token=None,
                generic=True,
            )

        if isinstance(parent, mdtable.TypeSpecRow):
            return MethodReference(
                token=token,
                kind=ReferenceKind.MEMBER_REF,
                name=name,
                declaring_type="<typespec>",
                generic=True,
            )

        raise MetadataError(f"MemberRef token 0x{token.value:08X} has unsupported parent {type(parent).__name__}")

    def _resolve_method_spec(self, token: Token) -> MethodReference:
        rows = getattr(self.tables, "MethodSpec", None)
        if rows is None or token.rid < 1 or token.rid > len(rows.rows):
            raise MetadataError(f"unresolved MethodSpec token 0x{token.value:08X}")

        row = rows.rows[token.rid - 1]
        target = row.Method.row
        if target is None:
            raise MetadataError(f"MethodSpec token 0x{token.value:08X} has no target")

        from dnfile import mdtable

        if isinstance(target, mdtable.MethodDefRow):
            rid = self._rid_by_row_id.get(id(target))
            if rid is None:
                raise MetadataError(f"MethodSpec token 0x{token.value:08X} targets a foreign MethodDef")
            return MethodReference(
                token=token,
                kind=ReferenceKind.METHOD_SPEC,
                name=_text(target.Name),
                declaring_type=self._declaring_type.get(rid, "<unknown>"),
                method_def_token=Token((0x06 << Token.TABLE_SHIFT) | rid),
                generic=True,
                has_generic_params=True,
            )

        target_ref = self._resolve_member_ref(Token((0x0A << Token.TABLE_SHIFT) | self._member_ref_rid(target)))
        return MethodReference(
            token=token,
            kind=ReferenceKind.METHOD_SPEC,
            name=target_ref.name,
            declaring_type=target_ref.declaring_type,
            module=target_ref.module,
            method_def_token=target_ref.method_def_token,
            generic=True,
            has_generic_params=True,
        )

    def _member_ref_rid(self, row: Any) -> int:
        rows = getattr(self.tables, "MemberRef", None)
        if rows is None:
            raise MetadataError("MemberRef table is absent")
        for index, candidate in enumerate(rows.rows, start=1):
            if candidate is row:
                return index
        raise MetadataError("MethodSpec target is not present in the MemberRef table")


def _text(value: Any) -> str:
    return str(value) if value is not None else ""


def _type_name(row: Any) -> str:
    namespace = _text(getattr(row, "TypeNamespace", ""))
    name = _text(getattr(row, "TypeName", ""))
    return f"{namespace}.{name}" if namespace else name


def review_pe(pe: "dnPE", entries: Optional[Sequence[Any]] = None, limits: Any = None):
    """convenience wrapper: build a view and review a parsed PE."""
    from dncil.analysis.review import review_entry_points

    view = DnfileMetadataView(pe)
    return review_entry_points(view, entries, limits)

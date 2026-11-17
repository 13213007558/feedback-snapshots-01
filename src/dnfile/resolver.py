# -*- coding: utf-8 -*-
"""
Offline resolution of ExportedType rows against a fixed, caller-provided
set of assemblies.

An ExportedType row tells an investigator where a type *really* lives, but
the row alone is ambiguous.  Its ``Implementation`` coded index has three
different meanings:

- ``File``:        the type is defined in another module (file) of this
                   same assembly.  Only resolvable if the caller supplied
                   that module.
- ``AssemblyRef``: the row is a *type forwarder*.  The type is defined in
                   a different assembly, identified by name, version,
                   culture, and public key token.  A forwarder is only a
                   declaration; it is never a definition in this file.
- ``ExportedType``: the row is a nested type, and the referenced
                   ExportedType row is its enclosing type.  The nested
                   type lives wherever its enclosing type lives.

Additionally, a non-zero ``TypeDefId`` is a hint that the type is defined
in this very file; it is only trusted after verifying the referenced
TypeDef row actually carries the same name and namespace.

This resolver is strictly offline: it only consults the assemblies the
caller explicitly handed to it.  It never probes the filesystem, the GAC,
or the network for dependencies.  Assembly references are matched by full
identity (name, version, culture, public key token); a reference whose
name matches but whose version, culture, or public key token differs is
NOT considered a match.  Forwarding cycles and missing dependencies are
reported as unresolved instead of being guessed.

Typical usage::

    import dnfile
    from dnfile.resolver import ExportedTypeResolver

    pes = [dnfile.dnPE(path) for path in paths]
    resolver = ExportedTypeResolver(pes)
    result = resolver.resolve(pes[0], 1)   # ExportedType rid 1
    print(result.status, result.definition_token)
    for step in result.steps:
        print(hex(step.token), step.action)
"""

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from . import mdtable

TOKEN_TYPEDEF = mdtable.TypeDef.number << 24
TOKEN_ASSEMBLYREF = mdtable.AssemblyRef.number << 24
TOKEN_FILE = mdtable.File.number << 24
TOKEN_EXPORTEDTYPE = mdtable.ExportedType.number << 24


def _as_str(value) -> str:
    """Normalize a row string attribute (str or HeapItemString) to str."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _as_bytes(value) -> bytes:
    """Normalize a row blob attribute (bytes or HeapItemBinary) to bytes."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    inner = getattr(value, "value", None)
    return inner if isinstance(inner, bytes) else b""


def public_key_token(public_key: bytes) -> bytes:
    """
    Compute the public key token of a full public key, per ECMA-335:
    the low 8 bytes of the SHA-1 hash of the key, in reverse order.
    An empty key yields an empty (null) token.
    """
    if not public_key:
        return b""
    digest = hashlib.sha1(public_key).digest()
    return digest[-8:][::-1]


def _normalize_culture(culture: Optional[str]) -> str:
    if not culture:
        return "neutral"
    culture = culture.strip()
    return culture.lower() if culture else "neutral"


@dataclass(frozen=True)
class AssemblyIdentity:
    """
    Full assembly identity: name, version, culture, and public key token.
    A reference matches a candidate assembly only if ALL four agree.
    """

    name: str
    version: Tuple[int, int, int, int]
    culture: str
    public_key_token: bytes

    @classmethod
    def from_assembly_row(cls, row: "mdtable.AssemblyRow") -> "AssemblyIdentity":
        return cls(
            name=_as_str(row.Name),
            version=(
                row.MajorVersion,
                row.MinorVersion,
                row.BuildNumber,
                row.RevisionNumber,
            ),
            culture=_normalize_culture(_as_str(row.Culture)),
            public_key_token=public_key_token(_as_bytes(row.PublicKey)),
        )

    @classmethod
    def from_assembly_ref_row(cls, row: "mdtable.AssemblyRefRow") -> "AssemblyIdentity":
        key = _as_bytes(row.PublicKey)
        # the AssemblyRef PublicKeyOrToken blob usually holds the 8-byte
        # token; if it carries a full public key, derive the token from it.
        token = key if len(key) <= 8 else public_key_token(key)
        return cls(
            name=_as_str(row.Name),
            version=(
                row.MajorVersion,
                row.MinorVersion,
                row.BuildNumber,
                row.RevisionNumber,
            ),
            culture=_normalize_culture(_as_str(row.Culture)),
            public_key_token=token,
        )

    def matches(self, other: "AssemblyIdentity") -> bool:
        """
        Exact identity match.  Assembly names compare case-insensitively
        (CLR convention); version, culture, and public key token must be
        exactly equal.  A same-named assembly with a different version,
        culture, or public key token is NOT a match.
        """
        return (
            self.name.casefold() == other.name.casefold()
            and self.version == other.version
            and self.culture == other.culture
            and self.public_key_token == other.public_key_token
        )

    def __str__(self) -> str:
        pkt = self.public_key_token.hex() if self.public_key_token else "null"
        return "{0}, Version={1}.{2}.{3}.{4}, Culture={5}, PublicKeyToken={6}".format(
            self.name, *self.version, self.culture, pkt
        )


class ResolutionStatus(enum.Enum):
    #: the type is defined by a TypeDef in the queried file itself
    DEFINED_HERE = "defined-here"
    #: the type is defined in another module (File) of the same assembly,
    #: and that module was part of the provided set
    DEFINED_IN_MODULE = "defined-in-module"
    #: the row is a forwarder, and the chain was followed to a TypeDef in
    #: another assembly of the provided set
    FORWARDED = "forwarded"
    #: the type could not be resolved with the provided assemblies alone
    UNRESOLVED = "unresolved"


class UnresolvedReason(enum.Enum):
    #: no assembly with the referenced name was provided
    MISSING_ASSEMBLY = "missing-assembly"
    #: same-named assemblies were provided, but version, culture, or
    #: public key token differ, so none of them may satisfy the reference
    IDENTITY_MISMATCH = "identity-mismatch"
    #: the File-named module of this assembly was not provided
    MISSING_MODULE = "missing-module"
    #: the target assembly/module was found, but it does not contain the type
    MISSING_TYPE = "missing-type"
    #: following forwarders led back to an already-visited ExportedType
    CYCLE = "cycle"
    #: the ExportedType row has neither a usable TypeDefId nor a usable
    #: Implementation
    INVALID = "invalid-implementation"


@dataclass
class ResolutionStep:
    """
    One hop of the resolution trace.  ``token`` always cites the metadata
    token of the row this step was derived from, so every conclusion can
    be traced back to its source.
    """

    assembly: str
    token: int
    table: str
    row_index: int
    action: str
    target_token: Optional[int] = None

    def __str__(self) -> str:
        return "[0x{0:08x}] {1}: {2}".format(self.token, self.assembly, self.action)


@dataclass
class ResolutionResult:
    status: ResolutionStatus
    reason: Optional[UnresolvedReason] = None
    steps: List[ResolutionStep] = field(default_factory=list)
    definition_token: Optional[int] = None
    definition_assembly: Optional[str] = None
    detail: str = ""

    @property
    def resolved(self) -> bool:
        return self.status is not ResolutionStatus.UNRESOLVED

    @property
    def is_forwarder(self) -> bool:
        """True if the queried row was a forwarder declaration (resolved or not)."""
        return any(s.table == "AssemblyRef" for s in self.steps)


class _AssemblyContext:
    """Pre-indexed view of one caller-provided module."""

    def __init__(self, pe):
        self.pe = pe
        self.identity: Optional[AssemblyIdentity] = None
        self.module_name: Optional[str] = None
        self.typedef_table = None
        self.exported_table = None
        self.file_table = None
        self.typedefs: Dict[Tuple[str, str], int] = {}
        self.exported: Dict[Tuple[str, str], int] = {}

        net = getattr(pe, "net", None)
        tables = getattr(net, "mdtables", None) if net else None
        if tables is None:
            self.label = getattr(pe, "filename", None) or "<unparsed>"
            return

        assembly = getattr(tables, "Assembly", None)
        if assembly is not None and assembly.num_rows >= 1:
            row = assembly.get_with_row_index(1)
            if row is not None:
                self.identity = AssemblyIdentity.from_assembly_row(row)

        module = getattr(tables, "Module", None)
        if module is not None and module.num_rows >= 1:
            row = module.get_with_row_index(1)
            if row is not None:
                self.module_name = _as_str(row.Name) or None

        self.typedef_table = getattr(tables, "TypeDef", None)
        self.exported_table = getattr(tables, "ExportedType", None)
        self.file_table = getattr(tables, "File", None)

        if self.typedef_table is not None:
            for rid, row in enumerate(self.typedef_table.rows, start=1):
                if row is None:
                    continue
                self.typedefs.setdefault(
                    (_as_str(row.TypeNamespace), _as_str(row.TypeName)), rid
                )
        if self.exported_table is not None:
            for rid, row in enumerate(self.exported_table.rows, start=1):
                if row is None:
                    continue
                self.exported.setdefault(
                    (_as_str(row.TypeNamespace), _as_str(row.TypeName)), rid
                )

        if self.identity is not None:
            self.label = str(self.identity)
        elif self.module_name:
            self.label = self.module_name
        else:
            self.label = getattr(pe, "filename", None) or "<unnamed module>"

    def typedef_row(self, rid: int):
        if self.typedef_table is None or rid < 1:
            return None
        try:
            return self.typedef_table.get_with_row_index(rid)
        except IndexError:
            return None

    def find_typedef(self, namespace: str, name: str, hint: int = 0) -> Optional[int]:
        if hint:
            row = self.typedef_row(hint)
            if (
                row is not None
                and _as_str(row.TypeName) == name
                and _as_str(row.TypeNamespace) == namespace
            ):
                return hint
        return self.typedefs.get((namespace, name))

    def find_exported(self, namespace: str, name: str) -> Optional[int]:
        return self.exported.get((namespace, name))


class ExportedTypeResolver:
    """
    Resolves ExportedType rows using only the assemblies given at
    construction time.  Nothing is loaded from disk or the network.
    """

    def __init__(self, assemblies: Iterable):
        self._contexts: List[_AssemblyContext] = [
            _AssemblyContext(pe) for pe in assemblies
        ]

    def resolve(self, pe, exported_type) -> ResolutionResult:
        """
        Resolve an ExportedType of ``pe``.

        ``exported_type`` may be an ExportedTypeRow, a 1-based row id, or
        a metadata token (0x27000000 | rid).  ``pe`` must be one of the
        objects this resolver was built with.
        """
        ctx = self._context_for(pe)
        if ctx is None:
            raise ValueError(
                "the given module is not part of this resolver's assembly set"
            )
        result = ResolutionResult(status=ResolutionStatus.UNRESOLVED)
        if ctx.exported_table is None:
            result.reason = UnresolvedReason.MISSING_TYPE
            result.detail = "module has no ExportedType table"
            return result
        rid = self._coerce_rid(ctx, exported_type)
        hops: List[str] = []
        final = self._resolve_exported(ctx, rid, result, set(), hops)
        if final is not None:
            final_ctx, typedef_rid = final
            result.definition_token = TOKEN_TYPEDEF | typedef_rid
            result.definition_assembly = final_ctx.label
            result.reason = None
            if final_ctx is ctx and not hops:
                result.status = ResolutionStatus.DEFINED_HERE
            elif "forwarder" in hops:
                result.status = ResolutionStatus.FORWARDED
            else:
                result.status = ResolutionStatus.DEFINED_IN_MODULE
        return result

    #### internals

    def _context_for(self, pe) -> Optional[_AssemblyContext]:
        for ctx in self._contexts:
            if ctx.pe is pe:
                return ctx
        return None

    @staticmethod
    def _coerce_rid(ctx: _AssemblyContext, exported_type) -> int:
        if isinstance(exported_type, mdtable.ExportedTypeRow):
            for rid, row in enumerate(ctx.exported_table.rows, start=1):
                if row is exported_type:
                    return rid
            raise ValueError("row does not belong to the given module")
        if isinstance(exported_type, int):
            if exported_type >> 24 == mdtable.ExportedType.number:
                return exported_type & 0x00FFFFFF
            return exported_type
        raise TypeError(
            "expected ExportedTypeRow, row id, or ExportedType token; "
            "got {0!r}".format(type(exported_type))
        )

    def _resolve_exported(
        self,
        ctx: _AssemblyContext,
        rid: int,
        result: ResolutionResult,
        visited: Set[Tuple[int, int]],
        hops: List[str],
    ) -> Optional[Tuple[_AssemblyContext, int]]:
        token = TOKEN_EXPORTEDTYPE | rid
        row = None
        if ctx.exported_table is not None and rid >= 1:
            try:
                row = ctx.exported_table.get_with_row_index(rid)
            except IndexError:
                row = None
        if row is None:
            result.steps.append(
                ResolutionStep(
                    ctx.label,
                    token,
                    "ExportedType",
                    rid,
                    "ExportedType row {0} does not exist in this module".format(rid),
                )
            )
            result.reason = UnresolvedReason.MISSING_TYPE
            result.detail = "ExportedType row {0} not found".format(rid)
            return None

        key = (id(ctx), rid)
        if key in visited:
            result.steps.append(
                ResolutionStep(
                    ctx.label,
                    token,
                    "ExportedType",
                    rid,
                    "already visited this ExportedType; forwarding cycle, "
                    "leaving the type unresolved",
                )
            )
            result.reason = UnresolvedReason.CYCLE
            result.detail = "forwarding cycle detected"
            return None
        visited.add(key)

        namespace = _as_str(row.TypeNamespace)
        name = _as_str(row.TypeName)
        impl = row.Implementation
        target_token = None
        if (
            impl is not None
            and impl.table is not None
            and impl.row_index is not None
            and impl.row_index >= 1
        ):
            target_token = (impl.table.number << 24) | impl.row_index
        result.steps.append(
            ResolutionStep(
                ctx.label,
                token,
                "ExportedType",
                rid,
                "examining exported type '{0}{1}'".format(
                    namespace, "." + name if namespace else name
                ),
                target_token=target_token,
            )
        )

        # a non-zero TypeDefId hints that the type is defined in this very
        # file; only trust it if the referenced TypeDef row agrees on the
        # name and namespace.
        if row.TypeDefId:
            td = ctx.typedef_row(row.TypeDefId)
            if (
                td is not None
                and _as_str(td.TypeName) == name
                and _as_str(td.TypeNamespace) == namespace
            ):
                result.steps.append(
                    ResolutionStep(
                        ctx.label,
                        TOKEN_TYPEDEF | row.TypeDefId,
                        "TypeDef",
                        row.TypeDefId,
                        "TypeDefId hint verified: the type is defined in "
                        "this file",
                    )
                )
                return (ctx, row.TypeDefId)
            result.steps.append(
                ResolutionStep(
                    ctx.label,
                    TOKEN_TYPEDEF | row.TypeDefId,
                    "TypeDef",
                    row.TypeDefId,
                    "TypeDefId hint does not match a TypeDef in this file; "
                    "ignoring it",
                )
            )

        if target_token is None:
            result.steps.append(
                ResolutionStep(
                    ctx.label,
                    token,
                    "ExportedType",
                    rid,
                    "row has no usable Implementation and no verifiable "
                    "TypeDefId; cannot resolve offline",
                )
            )
            result.reason = UnresolvedReason.INVALID
            result.detail = "ExportedType has neither TypeDefId nor Implementation"
            return None

        table_name = impl.table.name
        if table_name == "File":
            return self._resolve_via_file(
                ctx, row, impl.row_index, namespace, name, result, visited, hops
            )
        elif table_name == "AssemblyRef":
            return self._resolve_via_assembly_ref(
                ctx, row, impl.row_index, namespace, name, result, visited, hops
            )
        elif table_name == "ExportedType":
            return self._resolve_via_enclosing(
                ctx, rid, impl.row_index, namespace, name, result, visited, hops
            )

        result.reason = UnresolvedReason.INVALID
        result.detail = "unexpected Implementation table {0!r}".format(table_name)
        return None

    def _resolve_via_file(
        self, ctx, row, file_rid, namespace, name, result, visited, hops
    ) -> Optional[Tuple[_AssemblyContext, int]]:
        file_row = None
        if ctx.file_table is not None:
            try:
                file_row = ctx.file_table.get_with_row_index(file_rid)
            except IndexError:
                file_row = None
        module_name = _as_str(getattr(file_row, "Name", None)) if file_row else None
        token = TOKEN_FILE | file_rid
        result.steps.append(
            ResolutionStep(
                ctx.label,
                token,
                "File",
                file_rid,
                "Implementation is a File: the type is defined in module "
                "'{0}' of this same assembly".format(module_name),
            )
        )
        target = self._find_module(module_name)
        if target is None:
            result.steps.append(
                ResolutionStep(
                    ctx.label,
                    token,
                    "File",
                    file_rid,
                    "module '{0}' was not provided; the resolver stays "
                    "offline and does not look for files".format(module_name),
                )
            )
            result.reason = UnresolvedReason.MISSING_MODULE
            result.detail = "module '{0}' not in the provided set".format(module_name)
            return None
        hops.append("file")
        td_rid = target.find_typedef(namespace, name, hint=row.TypeDefId)
        if td_rid is not None:
            result.steps.append(
                ResolutionStep(
                    target.label,
                    TOKEN_TYPEDEF | td_rid,
                    "TypeDef",
                    td_rid,
                    "type is defined in this module of the assembly",
                )
            )
            return (target, td_rid)
        et_rid = target.find_exported(namespace, name)
        if et_rid is not None:
            return self._resolve_exported(target, et_rid, result, visited, hops)
        result.steps.append(
            ResolutionStep(
                target.label,
                token,
                "File",
                file_rid,
                "module '{0}' does not contain the type".format(module_name),
            )
        )
        result.reason = UnresolvedReason.MISSING_TYPE
        result.detail = "type not found in module '{0}'".format(module_name)
        return None

    def _resolve_via_assembly_ref(
        self, ctx, row, ref_rid, namespace, name, result, visited, hops
    ) -> Optional[Tuple[_AssemblyContext, int]]:
        ref_row = None
        ref_table = getattr(ctx.pe.net.mdtables, "AssemblyRef", None)
        if ref_table is not None:
            try:
                ref_row = ref_table.get_with_row_index(ref_rid)
            except IndexError:
                ref_row = None
        token = TOKEN_ASSEMBLYREF | ref_rid
        if ref_row is None:
            result.steps.append(
                ResolutionStep(
                    ctx.label,
                    token,
                    "AssemblyRef",
                    ref_rid,
                    "AssemblyRef row {0} does not exist".format(ref_rid),
                )
            )
            result.reason = UnresolvedReason.INVALID
            result.detail = "missing AssemblyRef row {0}".format(ref_rid)
            return None
        ref_identity = AssemblyIdentity.from_assembly_ref_row(ref_row)
        result.steps.append(
            ResolutionStep(
                ctx.label,
                token,
                "AssemblyRef",
                ref_rid,
                "Implementation is an AssemblyRef: this row is only a "
                "forwarder declaration for '{0}'".format(ref_identity),
            )
        )
        target = self._find_assembly(ctx, token, ref_rid, ref_identity, result)
        if target is None:
            return None
        hops.append("forwarder")
        td_rid = target.find_typedef(namespace, name)
        if td_rid is not None:
            result.steps.append(
                ResolutionStep(
                    target.label,
                    TOKEN_TYPEDEF | td_rid,
                    "TypeDef",
                    td_rid,
                    "forwarder chain ends here: the type is defined in "
                    "this assembly",
                )
            )
            return (target, td_rid)
        et_rid = target.find_exported(namespace, name)
        if et_rid is not None:
            return self._resolve_exported(target, et_rid, result, visited, hops)
        result.steps.append(
            ResolutionStep(
                target.label,
                token,
                "AssemblyRef",
                ref_rid,
                "assembly '{0}' was provided but contains no such type".format(
                    target.label
                ),
            )
        )
        result.reason = UnresolvedReason.MISSING_TYPE
        result.detail = "type not found in assembly '{0}'".format(target.label)
        return None

    def _resolve_via_enclosing(
        self, ctx, rid, enclosing_rid, namespace, name, result, visited, hops
    ) -> Optional[Tuple[_AssemblyContext, int]]:
        token = TOKEN_EXPORTEDTYPE | enclosing_rid
        result.steps.append(
            ResolutionStep(
                ctx.label,
                token,
                "ExportedType",
                enclosing_rid,
                "Implementation is an ExportedType: this is a nested type; "
                "it lives wherever its enclosing type lives",
            )
        )
        final = self._resolve_exported(ctx, enclosing_rid, result, visited, hops)
        if final is None:
            return None
        final_ctx, enclosing_typedef = final
        inner = final_ctx.find_typedef(namespace, name)
        if inner is not None:
            result.steps.append(
                ResolutionStep(
                    final_ctx.label,
                    TOKEN_TYPEDEF | inner,
                    "TypeDef",
                    inner,
                    "nested type '{0}' is defined here, alongside its "
                    "enclosing type".format(name),
                )
            )
            return (final_ctx, inner)
        result.steps.append(
            ResolutionStep(
                final_ctx.label,
                TOKEN_TYPEDEF | enclosing_typedef,
                "TypeDef",
                enclosing_typedef,
                "nested TypeDef not separately located; the nested type "
                "shares the location of its enclosing type",
            )
        )
        return final

    def _find_module(self, module_name) -> Optional[_AssemblyContext]:
        if not module_name:
            return None
        wanted = module_name.casefold()
        for ctx in self._contexts:
            if ctx.module_name and ctx.module_name.casefold() == wanted:
                return ctx
        return None

    def _find_assembly(
        self, from_ctx, token, ref_rid, ref_identity, result
    ) -> Optional[_AssemblyContext]:
        named = [
            ctx
            for ctx in self._contexts
            if ctx.identity is not None
            and ctx.identity.name.casefold() == ref_identity.name.casefold()
        ]
        if not named:
            result.steps.append(
                ResolutionStep(
                    from_ctx.label,
                    token,
                    "AssemblyRef",
                    ref_rid,
                    "no assembly named '{0}' was provided; the resolver "
                    "stays offline and does not search disk, GAC, or "
                    "network".format(ref_identity.name),
                )
            )
            result.reason = UnresolvedReason.MISSING_ASSEMBLY
            result.detail = "assembly '{0}' not in the provided set".format(
                ref_identity.name
            )
            return None
        for ctx in named:
            if ref_identity.matches(ctx.identity):
                return ctx
        result.steps.append(
            ResolutionStep(
                from_ctx.label,
                token,
                "AssemblyRef",
                ref_rid,
                "provided assemblies named '{0}' do not match the "
                "requested identity {1}; a same-named assembly with a "
                "different version, culture, or public key token is not a "
                "substitute".format(
                    ref_identity.name,
                    ref_identity,
                ),
            )
        )
        result.reason = UnresolvedReason.IDENTITY_MISMATCH
        result.detail = "no provided assembly matches identity {0}".format(
            ref_identity
        )
        return None

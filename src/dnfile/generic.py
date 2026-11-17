# -*- coding: utf-8 -*-
"""
Read-only analysis of CLR generic-parameter ownership and constraints.

This module inspects the metadata tables only.  It never loads the CLR, never
executes IL, and never treats successful metadata parsing as proof that the
CLR would accept the assembly.

The central rule is that a generic parameter is identified by

    (owning table, owning row, parameter number)

and never by its number alone.  A method parameter ``!!0`` and a type
parameter ``!0`` are different objects even though both carry number 0.
"""
from typing import Any, Dict, List, Tuple, Optional, Sequence
from collections import OrderedDict, defaultdict

from . import utils

__all__ = (
    "TokenRef",
    "Finding",
    "GenericParameter",
    "ConstraintEdge",
    "GenericAnalysis",
    "analyze_generic_constraints",
    "analyze",
)


TABLE_NUMBERS = {
    "Module": 0,
    "TypeRef": 1,
    "TypeDef": 2,
    "Field": 4,
    "MethodDef": 6,
    "Param": 8,
    "InterfaceImpl": 9,
    "MemberRef": 10,
    "TypeSpec": 27,
    "Assembly": 32,
    "AssemblyRef": 35,
    "GenericParam": 42,
    "MethodSpec": 43,
    "GenericParamConstraint": 44,
}

TYPE_DEF_OR_REF_NAMES = ("TypeDef", "TypeRef", "TypeSpec")


class TokenRef(object):
    """One concrete metadata token in an evidence path.

    ``row_index`` is one-based.  ``offset`` is an offset inside a signature
    blob, not a file offset.  ``role`` and ``detail`` are for display only.
    """

    __slots__ = ("table", "row_index", "role", "offset", "detail")

    def __init__(
        self,
        table: str,
        row_index: int,
        role: Optional[str] = None,
        offset: Optional[int] = None,
        detail: Optional[str] = None,
    ):
        self.table = table
        self.row_index = row_index
        self.role = role
        self.offset = offset
        self.detail = detail

    @property
    def token(self) -> Optional[int]:
        table_number = TABLE_NUMBERS.get(self.table)
        if table_number is None or self.row_index <= 0:
            return None
        return (table_number << 24) | self.row_index

    def __str__(self) -> str:
        result = "{}[{}]".format(self.table, self.row_index)
        if self.role:
            result = "{} {}".format(self.role, result)
        if self.offset is not None:
            result += "+0x{:x}".format(self.offset)
        if self.detail:
            result += " {}".format(self.detail)
        return result

    def __repr__(self) -> str:
        return "TokenRef({!r}, {!r}{})".format(
            self.table,
            self.row_index,
            ", role={!r}".format(self.role) if self.role else "",
        )


class Finding(object):
    """A structural finding.

    Severity is one of ``error`` (the metadata graph cannot be consistent as
    written), ``warning`` (redundant or surprising but not necessarily fatal),
    ``unknown`` (the structure cannot be decided statically), or ``info``.
    """

    def __init__(
        self,
        code: str,
        severity: str,
        message: str,
        path: Sequence[TokenRef] = (),
        details: Optional[Dict[str, Any]] = None,
    ):
        self.code = code
        self.severity = severity
        self.message = message
        self.path = tuple(path)
        self.details = details or {}

    @property
    def path_text(self) -> str:
        return " -> ".join(str(item) for item in self.path)

    @property
    def tokens(self) -> List[int]:
        return [item.token for item in self.path if item.token is not None]

    def __str__(self) -> str:
        text = "{} [{}]: {}".format(self.severity, self.code, self.message)
        if self.path_text:
            text += " | " + self.path_text
        return text

    def __repr__(self) -> str:
        return "Finding(code={!r}, severity={!r}, path={!r})".format(
            self.code, self.severity, self.path_text
        )


class GenericParameter(object):
    """A GenericParam row, scoped to its owner."""

    def __init__(self, row_index: int, row: Any, owner_table: Optional[str],
                 owner_index: int, owner_row: Any, number: Optional[int]):
        self.row_index = row_index
        self.row = row
        self.owner_table = owner_table
        self.owner_index = owner_index
        self.owner_row = owner_row
        self.number = number
        self.name = str(getattr(row, "Name", "") or "")

    @property
    def key(self) -> Optional[Tuple[str, int, int]]:
        if self.owner_table is None or self.owner_index <= 0 or self.number is None:
            return None
        return (self.owner_table, self.owner_index, self.number)

    @property
    def token_ref(self) -> TokenRef:
        return TokenRef("GenericParam", self.row_index, role="parameter")

    @property
    def owner_ref(self) -> TokenRef:
        table = self.owner_table or "?"
        return TokenRef(table, self.owner_index, role="owner")

    def __repr__(self) -> str:
        return "GenericParameter({!r}, number={!r}, row={})".format(
            self.key, self.number, self.row_index
        )


class ConstraintEdge(object):
    """An edge from one generic parameter to another through a constraint."""

    def __init__(self, source: GenericParameter, target: GenericParameter,
                 constraint_row: int, typespec_row: Optional[int],
                 signature_offset: Optional[int], in_generic_instance: bool):
        self.source = source
        self.target = target
        self.constraint_row = constraint_row
        self.typespec_row = typespec_row
        self.signature_offset = signature_offset
        self.in_generic_instance = in_generic_instance

    @property
    def is_self_reference(self) -> bool:
        return self.source.key == self.target.key

    @property
    def is_legal_f_bound(self) -> bool:
        return self.is_self_reference and self.in_generic_instance

    @property
    def path(self) -> Tuple[TokenRef, ...]:
        path = [
            TokenRef("GenericParamConstraint", self.constraint_row, role="constraint-row"),
            TokenRef("GenericParam", self.source.row_index, role="owner"),
        ]
        if self.typespec_row is not None:
            path.append(TokenRef("TypeSpec", self.typespec_row, role="constraint"))
            if self.signature_offset is not None:
                path.append(TokenRef(
                    "TypeSpec", self.typespec_row, role="signature",
                    offset=self.signature_offset,
                    detail="{}[{}]".format(
                        "MVAR" if self.target.owner_table == "MethodDef" else "VAR",
                        self.target.number,
                    ),
                ))
        return tuple(path)

    def __repr__(self) -> str:
        return "ConstraintEdge({!r} -> {!r}, f-bound={!r})".format(
            self.source.key, self.target.key, self.is_legal_f_bound
        )


class GenericAnalysis(object):
    """Result of :func:`analyze_generic_constraints`."""

    def __init__(self) -> None:
        self.parameters: "OrderedDict[Tuple[str, int, int], GenericParameter]" = OrderedDict()
        self.parameters_by_row: Dict[int, GenericParameter] = {}
        self.owners: Dict[Tuple[str, int], List[GenericParameter]] = {}
        self.edges: List[ConstraintEdge] = []
        self.findings: List[Finding] = []
        # Successful parsing cannot establish CLR loadability.
        self.clr_loadable: Optional[bool] = None
        self.limitations: List[str] = []

    @property
    def errors(self) -> List[Finding]:
        return [finding for finding in self.findings if finding.severity == "error"]

    @property
    def warnings(self) -> List[Finding]:
        return [finding for finding in self.findings if finding.severity == "warning"]

    @property
    def undetermined(self) -> List[Finding]:
        return [finding for finding in self.findings if finding.severity == "unknown"]

    @property
    def structurally_consistent(self) -> bool:
        """No structural contradiction was found.

        This is deliberately weaker than ``clr_loadable``.  Unknowns do not
        make the graph structurally inconsistent, but they also do not prove
        that the CLR will accept it.
        """
        return not self.errors

    @property
    def graph(self) -> Dict[Tuple[str, int, int], List[Tuple[str, int, int]]]:
        result = defaultdict(list)
        for edge in self.edges:
            if edge.source.key is not None and edge.target.key is not None:
                result[edge.source.key].append(edge.target.key)
        return dict(result)

    @property
    def legal_f_bounds(self) -> List[ConstraintEdge]:
        return [edge for edge in self.edges if edge.is_legal_f_bound]

    def describe(self) -> str:
        """Human-readable evidence report with token paths."""
        lines = [
            "generic parameters: {}".format(len(self.parameters)),
            "constraint edges: {}".format(len(self.edges)),
            "structural errors: {}".format(len(self.errors)),
            "statically undetermined: {}".format(len(self.undetermined)),
            "clr_loadable: unknown (metadata parsing alone is not proof)",
        ]
        for edge in self.legal_f_bounds:
            lines.append("legal f-bound: " + " -> ".join(str(item) for item in edge.path))
        for finding in self.findings:
            lines.append(str(finding))
        for limitation in self.limitations:
            lines.append("limitation: {}".format(limitation))
        return "\n".join(lines)

    def __repr__(self) -> str:
        return "GenericAnalysis(parameters={}, edges={}, errors={}, unknown={})".format(
            len(self.parameters), len(self.edges), len(self.errors), len(self.undetermined)
        )


class _SignatureError(Exception):
    def __init__(self, reason: str, path: str, offset: int):
        super().__init__(reason)
        self.reason = reason
        self.path = path
        self.offset = offset


class _ParamRef(object):
    def __init__(self, kind: str, number: int, offset: int,
                 path: str, in_generic_instance: bool):
        self.kind = kind
        self.number = number
        self.offset = offset
        self.path = path
        self.in_generic_instance = in_generic_instance

    def __repr__(self) -> str:
        return "_ParamRef({}, {}, offset=0x{:x})".format(
            self.kind, self.number, self.offset
        )


class _TypeRefUse(object):
    def __init__(self, table: str, row_index: int, offset: int,
                 path: str, in_generic_instance: bool,
                 generic_argument_count: Optional[int] = None):
        self.table = table
        self.row_index = row_index
        self.offset = offset
        self.path = path
        self.in_generic_instance = in_generic_instance
        self.generic_argument_count = generic_argument_count

    def __repr__(self) -> str:
        return "_TypeRefUse({}[{}], offset=0x{:x})".format(
            self.table, self.row_index, self.offset
        )


class _ParsedTypeSpec(object):
    def __init__(self):
        self.params: List[_ParamRef] = []
        self.type_refs: List[_TypeRefUse] = []
        self.error: Optional[_SignatureError] = None


class _TypeSpecParser(object):
    """Small structural parser for ECMA-335 type signature blobs.

    It does not interpret type identity or execute anything.  It only finds
    VAR/MVAR references, TypeDefOrRef tokens, generic instances and the point
    at which a malformed blob stops.
    """

    MAX_DEPTH = 64
    MAX_ELEMENTS = 4096

    SIMPLE = frozenset((
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x16, 0x18, 0x19, 0x1C,
    ))

    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.offset = 0
        self.elements = 0
        self.result = _ParsedTypeSpec()

    def parse(self) -> _ParsedTypeSpec:
        try:
            self._read_type("$", 0, False)
            if self.offset != len(self.data):
                raise _SignatureError(
                    "trailing bytes after the type signature",
                    "$", self.offset,
                )
        except _SignatureError as error:
            self.result.error = error
        return self.result

    def _fail(self, reason: str, path: str, offset: Optional[int] = None):
        raise _SignatureError(reason, path, self.offset if offset is None else offset)

    def _read_byte(self, path: str) -> int:
        if self.offset >= len(self.data):
            self._fail("unexpected end of signature blob", path)
        value = self.data[self.offset]
        self.offset += 1
        return value

    def _read_compressed(self, path: str) -> int:
        start = self.offset
        result = utils.read_compressed_int(self.data[self.offset:self.offset + 4])
        if result is None:
            self._fail("invalid compressed integer", path, start)
        value, size = result
        self.offset += size
        return value

    def _read_token(self, path: str):
        start = self.offset
        value = self._read_compressed(path)
        tag = value & 0x03
        row_index = value >> 2
        if tag >= len(TYPE_DEF_OR_REF_NAMES):
            self._fail(
                "invalid TypeDefOrRef tag {} in coded index".format(tag),
                path, start,
            )
        return TYPE_DEF_OR_REF_NAMES[tag], row_index, start

    def _count_element(self, path: str):
        self.elements += 1
        if self.elements > self.MAX_ELEMENTS:
            self._fail("signature is too large to analyze", path)

    def _read_type(self, path: str, depth: int, in_generic: bool) -> None:
        if depth > self.MAX_DEPTH:
            self._fail("type signature nesting is too deep", path)
        self._count_element(path)
        start = self.offset
        element = self._read_byte(path)

        if element in self.SIMPLE:
            return

        if element in (0x0F, 0x10, 0x1D, 0x45):  # PTR, BYREF, SZARRAY, PINNED
            self._read_type(path + ".inner", depth + 1, in_generic)
            return

        if element in (0x11, 0x12):  # VALUETYPE, CLASS
            table, row_index, token_offset = self._read_token(path + ".token")
            self.result.type_refs.append(_TypeRefUse(
                table, row_index, token_offset, path, in_generic,
            ))
            return

        if element in (0x13, 0x1E):  # VAR, MVAR
            number = self._read_compressed(path + ".number")
            self.result.params.append(_ParamRef(
                "VAR" if element == 0x13 else "MVAR",
                number, start, path, in_generic,
            ))
            return

        if element == 0x14:  # ARRAY
            self._read_type(path + ".inner", depth + 1, in_generic)
            rank = self._read_compressed(path + ".rank")
            if rank > self.MAX_ELEMENTS:
                self._fail("array rank is unreasonable", path)
            size_count = self._read_compressed(path + ".size-count")
            for index in range(size_count):
                self._read_compressed("{}.size[{}]".format(path, index))
            lower_count = self._read_compressed(path + ".lower-bound-count")
            for index in range(lower_count):
                self._read_compressed("{}.lower-bound[{}]".format(path, index))
            return

        if element == 0x15:  # GENERICINST
            kind = self._read_byte(path + ".class-or-valuetype")
            if kind not in (0x11, 0x12):
                self._fail(
                    "generic instance has invalid class/valuetype marker 0x{:02x}".format(kind),
                    path,
                )
            table, row_index, token_offset = self._read_token(path + ".token")
            count = self._read_compressed(path + ".argument-count")
            if count > self.MAX_ELEMENTS:
                self._fail("generic argument count is unreasonable", path)
            self.result.type_refs.append(_TypeRefUse(
                table, row_index, token_offset, path, True,
                generic_argument_count=count,
            ))
            for index in range(count):
                self._read_type(
                    "{}.argument[{}]".format(path, index), depth + 1, True,
                )
            return

        if element == 0x1B:  # FNPTR
            self._read_method_signature(path + ".signature", depth + 1, in_generic)
            return

        if element in (0x1F, 0x20):  # CMOD_REQD, CMOD_OPT
            table, row_index, token_offset = self._read_token(path + ".modifier")
            self.result.type_refs.append(_TypeRefUse(
                table, row_index, token_offset, path, in_generic,
            ))
            self._read_type(path + ".inner", depth + 1, in_generic)
            return

        if element == 0x41:
            self._fail("SENTINEL is only valid in a vararg parameter list", path, start)
        if element == 0x21:
            self._fail("INTERNAL element type is not valid in metadata signatures", path, start)
        self._fail("unsupported element type 0x{:02x}".format(element), path, start)

    def _read_method_signature(self, path: str, depth: int, in_generic: bool) -> None:
        flags = self._read_byte(path + ".flags")
        if flags & 0x10:
            self._read_compressed(path + ".generic-param-count")
        parameter_count = self._read_compressed(path + ".parameter-count")
        if parameter_count > self.MAX_ELEMENTS:
            self._fail("method parameter count is unreasonable", path)
        self._read_type(path + ".return", depth + 1, in_generic)
        for index in range(parameter_count):
            self._read_type(
                "{}.parameter[{}]".format(path, index), depth + 1, in_generic,
            )


class _Analyzer(object):
    def __init__(self, tables: Any):
        self.tables = tables
        self.result = GenericAnalysis()
        self._method_owners: Dict[int, List[Tuple[int, Any]]] = defaultdict(list)
        self._method_arities: Dict[int, Optional[int]] = {}
        self._typespec_cache: Dict[int, _ParsedTypeSpec] = {}
        self._seen_constraints: Dict[Tuple[int, int, int], int] = {}

    def run(self) -> GenericAnalysis:
        self._collect_parameters()
        self._check_parameter_numbering()
        self._map_methods_to_types()
        self._collect_constraints()
        self._add_limitations()
        return self.result

    # ------------------------------------------------------------------
    # table helpers

    def _table(self, name: str):
        table = getattr(self.tables, name, None)
        if table is not None:
            return table
        for candidate in getattr(self.tables, "tables_list", ()) or ():
            if getattr(candidate, "name", None) == name:
                return candidate
        return None

    def _row(self, table_name: str, row_index: int):
        if row_index <= 0:
            return None
        table = self._table(table_name)
        if table is None:
            return None
        try:
            return table.get_with_row_index(row_index)
        except (IndexError, TypeError):
            return None

    def _rows(self, table_name: str):
        table = self._table(table_name)
        if table is None:
            return
        for row_index in range(1, getattr(table, "num_rows", 0) + 1):
            try:
                row = table.get_with_row_index(row_index)
            except (IndexError, TypeError):
                row = None
            yield row_index, row

    @staticmethod
    def _heap_bytes(item) -> Optional[bytes]:
        if item is None:
            return None
        if isinstance(item, (bytes, bytearray)):
            return bytes(item)
        value = getattr(item, "value", None)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        raw = getattr(item, "raw_data", None)
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw)
        return None

    def _add(self, code: str, severity: str, message: str,
             path: Sequence[TokenRef] = (), **details):
        self.result.findings.append(Finding(
            code, severity, message, path, details or None,
        ))

    # ------------------------------------------------------------------
    # GenericParam

    def _collect_parameters(self) -> None:
        table = self._table("GenericParam")
        if table is None:
            return

        for row_index, row in self._rows("GenericParam"):
            row_ref = TokenRef("GenericParam", row_index)
            if row is None:
                self._add(
                    "generic-param-row-unparsed", "unknown",
                    "GenericParam row could not be parsed; its owner and number are unknown",
                    (row_ref,),
                )
                continue

            number = getattr(row, "Number", None)
            owner = getattr(row, "Owner", None)
            owner_table = None
            owner_index = 0
            owner_row = None

            if owner is None:
                self._add(
                    "generic-param-owner-missing", "error",
                    "GenericParam row has no resolved TypeOrMethodDef owner",
                    (row_ref,),
                )
            elif getattr(owner, "table", None) is None:
                self._add(
                    "generic-param-owner-table-missing", "error",
                    "GenericParam owner selects a metadata table that is not present",
                    (row_ref, TokenRef("TypeOrMethodDef", getattr(owner, "row_index", 0), role="owner")),
                )
            elif getattr(owner, "row_index", 0) <= 0:
                self._add(
                    "generic-param-owner-null", "error",
                    "GenericParam owner is the null coded index",
                    (row_ref, TokenRef("TypeOrMethodDef", getattr(owner, "row_index", 0), role="owner")),
                )
            else:
                owner_table = getattr(owner.table, "name", None)
                owner_index = owner.row_index
                try:
                    owner_row = owner.row
                except (IndexError, TypeError):
                    owner_row = None
                if owner_table not in ("TypeDef", "MethodDef"):
                    self._add(
                        "generic-param-owner-invalid-table", "error",
                        "GenericParam owner is not TypeDef or MethodDef",
                        (row_ref, TokenRef(owner_table or "?", owner_index, role="owner")),
                    )
                    owner_table = None
                elif owner_row is None:
                    self._add(
                        "generic-param-owner-row-missing", "error",
                        "GenericParam owner row does not exist",
                        (row_ref, TokenRef(owner_table, owner_index, role="owner")),
                    )
                    owner_table = None

            if number is None:
                self._add(
                    "generic-param-number-missing", "error",
                    "GenericParam row has no parameter number",
                    (row_ref,),
                )

            parameter = GenericParameter(
                row_index, row, owner_table, owner_index, owner_row, number,
            )
            self.result.parameters_by_row[row_index] = parameter
            key = parameter.key
            if key is None:
                continue
            existing = self.result.parameters.get(key)
            if existing is not None:
                self._add(
                    "duplicate-generic-parameter", "error",
                    "two GenericParam rows claim {}.{} parameter number {}".format(
                        key[0], key[1], key[2],
                    ),
                    (
                        TokenRef("GenericParam", existing.row_index, role="first"),
                        TokenRef("GenericParam", row_index, role="duplicate"),
                        TokenRef(key[0], key[1], role="owner"),
                    ),
                    key=list(key),
                )
                continue
            self.result.parameters[key] = parameter
            self.result.owners.setdefault((key[0], key[1]), []).append(parameter)

    def _method_arity(self, method_index: int) -> Optional[int]:
        if method_index in self._method_arities:
            return self._method_arities[method_index]
        row = self._row("MethodDef", method_index)
        if row is None:
            self._method_arities[method_index] = None
            return None
        data = self._heap_bytes(getattr(row, "Signature", None))
        if not data:
            self._method_arities[method_index] = None
            return None
        flags = data[0]
        if not flags & 0x10:
            self._method_arities[method_index] = 0
            return 0
        result = utils.read_compressed_int(data[1:5])
        if result is None:
            self._method_arities[method_index] = None
            return None
        arity = result[0]
        self._method_arities[method_index] = arity
        return arity

    def _check_parameter_numbering(self) -> None:
        for (owner_table, owner_index), parameters in self.result.owners.items():
            numbers = [parameter.number for parameter in parameters]
            path = [TokenRef(owner_table, owner_index, role="owner")]
            path.extend(
                TokenRef("GenericParam", parameter.row_index)
                for parameter in parameters
            )

            unique = sorted(set(numbers))
            if unique and unique[0] != 0:
                self._add(
                    "generic-parameter-number-gap", "error",
                    "{}[{}] parameters do not start at number 0".format(owner_table, owner_index),
                    path,
                    numbers=unique,
                )
            elif unique:
                expected = set(range(len(parameters)))
                if set(numbers) != expected:
                    missing = sorted(expected - set(numbers))
                    outside = sorted(set(numbers) - expected)
                    self._add(
                        "generic-parameter-number-gap", "error",
                        "{}[{}] parameter numbers are not a contiguous 0..{} sequence".format(
                            owner_table, owner_index, len(parameters) - 1,
                        ),
                        path,
                        missing=missing,
                        outside_range=outside,
                    )
            if owner_table == "MethodDef":
                arity = self._method_arity(owner_index)
                if arity is None:
                    self._add(
                        "method-generic-arity-unknown", "unknown",
                        "MethodDef[{}] signature does not yield a readable generic arity".format(owner_index),
                        path,
                    )
                elif len(parameters) != arity or set(numbers) != set(range(arity)):
                    self._add(
                        "method-generic-parameter-arity-mismatch", "error",
                        "MethodDef[{}] declares generic arity {} but GenericParam rows are {}".format(
                            owner_index, arity, numbers,
                        ),
                        path,
                        arity=arity,
                        numbers=numbers,
                    )

    # ------------------------------------------------------------------
    # owner scoping

    def _map_methods_to_types(self) -> None:
        for type_index, type_row in self._rows("TypeDef"):
            if type_row is None:
                continue
            method_list = getattr(type_row, "MethodList", None) or ()
            for method_index in method_list:
                row_index = getattr(method_index, "row_index", 0)
                if row_index:
                    self._method_owners[row_index].append((type_index, type_row))
        for method_index, owners in self._method_owners.items():
            if len(owners) > 1:
                path = [TokenRef("MethodDef", method_index, role="method")]
                path.extend(TokenRef("TypeDef", index, role="declared-by") for index, _ in owners)
                self._add(
                    "method-multiple-type-owners", "error",
                    "MethodDef[{}] appears in more than one TypeDef MethodList".format(method_index),
                    path,
                )

    def _lookup_parameter(self, table: str, owner_index: int,
                          number: int) -> Optional[GenericParameter]:
        return self.result.parameters.get((table, owner_index, number))

    # ------------------------------------------------------------------
    # GenericParamConstraint

    def _collect_constraints(self) -> None:
        table = self._table("GenericParamConstraint")
        if table is None:
            return
        for row_index, row in self._rows("GenericParamConstraint"):
            row_ref = TokenRef("GenericParamConstraint", row_index, role="constraint-row")
            if row is None:
                self._add(
                    "constraint-row-unparsed", "unknown",
                    "GenericParamConstraint row could not be parsed",
                    (row_ref,),
                )
                continue

            source = self._constraint_source(row, row_index, row_ref)
            constraint = getattr(row, "Constraint", None)
            expansion = self._expand_constraint(constraint, row_index, row_ref)
            if source is None or expansion is None:
                continue

            typespec_row, refs, paths = expansion
            if typespec_row is not None:
                key = (row_index, 1, typespec_row)
            else:
                key = (row_index, 2, getattr(constraint, "row_index", 0))
            # The same source constraint declaration repeated is redundant.
            previous = self._seen_constraints.get((source.row_index, 1, key[2]))
            if previous is not None:
                self._add(
                    "duplicate-constraint", "warning",
                    "GenericParamConstraint[{}] repeats the constraint of GenericParamConstraint[{}]".format(
                        row_index, previous,
                    ),
                    (row_ref, TokenRef("GenericParamConstraint", previous, role="previous")),
                )
                continue
            else:
                if typespec_row is not None:
                    self._seen_constraints[(source.row_index, 1, typespec_row)] = row_index
                else:
                    self._seen_constraints[(source.row_index, 2, getattr(constraint, "row_index", 0))] = row_index
            for reference in refs:
                self._apply_reference(
                    source, reference, row_index, typespec_row,
                    (row_ref,) + tuple(paths.get(id(reference), ())),
                )

    def _constraint_source(self, row, row_index: int,
                           row_ref: TokenRef) -> Optional[GenericParameter]:
        owner = getattr(row, "Owner", None)
        if owner is None:
            self._add(
                "constraint-owner-missing", "error",
                "GenericParamConstraint has no resolved GenericParam owner",
                (row_ref,),
            )
            return None
        owner_table = getattr(owner, "table", None)
        owner_index = getattr(owner, "row_index", 0)
        owner_ref = TokenRef("GenericParam", owner_index, role="owner")
        if owner_table is None or getattr(owner_table, "name", None) != "GenericParam":
            self._add(
                "constraint-owner-missing", "error",
                "GenericParamConstraint owner does not resolve to the GenericParam table",
                (row_ref, owner_ref),
            )
            return None
        if owner_index <= 0:
            self._add(
                "constraint-owner-missing", "error",
                "GenericParamConstraint owner is the null row index",
                (row_ref, owner_ref),
            )
            return None
        try:
            owner_row = owner.row
        except (IndexError, TypeError):
            owner_row = None
        if owner_row is None:
            self._add(
                "constraint-owner-row-missing", "error",
                "GenericParamConstraint owner row {} does not exist".format(owner_index),
                (row_ref, owner_ref),
            )
            return None
        parameter = self.result.parameters_by_row.get(owner_index)
        if parameter is None:
            self._add(
                "constraint-owner-row-missing", "error",
                "GenericParamConstraint owner row {} was not parsed".format(owner_index),
                (row_ref, owner_ref),
            )
            return None
        if parameter.key is None:
            self._add(
                "constraint-owner-unscoped", "error",
                "GenericParamConstraint owner has no valid TypeDef/MethodDef scope",
                (row_ref, owner_ref),
            )
            return None
        return parameter

    def _expand_constraint(self, constraint, constraint_row: int,
                           row_ref: TokenRef):
        if constraint is None:
            self._add(
                "constraint-target-missing", "error",
                "GenericParamConstraint has no resolved TypeDefOrRef target",
                (row_ref,),
            )
            return None
        table = getattr(constraint, "table", None)
        row_index = getattr(constraint, "row_index", 0)
        table_name = getattr(table, "name", None)
        target_ref = TokenRef(table_name or "TypeDefOrRef", row_index, role="constraint")
        if table is None:
            self._add(
                "constraint-target-table-missing", "error",
                "constraint coded index selects a table that is not present",
                (row_ref, target_ref),
            )
            return None
        if row_index <= 0:
            self._add(
                "constraint-target-null", "error",
                "constraint is the null coded index",
                (row_ref, target_ref),
            )
            return None
        try:
            target_row = constraint.row
        except (IndexError, TypeError):
            target_row = None
        if target_row is None:
            self._add(
                "constraint-target-row-missing", "error",
                "constraint target {}[{}] does not exist".format(table_name, row_index),
                (row_ref, target_ref),
            )
            return None

        if table_name == "TypeSpec":
            refs, paths = self._expand_typespec(row_index, (), row_ref)
            return row_index, refs, paths
        if table_name == "TypeDef":
            # A constraint on a non-constructed type has no parameter edges.
            return None, [], {}
        if table_name == "TypeRef":
            self._add(
                "external-constraint", "unknown",
                "constraint targets TypeRef[{}]; its declaring assembly was not loaded".format(row_index),
                (row_ref, target_ref),
            )
            return None, [], {}
        self._add(
            "constraint-target-invalid-table", "error",
            "constraint coded index resolves to unsupported table {}".format(table_name),
            (row_ref, target_ref),
        )
        return None, [], {}

    def _expand_typespec(self, row_index: int, chain: Tuple[int, ...],
                         row_ref: TokenRef):
        """Return parameter references and the evidence path for each one."""
        path = [TokenRef("TypeSpec", row_index, role="constraint")]
        if row_index in chain:
            cycle = chain + (row_index,)
            self._add(
                "typespec-cycle", "unknown",
                "TypeSpec reference cycle cannot be expanded statically; it is not rejected by itself",
                [TokenRef("TypeSpec", item, role="cycle") for item in cycle],
                cycle=list(cycle),
            )
            return [], {}

        if row_index in self._typespec_cache:
            parsed = self._typespec_cache[row_index]
        else:
            target = self._row("TypeSpec", row_index)
            if target is None:
                self._add(
                    "constraint-target-row-missing", "error",
                    "TypeSpec[{}] does not exist".format(row_index),
                    [TokenRef("TypeSpec", row_index, role="constraint")],
                )
                return [], {}
            data = self._heap_bytes(getattr(target, "Signature", None))
            if data is None:
                self._add(
                    "typespec-signature-missing", "unknown",
                    "TypeSpec[{}] signature blob could not be read".format(row_index),
                    [TokenRef("TypeSpec", row_index, role="signature")],
                )
                return [], {}
            parsed = _TypeSpecParser(data).parse()
            self._typespec_cache[row_index] = parsed

        if parsed.error is not None:
            self._add(
                "typespec-signature-invalid", "unknown",
                "TypeSpec[{}] signature cannot be interpreted: {}".format(
                    row_index, parsed.error.reason,
                ),
                [
                    TokenRef("TypeSpec", row_index, role="signature",
                             offset=parsed.error.offset, detail=parsed.error.path),
                ],
                offset=parsed.error.offset,
                reason=parsed.error.reason,
            )

        # References read before a truncation point are not authoritative;
        # keep them undetermined instead of deriving structural errors from
        # a partially interpreted signature.
        if parsed.error is not None:
            return [], {}

        refs = list(parsed.params)
        paths = {id(reference): path for reference in refs}

        for type_ref in parsed.type_refs:
            ref_path = path + [
                TokenRef(type_ref.table, type_ref.row_index, role="referenced-type",
                         offset=type_ref.offset, detail=type_ref.path),
            ]
            if type_ref.row_index <= 0:
                self._add(
                    "constraint-target-null", "error",
                    "TypeSpec[{}] contains a null TypeDefOrRef token".format(row_index),
                    ref_path,
                )
                continue
            if type_ref.table == "TypeSpec":
                nested_refs, nested_paths = self._expand_typespec(
                    type_ref.row_index, chain + (row_index,), row_ref,
                )
                for reference in nested_refs:
                    refs.append(reference)
                    paths[id(reference)] = ref_path + list(nested_paths.get(id(reference), ()))
            else:
                target_row = self._row(type_ref.table, type_ref.row_index)
                if target_row is None:
                    self._add(
                        "constraint-target-row-missing", "error",
                        "TypeSpec[{}] refers to missing {}[{}]".format(
                            row_index, type_ref.table, type_ref.row_index,
                        ),
                        ref_path,
                    )
                elif type_ref.table == "TypeRef":
                    self._add(
                        "external-constraint", "unknown",
                        "TypeSpec[{}] depends on external TypeRef[{}]; its definition was not loaded".format(
                            row_index, type_ref.row_index,
                        ),
                        ref_path,
                    )
                elif type_ref.table == "TypeDef" and type_ref.generic_argument_count is not None:
                    declared = len(self.result.owners.get(("TypeDef", type_ref.row_index), ()))
                    if declared != type_ref.generic_argument_count:
                        self._add(
                            "generic-instance-arity-mismatch", "error",
                            "TypeSpec[{}] instantiates TypeDef[{}] with {} arguments but the type declares {}".format(
                                row_index, type_ref.row_index,
                                type_ref.generic_argument_count, declared,
                            ),
                            ref_path,
                            supplied=type_ref.generic_argument_count,
                            declared=declared,
                        )
        return refs, paths

    # ------------------------------------------------------------------
    # graph edges and scope checks

    def _apply_reference(self, source: GenericParameter, reference: _ParamRef,
                         constraint_row: int, typespec_row: Optional[int],
                         path: Sequence[TokenRef]) -> None:
        signature_ref = TokenRef(
            "TypeSpec", typespec_row or 0, role="signature",
            offset=reference.offset,
            detail="{}[{}]".format(reference.kind, reference.number),
        )
        full_path = tuple(path) + (signature_ref,)

        target = None
        if reference.kind == "VAR":
            if source.owner_table == "TypeDef":
                if reference.number == source.number and not reference.in_generic_instance:
                    self._add(
                        "bare-self-parameter-constraint", "error",
                        "type parameter constraint is the parameter itself, not a constructed type",
                        full_path,
                    )
                target = self._lookup_parameter("TypeDef", source.owner_index, reference.number)
                if target is None:
                    self._add(
                        "constraint-parameter-target-missing", "error",
                        "VAR[{}] does not resolve to a GenericParam of TypeDef[{}]".format(
                            reference.number, source.owner_index,
                        ),
                        full_path,
                    )
            elif source.owner_table == "MethodDef":
                owners = self._method_owners.get(source.owner_index, ())
                if not owners:
                    self._add(
                        "constraint-var-scope-unknown", "unknown",
                        "method parameter constraint uses VAR[{}] but no enclosing TypeDef was established".format(
                            reference.number,
                        ),
                        full_path,
                    )
                elif len(owners) > 1:
                    self._add(
                        "constraint-var-scope-ambiguous", "error",
                        "method parameter constraint uses VAR[{}] but its enclosing TypeDef is ambiguous".format(
                            reference.number,
                        ),
                        full_path,
                    )
                else:
                    type_index = owners[0][0]
                    target = self._lookup_parameter("TypeDef", type_index, reference.number)
                    if target is None:
                        self._add(
                            "constraint-parameter-target-missing", "error",
                            "VAR[{}] does not resolve to a GenericParam of TypeDef[{}]".format(
                                reference.number, type_index,
                            ),
                            full_path,
                        )
            else:
                self._add(
                    "constraint-parameter-scope-unknown", "unknown",
                    "constraint parameter reference has no valid owner scope",
                    full_path,
                )
        elif reference.kind == "MVAR":
            if source.owner_table == "TypeDef":
                self._add(
                    "method-parameter-in-type-constraint", "error",
                    "a type parameter constraint references MVAR[{}], which is not in type scope".format(
                        reference.number,
                    ),
                    full_path,
                )
            elif source.owner_table == "MethodDef":
                if reference.number == source.number and not reference.in_generic_instance:
                    self._add(
                        "bare-self-parameter-constraint", "error",
                        "method parameter constraint is the parameter itself, not a constructed type",
                        full_path,
                    )
                target = self._lookup_parameter("MethodDef", source.owner_index, reference.number)
                if target is None:
                    self._add(
                        "constraint-parameter-target-missing", "error",
                        "MVAR[{}] does not resolve to a GenericParam of MethodDef[{}]".format(
                            reference.number, source.owner_index,
                        ),
                        full_path,
                    )
            else:
                self._add(
                    "constraint-parameter-scope-unknown", "unknown",
                    "constraint parameter reference has no valid owner scope",
                    full_path,
                )
        if target is not None:
            self.result.edges.append(ConstraintEdge(
                source, target, constraint_row, typespec_row,
                reference.offset, reference.in_generic_instance,
            ))

    # ------------------------------------------------------------------
    # limitations

    def _add_limitations(self) -> None:
        self.result.limitations.append(
            "Type arity is inferred from GenericParam rows; metadata has no independent TypeDef arity field."
        )
        self.result.limitations.append(
            "TypeRef constraints depend on assemblies that were not loaded; their declarations were not checked."
        )
        self.result.limitations.append(
            "Successful metadata parsing does not establish CLR loadability; no runtime binding or verification was performed."
        )
        if any(finding.code == "typespec-cycle" for finding in self.result.findings):
            self.result.limitations.append(
                "A TypeSpec cycle was observed but not treated as an error; its runtime meaning was not decided."
            )


def analyze_generic_constraints(tables: Any) -> GenericAnalysis:
    """Analyze GenericParam/GenericParamConstraint/TypeSpec ownership.

    ``tables`` is normally ``dnPE.net.mdtables`` (a
    :class:`dnfile.stream.MetaDataTables`).  A table-like object exposing
    ``GenericParam``, ``GenericParamConstraint`` and ``TypeSpec`` attributes
    (or a ``tables_list``) is also accepted.

    The result separates structural errors, warnings, and statically
    undetermined facts.  ``result.clr_loadable`` is always ``None``: this
    function proves metadata relationships, not runtime acceptance.
    """
    if tables is None:
        result = GenericAnalysis()
        result.findings.append(Finding(
            "metadata-tables-missing", "unknown",
            "no metadata tables were supplied",
        ))
        result.limitations.append(
            "No metadata was available; no generic relationship could be checked."
        )
        return result
    return _Analyzer(tables).run()


def analyze(pe: Any) -> GenericAnalysis:
    """Convenience wrapper accepting a ``dnfile.dnPE`` or table container."""
    tables = getattr(pe, "mdtables", None)
    if tables is None:
        net = getattr(pe, "net", None)
        tables = getattr(net, "mdtables", None) if net is not None else None
    if tables is None and hasattr(pe, "GenericParam"):
        tables = pe
    return analyze_generic_constraints(tables)

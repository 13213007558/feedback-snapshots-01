"""Assembly and type identity as declared in ECMA-335 metadata.

The distinction this module keeps explicit:

  * declaration  - what an AssemblyRef / TypeRef row literally says;
  * candidate    - what a file on disk says about itself;
  * binding      - what a runtime or an analyst policy decides to load.

`AssemblyRefRow.PublicKey` in dnfile is the *PublicKeyOrToken* blob.  When
AssemblyFlags.afPublicKey (0x0001) is clear the blob is an 8-byte token;
when it is set the blob is a full public key and the token must be derived.
Conflating the two is the most common way to get identity comparison wrong,
so every identity below carries `key_kind` and both forms.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import dnfile

AF_PUBLIC_KEY = 0x0001
AF_RETARGETABLE = 0x0100
AF_PA_MASK = 0x0070
PA_NAMES = {
    0x0000: "unspecified",
    0x0010: "msil",
    0x0020: "x86",
    0x0030: "ia64",
    0x0040: "amd64",
}

TYPE_DEF = 0x02000000
TYPE_REF = 0x01000000
MEMBER_REF = 0x0A000000
ASSEMBLY_REF = 0x23000000


def public_key_token(public_key: bytes) -> bytes:
    """ECMA-335 strong-name token: low 8 bytes of SHA-1, reversed."""
    return hashlib.sha1(public_key).digest()[-8:][::-1]


def normalize_culture(value: str | None) -> str:
    if not value:
        return ""
    if value.strip().lower() == "neutral":
        return ""
    return value


def _row_evidence(pe: Any, row: Any, table: Any) -> dict[str, Any]:
    """Byte-level provenance for one metadata row."""
    offset = row.struct.__file_offset__
    size = table.row_size
    raw = pe.__data__[offset : offset + size]
    return {
        "file_offset": offset,
        "row_size": size,
        "raw_hex": raw.hex(),
        "row_sha256": hashlib.sha256(raw).hexdigest(),
    }


@dataclass(frozen=True)
class AssemblyIdentity:
    name: str
    version: tuple[int, int, int, int]
    culture: str
    key_blob: bytes
    key_kind: str          # "full_key" | "token" | "none" | "ambiguous"
    raw_flags: int = 0
    retargetable: bool = False
    pa: str = "unspecified"
    source: str = "declaration"

    @property
    def version_str(self) -> str:
        return ".".join(str(part) for part in self.version)

    @property
    def culture_norm(self) -> str:
        return normalize_culture(self.culture)

    @property
    def key_kind_effective(self) -> str:
        if self.key_kind == "ambiguous":
            return "ambiguous"
        if not self.key_blob:
            return "none"
        return self.key_kind

    @property
    def token(self) -> bytes | None:
        kind = self.key_kind_effective
        if kind == "token":
            return self.key_blob
        if kind == "full_key":
            return public_key_token(self.key_blob)
        return None

    @property
    def token_hex(self) -> str | None:
        token = self.token
        return token.hex() if token else None

    def canonical(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": list(self.version),
            "culture": self.culture_norm,
            "public_key_token": self.token_hex,
            "key_kind": self.key_kind_effective,
            "retargetable": self.retargetable,
            "pa": self.pa,
        }


def assembly_ref_identity(row: Any, pe: Any | None = None, table: Any | None = None) -> AssemblyIdentity:
    blob = row.PublicKey.value if row.PublicKey is not None else b""
    raw_flags = int(row.struct.Flags)
    is_full = bool(raw_flags & AF_PUBLIC_KEY)

    if not blob:
        key_kind = "none"
    elif is_full:
        key_kind = "full_key"
    elif len(blob) == 8:
        key_kind = "token"
    else:
        # afPublicKey is clear but the blob is not token-shaped.  Preserve the
        # fact instead of guessing: callers must decide how to treat it.
        key_kind = "ambiguous"

    return AssemblyIdentity(
        name=str(row.Name),
        version=(row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber),
        culture=str(row.Culture),
        key_blob=bytes(blob),
        key_kind=key_kind,
        raw_flags=raw_flags,
        retargetable=bool(raw_flags & AF_RETARGETABLE),
        pa=PA_NAMES.get(raw_flags & AF_PA_MASK, "unknown"),
        source="assembly_ref",
    )


def assembly_def_identity(row: Any) -> AssemblyIdentity:
    blob = row.PublicKey.value if row.PublicKey is not None else b""
    return AssemblyIdentity(
        name=str(row.Name),
        version=(row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber),
        culture=str(row.Culture),
        key_blob=bytes(blob),
        key_kind="full_key" if blob else "none",
        raw_flags=int(row.struct.Flags),
        retargetable=bool(int(row.struct.Flags) & AF_RETARGETABLE),
        pa=PA_NAMES.get(int(row.struct.Flags) & AF_PA_MASK, "unknown"),
        source="assembly",
    )


def compare_identities(ref: AssemblyIdentity, cand: AssemblyIdentity) -> dict[str, Any]:
    """Field-by-field comparison with an explicit verdict per field."""
    name_match = ref.name.lower() == cand.name.lower()
    version_cmp = (ref.version > cand.version) - (ref.version < cand.version)
    culture_match = ref.culture_norm.lower() == cand.culture_norm.lower()

    ref_kind, cand_kind = ref.key_kind_effective, cand.key_kind_effective
    if ref_kind == "ambiguous" or cand_kind == "ambiguous":
        token_status = "indeterminate"
    elif ref_kind == "none" and cand_kind == "none":
        token_status = "both_unsigned"
    elif ref_kind == "none":
        token_status = "ref_unsigned_candidate_signed"
    elif cand_kind == "none":
        token_status = "ref_signed_candidate_unsigned"
    elif ref.token == cand.token:
        token_status = "match"
    else:
        token_status = "mismatch"

    if token_status in ("match", "both_unsigned"):
        token_ok = True
    elif token_status == "indeterminate":
        token_ok = None
    else:
        token_ok = False

    return {
        "name": {
            "ref": ref.name,
            "candidate": cand.name,
            "match": name_match,
            "note": "CLR assembly simple names bind case-insensitively",
        },
        "version": {
            "ref": ref.version_str,
            "candidate": cand.version_str,
            "relation": "equal" if version_cmp == 0 else ("ref_older" if version_cmp < 0 else "ref_newer"),
        },
        "culture": {
            "ref": ref.culture_norm or "neutral",
            "candidate": cand.culture_norm or "neutral",
            "match": culture_match,
        },
        "public_key_token": {
            "ref": ref.token_hex,
            "candidate": cand.token_hex,
            "ref_key_kind": ref.key_kind_effective,
            "candidate_key_kind": cand.key_kind_effective,
            "status": token_status,
            "match": token_ok,
        },
    }


def identity_exact(comparison: dict[str, Any]) -> bool:
    return (
        comparison["name"]["match"]
        and comparison["version"]["relation"] == "equal"
        and comparison["culture"]["match"]
        and comparison["public_key_token"]["match"] is True
    )


def assembly_identity(pe: Any) -> AssemblyIdentity | None:
    tables = pe.net.mdtables if pe.net else None
    if tables is None or tables.Assembly is None or not tables.Assembly.rows:
        return None
    return assembly_def_identity(tables.Assembly.rows[0])


@dataclass
class ParsedAssembly:
    path: str
    sha256: str
    identity: AssemblyIdentity | None
    mvid: str | None
    assembly_row_evidence: dict[str, Any] = field(default_factory=dict)
    type_defs: list[dict[str, Any]] = field(default_factory=list)
    methods: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "identity": self.identity.canonical() if self.identity else None,
            "mvid": self.mvid,
            "assembly_row_evidence": self.assembly_row_evidence,
            "type_defs": self.type_defs,
            "methods": self.methods,
        }


def _type_def_full_name(namespace: str, name: str, enclosing: str | None) -> str:
    if enclosing:
        return f"{enclosing}+{name}"
    return f"{namespace}.{name}" if namespace else name


def read_type_defs(pe: Any) -> list[dict[str, Any]]:
    tables = pe.net.mdtables
    if tables.TypeDef is None:
        return []

    nested_parent: dict[int, int] = {}
    if tables.NestedClass is not None:
        for row in tables.NestedClass.rows:
            nested_parent[row.NestedClass.row_index] = row.EnclosingClass.row_index

    rows = tables.TypeDef.rows
    full_names: dict[int, str] = {}
    result: list[dict[str, Any]] = []

    # Enclosing rows always precede nested rows in practice; resolve
    # iteratively so a malformed order cannot loop forever.
    pending = list(range(1, len(rows) + 1))
    guard = 0
    while pending and guard <= len(rows) * 2:
        guard += 1
        remaining = []
        for rid in pending:
            row = rows[rid - 1]
            parent = nested_parent.get(rid)
            if parent is not None and parent not in full_names:
                remaining.append(rid)
                continue
            full_names[rid] = _type_def_full_name(
                str(row.TypeNamespace), str(row.TypeName), full_names.get(parent) if parent else None
            )
        pending = remaining

    for rid, row in enumerate(rows, start=1):
        methods = []
        for method_index in row.MethodList:
            method = method_index.row
            if method is None:
                continue
            methods.append(
                {
                    "rid": method_index.row_index,
                    "token": f"0x{0x06000000 | method_index.row_index:08X}",
                    "name": str(method.Name),
                    "rva": method.Rva,
                    "signature_hex": (
                        bytes(method.Signature.value) if method.Signature is not None else b""
                    ).hex(),
                }
            )
        result.append(
            {
                "rid": rid,
                "token": f"0x{TYPE_DEF | rid:08X}",
                "namespace": str(row.TypeNamespace),
                "name": str(row.TypeName),
                "full_name": full_names.get(rid, str(row.TypeName)),
                "enclosing_rid": nested_parent.get(rid),
                "methods": methods,
                "method_rva": [method["rva"] for method in methods],
            }
        )
    return result


def read_methods(pe: Any) -> list[dict[str, Any]]:
    tables = pe.net.mdtables
    if tables.MethodDef is None:
        return []
    return [
        {
            "rid": rid,
            "token": f"0x{0x06000000 | rid:08X}",
            "name": str(row.Name),
            "rva": row.Rva,
            "signature_hex": bytes(row.Signature.value).hex() if row.Signature is not None else "",
        }
        for rid, row in enumerate(tables.MethodDef.rows, start=1)
    ]


def parse_assembly(path: str, display_path: str | None = None) -> ParsedAssembly:
    with open(path, "rb") as handle:
        data = handle.read()
    pe = dnfile.dnPE(path)
    try:
        identity = assembly_identity(pe)
        mvid = None
        evidence: dict[str, Any] = {}
        if pe.net and pe.net.mdtables.Module is not None and pe.net.mdtables.Module.rows:
            mvid = str(pe.net.mdtables.Module.rows[0].Mvid)
        if pe.net and pe.net.mdtables.Assembly is not None and pe.net.mdtables.Assembly.rows:
            table = pe.net.mdtables.Assembly
            row = table.rows[0]
            evidence = {"table": "Assembly", **_row_evidence(pe, row, table)}
        return ParsedAssembly(
            path=display_path or path,
            sha256=hashlib.sha256(data).hexdigest(),
            identity=identity,
            mvid=mvid,
            assembly_row_evidence=evidence,
            type_defs=read_type_defs(pe),
            methods=read_methods(pe),
        )
    finally:
        pe.close()

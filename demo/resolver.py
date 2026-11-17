"""Static resolution over AssemblyRef / TypeRef / NestedClass.

Three distinct operations, deliberately kept apart:

  declared_view()   what the host's metadata says, with no file lookup.
  resolve()         a *policy* that picks candidates from a fixed file set.
  probe_runtime()   what the .NET binder is configured to do, if we can
                    observe the configuration.  Never inferred.

A resolution result is always tagged with the layer that produced it, and
candidate choices carry the evidence used to make them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

import dnfile

import identity as ident

CONFIDENCE_ORDER = {"exact": 0, "policy": 1, "weak": 2, "ambiguous": 3, "none": 4}

CLR_HEADER_RT_NAMES = {
    0x00000001: "ILONLY",
    0x00000002: "32BITREQUIRED",
    0x00000004: "IL_LIBRARY",
    0x00000008: "STRONGNAMESIGNED",
    0x00000010: "NATIVE_ENTRYPOINT",
    0x00010000: "TRACKDEBUGDATA",
    0x00020000: "PREFER_32BIT",
}


@dataclass
class HostAssemblyRef:
    rid: int
    token: str
    identity: ident.AssemblyIdentity
    evidence: dict[str, Any]
    name_index: int | None = None
    key_blob_index: int | None = None


@dataclass
class HostTypeRef:
    rid: int
    token: str
    scope_kind: str | None
    scope_rid: int | None
    namespace: str
    name: str
    evidence: dict[str, Any]

    @property
    def nested(self) -> bool:
        return self.scope_kind == "TypeRef"


@dataclass
class TypeRefResolution:
    rid: int
    token: str
    display: str
    chain: list[dict[str, Any]]
    anchor_assembly_ref: int | None
    assembly_identity: ident.AssemblyIdentity | None
    status: str                  # resolved | unbalanced | broken_scope
    notes: list[str] = field(default_factory=list)


@dataclass
class CandidateChoice:
    assembly_ref_rid: int
    ref_identity: ident.AssemblyIdentity
    selected: ident.ParsedAssembly | None
    rejected: list[dict[str, Any]]
    policy: str
    confidence: str              # exact | policy | none
    comparison: dict[str, Any] | None = None
    reason: str = ""


def clr_header_flags(pe: Any) -> dict[str, Any]:
    raw = int(pe.net.struct.Flags) if pe.net is not None else 0
    names = [name for bit, name in CLR_HEADER_RT_NAMES.items() if raw & bit]
    return {"raw": hex(raw), "names": names}


def read_host_refs(path: str) -> tuple[list[HostAssemblyRef], list[HostTypeRef], list[dict[str, Any]]]:
    pe = dnfile.dnPE(path)
    try:
        tables = pe.net.mdtables
        refs: list[HostAssemblyRef] = []
        for rid, row in enumerate(tables.AssemblyRef.rows, start=1):
            refs.append(
                HostAssemblyRef(
                    rid=rid,
                    token=f"0x{ident.ASSEMBLY_REF | rid:08X}",
                    identity=ident.assembly_ref_identity(row),
                    evidence={
                        "table": "AssemblyRef",
                        **_row_bytes(pe, row, tables.AssemblyRef),
                        "name_index": row.struct.Name_StringIndex,
                        "key_blob_index": row.struct.PublicKey_BlobIndex,
                        "flags_raw": hex(int(row.struct.Flags)),
                    },
                )
            )

        type_refs: list[HostTypeRef] = []
        for rid, row in enumerate(tables.TypeRef.rows, start=1):
            scope = row.ResolutionScope
            type_refs.append(
                HostTypeRef(
                    rid=rid,
                    token=f"0x{ident.TYPE_REF | rid:08X}",
                    scope_kind=scope.table.name if scope.table is not None else None,
                    scope_rid=scope.row_index if scope.table is not None else None,
                    namespace=str(row.TypeNamespace),
                    name=str(row.TypeName),
                    evidence={
                        "table": "TypeRef",
                        **_row_bytes(pe, row, tables.TypeRef),
                    },
                )
            )

        member_refs: list[dict[str, Any]] = []
        if tables.MemberRef is not None:
            for rid, row in enumerate(tables.MemberRef.rows, start=1):
                parent = row.Class
                member_refs.append(
                    {
                        "rid": rid,
                        "token": f"0x{ident.MEMBER_REF | rid:08X}",
                        "name": str(row.Name),
                        "parent_kind": parent.table.name if parent.table is not None else None,
                        "parent_rid": parent.row_index if parent.table is not None else None,
                        "signature_hex": bytes(row.Signature.value).hex() if row.Signature is not None else "",
                        "evidence": {"table": "MemberRef", **_row_bytes(pe, row, tables.MemberRef)},
                    }
                )
        return refs, type_refs, member_refs
    finally:
        pe.close()


def _row_bytes(pe: Any, row: Any, table: Any) -> dict[str, Any]:
    offset = row.struct.__file_offset__
    size = table.row_size
    raw = pe.__data__[offset : offset + size]
    return {"file_offset": offset, "row_size": size, "raw_hex": raw.hex()}


def declared_view(path: str) -> dict[str, Any]:
    """Everything the host declares, with zero file lookup."""
    refs, type_refs, member_refs = read_host_refs(path)
    pe = dnfile.dnPE(path)
    try:
        header = clr_header_flags(pe)
        asm = ident.assembly_identity(pe)
    finally:
        pe.close()

    by_rid = {ref.rid: ref for ref in refs}
    resolutions: list[TypeRefResolution] = []
    for tr in type_refs:
        resolutions.append(_resolve_type_ref(tr, type_refs, by_rid))

    return {
        "host": path,
        "host_identity": asm.canonical() if asm else None,
        "clr_header_flags": header,
        "assembly_refs": [
            {
                "rid": ref.rid,
                "token": ref.token,
                "identity": ref.identity.canonical(),
                "declared": {
                    "name": ref.identity.name,
                    "version": ref.identity.version_str,
                    "culture": ref.identity.culture_norm or "neutral",
                    "public_key_or_token_hex": ref.identity.key_blob.hex(),
                    "key_kind": ref.identity.key_kind_effective,
                    "derived_token_hex": ref.identity.token_hex,
                    "flags": hex(ref.identity.raw_flags),
                    "retargetable": ref.identity.retargetable,
                    "processor_architecture": ref.identity.pa,
                },
                "evidence": ref.evidence,
            }
            for ref in refs
        ],
        "type_refs": [
            {
                "rid": tr.rid,
                "token": tr.token,
                "namespace": tr.namespace,
                "name": tr.name,
                "scope_kind": tr.scope_kind,
                "scope_rid": tr.scope_rid,
                "nested": tr.nested,
                "evidence": tr.evidence,
            }
            for tr in type_refs
        ],
        "typename_resolution": [_resolution_dict(r) for r in resolutions],
        "member_refs": member_refs,
    }


def _resolve_type_ref(
    tr: HostTypeRef,
    by_rid_number: list[HostTypeRef],
    refs_by_rid: dict[int, HostAssemblyRef],
) -> TypeRefResolution:
    if tr.scope_kind == "AssemblyRef":
        anchor = refs_by_rid.get(tr.scope_rid)
        return TypeRefResolution(
            rid=tr.rid,
            token=tr.token,
            display=_join(tr.namespace, tr.name),
            chain=[{"level": "type", "rid": tr.rid, "name": tr.name, "namespace": tr.namespace},
                   {"level": "assembly_ref", "rid": tr.scope_rid}],
            anchor_assembly_ref=tr.scope_rid,
            assembly_identity=anchor.identity if anchor else None,
            status="resolved" if anchor else "broken_scope",
            notes=[] if anchor else [f"AssemblyRef rid {tr.scope_rid} missing"],
        )

    if tr.scope_kind == "TypeRef":
        # Walk outward through enclosing TypeRefs, then find the assembly.
        # `nodes` is innermost-first and always ends at a TypeRef whose scope
        # is not another TypeRef.
        nodes: list[HostTypeRef] = []
        current: HostTypeRef | None = tr
        seen: set[int] = set()
        while current is not None:
            if current.rid in seen:
                return TypeRefResolution(
                    rid=tr.rid, token=tr.token, display=tr.name,
                    chain=[_type_node(node) for node in nodes],
                    anchor_assembly_ref=None, assembly_identity=None,
                    status="broken_scope", notes=["cycle in TypeRef scopes"],
                )
            seen.add(current.rid)
            nodes.append(current)
            if current.scope_kind != "TypeRef":
                break
            index = current.scope_rid - 1 if current.scope_rid else -1
            current = by_rid_number[index] if 0 <= index < len(by_rid_number) else None

        outermost = nodes[-1]
        if outermost.scope_kind != "AssemblyRef":
            return TypeRefResolution(
                rid=tr.rid, token=tr.token, display=tr.name,
                chain=[_type_node(node) for node in nodes],
                anchor_assembly_ref=None, assembly_identity=None,
                status="broken_scope",
                notes=["nested chain does not end at an AssemblyRef"],
            )

        anchor_rid = outermost.scope_rid
        anchor = refs_by_rid.get(anchor_rid)
        chain = [_type_node(node) for node in reversed(nodes)]
        chain.append({"level": "assembly_ref", "rid": anchor_rid})

        # Nested metadata naming: Outer+Inner, namespace of the outermost type.
        names = [node.name for node in reversed(nodes)]
        display = "+".join(names)
        if outermost.namespace:
            display = f"{outermost.namespace}.{display}"
        return TypeRefResolution(
            rid=tr.rid,
            token=tr.token,
            display=display,
            chain=chain,
            anchor_assembly_ref=anchor_rid,
            assembly_identity=anchor.identity if anchor else None,
            status="resolved" if anchor else "broken_scope",
            notes=[] if anchor else [f"AssemblyRef rid {anchor_rid} missing"],
        )

    return TypeRefResolution(
        rid=tr.rid, token=tr.token, display=_join(tr.namespace, tr.name),
        chain=[{"level": "type", "rid": tr.rid, "name": tr.name, "namespace": tr.namespace},
               {"level": tr.scope_kind or "none", "rid": tr.scope_rid}],
        anchor_assembly_ref=None,
        assembly_identity=None,
        status="no_assembly_anchor" if tr.scope_kind in (None, "Module") else "broken_scope",
        notes=[f"scope is {tr.scope_kind or 'nil'}; no AssemblyRef anchor"],
    )


def _type_node(node: HostTypeRef) -> dict[str, Any]:
    return {"level": "type", "rid": node.rid, "name": node.name, "namespace": node.namespace}


def _join(namespace: str, name: str) -> str:
    return f"{namespace}.{name}" if namespace else name


def _resolution_dict(resolution: TypeRefResolution) -> dict[str, Any]:
    return {
        "rid": resolution.rid,
        "token": resolution.token,
        "display": resolution.display,
        "chain": resolution.chain,
        "anchor_assembly_ref": resolution.anchor_assembly_ref,
        "assembly_identity": (
            resolution.assembly_identity.canonical() if resolution.assembly_identity else None
        ),
        "status": resolution.status,
        "notes": resolution.notes,
    }


# ------------------------------------------------------------------ policies

POLICY_DESCRIPTIONS = {
    "exact_identity": (
        "Select only a candidate whose name, version, culture and public key "
        "token all equal the AssemblyRef. No version substitution."
    ),
    "name_and_token_prefer_highest": (
        "Require name and key token to match; among those choose the highest "
        "version. This is the closest static analogue of the .NET Framework "
        "unification rule, but it is a *policy choice*, not runtime behaviour."
    ),
    "name_only_highest_version": (
        "Require only the simple name and choose the highest version. This is "
        "the aggressive 'latest same-named DLL' redirection and is unsound for "
        "any identity-bearing reference."
    ),
}


def _candidate_reasons(ref: ident.AssemblyIdentity, cand: ident.AssemblyIdentity) -> tuple[bool, dict[str, Any]]:
    comparison = ident.compare_identities(ref, cand)
    return ident.identity_exact(comparison), comparison


def choose_candidate(
    ref: ident.AssemblyIdentity,
    candidates: Iterable[ident.ParsedAssembly],
    policy: str,
) -> CandidateChoice:
    candidates = [c for c in candidates if c.identity is not None]
    rejected: list[dict[str, Any]] = []
    viable: list[tuple[ident.ParsedAssembly, dict[str, Any]]] = []

    for cand in candidates:
        comparison = ident.compare_identities(ref, cand.identity)
        exact = ident.identity_exact(comparison)
        same_name = comparison["name"]["match"]
        token_match = comparison["public_key_token"]["match"]
        version_relation = comparison["version"]["relation"]

        if policy == "exact_identity":
            ok = exact
            why = "exact identity" if exact else "identity differs"
        elif policy == "name_and_token_prefer_highest":
            ok = same_name and token_match is True
            if same_name and token_match is False:
                why = "token differs"
            elif same_name:
                why = "token undecidable (no key on one side)"
            else:
                why = "simple name differs"
        elif policy == "name_only_highest_version":
            ok = same_name
            why = "simple name matches" if ok else "simple name differs"
        else:
            raise ValueError(f"unknown policy: {policy}")

        entry = {
            "path": cand.path,
            "sha256": cand.sha256,
            "identity": cand.identity.canonical(),
            "comparison": comparison,
            "reason": why,
        }
        if ok:
            viable.append((cand, entry))
        else:
            rejected.append(entry)

    if not viable:
        return CandidateChoice(
            assembly_ref_rid=0,
            ref_identity=ref,
            selected=None,
            rejected=rejected,
            policy=policy,
            confidence="none",
            reason="no candidate satisfies the policy",
        )

    # Highest version wins among viable candidates; ties are ambiguous.
    viable.sort(key=lambda item: item[0].identity.version, reverse=True)
    top_version = viable[0][0].identity.version
    tied = [item for item in viable if item[0].identity.version == top_version]

    selected, selected_entry = viable[0]
    comparison = selected_entry["comparison"]
    if ident.identity_exact(comparison):
        confidence = "exact"
        reason = "all four identity fields match"
    elif policy == "name_only_highest_version":
        confidence = "weak"
        reason = "only the simple name matches; version and key token were overridden"
    else:
        confidence = "policy"
        reason = selected_entry["reason"]
    if len(tied) > 1:
        confidence = "ambiguous"
        reason = f"{len(tied)} candidates tie on version; caller must break the tie"

    for cand, entry in viable:
        if cand is not selected:
            # Shadowing compares the candidate with the *winner*, not with the
            # AssemblyRef: several candidates can differ from the ref in
            # different directions yet still be eligible under a loose policy.
            entry["shadowed_by"] = selected.path
            if cand.identity.version != selected.identity.version:
                entry["shadow_reason"] = (
                    f"eligible under policy, but {selected.identity.version_str} "
                    f"outranks {cand.identity.version_str}"
                )
            else:
                entry["shadow_reason"] = "eligible under policy, but tied and not chosen"
            rejected.append(entry)

    return CandidateChoice(
        assembly_ref_rid=0,
        ref_identity=ref,
        selected=selected,
        rejected=rejected,
        policy=policy,
        confidence=confidence,
        comparison=selected_entry["comparison"],
        reason=reason,
    )


def resolve(
    host_path: str,
    candidate_paths: Iterable[str],
    policy: str,
    display_paths: dict[str, str] | None = None,
    display_host: str | None = None,
) -> dict[str, Any]:
    """Resolve every host AssemblyRef against a fixed candidate set."""
    display_paths = display_paths or {}
    parsed = [
        ident.parse_assembly(path, display_paths.get(path, path)) for path in candidate_paths
    ]
    refs, _, member_refs = read_host_refs(host_path)

    choices = []
    chosen_by_ref: dict[int, CandidateChoice] = {}
    for ref in refs:
        choice = choose_candidate(ref.identity, parsed, policy)
        choice.assembly_ref_rid = ref.rid
        chosen_by_ref[ref.rid] = choice
        choices.append(
            {
                "assembly_ref_rid": ref.rid,
                "assembly_ref_token": ref.token,
                "ref_identity": ref.identity.canonical(),
                "policy": choice.policy,
                "confidence": choice.confidence,
                "reason": choice.reason,
                "selected": (
                    {
                        "path": choice.selected.path,
                        "sha256": choice.selected.sha256,
                        "identity": choice.selected.identity.canonical(),
                    }
                    if choice.selected
                    else None
                ),
                "rejected": choice.rejected,
                "comparison": choice.comparison,
            }
        )

    # Re-run type resolution, this time attaching the chosen target's type.
    declared = declared_view(host_path)
    types = []
    for resolution in declared["typename_resolution"]:
        entry = dict(resolution)
        anchor = resolution["anchor_assembly_ref"]
        choice = chosen_by_ref.get(anchor) if anchor else None
        if resolution["status"] == "resolved" and choice is not None:
            entry["candidate"] = (
                {
                    "path": choice.selected.path,
                    "sha256": choice.selected.sha256,
                }
                if choice.selected
                else None
            )
            entry["target_lookup"] = (
                _lookup_type(choice.selected, resolution["display"]) if choice.selected else None
            )
        else:
            entry["candidate"] = None
            entry["target_lookup"] = None
        types.append(entry)

    member_refs = []
    for member in declared["member_refs"]:
        entry = dict(member)
        entry["target"] = None
        chain = _member_chain(entry["parent_rid"], declared["typename_resolution"])
        entry["declaring_type"] = chain
        if chain is not None and chain.get("anchor_assembly_ref") is not None:
            choice = chosen_by_ref.get(chain["anchor_assembly_ref"])
            if choice is not None and choice.selected is not None:
                entry["target"] = _lookup_method(
                    choice.selected, chain["display"], entry["name"], entry["signature_hex"]
                )
        member_refs.append(entry)

    return {
        "host": display_host or host_path,
        "policy": policy,
        "policy_description": POLICY_DESCRIPTIONS[policy],
        "candidates": [assembly.to_dict() for assembly in parsed],
        "assembly_refs": choices,
        "types": types,
        "member_refs": member_refs,
        "clr_header_flags": declared["clr_header_flags"],
        "layer": "static-policy",
        "runtime_claim": "none: no runtime configuration was observed",
    }


def _member_chain(
    parent_rid: int | None, resolutions: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if parent_rid is None:
        return None
    for resolution in resolutions:
        if resolution["rid"] == parent_rid and resolution["status"] == "resolved":
            return resolution
    return None


def _lookup_method(
    candidate: ident.ParsedAssembly,
    type_display: str,
    name: str,
    signature_hex: str,
) -> dict[str, Any]:
    for type_def in candidate.type_defs:
        if type_def["full_name"] != type_display:
            continue
        for method in type_def["methods"]:
            if method["name"] != name:
                continue
            return {
                "found": True,
                "type": type_def["full_name"],
                "type_token": type_def["token"],
                "method_token": method["token"],
                "name": method["name"],
                "signature_hex": method["signature_hex"],
                "rva": method["rva"],
                "signature_matches_ref": method["signature_hex"] == signature_hex,
            }
        return {
            "found": False,
            "type": type_def["full_name"],
            "name": name,
            "reason": "type found, member name absent",
        }
    return {"found": False, "type": type_display, "name": name, "reason": "type absent"}


def _lookup_type(candidate: ident.ParsedAssembly, display: str) -> dict[str, Any]:
    for type_def in candidate.type_defs:
        if type_def["full_name"] == display:
            return {
                "found": True,
                "type_def_rid": type_def["rid"],
                "token": type_def["token"],
                "full_name": type_def["full_name"],
                "method_rvas": type_def["method_rva"],
            }
    return {"found": False, "full_name": display}


def as_text(report: dict[str, Any]) -> str:
    """Deterministic, assertion-friendly text rendering."""
    lines = []
    lines.append(f"host: {report['host']}")
    lines.append(f"layer: {report['layer']}")
    lines.append(f"policy: {report['policy']} - {report['policy_description']}")
    lines.append(f"runtime: {report['runtime_claim']}")
    lines.append("")
    for ref in report["assembly_refs"]:
        ident_ = ref["ref_identity"]
        lines.append(
            f"AssemblyRef[{ref['assembly_ref_rid']}] {ident_['name']} "
            f"{'.'.join(map(str, ident_['version']))} culture={ident_['culture'] or 'neutral'} "
            f"token={ident_['public_key_token'] or '-'} retargetable={ident_['retargetable']}"
        )
        lines.append(f"  policy result: {ref['confidence']} ({ref['reason']})")
        if ref["selected"]:
            sel = ref["selected"]
            lines.append(f"  selected: {sel['path']} sha256={sel['sha256'][:12]}")
            lines.append(
                "  selected identity: "
                f"{sel['identity']['name']} {'.'.join(map(str, sel['identity']['version']))} "
                f"token={sel['identity']['public_key_token'] or '-'}"
            )
        else:
            lines.append("  selected: <none>")
        for rej in ref["rejected"]:
            c = rej["comparison"]
            lines.append(
                f"  rejected: {rej['path']} version={c['version']['candidate']} "
                f"token={c['public_key_token']['candidate'] or '-'} ({rej['reason']})"
            )
        lines.append("")
    for type_ in report["types"]:
        chain = " <- ".join(
            f"{part['level']}:{part.get('rid')}" for part in type_["chain"]
        )
        lines.append(f"TypeRef[{type_['rid']}] {type_['token']} {type_['display']}")
        lines.append(f"  chain: {chain}")
        lines.append(f"  anchor: AssemblyRef[{type_['anchor_assembly_ref']}]")
        if type_["target_lookup"]:
            lookup = type_["target_lookup"]
            if lookup["found"]:
                lines.append(
                    f"  target: {lookup['full_name']} {lookup['token']} "
                    f"methods@rva={lookup['method_rvas']}"
                )
            else:
                lines.append(f"  target: NOT FOUND ({lookup['full_name']})")
        else:
            lines.append("  target: <unresolved>")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"

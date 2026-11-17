"""Assemble the evidence report and its deterministic text rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import conflicts
import identity as ident
import resolver
import runtime_probe


def build_report(
    host_path: str,
    candidate_paths: list[str],
    policy: str,
    display_paths: dict[str, str] | None = None,
    display_host: str | None = None,
) -> dict[str, Any]:
    declared = resolver.declared_view(host_path)
    resolution = resolver.resolve(
        host_path,
        candidate_paths,
        policy,
        display_paths=display_paths,
        display_host=display_host,
    )
    runtime = runtime_probe.probe(host_path, display_host=display_host)

    # Conflicts are evaluated over the resolution, which includes member
    # targets; declared_view supplies the per-assembly-ref member index.
    refs_for_conflicts = []
    for ref in resolution["assembly_refs"]:
        members = []
        for member in resolution["member_refs"]:
            if (
                member["declaring_type"]
                and member["declaring_type"]["anchor_assembly_ref"] == ref["assembly_ref_rid"]
            ):
                members.append(member)
        refs_for_conflicts.append({**ref, "member_refs": members})

    findings = conflicts.detect(
        refs_for_conflicts,
        resolution["candidates"],
        resolution["types"],
        runtime,
    )

    return {
        "schema": "dnfile-retarget-analysis/1",
        "declared": {**declared, "host": display_host or declared["host"]},
        "resolution": resolution,
        "runtime": runtime,
        "conflicts": findings,
        "layer_legend": {
            "declared": "bytes in the host's metadata; no file lookup",
            "static-policy": "an explicit selection rule over a fixed candidate set",
            "runtime-observed": "only what deps.json / runtimeconfig.json / app.config say",
        },
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False, ensure_ascii=False)


def to_text(report: dict[str, Any]) -> str:
    declared = report["declared"]
    resolution = report["resolution"]
    runtime = report["runtime"]
    lines: list[str] = []

    lines.append("=" * 78)
    lines.append("LAYER 1 - DECLARED (host metadata only, no file lookup)")
    lines.append("=" * 78)
    host_id = declared["host_identity"]
    if host_id:
        lines.append(
            f"host assembly: {host_id['name']} {'.'.join(map(str, host_id['version']))} "
            f"culture={host_id['culture'] or 'neutral'} token={host_id['public_key_token'] or '-'}"
        )
    lines.append(f"CLR header flags: {declared['clr_header_flags']['names']}")
    lines.append("")
    for ref in declared["assembly_refs"]:
        d = ref["declared"]
        lines.append(f"AssemblyRef[{ref['rid']}] {ref['token']} {d['name']}")
        lines.append(f"  version   : {d['version']}")
        lines.append(f"  culture   : {d['culture']}")
        lines.append(f"  key blob  : {d['public_key_or_token_hex']}")
        lines.append(f"  key kind  : {d['key_kind']}  (derived token: {d['derived_token_hex']})")
        lines.append(
            f"  flags     : {d['flags']}  retargetable={d['retargetable']}  "
            f"PA={d['processor_architecture']}"
        )
        ev = ref["evidence"]
        lines.append(
            f"  evidence  : file_offset={ev['file_offset']} size={ev['row_size']} "
            f"sha256(row)={__import__('hashlib').sha256(bytes.fromhex(ev['raw_hex'])).hexdigest()[:16]}"
        )
        lines.append("")

    lines.append("TypeRef chains (declared):")
    for type_ in declared["typename_resolution"]:
        chain = " <- ".join(f"{p['level']}#{p.get('rid')}" for p in type_["chain"])
        lines.append(f"  [{type_['rid']}] {type_['display']}  ({type_['status']})  {chain}")
    lines.append("")

    lines.append("=" * 78)
    lines.append("LAYER 2 - STATIC POLICY (explicit rule over a fixed file set)")
    lines.append("=" * 78)
    lines.append(f"policy: {resolution['policy']}")
    lines.append(f"  {resolution['policy_description']}")
    lines.append("")
    lines.append("candidate files (identity as each file declares itself):")
    for cand in resolution["candidates"]:
        cid = cand["identity"]
        if cid is None:
            lines.append(f"  {cand['path']}: no Assembly row")
            continue
        lines.append(
            f"  {cand['path']}\n"
            f"    sha256={cand['sha256']}\n"
            f"    {cid['name']} {'.'.join(map(str, cid['version']))} "
            f"culture={cid['culture'] or 'neutral'} token={cid['public_key_token'] or '-'} "
            f"key_kind={cid['key_kind']}"
        )
        ev = cand["assembly_row_evidence"]
        if ev:
            lines.append(
                f"    Assembly row @ {ev['file_offset']} size={ev['row_size']} "
                f"sha256(row)={__import__('hashlib').sha256(bytes.fromhex(ev['raw_hex'])).hexdigest()[:16]}"
            )
    lines.append("")

    for ref in resolution["assembly_refs"]:
        rid = ref["assembly_ref_rid"]
        rid_id = ref["ref_identity"]
        lines.append(
            f"AssemblyRef[{rid}] {rid_id['name']} {'.'.join(map(str, rid_id['version']))} "
            f"token={rid_id['public_key_token'] or '-'} retargetable={rid_id['retargetable']}"
        )
        lines.append(f"  verdict: {ref['confidence']} - {ref['reason']}")
        if ref["selected"]:
            sel = ref["selected"]
            lines.append(f"  selected: {sel['path']}")
            lines.append(
                f"    {sel['identity']['name']} "
                f"{'.'.join(map(str, sel['identity']['version']))} "
                f"token={sel['identity']['public_key_token'] or '-'}"
            )
        else:
            lines.append("  selected: <none>")
        for rej in ref["rejected"]:
            cmp_ = rej["comparison"]
            note = rej.get("shadow_reason") or rej["reason"]
            lines.append(
                f"  rejected: {rej['path']} version={cmp_['version']['candidate']} "
                f"token={cmp_['public_key_token']['candidate'] or '-'} - {note}"
            )
        lines.append("")

    lines.append("Resolved type identities under this policy:")
    for type_ in resolution["types"]:
        if type_["status"] != "resolved":
            lines.append(f"  TypeRef[{type_['rid']}] {type_['display']}: {type_['status']}")
            continue
        target = type_["target_lookup"]
        if target and target["found"]:
            lines.append(
                f"  TypeRef[{type_['rid']}] {type_['display']} -> "
                f"{target['full_name']} ({target['token']}) in {type_['candidate']['path']}"
            )
        elif target:
            lines.append(
                f"  TypeRef[{type_['rid']}] {type_['display']} -> NOT FOUND in "
                f"{type_['candidate']['path'] if type_['candidate'] else '<none>'}"
            )
        else:
            lines.append(f"  TypeRef[{type_['rid']}] {type_['display']} -> <no candidate>")
    lines.append("")

    lines.append("Resolved method identities under this policy:")
    for member in resolution["member_refs"]:
        target = member["target"]
        if target and target["found"]:
            flag = "ok" if target["signature_matches_ref"] else "SIGNATURE MISMATCH"
            lines.append(
                f"  MemberRef[{member['rid']}] {member['name']}{member['signature_hex']} -> "
                f"{target['type']}::{target['name']}{target['signature_hex']} "
                f"{target['method_token']} [{flag}]"
            )
        elif target:
            lines.append(
                f"  MemberRef[{member['rid']}] {member['name']}{member['signature_hex']} -> "
                f"unresolved ({target.get('reason')})"
            )
        else:
            lines.append(
                f"  MemberRef[{member['rid']}] {member['name']}{member['signature_hex']} -> "
                f"unresolved (no candidate)"
            )
    lines.append("")

    lines.append("=" * 78)
    lines.append("LAYER 3 - RUNTIME (observed configuration only)")
    lines.append("=" * 78)
    lines.append(f"verdict: {runtime['verdict']}")
    lines.append(f"claim  : {runtime['claim']}")
    for source in runtime["sources"]:
        lines.append(f"  source: {json.dumps(source, ensure_ascii=False)}")
    for directive in runtime["directives"]:
        lines.append(f"  directive: {json.dumps(directive, ensure_ascii=False)}")
    if not runtime["configured"]:
        lines.append(
            "  NOTE: no deps.json, runtimeconfig.json, or app.config was present. "
            "No statement about which candidate the CLR actually loads is made."
        )
    lines.append("")

    lines.append("=" * 78)
    lines.append("CONFLICTS REQUIRING A CALLER DECISION")
    lines.append("=" * 78)
    if not report["conflicts"]:
        lines.append("  none detected")
    for finding in report["conflicts"]:
        lines.append(f"- {finding['kind']} [{finding['severity']}]")
        for key, value in finding.items():
            if key in ("kind", "severity"):
                continue
            lines.append(f"    {key}: {value}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_report(report: dict[str, Any], directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "report.json"
    text_path = directory / "report.txt"
    json_path.write_text(to_json(report) + "\n", encoding="utf-8")
    text_path.write_text(to_text(report), encoding="utf-8")
    return json_path, text_path

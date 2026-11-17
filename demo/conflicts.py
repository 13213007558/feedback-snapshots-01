"""Conflicts that a candidate-selection policy must not silently absorb.

Each check returns a record with:
  kind        machine-readable identifier
  severity    "caller_decision" | "warn" | "info"
  question    what the caller must answer, when severity is caller_decision

The intent is to make the *undecidable* parts of redirection explicit rather
than burying them in a score.
"""

from __future__ import annotations

from typing import Any

import identity as ident


def detect(
    refs: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    types: list[dict[str, Any]],
    runtime: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings += _same_simple_name(refs, candidates)
    findings += _same_version_different_key(refs, candidates)
    findings += _retargetable_without_config(refs, runtime)
    findings += _nested_type_ambiguity(types)
    findings += _unsigned_vs_signed(refs, candidates)
    findings += _key_kind_mismatch(refs, candidates)
    findings += _member_signature_drift(refs)
    return findings


def _same_simple_name(refs, candidates) -> list[dict[str, Any]]:
    by_name: dict[str, set[str]] = {}
    for ref in refs:
        by_name.setdefault(ref["ref_identity"]["name"].lower(), set()).add(
            ref["ref_identity"]["public_key_token"] or "unsigned"
        )
    hits = []
    for name, tokens in sorted(by_name.items()):
        if len(tokens) > 1:
            hits.append(
                {
                    "kind": "same_simple_name_multiple_identities",
                    "severity": "caller_decision",
                    "name": name,
                    "distinct_key_tokens": sorted(tokens),
                    "question": (
                        f"The host references '{name}' under {len(tokens)} different "
                        "key tokens. Name-only redirection cannot satisfy both. "
                        "Decide whether to keep per-identity resolution or accept "
                        "one target for both."
                    ),
                }
            )
    return hits


def _same_version_different_key(refs, candidates) -> list[dict[str, Any]]:
    hits = []
    for ref in refs:
        ref_id = ref["ref_identity"]
        for cand in candidates:
            cand_id = cand["identity"]
            if not cand_id:
                continue
            if (
                ref_id["name"].lower() == cand_id["name"].lower()
                and tuple(ref_id["version"]) == tuple(cand_id["version"])
                and (ref_id["public_key_token"] or None) != (cand_id["public_key_token"] or None)
            ):
                hits.append(
                    {
                        "kind": "same_name_and_version_different_key",
                        "severity": "caller_decision",
                        "assembly_ref": ref["assembly_ref_rid"],
                        "candidate": cand["path"],
                        "ref_token": ref_id["public_key_token"],
                        "candidate_token": cand_id["public_key_token"],
                        "question": (
                            "Version cannot disambiguate these two. Treating them as "
                            "interchangeable is a trust decision, not a parsing detail."
                        ),
                    }
                )
    return hits


def _retargetable_without_config(refs, runtime) -> list[dict[str, Any]]:
    hits = []
    for ref in refs:
        if not ref["ref_identity"]["retargetable"]:
            continue
        hits.append(
            {
                "kind": "retargetable_assembly_ref",
                "severity": "caller_decision" if not runtime["configured"] else "warn",
                "assembly_ref": ref["assembly_ref_rid"],
                "name": ref["ref_identity"]["name"],
                "runtime_configured": runtime["configured"],
                "question": (
                    "afRetargetable permits the runtime to bind a different "
                    "publisher/version. No deployment configuration was observed, "
                    "so no specific substitute may be asserted. Decide whether to "
                    "model the retarget or to pin the declared identity."
                )
                if not runtime["configured"]
                else (
                    "afRetargetable is set and deployment configuration exists; "
                    "read the redirect target from the configuration."
                ),
            }
        )
    return hits


def _nested_type_ambiguity(types) -> list[dict[str, Any]]:
    # Only nested references matter here: a top-level TypeRef is already keyed
    # by its AssemblyRef, while a nested TypeRef inherits its parent's anchor.
    by_display: dict[str, list[int]] = {}
    for type_ in types:
        if not _is_nested(type_):
            continue
        by_display.setdefault(type_["display"], []).append(type_["rid"])
    hits = []
    for display, rids in sorted(by_display.items()):
        anchors = {
            type_["anchor_assembly_ref"]
            for type_ in types
            if type_["display"] == display
        }
        if len(anchors) > 1:
            hits.append(
                {
                    "kind": "same_nested_typename_different_assembly_refs",
                    "severity": "caller_decision",
                    "display": display,
                    "type_refs": rids,
                    "anchors": sorted(a for a in anchors if a is not None),
                    "question": (
                        "The same nested type name is referenced through different "
                        "AssemblyRefs. A flat name map collapses two distinct "
                        "identities. Decide whether the analysis is per-anchor or "
                        "name-global."
                    ),
                }
            )
    return hits


def _is_nested(type_: dict[str, Any]) -> bool:
    return sum(1 for part in type_["chain"] if part["level"] == "type") > 1


def _unsigned_vs_signed(refs, candidates) -> list[dict[str, Any]]:
    hits = []
    for ref in refs:
        if ref["ref_identity"]["public_key_token"]:
            continue
        for cand in candidates:
            if not cand["identity"] or not cand["identity"]["public_key_token"]:
                continue
            if ref["ref_identity"]["name"].lower() != cand["identity"]["name"].lower():
                continue
            hits.append(
                {
                    "kind": "unsigned_ref_signed_candidate",
                    "severity": "caller_decision",
                    "assembly_ref": ref["assembly_ref_rid"],
                    "candidate": cand["path"],
                    "question": (
                        "The reference carries no key, the candidate is signed. "
                        "Whether an unsigned reference may bind a signed assembly "
                        "depends on the runtime and on trust policy."
                    ),
                }
            )
    return hits


def _key_kind_mismatch(refs, candidates) -> list[dict[str, Any]]:
    hits = []
    for ref in refs:
        ref_id = ref["ref_identity"]
        if ref_id["key_kind"] == "ambiguous":
            hits.append(
                {
                    "kind": "ambiguous_key_blob",
                    "severity": "caller_decision",
                    "assembly_ref": ref["assembly_ref_rid"],
                    "question": (
                        "afPublicKey is clear but the blob is not 8 bytes. "
                        "It is neither a well-formed token nor a declared full key."
                    ),
                }
            )
        for cand in candidates:
            cand_id = cand["identity"]
            if not cand_id or cand_id["name"].lower() != ref_id["name"].lower():
                continue
            if ref_id["key_kind"] == "full_key" and cand_id["key_kind"] == "token":
                hits.append(
                    {
                        "kind": "ref_full_key_candidate_token",
                        "severity": "info",
                        "assembly_ref": ref["assembly_ref_rid"],
                        "candidate": cand["path"],
                        "note": "token was derived from the reference's full key before comparison",
                    }
                )
    return hits


def _member_signature_drift(refs) -> list[dict[str, Any]]:
    hits = []
    for ref in refs:
        for member in ref.get("member_refs", []):
            target = member.get("target")
            if not target or not target.get("found"):
                continue
            if target.get("signature_matches_ref") is False:
                hits.append(
                    {
                        "kind": "member_ref_signature_mismatch",
                        "severity": "caller_decision",
                        "member_ref": member["token"],
                        "member": member["name"],
                        "declared_signature_hex": member["signature_hex"],
                        "candidate_signature_hex": target["signature_hex"],
                        "candidate_method_token": target["method_token"],
                        "question": (
                            "The selected candidate has a same-named method with a "
                            "different signature. This is exactly how redirection "
                            "changes the method identity an analyst sees. Decide "
                            "whether to accept the candidate or mark the call site "
                            "unresolved."
                        ),
                    }
                )
    return hits

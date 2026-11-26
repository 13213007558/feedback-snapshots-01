"""Version check + handling rules for reading a cached external preview.

The read path distinguishes three required outcomes:

``current``
    Cache was produced under the current rule version -> reuse it (while still
    enforcing field withdrawal against the canonical ticket).

``recleaned``
    Cache is a stale/legacy artifact *and* carries a verifiable original ->
    re-run the current Bleach policy and persist a new cache.

``unverifiable``
    Cache is a stale finished artifact without a provable original (or with a
    broken attestation) -> fail closed and return an explicit status instead of
    serving the old product.

A fourth internal outcome, ``built``, is used for a plain cache miss (there is
no legacy product to distrust, so the authoritative canonical ticket is cleaned
immediately).
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import policy

DECISION_CURRENT = "current"
DECISION_RECLEANED = "recleaned"
DECISION_UNVERIFIABLE = "unverifiable"
DECISION_BUILT = "built"

DECISION_TEXT_ZH = {
    DECISION_CURRENT: "沿用现行规则缓存",
    DECISION_RECLEANED: "依现行规则重新清洗",
    DECISION_UNVERIFIABLE: "暂时无法确认，已暂缓外部预览",
    DECISION_BUILT: "无缓存，已按现行规则生成",
}

HTTP_STATUS_SERVED = 200
HTTP_STATUS_UNVERIFIABLE = 422


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _combine(parts: dict, order=None) -> str:
    """Join cleaned fragments strictly in the authoritative field order.

    Keys absent from ``order`` are never appended: field scope is an allowlist,
    so an unexpected cached part cannot slip into the public page.
    """
    if order:
        return "\n".join(parts[key] for key in order if parts.get(key))
    return "\n".join(value for value in parts.values() if value)


def build_current_envelope(ticket, *, reason="authoritative-build"):
    """Clean the canonical public fields under the current policy."""
    ticket_id = ticket["id"]
    withdrawn = set((ticket.get("withdrawn_fields") or {}).keys())
    order = list(ticket.get("public_field_order") or [])
    raw = ticket.get("raw") or {}

    parts = {}
    redacted = []
    for key in order:
        if key in withdrawn:
            redacted.append(key)
            continue
        parts[key] = policy.clean_public(raw.get(key, ""))

    envelope = {
        "ticket_id": ticket_id,
        "rule_version": policy.POLICY_VERSION,
        "policy": policy.POLICY_VERSION_LABEL,
        "cached_at": _now(),
        "bleach_version": policy.bleach_version(),
        "build_reason": reason,
        "parts": parts,
        "html": _combine(parts, order),
    }
    return envelope, sorted(redacted)


def _base_receipt(ticket, envelope, load_error):
    cached_version = None
    if isinstance(envelope, dict):
        cached_version = envelope.get("rule_version")
    return {
        "ticket_id": ticket.get("id"),
        "rule_version_current": policy.POLICY_VERSION,
        "rule_version_cached": cached_version,
        "policy_current": policy.POLICY_VERSION_LABEL,
        "bleach_version": policy.bleach_version(),
        "cache_present": envelope is not None,
        "load_error": load_error,
        "withdrawn_fields": sorted(
            (ticket.get("withdrawn_fields") or {}).keys()
        ),
        "redacted_withdrawn": [],
        "source_present": False,
        "source_verified": False,
    }


def _result(decision, http_status, receipt, *, html=None, persist_envelope=None):
    receipt["decision"] = decision
    receipt["decision_zh"] = DECISION_TEXT_ZH[decision]
    receipt["served"] = html is not None
    return {
        "decision": decision,
        "decision_zh": DECISION_TEXT_ZH[decision],
        "http_status": http_status,
        "served": html is not None,
        "html": html,
        "receipt": receipt,
        "persist_envelope": persist_envelope,
    }


def evaluate_preview(ticket, envelope, load_error=None):
    """Return a decision result for one ticket + its loaded cache envelope."""
    receipt = _base_receipt(ticket, envelope, load_error)
    withdrawn = set((ticket.get("withdrawn_fields") or {}).keys())
    public_order = list(ticket.get("public_field_order") or [])
    public_scope = set(public_order)

    # Unreadable cache bytes: fail closed; never eval/serve unknown content.
    if load_error:
        receipt["reason"] = load_error
        return _result(
            DECISION_UNVERIFIABLE,
            HTTP_STATUS_UNVERIFIABLE,
            receipt,
        )

    # Clean cache miss: no legacy product to distrust, build from authority.
    if envelope is None:
        new_envelope, redacted = build_current_envelope(
            ticket, reason="cache-miss-build"
        )
        receipt["redacted_withdrawn"] = redacted
        receipt["reason"] = "cache-miss-built-from-canonical-ticket"
        return _result(
            DECISION_BUILT,
            HTTP_STATUS_SERVED,
            receipt,
            html=new_envelope["html"],
            persist_envelope=new_envelope,
        )

    cached_version = envelope.get("rule_version")
    if not isinstance(cached_version, int):
        # Unversioned/unknown records are treated as the oldest legacy product.
        cached_version = policy.LEGACY_POLICY_VERSION
        receipt["rule_version_cached"] = cached_version
        receipt["version_inferred"] = True

    # ------------------------------------------------------------------
    # Current-rule cache -> reuse, but always enforce field withdrawal.
    # ------------------------------------------------------------------
    if cached_version >= policy.POLICY_VERSION:
        parts = envelope.get("parts")
        if not isinstance(parts, dict):
            # Without field-keyed parts we cannot prove a withdrawn field is
            # absent from the cached html, so fail closed.
            receipt["reason"] = "current-cache-missing-parts-for-withdrawal-guard"
            return _result(
                DECISION_UNVERIFIABLE,
                HTTP_STATUS_UNVERIFIABLE,
                receipt,
            )

        redacted = sorted(withdrawn & set(parts.keys()))
        receipt["redacted_withdrawn"] = redacted
        receipt["reason"] = (
            "cache-current-reuse-with-withdrawal-filter"
            if redacted
            else "cache-current-reuse"
        )

        if redacted:
            filtered = {
                key: value
                for key, value in parts.items()
                if key not in withdrawn
            }
            html = _combine(filtered, public_order)
        else:
            # No withdrawn field is present as a cached part: the cached
            # finished html is safe to reuse verbatim.
            html = envelope.get("html") or _combine(parts, public_order)

        return _result(
            DECISION_CURRENT,
            HTTP_STATUS_SERVED,
            receipt,
            html=html,
        )

    # ------------------------------------------------------------------
    # Stale / legacy artifact.  Rebuild only from a provable original.
    # ------------------------------------------------------------------
    original = envelope.get("original")
    has_original = (
        isinstance(original, dict)
        and isinstance(original.get("parts"), dict)
        and bool(original.get("parts"))
    )
    receipt["source_present"] = has_original

    if not has_original:
        receipt["reason"] = "stale-version-missing-original"
        return _result(
            DECISION_UNVERIFIABLE,
            HTTP_STATUS_UNVERIFIABLE,
            receipt,
        )

    if not policy.verify_original(original):
        receipt["source_verified"] = False
        receipt["reason"] = "original-digest-mismatch"
        return _result(
            DECISION_UNVERIFIABLE,
            HTTP_STATUS_UNVERIFIABLE,
            receipt,
        )

    receipt["source_verified"] = True
    raw_parts = original["parts"]

    rebuilt_parts = {}
    redacted = []
    excluded_scope = []
    for key, raw_value in raw_parts.items():
        if key in withdrawn:
            redacted.append(key)
            continue
        if key not in public_scope:
            excluded_scope.append(key)
            continue
        rebuilt_parts[key] = policy.clean_public(raw_value)

    receipt["redacted_withdrawn"] = sorted(redacted)
    receipt["excluded_out_of_scope"] = sorted(excluded_scope)
    receipt["reason"] = "stale-version-rebuilt-from-attested-original"

    html = _combine(rebuilt_parts, public_order)

    new_envelope = {
        "ticket_id": ticket.get("id"),
        "rule_version": policy.POLICY_VERSION,
        "policy": policy.POLICY_VERSION_LABEL,
        "cached_at": _now(),
        "bleach_version": policy.bleach_version(),
        "build_reason": "reclean-legacy-with-original",
        "rebuilt_from_version": cached_version,
        "parts": rebuilt_parts,
        "html": html,
        # Carry the attested original forward so future rule bumps can rebuild.
        "original": original,
    }

    return _result(
        DECISION_RECLEANED,
        HTTP_STATUS_SERVED,
        receipt,
        html=html,
        persist_envelope=new_envelope,
    )

"""
Build shareable forensics reports from an OpenFGA Expand response.

The builder takes the in-memory SDK models returned by ``expand`` plus the
tuples read to substantiate them, and produces two artifacts:

* a public, shareable :class:`ForensicsReport` in which every internal subject
  reference is replaced by a stable public id;
* an :class:`InternalInvestigation` that keeps the raw Expand response and the
  subject reverse mapping for internal re-checking.

Tree children and evidence lists are always emitted in a canonical order, so
two responses whose children arrive in different orders still serialize to
directly comparable reports.
"""

import hashlib
import json
import re

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from openfga_sdk.forensics.identifiers import (
    DEFAULT_PUBLIC_ID_PREFIX,
    SubjectRegistry,
    evidence_identifier,
)
from openfga_sdk.forensics.models import (
    REPORT_SCHEMA_VERSION,
    ForensicsReport,
    InternalInvestigation,
)
from openfga_sdk.models.expand_response import ExpandResponse


_CONTAINER_KINDS = ("union", "intersection")
_OBJECT_REF_PATTERN = re.compile(r"[A-Za-z0-9_\-*.]+:[^\s#<>()\[\]{}]+")


def _plain(value: Any) -> Any:
    """Convert SDK model instances to plain dicts without mutating input."""
    if value is None:
        return None
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return value


class ForensicsBuilder:
    """
    Construct a shareable report from Expand data.

    :param internal_types: object types whose references must be replaced by
        public ids everywhere in the shareable report.
    :param salt: scopes public ids to one report family; keep it stable across
        the two reports that need to be compared.
    :param display_name_resolver: optional callable mapping an object reference
        to a non-authoritative display name. Names never influence identity.
    """

    def __init__(
        self,
        *,
        internal_types: tuple[str, ...] = ("user", "employee"),
        salt: str = "",
        display_name_resolver: Callable[[str], str | None] | None = None,
        generated_at: datetime | None = None,
    ) -> None:
        self.internal_types = tuple(internal_types)
        self.salt = salt
        self.display_name_resolver = display_name_resolver
        self.generated_at = generated_at or datetime.now(timezone.utc)
        self.registry = SubjectRegistry(
            salt=salt,
            prefix=DEFAULT_PUBLIC_ID_PREFIX,
            display_name_resolver=display_name_resolver,
        )
        self._evidence_by_id: dict[str, dict] = {}
        self._evidence_index: dict[tuple, list[dict]] = {}
        self._raw_relation_keys: dict[str, dict] = {}
        self.unconfirmed_branches: list[dict] = []
        self.relations_read: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # identity and redaction
    # ------------------------------------------------------------------
    def _is_internal_ref(self, object_ref: str) -> bool:
        return object_ref.split(":", 1)[0] in self.internal_types

    def _public_ref(self, object_ref: str) -> str:
        """
        Return the public form of an object reference.

        Internal subjects become public ids; non-internal objects keep their
        original reference because they are not internal accounts.
        """
        if self._is_internal_ref(object_ref):
            return self.registry.public_id(object_ref)
        return object_ref

    def _redact_text(self, text: str) -> str:
        """Replace every internal object reference embedded in a string."""

        def replace(match: re.Match) -> str:
            ref = match.group(0)
            if self._is_internal_ref(ref):
                return self.registry.public_id(ref)
            return ref

        return _OBJECT_REF_PATTERN.sub(replace, text)

    # ------------------------------------------------------------------
    # evidence handling
    # ------------------------------------------------------------------
    def _register_evidence(self, tuple_model: Any) -> dict:
        raw_tuple = (
            tuple_model.to_dict()
            if hasattr(tuple_model, "to_dict")
            else dict(tuple_model)
        )
        key = raw_tuple.get("key", raw_tuple)
        key = _plain(key)
        user = key.get("user", "")
        relation = key.get("relation", "")
        obj = key.get("object", "")

        evidence_id = evidence_identifier(key, salt=self.salt)
        if evidence_id in self._evidence_by_id:
            return self._evidence_by_id[evidence_id]

        observed_at = raw_tuple.get("timestamp")
        if isinstance(observed_at, datetime):
            observed_at = observed_at.isoformat()

        public_tuple = {
            "user": self._public_ref(user),
            "relation": relation,
            "object": obj,
        }
        record = {
            "evidence_id": evidence_id,
            "public_tuple": public_tuple,
            "observed_at": observed_at,
            "status": "observed",
        }
        self._evidence_by_id[evidence_id] = record
        self._evidence_index.setdefault((relation, obj), []).append(record)
        self._evidence_index.setdefault((user, relation, obj), []).append(record)
        self._raw_relation_keys[evidence_id] = {
            "user": user,
            "relation": relation,
            "object": obj,
        }
        return record

    def _matching_evidence(
        self,
        *,
        user: str | None = None,
        relation: str | None = None,
        obj: str | None = None,
    ) -> list[dict]:
        if user is not None:
            matches = self._evidence_index.get((user, relation, obj), [])
        else:
            matches = [
                record
                for record in self._evidence_index.get((relation, obj), [])
                if record["status"] == "observed"
            ]
        return sorted(matches, key=lambda record: record["evidence_id"])

    def _mark_unconfirmed(
        self,
        path: list[str],
        reason: str,
        *,
        userset: str | None = None,
        expected: dict | None = None,
    ) -> None:
        branch: dict[str, Any] = {
            "path": [self._redact_text(step) for step in path],
            "reason": reason,
        }
        if userset is not None:
            branch["userset"] = self._redact_text(userset)
        if expected is not None:
            branch["expected_relation"] = {
                key: self._redact_text(value) if isinstance(value, str) else value
                for key, value in expected.items()
            }
        self.unconfirmed_branches.append(branch)

    # ------------------------------------------------------------------
    # tree walking
    # ------------------------------------------------------------------
    def _walk_node(
        self,
        node: dict | None,
        path: list[str],
        parent_operator: str | None = None,
    ) -> dict | None:
        if node is None:
            return None

        name = node.get("name", "")
        current_path = [*path, name]
        result: dict[str, Any] = {
            "userset": self._redact_text(name),
            "path": [self._redact_text(step) for step in current_path],
        }

        leaf = node.get("leaf")
        if leaf is not None:
            result["leaf"] = self._walk_leaf(leaf, current_path, name)
            result["node_id"] = self._stable_node_id(result)
            return result

        difference = node.get("difference")
        if difference is not None:
            result["operator"] = "difference"
            result["children"] = {
                "base": self._walk_node(difference.get("base"), current_path),
                "subtract": self._walk_node(
                    difference.get("subtract"), current_path, "difference.subtract"
                ),
            }
            result["node_id"] = self._stable_node_id(result)
            return result

        for kind in _CONTAINER_KINDS:
            container = node.get(kind)
            if container is not None:
                children = container.get("nodes", [])
                walked = [
                    child
                    for child in (
                        self._walk_node(child, current_path, kind) for child in children
                    )
                    if child is not None
                ]
                walked.sort(key=lambda child: child["node_id"])
                result["operator"] = kind
                result["children"] = walked
                result["node_id"] = self._stable_node_id(result)
                return result

        result["operator"] = "unknown"
        result["node_id"] = self._stable_node_id(result)
        self._mark_unconfirmed(
            current_path,
            "unrecognized_node_shape",
            userset=name,
        )
        return result

    def _walk_leaf(self, leaf: dict, path: list[str], userset: str) -> dict[str, Any]:
        users = leaf.get("users")
        if users is not None:
            return self._walk_users_leaf(users, path, userset)

        computed = leaf.get("computed")
        if computed is not None:
            return self._walk_computed_leaf(computed, path, userset)

        tuple_to_userset = leaf.get("tuple_to_userset")
        if tuple_to_userset is not None:
            return self._walk_tuple_to_userset_leaf(tuple_to_userset, path, userset)

        self._mark_unconfirmed(path, "empty_leaf", userset=userset)
        return {"kind": "empty", "status": "unconfirmed"}

    def _walk_users_leaf(
        self, users: dict, path: list[str], userset: str
    ) -> dict[str, Any]:
        object_ref = _userset_object(userset)
        relation = _userset_relation(userset)
        member_refs = sorted(users.get("users", []))
        members = []
        missing = []

        for member_ref in member_refs:
            evidence = self._matching_evidence(
                user=member_ref, relation=relation, obj=object_ref
            )
            public_member = self._public_ref(member_ref)
            if self.display_name_resolver is not None:
                name = self.display_name_resolver(member_ref)
                if name:
                    self.registry.record_display_name(member_ref, name)
            member = {
                "public_user": public_member,
                "evidence_ids": [record["evidence_id"] for record in evidence],
                "status": "confirmed" if evidence else "unconfirmed",
            }
            members.append(member)
            if not evidence:
                missing.append(member_ref)

        members.sort(key=lambda member: member["public_user"])
        status = "confirmed" if members and not missing else "unconfirmed"
        if missing:
            self._mark_unconfirmed(
                path,
                "missing_relationship_evidence",
                userset=userset,
                expected={
                    "object": object_ref,
                    "relation": relation,
                    "users": [self._public_ref(ref) for ref in missing],
                },
            )
        return {"kind": "users", "status": status, "members": members}

    def _walk_computed_leaf(
        self, computed: dict, path: list[str], userset: str
    ) -> dict[str, Any]:
        target = computed.get("userset", "")
        object_ref = _userset_object(userset)
        relation = target.split("#", 1)[1] if "#" in target else target
        evidence = self._matching_evidence(relation=relation, obj=object_ref)
        status = "confirmed" if evidence else "unconfirmed"
        if not evidence:
            self._mark_unconfirmed(
                path,
                "no_evidence_for_computed_userset",
                userset=userset,
                expected={"object": object_ref, "relation": relation},
            )
        return {
            "kind": "computed",
            "target_userset": self._redact_text(target),
            "evidence_ids": [record["evidence_id"] for record in evidence],
            "status": status,
        }

    def _walk_tuple_to_userset_leaf(
        self, t2u: dict, path: list[str], userset: str
    ) -> dict[str, Any]:
        object_ref = _userset_object(userset)
        tupleset_relation = t2u.get("tupleset", "")
        computed_targets = sorted(
            item.get("userset", "") for item in t2u.get("computed", [])
        )
        tupleset_evidence = self._matching_evidence(
            relation=tupleset_relation, obj=object_ref
        )
        downstream = [self._redact_text(target) for target in computed_targets]
        status = "confirmed" if tupleset_evidence else "unconfirmed"
        if not tupleset_evidence:
            self._mark_unconfirmed(
                path,
                "no_evidence_for_tupleset",
                userset=userset,
                expected={"object": object_ref, "relation": tupleset_relation},
            )
        return {
            "kind": "tuple_to_userset",
            "tupleset_relation": tupleset_relation,
            "computed_usersets": downstream,
            "evidence_ids": [record["evidence_id"] for record in tupleset_evidence],
            "status": status,
        }

    def _stable_node_id(self, public_node: dict) -> str:
        """
        Content-derived id built from the redacted, canonicalized node so
        reordered siblings keep identical node ids across reports.
        """
        payload = _canonical_json(public_node)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return f"node_{digest[:12]}"

    def _canonical_relations_read(self, entries: list[dict]) -> list[dict]:
        normalized = []
        for entry in entries:
            item = dict(entry)
            if isinstance(item.get("relations"), list):
                item["relations"] = sorted(item["relations"])
            normalized.append(item)
        normalized.sort(key=lambda item: _canonical_json(item))
        return normalized

    # ------------------------------------------------------------------
    # report assembly
    # ------------------------------------------------------------------
    def build(
        self,
        *,
        request: Any,
        expand_response: ExpandResponse,
        evidence_tuples: list[Any],
        authorization_model: Any | None = None,
        relations_read: list[dict[str, Any]] | None = None,
    ) -> InternalInvestigation:
        for tuple_model in evidence_tuples:
            self._register_evidence(tuple_model)
        self.relations_read = self._canonical_relations_read(
            _plain(relations_read or [])
        )

        raw_tree = (
            expand_response.tree.to_dict()
            if hasattr(expand_response.tree, "to_dict")
            else dict(expand_response.tree)
        )
        public_tree = {"root": self._walk_node(raw_tree.get("root"), [])}

        evidence = sorted(
            self._evidence_by_id.values(),
            key=lambda record: record["evidence_id"],
        )
        self.unconfirmed_branches.sort(key=lambda branch: _canonical_json(branch))
        collisions = self.registry.display_name_collisions()

        redaction = {
            "internal_types": list(self.internal_types),
            "rule": "internal object references are replaced by stable public "
            "subject ids; identity is keyed on '<type>:<id>', never on display "
            "name",
            "public_id_algorithm": "sha256(salt + object_ref) truncated to 10 hex",
        }
        confirmed_evidence = sum(
            1 for record in evidence if record["status"] == "observed"
        )
        summary = {
            "evidence_records": len(evidence),
            "confirmed_evidence_records": confirmed_evidence,
            "subject_count": len(self.registry.raw_mapping()),
            "unconfirmed_branch_count": len(self.unconfirmed_branches),
            "display_name_collision_count": len(collisions),
        }

        model_dict = _plain(authorization_model)
        report = ForensicsReport(
            schema_version=REPORT_SCHEMA_VERSION,
            report_id=self._report_id(request, public_tree, evidence),
            generated_at=self.generated_at.isoformat(),
            request=self._public_request(request),
            authorization_model=model_dict,
            relations_read=self.relations_read,
            tree=public_tree,
            evidence=evidence,
            subjects=self.registry.public_records(),
            unconfirmed_branches=self.unconfirmed_branches,
            display_name_collisions=collisions,
            redaction=redaction,
            summary=summary,
        )
        investigation = InternalInvestigation(
            report=report,
            raw_expand={"tree": _plain(raw_tree)},
            raw_evidence=[
                self._raw_relation_keys[record["evidence_id"]] for record in evidence
            ],
            subject_mapping=self.registry.raw_mapping(),
        )
        _assert_no_internal_leak(investigation.public_report(), self.internal_types)
        return investigation

    def _public_request(self, request: Any) -> dict:
        plain_request = _plain(request)
        tuple_key = plain_request.get("tuple_key", plain_request)
        return {
            "store_id": plain_request.get("store_id"),
            "tuple_key": {
                "relation": tuple_key.get("relation"),
                "object": tuple_key.get("object"),
            },
            "authorization_model_id": plain_request.get("authorization_model_id"),
            "consistency": plain_request.get("consistency"),
        }

    def _report_id(self, request: Any, tree: dict, evidence: list[dict]) -> str:
        payload = _canonical_json(
            {
                "request": self._public_request(request),
                "tree": tree,
                "evidence": [
                    self._raw_relation_keys[record["evidence_id"]]
                    for record in evidence
                ],
            }
        )
        return f"rpt_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def _userset_object(userset: str) -> str:
    return userset.split("#", 1)[0] if "#" in userset else userset


def _userset_relation(userset: str) -> str:
    return userset.split("#", 1)[1] if "#" in userset else ""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _assert_no_internal_leak(
    public_report: dict, internal_types: tuple[str, ...]
) -> None:
    leaked: list[str] = []

    def scan(value: Any) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                scan(nested)
        elif isinstance(value, list):
            for nested in value:
                scan(nested)
        elif isinstance(value, str):
            for match in _OBJECT_REF_PATTERN.findall(value):
                if match.split(":", 1)[0] in internal_types:
                    leaked.append(match)

    scan(public_report)
    if leaked:
        raise ValueError(
            "Refusing to export report: internal references leaked into public "
            f"output: {sorted(set(leaked))}"
        )


def build_forensics_report(
    *,
    request: Any,
    expand_response: ExpandResponse,
    evidence_tuples: list[Any],
    authorization_model: Any | None = None,
    relations_read: list[dict[str, Any]] | None = None,
    internal_types: tuple[str, ...] = ("user", "employee"),
    salt: str = "",
    display_name_resolver: Callable[[str], str | None] | None = None,
    generated_at: datetime | None = None,
) -> InternalInvestigation:
    """Convenience wrapper around :class:`ForensicsBuilder`."""
    builder = ForensicsBuilder(
        internal_types=internal_types,
        salt=salt,
        display_name_resolver=display_name_resolver,
        generated_at=generated_at,
    )
    return builder.build(
        request=request,
        expand_response=expand_response,
        evidence_tuples=evidence_tuples,
        authorization_model=authorization_model,
        relations_read=relations_read,
    )

# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Evidence model for shadow policy checks.

A shadow check runs the *same* authorization input against both the approved
policy version (the one that drives the real business decision) and a candidate
policy version that is being evaluated for promotion.  The candidate response is
allowed to be late or fail without ever affecting the approved response.

The comparison can only reach one of three conclusions, represented by
:class:`ShadowOutcome`:

* ``MATCH`` - both versions produced a concrete, identical answer for this use
  case.
* ``DIFFER`` - both versions produced concrete answers and they disagree.
* ``INCONCLUSIVE`` - the candidate produced no usable answer (it timed out,
  failed or returned an undefined plan result), so no comparison can be made.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cerbos.sdk.model import Effect, PlanResourcesFilterKind, PlanResourcesResponse


class ShadowOutcome(str, Enum):
    """Conclusion reached when comparing the two policy versions."""

    MATCH = "MATCH"
    DIFFER = "DIFFER"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ShadowCheckReport:
    """Result of shadowing a single ``check_resources`` action.

    Attributes:
        resource_id: identifier of the resource that was checked.
        action: the action whose effect was compared.
        approved_effect: effect returned by the approved policy version. This
            is the effect that the business actually enforces.
        candidate_effect: effect returned by the candidate version, or ``None``
            when the candidate did not produce a usable answer.
        outcome: the comparison conclusion.
        error: an error message explaining why the candidate was inconclusive
            (for example a timeout), or ``None``.
    """

    resource_id: str
    action: str
    approved_effect: Effect
    candidate_effect: Effect | None
    outcome: ShadowOutcome
    error: str | None = None

    @property
    def source(self) -> dict[str, Any]:
        """Which version each effect came from."""
        return {
            "approved": self.approved_effect,
            "candidate": self.candidate_effect,
        }


@dataclass
class ShadowPlanResourceReport:
    """Plan comparison evaluated against one concrete resource.

    Attributes:
        resource_id: identifier of the resource the plans were evaluated on.
        approved_decision: concrete boolean the approved plan resolves to for
            this resource, or ``None`` when the plan cannot be decided because
            a required attribute is missing.
        candidate_decision: concrete boolean the candidate plan resolves to, or
            ``None`` when it cannot be decided / did not answer.
        outcome: the comparison conclusion.
        error: an error message when the candidate plan was unavailable.
    """

    resource_id: str
    approved_decision: bool | None
    candidate_decision: bool | None
    outcome: ShadowOutcome
    error: str | None = None

    @property
    def source(self) -> dict[str, Any]:
        """Which version each decision came from."""
        return {
            "approved": self.approved_decision,
            "candidate": self.candidate_decision,
        }


@dataclass
class ShadowPlanReport:
    """Result of shadowing a ``plan_resources`` call.

    The raw plans are retained so that reviewers can see the two sources even
    when their expression ordering differs.  ``resource_reports`` holds the
    per-resource evaluation, and ``outcome`` is the worst conclusion observed
    across those resources (``DIFFER`` wins over ``INCONCLUSIVE`` which wins
    over ``MATCH``).
    """

    action: str | list[str]
    resource_kind: str
    approved_plan: PlanResourcesResponse
    candidate_plan: PlanResourcesResponse | None
    resource_reports: list[ShadowPlanResourceReport] = field(default_factory=list)
    outcome: ShadowOutcome = ShadowOutcome.MATCH
    error: str | None = None

    @property
    def filter_kinds(self) -> dict[str, PlanResourcesFilterKind | None]:
        """The filter kind emitted by each policy version."""
        candidate_kind = (
            None
            if self.candidate_plan is None or self.candidate_plan.filter is None
            else self.candidate_plan.filter.kind
        )
        approved_kind = (
            None
            if self.approved_plan is None or self.approved_plan.filter is None
            else self.approved_plan.filter.kind
        )
        return {"approved": approved_kind, "candidate": candidate_kind}


@dataclass
class ShadowAuditEntry:
    """One recorded shadow operation, for audit consumption."""

    operation: str
    request_id: str
    outcome: ShadowOutcome
    check_reports: list[ShadowCheckReport] = field(default_factory=list)
    plan_report: ShadowPlanReport | None = None
    error: str | None = None

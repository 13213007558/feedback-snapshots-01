#!/usr/bin/env python
"""Unit tests for the time bounded audience migration policy."""

import calendar
import time

from saml2 import saml
from saml2.audience_migration import AudienceEntry
from saml2.audience_migration import AudienceMigrationDecision
from saml2.audience_migration import AudienceMigrationPolicy
from saml2.audience_migration import Clock
from saml2.audience_migration import MigrationWindow
from saml2.time_util import str_to_time


IDP_A = "https://idp-a.example.com"
IDP_B = "https://idp-b.example.com"

LEGACY_AUDIENCE = "urn:mace:example.com:portal"
ENTRY_A = "https://portal.example.com/brand/a"
ENTRY_B = "https://portal.example.com/brand/b"

# Window is open during June 2026 and closed afterwards.
WINDOW_START = "2026-06-01T00:00:00Z"
WINDOW_END = "2026-07-01T00:00:00Z"

DURING_WINDOW = "2026-06-15T12:00:00Z"
BEFORE_WINDOW = "2026-05-15T12:00:00Z"
AFTER_WINDOW = "2026-07-02T12:00:00Z"


def fake_clock(when):
    struct = str_to_time(when)
    return Clock(now=lambda: struct)


def build_policy(when, entries=None):
    entries = entries or {
        ENTRY_A: {"legacy_audiences": [LEGACY_AUDIENCE], "issuers": [IDP_A]},
        ENTRY_B: {"legacy_audiences": [LEGACY_AUDIENCE], "issuers": [IDP_A, IDP_B]},
    }
    return AudienceMigrationPolicy(
        {"window": {"start": WINDOW_START, "end": WINDOW_END}, "entries": entries},
        clock=fake_clock(when),
    )


def conditions_with_audiences(*audiences):
    return saml.Conditions(
        audience_restriction=[
            saml.AudienceRestriction(audience=[saml.Audience(text=value) for value in group])
            for group in audiences
        ]
    )


class TestMigrationWindow:
    def test_open_inside_window(self):
        window = MigrationWindow(WINDOW_START, WINDOW_END, clock=fake_clock(DURING_WINDOW))
        assert window.is_open() is True

    def test_closed_before_start(self):
        window = MigrationWindow(WINDOW_START, WINDOW_END, clock=fake_clock(BEFORE_WINDOW))
        assert window.is_open() is False

    def test_closed_after_end(self):
        window = MigrationWindow(WINDOW_START, WINDOW_END, clock=fake_clock(AFTER_WINDOW))
        assert window.is_open() is False

    def test_end_is_exclusive(self):
        window = MigrationWindow(WINDOW_START, WINDOW_END, clock=fake_clock(WINDOW_END))
        assert window.is_open() is False

    def test_open_ended_window(self):
        window = MigrationWindow(WINDOW_START, None, clock=fake_clock(AFTER_WINDOW))
        assert window.is_open() is True

    def test_window_state_tracks_injected_clock(self):
        clock = fake_clock(DURING_WINDOW)
        window = MigrationWindow(WINDOW_START, WINDOW_END, clock=clock)
        assert window.is_open() is True
        # Advance the same clock past the end; the policy tightens on its own.
        clock._now = lambda: str_to_time(AFTER_WINDOW)
        assert window.is_open() is False


class TestAudienceEntry:
    def test_legacy_only_while_open_for_known_issuer(self):
        entry = AudienceEntry(ENTRY_A, [LEGACY_AUDIENCE], [IDP_A])
        assert entry.allowed_audiences(IDP_A, True) == {ENTRY_A, LEGACY_AUDIENCE}
        assert entry.allowed_audiences(IDP_A, False) == {ENTRY_A}

    def test_issuer_double_constraint(self):
        entry = AudienceEntry(ENTRY_A, [LEGACY_AUDIENCE], [IDP_A])
        # A different issuer never gets the legacy audience, even in the window.
        assert entry.allowed_audiences(IDP_B, True) == {ENTRY_A}

    def test_empty_issuers_means_any_issuer(self):
        entry = AudienceEntry(ENTRY_A, [LEGACY_AUDIENCE])
        assert entry.allowed_audiences(IDP_B, True) == {ENTRY_A, LEGACY_AUDIENCE}


class TestPolicyEvaluation:
    def test_entry_audience_always_accepted(self):
        policy = build_policy(AFTER_WINDOW)
        decision = policy.evaluate(conditions_with_audiences([ENTRY_A]), ENTRY_A, IDP_A)
        assert decision.accepted is True
        assert decision.used_legacy_audience is False

    def test_legacy_audience_accepted_in_window_for_allowed_issuer(self):
        policy = build_policy(DURING_WINDOW)
        decision = policy.evaluate(conditions_with_audiences([LEGACY_AUDIENCE]), ENTRY_A, IDP_A)
        assert decision.accepted is True
        assert decision.window_open is True
        assert decision.used_legacy_audience is True
        assert LEGACY_AUDIENCE in decision.matched_audiences

    def test_legacy_audience_rejected_after_window(self):
        policy = build_policy(AFTER_WINDOW)
        decision = policy.evaluate(conditions_with_audiences([LEGACY_AUDIENCE]), ENTRY_A, IDP_A)
        assert decision.accepted is False
        assert decision.window_open is False
        assert decision.reason == "no allowed audience in AudienceRestriction"

    def test_legacy_audience_rejected_for_disallowed_issuer_even_in_window(self):
        policy = build_policy(DURING_WINDOW)
        # ENTRY_A only allows IDP_A to use the legacy audience.
        decision = policy.evaluate(conditions_with_audiences([LEGACY_AUDIENCE]), ENTRY_A, IDP_B)
        assert decision.accepted is False

    def test_other_brand_entry_allows_its_own_issuer_set(self):
        policy = build_policy(DURING_WINDOW)
        decision = policy.evaluate(conditions_with_audiences([LEGACY_AUDIENCE]), ENTRY_B, IDP_B)
        assert decision.accepted is True

    def test_closed_before_window_start(self):
        policy = build_policy(BEFORE_WINDOW)
        decision = policy.evaluate(conditions_with_audiences([LEGACY_AUDIENCE]), ENTRY_A, IDP_A)
        assert decision.accepted is False
        assert decision.window_open is False

    def test_all_restrictions_must_be_satisfied(self):
        policy = build_policy(DURING_WINDOW)
        # First restriction matches, second does not -> reject.
        conditions = conditions_with_audiences([LEGACY_AUDIENCE], ["https://elsewhere.example.com"])
        decision = policy.evaluate(conditions, ENTRY_A, IDP_A)
        assert decision.accepted is False

    def test_no_audience_restriction_is_accepted(self):
        policy = build_policy(DURING_WINDOW)
        decision = policy.evaluate(saml.Conditions(), ENTRY_A, IDP_A)
        assert decision.accepted is True

    def test_unknown_entry_falls_back_to_classic_check(self):
        policy = build_policy(DURING_WINDOW)
        unknown = "https://unknown.example.com"
        accepted = policy.evaluate(conditions_with_audiences([unknown]), unknown, IDP_A)
        rejected = policy.evaluate(conditions_with_audiences([LEGACY_AUDIENCE]), unknown, IDP_A)
        assert accepted.accepted is True
        assert rejected.accepted is False

    def test_decision_is_stable_and_serializable(self):
        policy = build_policy(DURING_WINDOW)
        decision = policy.evaluate(conditions_with_audiences([LEGACY_AUDIENCE]), ENTRY_A, IDP_A)
        snapshot = decision.as_dict()
        # The snapshot is plain data, independent of the moving clock.
        assert snapshot["accepted"] is True
        assert snapshot["entry_entity_id"] == ENTRY_A
        assert snapshot["issuer"] == IDP_A
        assert isinstance(decision, AudienceMigrationDecision)
        assert decision == AudienceMigrationDecision(
            True, ENTRY_A, IDP_A, [LEGACY_AUDIENCE], True, True, "legacy audience"
        )

    def test_disabled_without_entries(self):
        policy = AudienceMigrationPolicy({"window": {"start": WINDOW_START, "end": WINDOW_END}})
        assert policy.enabled is False


class TestEpochBoundary:
    def test_struct_time_consistent_with_calendar(self):
        # Guard the half-open boundary arithmetic used by the window.
        now = calendar.timegm(str_to_time(WINDOW_END))
        assert time.gmtime(now) == str_to_time(WINDOW_END)

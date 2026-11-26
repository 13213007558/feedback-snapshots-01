"""Scenario tests for authentication-method constraints during migration."""

import pytest

from auth_transition import LEGACY_METHOD
from auth_transition import SIGNATURE_METHOD
from auth_transition import AuthenticationMethodPolicy
from auth_transition import AuthTransitionHarness
from auth_transition import run_scenario
from auth_transition.policy import REASON_OPERATION_NOT_REGISTERED
from auth_transition.policy import REASON_STRONG_METHOD_REQUIRED
from auth_transition.policy import REASON_TRANSITION_CLOSED
from auth_transition.policy import TransitionWindow


@pytest.fixture
def harness():
    return AuthTransitionHarness()


def reset_validator_calls(harness):
    harness.legacy_validator.calls.clear()
    harness.signature_validator.calls.clear()


def test_two_recording_methods_return_the_same_registered_client(harness):
    assert harness.legacy_validator.client is harness.client
    assert harness.signature_validator.client is harness.client

    reset_validator_calls(harness)
    legacy_response, _ = harness.issue(LEGACY_METHOD)
    assert legacy_response.status_code == 200
    legacy_call = harness.legacy_validator.calls[-1]

    reset_validator_calls(harness)
    signature_response, _ = harness.issue(SIGNATURE_METHOD)
    assert signature_response.status_code == 200
    signature_call = harness.signature_validator.calls[-1]

    assert legacy_call["valid"] is True
    assert legacy_call["client_id"] == harness.client.client_id
    assert signature_call["valid"] is True
    assert signature_call["client_id"] == harness.client.client_id
    assert harness.query_client("fictional-client-7558") is harness.client


def test_normal_issuance_records_actual_legacy_method(harness):
    reset_validator_calls(harness)

    response, request = harness.issue(LEGACY_METHOD)

    assert response.status_code == 200
    assert request.auth_method == LEGACY_METHOD
    assert [call["method"] for call in harness.legacy_validator.calls] == [
        LEGACY_METHOD
    ]
    assert harness.signature_validator.calls == []

    token_value = response.body["access_token"]
    stored = harness.state.tokens[token_value]
    assert stored.auth_method == LEGACY_METHOD
    assert stored.assurance_tier == "legacy_record"
    assert stored.privilege == "normal"

    save_write = next(
        write for write in harness.state.writes if write["kind"] == "token_saved"
    )
    assert save_write["auth_method"] == LEGACY_METHOD
    assert save_write["privilege"] == "normal"


def test_signature_issuance_invokes_signature_validator_and_records_strength(harness):
    reset_validator_calls(harness)

    response, request = harness.issue(SIGNATURE_METHOD)

    assert response.status_code == 200
    assert request.auth_method == SIGNATURE_METHOD
    assert [call["method"] for call in harness.legacy_validator.calls] == [
        LEGACY_METHOD
    ]
    assert harness.legacy_validator.calls[0]["presented"] is False
    assert [call["method"] for call in harness.signature_validator.calls] == [
        SIGNATURE_METHOD
    ]
    assert harness.signature_validator.calls[0]["valid"] is True

    stored = harness.state.tokens[response.body["access_token"]]
    assert stored.auth_method == SIGNATURE_METHOD
    assert stored.assurance_tier == "strong_signature"


def test_legacy_method_cannot_create_privileged_approval(harness):
    writes_before = len(harness.state.writes)
    reset_validator_calls(harness)

    response, request = harness.issue(LEGACY_METHOD, privileged=True)

    assert response.status_code == 400
    assert response.body == {"error": "unauthorized_client"}
    assert request.policy_decision.allowed is False
    assert request.policy_decision.reason == REASON_STRONG_METHOD_REQUIRED
    assert request.policy_decision.privilege == "privileged"

    assert len(harness.legacy_validator.calls) == 1
    assert harness.legacy_validator.calls[0]["valid"] is True
    assert harness.signature_validator.calls == []
    assert len(harness.state.writes) == writes_before

    privileged_approvals = [
        record
        for record in harness.ledger.approvals()
        if record.get("privilege") == "privileged"
    ]
    assert privileged_approvals == []

    denial = harness.ledger.records[-1]
    assert denial["kind"] == "policy_decision"
    assert denial["outcome"] == "denied"
    assert denial["auth_method"] == LEGACY_METHOD
    assert denial["reason"] == REASON_STRONG_METHOD_REQUIRED


def test_signature_method_can_create_privileged_approval(harness):
    response, request = harness.issue(SIGNATURE_METHOD, privileged=True)

    assert response.status_code == 200
    assert request.policy_decision.allowed is True
    assert request.policy_decision.privilege == "privileged"

    stored = harness.state.tokens[response.body["access_token"]]
    assert stored.privilege == "privileged"
    assert stored.assurance_tier == "strong_signature"

    approval = harness.ledger.approvals()[-1]
    assert approval["auth_method"] == SIGNATURE_METHOD
    assert approval["assurance_tier"] == "strong_signature"
    assert approval["privilege"] == "privileged"


def test_legacy_revocation_requires_registered_maintenance_operation(harness):
    token_response, _ = harness.issue(SIGNATURE_METHOD)
    token_value = token_response.body["access_token"]

    unregistered_response, unregistered_request = harness.revoke(
        token_value,
        LEGACY_METHOD,
    )
    assert unregistered_response.status_code == 400
    assert unregistered_response.body == {"error": "unauthorized_client"}
    assert (
        unregistered_request.policy_decision.reason == REASON_OPERATION_NOT_REGISTERED
    )
    assert harness.state.tokens[token_value].revoked is False

    harness.register_maintenance(
        "maintenance-disabled",
        token_value,
        legacy_allowed=False,
    )
    disabled_response, disabled_request = harness.revoke(token_value, LEGACY_METHOD)
    assert disabled_response.status_code == 400
    assert disabled_request.policy_decision.reason == REASON_OPERATION_NOT_REGISTERED
    assert harness.state.tokens[token_value].revoked is False


def test_allowed_legacy_record_can_revoke_during_transition(harness):
    token_response, _ = harness.issue(LEGACY_METHOD)
    token_value = token_response.body["access_token"]
    harness.register_maintenance("maintenance-allowed", token_value)
    writes_before = len(harness.state.writes)
    reset_validator_calls(harness)

    response, request = harness.revoke(token_value, LEGACY_METHOD)

    assert response.status_code == 200
    assert response.body == {}
    assert request.auth_method == LEGACY_METHOD
    assert harness.legacy_validator.calls[0]["valid"] is True

    stored = harness.state.tokens[token_value]
    assert stored.revoked is True
    assert stored.revocation_method == LEGACY_METHOD
    assert stored.revocation_operation == "maintenance-allowed"

    new_writes = harness.state.writes[writes_before:]
    assert [write["kind"] for write in new_writes] == [
        "token_revoked",
        "maintenance_completed",
    ]
    assert all(write["auth_method"] == LEGACY_METHOD for write in new_writes)

    maintenance_record = next(
        record
        for record in harness.ledger.records
        if record.get("kind") == "maintenance"
    )
    assert maintenance_record["outcome"] == "completed"
    assert maintenance_record["auth_method"] == LEGACY_METHOD


def test_closing_transition_makes_legacy_result_explicit_and_public_error_minimal(
    harness,
):
    token_response, _ = harness.issue(SIGNATURE_METHOD)
    token_value = token_response.body["access_token"]
    harness.register_maintenance("maintenance-close-check", token_value)
    harness.close_transition()
    writes_before = len(harness.state.writes)
    reset_validator_calls(harness)

    response, request = harness.revoke(token_value, LEGACY_METHOD)

    assert response.status_code == 400
    assert response.body == {"error": "invalid_client"}
    assert "error_description" not in response.body
    assert request.policy_decision.allowed is False
    assert request.policy_decision.reason == REASON_TRANSITION_CLOSED
    assert request.policy_decision.public_error == "invalid_client"

    assert harness.legacy_validator.calls[0]["valid"] is True
    assert harness.signature_validator.calls == []
    assert len(harness.state.writes) == writes_before
    assert harness.state.tokens[token_value].revoked is False


def test_transition_deadline_has_same_explicit_expiry_result():
    window = TransitionWindow(closes_at=100, clock=lambda: 100)
    assert window.is_open() is False

    harness = AuthTransitionHarness()
    harness.policy.transition = window
    response, request = harness.issue(LEGACY_METHOD)

    assert response.status_code == 400
    assert response.body == {"error": "invalid_client"}
    assert request.policy_decision.reason == REASON_TRANSITION_CLOSED


def test_privileged_grant_type_also_requires_signature_without_admin_scope():
    policy = AuthenticationMethodPolicy(
        privileged_grant_types={"high_privilege_grant"},
    )
    client = AuthTransitionHarness().client
    client.approved_grant_types = frozenset(
        {"client_credentials", "high_privilege_grant"}
    )

    decision = policy.evaluate_issuance(
        client=client,
        auth_method=LEGACY_METHOD,
        grant_type="high_privilege_grant",
        scope="read",
    )

    assert decision.privilege == "privileged"
    assert decision.allowed is False
    assert decision.reason == REASON_STRONG_METHOD_REQUIRED


def test_signature_method_remains_usable_after_transition_closes(harness):
    harness.close_transition()

    token_response, _ = harness.issue(SIGNATURE_METHOD, privileged=True)
    assert token_response.status_code == 200
    token_value = token_response.body["access_token"]

    harness.register_maintenance("maintenance-new-method", token_value)
    revoke_response, _ = harness.revoke(token_value, SIGNATURE_METHOD)

    assert revoke_response.status_code == 200
    assert harness.state.tokens[token_value].revoked is True
    assert harness.state.tokens[token_value].revocation_method == SIGNATURE_METHOD


def test_end_to_end_scenario_verifies_tokens_writes_and_approvals():
    harness = run_scenario()

    token_values = set(harness.state.tokens)
    assert token_values == {
        "fictional-access-token-1",
        "fictional-access-token-2",
        "fictional-access-token-3",
    }

    first = harness.state.tokens["fictional-access-token-1"]
    privileged = harness.state.tokens["fictional-access-token-2"]
    after_close = harness.state.tokens["fictional-access-token-3"]

    assert first.auth_method == LEGACY_METHOD
    assert first.privilege == "normal"
    assert first.revoked is True
    assert first.revocation_method == LEGACY_METHOD

    assert privileged.auth_method == SIGNATURE_METHOD
    assert privileged.privilege == "privileged"
    assert privileged.revoked is False

    assert after_close.auth_method == SIGNATURE_METHOD
    assert after_close.revoked is False

    approval_pairs = {
        (record["auth_method"], record["privilege"])
        for record in harness.ledger.approvals()
    }
    assert (LEGACY_METHOD, "normal") in approval_pairs
    assert (SIGNATURE_METHOD, "privileged") in approval_pairs
    assert (SIGNATURE_METHOD, "normal") in approval_pairs
    assert (LEGACY_METHOD, "privileged") not in approval_pairs

    write_kinds = [write["kind"] for write in harness.state.writes]
    assert write_kinds == [
        "token_saved",
        "token_saved",
        "maintenance_registered",
        "token_revoked",
        "maintenance_completed",
        "token_saved",
        "maintenance_registered",
    ]

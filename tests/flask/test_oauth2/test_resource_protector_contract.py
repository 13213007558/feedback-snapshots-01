"""Contract tests for the Flask Authlib ``ResourceProtector`` integration.

The same fictional request set is reused by the Django contract module. These
tests pin:

* the standard HTTP response (status / JSON body / challenge header),
* the precise step at which authorization stopped, via the recording
  validator and the pre-conversion ``OAuth2Error`` boundary record,
* that the protected resource callback is only invoked after full success,
* the sanitized shareable evidence schema and its canary guarantee,
* that a status-only test double which skips validation is detected from
  actual calls and records rather than from its (identical) response.

A final group compares the Flask facts with the Django integration before and
after framework error conversion.
"""

from dataclasses import replace

import pytest

from tests import oauth2_resource_protector_contract as contract

pytestmark = pytest.mark.skipif(
    not contract.flask_available(), reason="Flask is not installed"
)

SCENARIOS = contract.FICTIONAL_REQUESTS
DENIALS = contract.DENIAL_SCENARIOS
SCENARIO_IDS = [scenario.id for scenario in SCENARIOS]
DENIAL_IDS = [scenario.id for scenario in DENIALS]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=SCENARIO_IDS)
def test_standard_response_calls_and_evidence(scenario):
    run = contract.run_flask(scenario)

    assert contract.evaluate_contract(scenario, run) == []

    evidence = contract.build_shareable_evidence(scenario, run)
    assert list(evidence) == list(contract.SHAREABLE_EVIDENCE_KEYS)
    assert contract.evidence_violations(evidence, scenario) == []
    assert contract.record_leak_violations(scenario, run, evidence) == []


@pytest.mark.parametrize("scenario", DENIALS, ids=DENIAL_IDS)
def test_protected_business_is_never_called_on_denial(scenario):
    run = contract.run_flask(scenario)

    assert run.business_calls == 0
    assert contract.build_shareable_evidence(scenario, run)["classification"] in {
        contract.CLASS_CREDENTIAL_UNAVAILABLE,
        contract.CLASS_PERMISSION_INSUFFICIENT,
    }


def test_allowed_control_invokes_business_once():
    scenario = next(item for item in SCENARIOS if item.id == "access_granted")
    run = contract.run_flask(scenario)

    assert run.status_code == 200
    assert run.business_calls == 1
    assert run.boundary_errors == []
    evidence = contract.build_shareable_evidence(scenario, run)
    assert evidence["classification"] == contract.CLASS_ACCESS_GRANTED
    assert evidence["stage"] == contract.STAGE_RESOURCE_CALLBACK


def test_same_denial_decision_from_credential_or_permission_is_distinguishable():
    missing = next(item for item in SCENARIOS if item.id == "credential_absent")
    forbidden = next(
        item for item in SCENARIOS if item.id == "permission_insufficient_scope"
    )

    missing_run = contract.run_flask(missing)
    forbidden_run = contract.run_flask(forbidden)

    missing_evidence = contract.build_shareable_evidence(missing, missing_run)
    forbidden_evidence = contract.build_shareable_evidence(forbidden, forbidden_run)

    # Both share the coarse "denied" outcome: access is not granted and the
    # protected business never runs.
    assert missing_run.business_calls == 0
    assert forbidden_run.business_calls == 0
    assert missing_evidence["classification"] != contract.CLASS_ACCESS_GRANTED
    assert forbidden_evidence["classification"] != contract.CLASS_ACCESS_GRANTED

    # The stage + approved classification locate the different stop points.
    assert missing_evidence["stage"] == contract.STAGE_PARSE_CREDENTIAL
    assert missing_evidence["classification"] == contract.CLASS_CREDENTIAL_UNAVAILABLE
    assert forbidden_evidence["stage"] == contract.STAGE_VALIDATE_TOKEN
    assert (
        forbidden_evidence["classification"] == contract.CLASS_PERMISSION_INSUFFICIENT
    )


def test_same_401_from_two_credential_phases_has_distinct_call_records():
    absent = next(item for item in SCENARIOS if item.id == "credential_absent")
    unknown = next(
        item for item in SCENARIOS if item.id == "credential_token_unresolvable"
    )

    absent_run = contract.run_flask(absent)
    unknown_run = contract.run_flask(unknown)

    # Identical standard status ...
    assert absent_run.status_code == unknown_run.status_code == 401
    # ... but the request stops at different steps, observable in call records.
    assert absent_run.step_names == []
    assert unknown_run.step_names == list(contract._VALIDATOR_STEPS)
    assert absent_run.boundary_errors[0]["code"] == "missing_authorization"
    assert unknown_run.boundary_errors[0]["code"] == "invalid_token"


def test_pre_conversion_error_is_richer_than_the_converted_response():
    scenario = next(item for item in SCENARIOS if item.id == "credential_absent")
    run = contract.run_flask(scenario)

    # Before conversion the typed Authlib error is fully recordable ...
    boundary = run.boundary_errors[0]
    assert boundary["type"] == "MissingAuthorizationError"
    assert boundary["code"] == "missing_authorization"
    assert boundary["status_code"] == 401

    # ... after conversion RFC 6750 section 3.1 deliberately drops the error
    # code from the body, leaving only the bare Bearer challenge.
    assert run.body == {}
    assert "error" not in run.body
    assert run.headers["www-authenticate"] == "Bearer"


def test_contract_detector_flags_business_invoked_on_a_denial():
    scenario = next(
        item for item in SCENARIOS if item.id == "permission_insufficient_scope"
    )
    honest_run = contract.run_flask(scenario)
    wrongly_called = replace(honest_run, business_calls=1)

    violations = contract.evaluate_contract(scenario, wrongly_called)
    assert any("resource callback" in item for item in violations)
    assert any("expected 0, got 1" in item for item in violations)


@pytest.mark.parametrize("scenario", DENIALS, ids=DENIAL_IDS)
def test_status_only_bypass_double_is_detected_from_calls_and_records(scenario):
    run = contract.run_flask(scenario, bypass=True)

    # The mutated double returns the identical standard response ...
    expected_wire = contract.standard_wire_facts(scenario)
    assert run.status_code == expected_wire["status"]
    assert contract.wire_facts(run) == expected_wire

    # ... so status/body-only assertions pass, but the contract detector must
    # identify the skipped validation from actual calls and records.
    violations = contract.evaluate_contract(scenario, run)
    assert violations
    text = "\n".join(violations).lower()
    assert "boundary" in text
    assert "pre-conversion" in text

    if scenario.expected_step_names:
        assert any("recording validator calls" in item for item in violations)

    with pytest.raises(AssertionError, match="contract violated"):
        contract.assert_contract(scenario, run)


@pytest.mark.skipif(
    not contract.django_available(), reason="Django integration is not installed"
)
@pytest.mark.parametrize("scenario", SCENARIOS, ids=SCENARIO_IDS)
def test_flask_and_django_share_pre_and_post_conversion_facts(scenario):
    flask_run = contract.run_flask(scenario)
    django_run = contract.run_django(scenario)

    contract.assert_contract(scenario, flask_run)
    contract.assert_contract(scenario, django_run)

    # After framework error conversion both adapters expose the same standard
    # HTTP facts.
    assert contract.wire_facts(flask_run) == contract.wire_facts(django_run)

    # Before conversion the shared core boundary records the same typed error,
    # the same validator step sequence and the same business call count.
    assert contract.pre_conversion_facts(flask_run) == (
        contract.pre_conversion_facts(django_run)
    )


@pytest.mark.skipif(
    not contract.django_available(), reason="Django integration is not installed"
)
@pytest.mark.parametrize("scenario", DENIALS, ids=DENIAL_IDS)
def test_django_status_only_bypass_is_also_detected(scenario):
    run = contract.run_django(scenario, bypass=True)

    assert contract.wire_facts(run) == contract.standard_wire_facts(scenario)
    violations = contract.evaluate_contract(scenario, run)
    assert violations
    assert any("boundary" in item for item in violations)

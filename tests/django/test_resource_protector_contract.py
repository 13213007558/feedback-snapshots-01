"""Contract tests for the Django Authlib ``ResourceProtector`` integration.

These are the Django half of the framework-neutral contract in
``tests/oauth2_resource_protector_contract.py``. They intentionally use an
in-memory recording validator and Django's ``RequestFactory`` directly, so no
database or ORM model is required.

The Flask contract module runs the identical fictional request set and also
performs the explicit Flask-vs-Django before/after conversion comparison.
"""

import pytest

from tests import oauth2_resource_protector_contract as contract

pytestmark = pytest.mark.skipif(
    not contract.django_available(), reason="Django is not installed"
)

SCENARIOS = contract.FICTIONAL_REQUESTS
DENIALS = contract.DENIAL_SCENARIOS
SCENARIO_IDS = [scenario.id for scenario in SCENARIOS]
DENIAL_IDS = [scenario.id for scenario in DENIALS]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=SCENARIO_IDS)
def test_standard_response_calls_and_evidence(scenario):
    run = contract.run_django(scenario)

    assert contract.evaluate_contract(scenario, run) == []

    evidence = contract.build_shareable_evidence(scenario, run)
    assert list(evidence) == list(contract.SHAREABLE_EVIDENCE_KEYS)
    assert contract.evidence_violations(evidence, scenario) == []
    assert contract.record_leak_violations(scenario, run, evidence) == []


def test_allowed_control_invokes_business_once():
    scenario = next(item for item in SCENARIOS if item.id == "access_granted")
    run = contract.run_django(scenario)

    assert run.status_code == 200
    assert run.business_calls == 1
    assert run.body == contract.standard_wire_facts(scenario)["body"]


@pytest.mark.parametrize("scenario", DENIALS, ids=DENIAL_IDS)
def test_protected_business_is_never_called_on_denial(scenario):
    run = contract.run_django(scenario)

    assert run.business_calls == 0
    assert contract.evaluate_contract(scenario, run) == []


def test_pre_conversion_error_is_richer_than_the_converted_response():
    scenario = next(item for item in SCENARIOS if item.id == "credential_absent")
    run = contract.run_django(scenario)

    boundary = run.boundary_errors[0]
    assert boundary["type"] == "MissingAuthorizationError"
    assert boundary["code"] == "missing_authorization"
    assert run.body == {}
    assert "error" not in run.body
    assert run.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("scenario", DENIALS, ids=DENIAL_IDS)
def test_status_only_bypass_double_is_detected_from_calls_and_records(scenario):
    run = contract.run_django(scenario, bypass=True)

    # Same standard status/body/header as the real integration ...
    assert contract.wire_facts(run) == contract.standard_wire_facts(scenario)

    # ... but the missing validation is identifiable from actual calls/records.
    violations = contract.evaluate_contract(scenario, run)
    assert violations
    text = "\n".join(violations).lower()
    assert "boundary" in text
    assert "pre-conversion" in text
    if scenario.expected_step_names:
        assert any("recording validator calls" in item for item in violations)

    with pytest.raises(AssertionError, match="contract violated"):
        contract.assert_contract(scenario, run)

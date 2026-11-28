"""ASGI verification that authorization audit only records real grants.

This is the async counterpart of ``tests/test_audit_authorization.py``. It
exercises the same four same-status-code paths, plus the preprocessing-approved
but later decode-failure request, and asserts that the ASGI middleware,
resource before/after hooks, and error handler each leave stage facts that a
later stage cannot rewrite.
"""

import falcon
import falcon.testing as testing
from tests._audit_harness import AuditJournal
from tests._audit_harness import AuditMiddleware
from tests._audit_harness import AuditResourceAsync
from tests._audit_harness import BusinessFailure
from tests._audit_harness import EarlyReturnMiddleware
from tests._audit_harness import handle_business_failure_async
from tests._audit_harness import JSON_HEADERS
from tests._audit_harness import STAGE_AFTER_HOOK
from tests._audit_harness import STAGE_BEFORE_HOOK
from tests._audit_harness import STAGE_BUSINESS
from tests._audit_harness import STAGE_ERROR_HANDLER
from tests._audit_harness import STAGE_REQUEST_MW
from tests._audit_harness import STAGE_RESOURCE_MW
from tests._audit_harness import STAGE_RESPONSE_MW

ROUTE = '/audited'


def _make_client(early_return=False):
    journal = AuditJournal()
    middleware = [AuditMiddleware(journal)]
    if early_return:
        middleware.append(EarlyReturnMiddleware())

    app = falcon.asgi.App(middleware=middleware)
    app.add_route(ROUTE, AuditResourceAsync())
    app.add_error_handler(BusinessFailure, handle_business_failure_async)
    return testing.TestClient(app), journal


def _post(client, request_id, **headers):
    merged = dict(JSON_HEADERS)
    merged['X-Request-Id'] = request_id
    merged.update(headers)
    return client.simulate_post(ROUTE, body=b'{"answer": 42}', headers=merged)


def test_middleware_early_return_is_not_authorized():
    client, journal = _make_client(early_return=True)
    result = _post(client, 'early-return')

    assert result.status_code == 400

    record = journal.get('early-return')
    assert record.stages == [
        STAGE_REQUEST_MW,
        STAGE_RESPONSE_MW,
    ]
    assert record.resource_ops == 0
    assert record.authorized is False
    assert record.entered_business is False
    assert record.granted is False
    assert record.business_completed is False
    assert record.error_handled is False
    assert record.final_status == 400
    assert record.response_succeeded is True


def test_resource_hook_denial_is_not_authorized():
    client, journal = _make_client()
    result = _post(client, 'hook-deny', **{'X-Deny': '1'})

    assert result.status_code == 400

    record = journal.get('hook-deny')
    assert record.stages == [
        STAGE_REQUEST_MW,
        STAGE_RESOURCE_MW,
        STAGE_BEFORE_HOOK,
        STAGE_RESPONSE_MW,
    ]
    assert record.resource_ops == 0
    assert record.authorized is False
    assert record.entered_business is False
    assert record.granted is False
    assert record.business_completed is False
    assert record.error_handled is False
    assert record.final_status == 400
    assert record.response_succeeded is False


def test_business_failure_converted_to_error_page_is_not_granted():
    client, journal = _make_client()
    result = _post(client, 'business-fail', **{'X-Fail-Business': '1'})

    assert result.status_code == 400

    record = journal.get('business-fail')
    assert record.stages == [
        STAGE_REQUEST_MW,
        STAGE_RESOURCE_MW,
        STAGE_BEFORE_HOOK,
        STAGE_BUSINESS,
        STAGE_ERROR_HANDLER,
        STAGE_RESPONSE_MW,
    ]
    # The business op really started (once), but it failed and is no grant.
    assert record.resource_ops == 1
    assert record.authorized is True
    assert record.entered_business is True
    assert record.granted is False
    assert record.business_completed is False
    assert record.error_handled is True
    assert record.after_hook_rewrote_response is False
    assert record.final_status == 400
    assert record.response_succeeded is False


def test_same_code_success_is_granted_despite_after_hook_rewrite():
    client, journal = _make_client()
    result = _post(client, 'success')

    assert result.status_code == 400

    record = journal.get('success')
    assert record.stages == [
        STAGE_REQUEST_MW,
        STAGE_RESOURCE_MW,
        STAGE_BEFORE_HOOK,
        STAGE_BUSINESS,
        STAGE_AFTER_HOOK,
        STAGE_RESPONSE_MW,
    ]
    assert record.resource_ops == 1
    assert record.authorized is True
    assert record.entered_business is True
    assert record.granted is True
    assert record.business_completed is True
    assert record.error_handled is False
    # The post-hook response change is observed but cannot erase the grant.
    assert record.after_hook_rewrote_response is True
    assert record.final_status == 400
    assert record.response_succeeded is True


def test_preprocessing_approved_but_decode_failure_keeps_real_steps():
    client, journal = _make_client()
    headers = dict(JSON_HEADERS)
    headers['X-Request-Id'] = 'decode-fail'
    result = client.simulate_post(ROUTE, body=b'{not valid json', headers=headers)

    assert result.status_code == 400

    record = journal.get('decode-fail')
    assert record.stages == [
        STAGE_REQUEST_MW,
        STAGE_RESOURCE_MW,
        STAGE_BEFORE_HOOK,
        STAGE_BUSINESS,
        STAGE_RESPONSE_MW,
    ]
    # The request really was authorized and the business op really started.
    assert record.resource_ops == 1
    assert record.authorized is True
    assert record.entered_business is True
    # Decoding failed before completion, so it is not registered as a grant.
    assert record.granted is False
    assert record.business_completed is False
    assert record.error_handled is False
    assert record.after_hook_rewrote_response is False
    assert record.final_status == 400
    assert record.response_succeeded is False


def test_audit_decisions_are_isolated_per_request_and_not_rewritten():
    client, journal = _make_client()

    outcomes = {
        'hook-deny': {'X-Deny': '1'},
        'business-fail': {'X-Fail-Business': '1'},
        'decode-fail': {},
        'success': {},
    }
    for request_id, extra in outcomes.items():
        if request_id == 'decode-fail':
            headers = dict(JSON_HEADERS)
            headers['X-Request-Id'] = request_id
            result = client.simulate_post(
                ROUTE, body=b'{not valid json', headers=headers
            )
        else:
            result = _post(client, request_id, **extra)
        assert result.status_code == 400

    by_id = {name: journal.get(name) for name in outcomes}

    assert by_id['hook-deny'].granted is False
    assert by_id['business-fail'].granted is False
    assert by_id['decode-fail'].granted is False
    assert by_id['success'].granted is True

    grants = [r.request_id for r in journal.records.values() if r.granted]
    assert grants == ['success']

    assert by_id['hook-deny'].resource_ops == 0
    assert by_id['business-fail'].resource_ops == 1
    assert by_id['decode-fail'].resource_ops == 1
    assert by_id['success'].resource_ops == 1


def test_inner_audit_component_still_leaves_response_fact_on_short_circuit():
    journal = AuditJournal()
    app = falcon.asgi.App(
        middleware=[EarlyReturnMiddleware(), AuditMiddleware(journal)]
    )
    app.add_route(ROUTE, AuditResourceAsync())
    client = testing.TestClient(app)

    result = _post(client, 'inner-placement')

    assert result.status_code == 400
    record = journal.get('inner-placement')
    assert record.stages == [STAGE_RESPONSE_MW]
    assert record.granted is False
    assert record.resource_ops == 0
    assert record.final_status == 400

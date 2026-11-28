"""WSGI verification that authorization audit only records real grants.

Requests that return the *same* status code can be fundamentally different:
a middleware short-circuit, a resource-hook denial, a business failure later
converted into an error page, or a genuine success rewritten by an after hook.
The audit must distinguish them by the stage facts each request really
traversed, and it must only register a grant when the request passed real
authorization (the resource before hook) and actually entered the business
operation (the responder started).
"""

import falcon
import falcon.testing as testing
from tests._audit_harness import AuditJournal
from tests._audit_harness import AuditMiddleware
from tests._audit_harness import AuditResource
from tests._audit_harness import BusinessFailure
from tests._audit_harness import EarlyReturnMiddleware
from tests._audit_harness import handle_business_failure
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
    # The audit component is outermost so it records the request entering the
    # middleware layer before any inner component is allowed to short-circuit.
    middleware = [AuditMiddleware(journal)]
    if early_return:
        middleware.append(EarlyReturnMiddleware())

    app = falcon.App(middleware=middleware)
    app.add_route(ROUTE, AuditResource())
    app.add_error_handler(BusinessFailure, handle_business_failure)
    return testing.TestClient(app), journal


def _post(client, request_id, **headers):
    merged = dict(JSON_HEADERS)
    merged['X-Request-Id'] = request_id
    merged.update(headers)
    return client.simulate_post(ROUTE, body=b'{"answer": 42}', headers=merged)


def test_middleware_early_return_is_not_authorized():
    client, journal = _make_client(early_return=True)
    result = _post(client, 'early-return')

    # The client only sees an ordinary 400, identical to the other paths.
    assert result.status_code == 400

    record = journal.get('early-return')
    # The request entered and left the middleware layer, but routing and the
    # resource pipeline were skipped entirely due to the short-circuit.
    assert record.stages == [
        STAGE_REQUEST_MW,
        STAGE_RESPONSE_MW,
    ]
    # Routing never happened: no resource middleware, hooks, or responder.
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
    # The before hook raised, so the responder never started.
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
    # Authorization passed and the business op really started (once), but it
    # failed and so it is never registered as a completed grant.
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

    # The after hook rewrites the successful response to the same 400 code.
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

    # MediaMalformedError is itself a 400 HTTPError, same code as the rest.
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

    # Every request returns the same 400 to the client, but only one genuinely
    # completes an authorized business operation.
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

    # Each record is independent; the after-hook 400 rewrite on 'success'
    # cannot alter any other request's facts or its own grant decision.
    assert by_id['hook-deny'].granted is False
    assert by_id['business-fail'].granted is False
    assert by_id['decode-fail'].granted is False
    assert by_id['success'].granted is True

    # Exactly one completed grant, regardless of the identical status codes.
    grants = [r.request_id for r in journal.records.values() if r.granted]
    assert grants == ['success']

    # Resource operation counts reflect real invocations, not status codes.
    assert by_id['hook-deny'].resource_ops == 0
    assert by_id['business-fail'].resource_ops == 1
    assert by_id['decode-fail'].resource_ops == 1
    assert by_id['success'].resource_ops == 1


def test_inner_audit_component_still_leaves_response_fact_on_short_circuit():
    # When the audit component is not outermost, an upstream short-circuit can
    # skip its process_request. The response stage must still open a record and
    # leave the one fact that really happened, rather than lose the request.
    journal = AuditJournal()
    app = falcon.App(middleware=[EarlyReturnMiddleware(), AuditMiddleware(journal)])
    app.add_route(ROUTE, AuditResource())
    client = testing.TestClient(app)

    result = _post(client, 'inner-placement')

    assert result.status_code == 400
    record = journal.get('inner-placement')
    assert record.stages == [STAGE_RESPONSE_MW]
    assert record.granted is False
    assert record.resource_ops == 0
    assert record.final_status == 400

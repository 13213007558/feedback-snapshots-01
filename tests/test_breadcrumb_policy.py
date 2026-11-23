import logging

import pytest

import sentry_sdk
from sentry_sdk.breadcrumb_policy import (
    BREADCRUMB_POLICY_DROP_REASON,
    POLICY_SOURCE_DIAGNOSTIC,
    POLICY_SOURCE_EXTERNAL_REQUEST,
    PROVENANCE_DATA_KEY,
    diagnostic_breadcrumbs,
    set_breadcrumb_limit,
    set_external_request_breadcrumb_limit,
)
from sentry_sdk.integrations.logging import LoggingIntegration


@pytest.fixture
def task_logger():
    log = logging.getLogger("test_breadcrumb_policy.task")
    log.setLevel(logging.DEBUG)
    return log


def _event_items(envelopes):
    items = []
    for envelope in envelopes:
        for item in envelope:
            if item.type == "event":
                items.append(item.payload.json)
    return items


def _crumb_row(crumb):
    provenance = crumb["data"][PROVENANCE_DATA_KEY]
    return crumb["category"], crumb["message"], provenance["source"]


def test_external_request_keeps_only_short_trail(
    sentry_init, capture_envelopes, capture_record_lost_event_calls
):
    sentry_init(max_breadcrumbs=100)
    envelopes = capture_envelopes()
    lost_calls = capture_record_lost_event_calls()

    sentry_sdk.apply_external_request_policy(3)
    for index in range(7):
        sentry_sdk.add_breadcrumb(
            message="log-%d" % index, category="app.request"
        )

    sentry_sdk.capture_message("boom")

    (event,) = _event_items(envelopes)
    crumbs = event["breadcrumbs"]["values"]

    # Oldest entries are evicted first; order and count are preserved.
    assert len(crumbs) == 3
    assert [c["message"] for c in crumbs] == ["log-4", "log-5", "log-6"]
    assert all(
        c["data"][PROVENANCE_DATA_KEY]["source"]
        == POLICY_SOURCE_EXTERNAL_REQUEST
        for c in crumbs
    )
    assert all(
        c["data"][PROVENANCE_DATA_KEY]["effective_limit"] == 3 for c in crumbs
    )

    # The tightening is observable through client reports.
    assert lost_calls == [
        (BREADCRUMB_POLICY_DROP_REASON, "default", None, 1)
    ] * 4


def test_global_max_breadcrumbs_remains_hard_cap(
    sentry_init, capture_envelopes
):
    # A diagnostic allowance above the client-wide cap is clamped.
    sentry_init(max_breadcrumbs=6)
    envelopes = capture_envelopes()

    with sentry_sdk.diagnostic_breadcrumbs_scope(50):
        for index in range(10):
            sentry_sdk.add_breadcrumb(
                message="diag-%d" % index, category="diagnostic"
            )
        sentry_sdk.capture_message("inside")

    (event,) = _event_items(envelopes)
    crumbs = event["breadcrumbs"]["values"]
    assert len(crumbs) == 6
    assert [c["message"] for c in crumbs] == [
        "diag-4",
        "diag-5",
        "diag-6",
        "diag-7",
        "diag-8",
        "diag-9",
    ]
    assert all(
        c["data"][PROVENANCE_DATA_KEY]["global_limit"] == 6 for c in crumbs
    )


def test_parallel_tasks_have_independent_scopes_and_quotas(
    sentry_init, capture_envelopes
):
    sentry_init(max_breadcrumbs=100)
    envelopes = capture_envelopes()
    shared_client = sentry_sdk.get_client()

    def run_task(name, limit):
        # Each task gets its own isolation scope but shares the Client.
        with sentry_sdk.isolation_scope() as scope:
            assert scope.get_client() is shared_client
            set_external_request_breadcrumb_limit(scope, limit)
            for index in range(limit + 2):
                sentry_sdk.add_breadcrumb(
                    message="%s-%d" % (name, index), category="task." + name
                )
            sentry_sdk.capture_message(name)

    run_task("a", 2)
    run_task("b", 4)

    event_a, event_b = _event_items(envelopes)

    crumbs_a = event_a["breadcrumbs"]["values"]
    crumbs_b = event_b["breadcrumbs"]["values"]

    assert [c["message"] for c in crumbs_a] == ["a-2", "a-3"]
    assert [c["message"] for c in crumbs_b] == ["b-2", "b-3", "b-4", "b-5"]

    # No cross-contamination between the two parallel tasks.
    assert all(c["category"] == "task.a" for c in crumbs_a)
    assert all(c["category"] == "task.b" for c in crumbs_b)


def test_diagnostic_scope_is_nested_and_restored(
    sentry_init, capture_envelopes
):
    sentry_init(max_breadcrumbs=100)
    envelopes = capture_envelopes()
    isolation = sentry_sdk.get_isolation_scope()

    sentry_sdk.apply_external_request_policy(3)
    for index in range(4):
        sentry_sdk.add_breadcrumb(
            message="outer-%d" % index, category="app.outer"
        )

    assert len(isolation._breadcrumbs) == 3

    with sentry_sdk.diagnostic_breadcrumbs_scope(10) as diagnostic_scope:
        assert diagnostic_scope is not isolation
        for index in range(6):
            sentry_sdk.add_breadcrumb(
                message="inner-%d" % index, category="diagnostic.inner"
            )
        # The fork inherited the surviving outer crumbs; the wider quota
        # cannot bring back the already-evicted outer-0.
        messages = [c["message"] for c in diagnostic_scope._breadcrumbs]
        assert messages == [
            "outer-1",
            "outer-2",
            "outer-3",
            "inner-0",
            "inner-1",
            "inner-2",
            "inner-3",
            "inner-4",
            "inner-5",
        ]
        assert all(
            c["data"][PROVENANCE_DATA_KEY]["source"]
            == POLICY_SOURCE_DIAGNOSTIC
            for c in diagnostic_scope._breadcrumbs
            if c["message"].startswith("inner")
        )
        sentry_sdk.capture_message("frozen-in-diagnostic")

    # On exit the parent scope is untouched and back on the tight tier.
    assert [c["message"] for c in isolation._breadcrumbs] == [
        "outer-1",
        "outer-2",
        "outer-3",
    ]
    assert (
        isolation._breadcrumb_policy.source == POLICY_SOURCE_EXTERNAL_REQUEST
    )

    frozen_event, = [
        event
        for event in _event_items(envelopes)
        if event["message"] == "frozen-in-diagnostic"
    ]
    frozen_rows = [_crumb_row(c) for c in frozen_event["breadcrumbs"]["values"]]
    assert frozen_rows == [
        ("app.outer", "outer-1", POLICY_SOURCE_EXTERNAL_REQUEST),
        ("app.outer", "outer-2", POLICY_SOURCE_EXTERNAL_REQUEST),
        ("app.outer", "outer-3", POLICY_SOURCE_EXTERNAL_REQUEST),
        ("diagnostic.inner", "inner-0", POLICY_SOURCE_DIAGNOSTIC),
        ("diagnostic.inner", "inner-1", POLICY_SOURCE_DIAGNOSTIC),
        ("diagnostic.inner", "inner-2", POLICY_SOURCE_DIAGNOSTIC),
        ("diagnostic.inner", "inner-3", POLICY_SOURCE_DIAGNOSTIC),
        ("diagnostic.inner", "inner-4", POLICY_SOURCE_DIAGNOSTIC),
        ("diagnostic.inner", "inner-5", POLICY_SOURCE_DIAGNOSTIC),
    ]


def test_tightening_evicts_observably_and_raising_never_backfills(
    sentry_init, capture_record_lost_event_calls
):
    sentry_init(max_breadcrumbs=100)
    lost_calls = capture_record_lost_event_calls()
    scope = sentry_sdk.get_isolation_scope()

    for index in range(5):
        sentry_sdk.add_breadcrumb(message="keep-%d" % index)

    # Tightening an existing buffer evicts immediately and is observable.
    set_breadcrumb_limit(scope, 2)
    assert [c["message"] for c in scope._breadcrumbs] == ["keep-3", "keep-4"]
    assert scope._breadcrumb_policy.n_evicted == 3
    assert (
        ("breadcrumb_policy_overflow", "default", None, 3)
        in lost_calls
    )

    # Raising the allowance does not restore anything; only new entries fill
    # the freed space.
    with diagnostic_breadcrumbs(scope, 10):
        sentry_sdk.add_breadcrumb(message="new-0")
        assert [c["message"] for c in scope._breadcrumbs] == [
            "keep-3",
            "keep-4",
            "new-0",
        ]

    # Exiting the diagnostic block restores the tight tier and re-evicts.
    assert [c["message"] for c in scope._breadcrumbs] == ["keep-4", "new-0"]


def test_interleaved_logging_breadcrumbs_and_frozen_event(
    sentry_init, capture_envelopes, task_logger
):
    # The logging integration produces breadcrumbs through the same
    # add_breadcrumb path, so the policy applies unchanged.
    sentry_init(
        integrations=[LoggingIntegration(event_level=None)],
        default_integrations=False,
        max_breadcrumbs=100,
    )
    envelopes = capture_envelopes()

    sentry_sdk.apply_external_request_policy(4)

    task_logger.info("normal-1")
    with sentry_sdk.diagnostic_breadcrumbs_scope(8):
        task_logger.info("diag-1")
        task_logger.info("diag-2")
        task_logger.info("diag-3")
        # Freeze an error event between the two scope switches.
        sentry_sdk.capture_message("frozen")
    task_logger.info("normal-2")

    # A late error arriving after the diagnostic context has exited must only
    # see the parent task's short, externally-scoped trail.
    sentry_sdk.capture_exception(RuntimeError("late"))
    sentry_sdk.flush()

    frozen_event, late_event = _event_items(envelopes)
    assert frozen_event["message"] == "frozen"
    assert late_event["exception"]["values"][0]["type"] == "RuntimeError"

    frozen_rows = [_crumb_row(c) for c in frozen_event["breadcrumbs"]["values"]]
    assert frozen_rows == [
        ("test_breadcrumb_policy.task", "normal-1", POLICY_SOURCE_EXTERNAL_REQUEST),
        ("test_breadcrumb_policy.task", "diag-1", POLICY_SOURCE_DIAGNOSTIC),
        ("test_breadcrumb_policy.task", "diag-2", POLICY_SOURCE_DIAGNOSTIC),
        ("test_breadcrumb_policy.task", "diag-3", POLICY_SOURCE_DIAGNOSTIC),
    ]
    # Timestamps keep the chronological order across scope switches.
    timestamps = [
        c["timestamp"] for c in frozen_event["breadcrumbs"]["values"]
    ]
    assert timestamps == sorted(timestamps)

    late_rows = [_crumb_row(c) for c in late_event["breadcrumbs"]["values"]]
    assert late_rows == [
        ("test_breadcrumb_policy.task", "normal-1", POLICY_SOURCE_EXTERNAL_REQUEST),
        ("test_breadcrumb_policy.task", "normal-2", POLICY_SOURCE_EXTERNAL_REQUEST),
    ]


def test_envelope_categories_order_and_counts(
    sentry_init, capture_envelopes, task_logger
):
    sentry_init(
        integrations=[LoggingIntegration(event_level=None)],
        default_integrations=False,
        enable_logs=True,
        max_breadcrumbs=100,
    )
    envelopes = capture_envelopes()

    sentry_sdk.apply_external_request_policy(2)
    task_logger.info("request-log")
    with sentry_sdk.diagnostic_breadcrumbs_scope(5):
        task_logger.info("diagnostic-log")
        sentry_sdk.capture_message("error-inside")

    sentry_sdk.flush()

    event_items = _event_items(envelopes)
    assert event_items
    event = event_items[0]
    rows = [_crumb_row(c) for c in event["breadcrumbs"]["values"]]
    assert rows == [
        ("test_breadcrumb_policy.task", "request-log", POLICY_SOURCE_EXTERNAL_REQUEST),
        ("test_breadcrumb_policy.task", "diagnostic-log", POLICY_SOURCE_DIAGNOSTIC),
    ]

    # Log items are attribute telemetry and are not breadcrumbs, but they go
    # through the same client and remain ordered in their own batch.
    log_bodies = []
    for captured in envelopes:
        for item in captured:
            if item.type == "log":
                log_bodies.extend(
                    entry["body"] for entry in item.payload.json["items"]
                )
    assert log_bodies == ["request-log", "diagnostic-log"]

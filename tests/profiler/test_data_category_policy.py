import time
from unittest import mock

import sentry_sdk
from sentry_sdk import start_transaction
from sentry_sdk.data_category_policy import DATA_CATEGORY_POLICY_REASON
from sentry_sdk.transport import HttpTransport, Transport

DSN = "https://foo@sentry.io/123"


class InMemoryTransport(Transport):
    """Stores the envelopes it would send and records lost events."""

    def __init__(self, options=None):
        Transport.__init__(self, options)
        self.envelopes = []
        self.lost_events = []

    def capture_envelope(self, envelope):
        envelope = self._apply_data_category_policy(envelope)
        if envelope.items:
            self.envelopes.append(envelope)

    def record_lost_event(self, reason, data_category=None, item=None, *, quantity=1):
        if data_category is None and item is not None:
            data_category = item.data_category
        self.lost_events.append((reason, data_category))


def _make_http_transport(**overrides):
    # Build a real HttpTransport so the assertions exercise the same
    # _prepare_envelope filtering used in production, without sending anything.
    options = dict(sentry_sdk.get_client().options)
    options.update(overrides)
    transport = HttpTransport(options)
    transport.kill()
    return transport


def _prepare(transport, envelopes, lost):
    transport.record_lost_event = (
        lambda reason, data_category=None, item=None, **_: lost.append(
            (reason, item.data_category if item is not None else data_category)
        )
    )

    prepared = []
    for envelope in envelopes:
        result = transport._prepare_envelope(envelope)
        if result is not None:
            prepared.append(result[0])
    return prepared


def _item_types(envelopes):
    return [
        item.type
        for envelope in envelopes
        for item in envelope.items
        if item.type != "client_report"
    ]


@mock.patch("sentry_sdk.profiler.transaction_profiler.PROFILE_MINIMUM_SAMPLES", 0)
def test_standalone_profile_is_dropped_when_category_not_approved(
    sentry_init, capture_envelopes, teardown_profiling
):
    sentry_init(
        dsn=DSN,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        data_category_policy=["transaction"],
    )

    envelopes = capture_envelopes()
    with start_transaction(name="profiled"):
        time.sleep(0.05)

    # the SDK still produces the profiler sample alongside the transaction
    assert _item_types(envelopes) == ["profile", "transaction"]

    lost = []
    prepared = _prepare(
        _make_http_transport(send_client_reports=False), envelopes, lost
    )

    assert _item_types(prepared) == ["transaction"]
    assert (DATA_CATEGORY_POLICY_REASON, "profile") in lost

    transaction = prepared[0].get_transaction_event()
    assert transaction is not None
    # the surviving transaction still identifies this run
    assert transaction["event_id"]
    assert transaction["contexts"]["trace"]["trace_id"]
    # the removed profiler sample leaves no reference behind
    assert all(item.type != "profile" for item in prepared[0].items)
    assert "profile" not in transaction


@mock.patch("sentry_sdk.profiler.transaction_profiler.PROFILE_MINIMUM_SAMPLES", 0)
def test_profile_attached_to_transaction_keeps_only_approved_categories(
    sentry_init, capture_envelopes, teardown_profiling
):
    sentry_init(
        dsn=DSN,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        data_category_policy=lambda category: category != "profile",
    )

    envelopes = capture_envelopes()
    with start_transaction(name="profiled"):
        time.sleep(0.05)

    lost = []
    prepared = _prepare(
        _make_http_transport(send_client_reports=False), envelopes, lost
    )

    # profile and transaction are produced in one envelope, but only the
    # approved transaction leaves the process
    assert _item_types(prepared) == ["transaction"]
    assert (DATA_CATEGORY_POLICY_REASON, "profile") in lost

    transaction = prepared[0].get_transaction_event()
    assert transaction["contexts"]["trace"]["trace_id"]
    assert all(item.type != "profile" for item in prepared[0].items)


@mock.patch("sentry_sdk.profiler.transaction_profiler.PROFILE_MINIMUM_SAMPLES", 0)
def test_profile_category_can_be_disabled_and_reenabled_at_runtime(
    sentry_init, capture_envelopes, teardown_profiling
):
    # The policy is consulted at send time, so a runtime flag is enough to
    # disable and later re-enable a category without re-initializing the SDK.
    state = {"profiles_allowed": True}
    sentry_init(
        dsn=DSN,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        data_category_policy=lambda category: (
            state["profiles_allowed"] or category != "profile"
        ),
    )

    envelopes = capture_envelopes()

    with start_transaction(name="first"):
        time.sleep(0.05)
    with start_transaction(name="second"):
        time.sleep(0.05)
    with start_transaction(name="third"):
        time.sleep(0.05)

    assert _item_types(envelopes) == [
        "profile",
        "transaction",
        "profile",
        "transaction",
        "profile",
        "transaction",
    ]

    transport = _make_http_transport(send_client_reports=False)
    lost = []
    transport.record_lost_event = (
        lambda reason, data_category=None, item=None, **_: lost.append(
            (reason, item.data_category if item is not None else data_category)
        )
    )

    first = transport._prepare_envelope(envelopes[0])
    assert first is not None
    assert [item.type for item in first[0].items] == ["profile", "transaction"]

    # disable profiler samples while the SDK keeps running
    state["profiles_allowed"] = False
    second = transport._prepare_envelope(envelopes[1])
    assert second is not None
    assert [item.type for item in second[0].items] == ["transaction"]

    # re-enable: the next profile goes out again
    state["profiles_allowed"] = True
    third = transport._prepare_envelope(envelopes[2])
    assert third is not None
    assert [item.type for item in third[0].items] == ["profile", "transaction"]

    profile_drops = [
        category for reason, category in lost if reason == DATA_CATEGORY_POLICY_REASON
    ]
    assert profile_drops == ["profile"]

    # every surviving transaction remains traceable to its own run
    transactions = [
        envelope[0].get_transaction_event() for envelope in (first, second, third)
    ]
    assert len({event["event_id"] for event in transactions}) == 3
    for event in transactions:
        assert event["contexts"]["trace"]["trace_id"]


@mock.patch("sentry_sdk.profiler.transaction_profiler.PROFILE_MINIMUM_SAMPLES", 0)
def test_in_memory_transport_filters_profiles_end_to_end(
    sentry_init, teardown_profiling
):
    transport = InMemoryTransport()
    state = {"profiles_allowed": False}
    sentry_init(
        dsn=DSN,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
        data_category_policy=lambda category: (
            state["profiles_allowed"] or category != "profile"
        ),
        transport=transport,
    )
    client = sentry_sdk.get_client()
    # the in-memory transport resolves the same policy object as the client
    transport.options = client.options

    with start_transaction(name="blocked"):
        time.sleep(0.05)

    assert [
        [item.type for item in envelope.items] for envelope in transport.envelopes
    ] == [["transaction"]]
    assert transport.lost_events == [(DATA_CATEGORY_POLICY_REASON, "profile")]

    transaction = transport.envelopes[0].get_transaction_event()
    assert transaction["event_id"]
    assert transaction["contexts"]["trace"]["trace_id"]
    assert "profile" not in transaction

    # re-enabling the category at runtime restores profile delivery
    state["profiles_allowed"] = True
    with start_transaction(name="allowed"):
        time.sleep(0.05)

    assert [
        item.type for envelope in transport.envelopes for item in envelope.items
    ] == ["transaction", "profile", "transaction"]

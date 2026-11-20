"""Executable criteria for the task-message format migration.

The two payloads below are deliberately ordinary, public-safe test data.
They contain no credentials, hostnames, or customer content; they only
exercise the two wire formats involved in the migration.
"""

from __future__ import annotations

import base64
import json
import pickle
from contextlib import contextmanager

import pytest

from kombu import Connection, Consumer, Exchange, Producer, Queue
from kombu.exceptions import ContentDisallowed
from kombu.serialization import (disable_insecure_serializers, dumps,
                                 register, registry, unregister)

TASK_V2 = 'task-v2-test'
TASK_V2_CONTENT_TYPE = 'application/vnd.kombu.test.task.v2+json'
LEGACY_CONTENT_TYPE = 'application/x-python-serialize'

NEW_MESSAGE = {
    'schema': 'task.v2',
    'task_id': 'T-1001',
    'action': 'echo',
    'payload': {'text': 'hello'},
}
OLD_MESSAGE = {
    'schema': 'task.v1',
    'task_id': 'T-1001',
    'action': 'echo',
    'payload': {'text': 'hello'},
}

NEW_WIRE = json.dumps(NEW_MESSAGE, separators=(',', ':'))
OLD_WIRE_B64 = base64.b64encode(
    pickle.dumps(OLD_MESSAGE, protocol=4),
).decode('ascii')


@pytest.fixture(scope='module', autouse=True)
def task_v2_serializer():
    register(TASK_V2, json.dumps, json.loads,
             TASK_V2_CONTENT_TYPE, 'utf-8')
    try:
        yield
    finally:
        unregister(TASK_V2)


@contextmanager
def _restored_disabled_content_types():
    saved = set(registry._disabled_content_types)
    try:
        yield
    finally:
        registry._disabled_content_types.clear()
        registry._disabled_content_types.update(saved)


def _queue(name):
    return Queue(name, Exchange(name, 'direct'), name)


def _publish(connection, queue, body, serializer):
    producer = Producer(connection, serializer=serializer)
    producer.publish(
        body,
        routing_key=queue.name,
        declare=[queue],
        serializer=serializer,
    )


def _consume(connection, queue, accept, expected=1):
    delivered = []
    rejected = []

    def on_message(body, message):
        delivered.append((body, message.content_type))
        message.ack()

    def on_decode_error(message, exc):
        rejected.append((type(exc), message.content_type))
        message.reject(requeue=False)

    with Consumer(connection, [queue], callbacks=[on_message],
                  accept=accept, on_decode_error=on_decode_error):
        while len(delivered) + len(rejected) < expected:
            connection.drain_events(timeout=1)
    return delivered, rejected


def _connection():
    return Connection('memory://')


def test_public_test_messages_are_plain_data():
    assert json.loads(NEW_WIRE) == NEW_MESSAGE
    assert pickle.loads(base64.b64decode(OLD_WIRE_B64)) == OLD_MESSAGE
    assert 'password' not in NEW_WIRE.lower()
    assert 'password' not in OLD_MESSAGE


def test_before_upgrade_legacy_worker_reads_old_and_rejects_new():
    """Phase 0: legacy-only consumer, explicit legacy acceptance."""
    conn = _connection()
    try:
        old_queue = _queue('migration-before-old')
        _publish(conn, old_queue, OLD_MESSAGE, 'pickle')
        delivered, rejected = _consume(conn, old_queue, ['pickle'])
        assert delivered == [(OLD_MESSAGE, LEGACY_CONTENT_TYPE)]
        assert rejected == []

        new_queue = _queue('migration-before-new')
        _publish(conn, new_queue, NEW_MESSAGE, TASK_V2)
        delivered, rejected = _consume(conn, new_queue, ['pickle'])
        assert delivered == []
        assert rejected == [(ContentDisallowed, TASK_V2_CONTENT_TYPE)]
    finally:
        conn.close()


def test_transition_worker_reads_both_formats():
    """Phase 1: dual-read worker accepts the historical backlog and new data."""
    conn = _connection()
    try:
        queue = _queue('migration-transition')
        _publish(conn, queue, OLD_MESSAGE, 'pickle')
        _publish(conn, queue, NEW_MESSAGE, TASK_V2)

        delivered, rejected = _consume(
            conn, queue, [TASK_V2, 'pickle'], expected=2,
        )
        assert delivered == [
            (OLD_MESSAGE, LEGACY_CONTENT_TYPE),
            (NEW_MESSAGE, TASK_V2_CONTENT_TYPE),
        ]
        assert rejected == []
    finally:
        conn.close()


def test_new_only_worker_rejects_legacy_but_reads_new():
    """Phase 2: new-only consumer, even while the legacy decoder is registered."""
    conn = _connection()
    try:
        new_queue = _queue('migration-after-new')
        _publish(conn, new_queue, NEW_MESSAGE, TASK_V2)
        delivered, rejected = _consume(conn, new_queue, [TASK_V2])
        assert delivered == [(NEW_MESSAGE, TASK_V2_CONTENT_TYPE)]
        assert rejected == []

        old_queue = _queue('migration-after-old')
        _publish(conn, old_queue, OLD_MESSAGE, 'pickle')
        delivered, rejected = _consume(conn, old_queue, [TASK_V2])
        assert delivered == []
        assert rejected == [(ContentDisallowed, LEGACY_CONTENT_TYPE)]
    finally:
        conn.close()


def test_global_disable_is_process_wide_and_accept_can_override_it():
    """Per-consumer accept is the precise switch; global disable is only a floor.

    With ``accept=None`` the process-wide disabled set applies.  A consumer
    that passes an explicit ``accept`` ignores that set, which is exactly why
    legacy acceptance can be limited to one integration, and also why a global
    disable is not a hard security boundary against in-process code.
    """
    conn = _connection()
    try:
        with _restored_disabled_content_types():
            disable_insecure_serializers(allowed=['json', TASK_V2])
            disabled_queue = _queue('migration-global-disabled')
            _publish(conn, disabled_queue, OLD_MESSAGE, 'pickle')
            delivered, rejected = _consume(conn, disabled_queue, None)
            assert delivered == []
            assert rejected == [(ContentDisallowed, LEGACY_CONTENT_TYPE)]

            scoped_queue = _queue('migration-scoped-opt-in')
            _publish(conn, scoped_queue, OLD_MESSAGE, 'pickle')
            delivered, rejected = _consume(conn, scoped_queue, ['pickle'])
            assert delivered == [(OLD_MESSAGE, LEGACY_CONTENT_TYPE)]
            assert rejected == []
    finally:
        conn.close()


def test_global_disable_does_not_restrict_producers():
    """Disabling insecure serializers only affects decoding.

    New producers must be constrained by their own configuration or by a
    wrapper; Kombu has no process-wide encoder allow-list.
    """
    with _restored_disabled_content_types():
        disable_insecure_serializers(allowed=['json', TASK_V2])
        content_type, content_encoding, payload = dumps(
            OLD_MESSAGE, serializer='pickle',
        )
        assert content_type == LEGACY_CONTENT_TYPE
        assert content_encoding == 'binary'
        assert pickle.loads(payload) == OLD_MESSAGE


def test_producer_serializer_is_per_instance():
    """Two producers in one process can have different output formats."""
    conn = _connection()
    try:
        new_queue = _queue('migration-producer-new')
        old_queue = _queue('migration-producer-old')
        new_producer = Producer(conn, serializer=TASK_V2)
        old_producer = Producer(conn, serializer='pickle')

        new_producer.publish(
            NEW_MESSAGE, routing_key=new_queue.name,
            declare=[new_queue], serializer=TASK_V2,
        )
        old_producer.publish(
            OLD_MESSAGE, routing_key=old_queue.name,
            declare=[old_queue], serializer='pickle',
        )

        delivered, _ = _consume(conn, new_queue, [TASK_V2])
        assert delivered == [(NEW_MESSAGE, TASK_V2_CONTENT_TYPE)]
        delivered, _ = _consume(conn, old_queue, ['pickle'])
        assert delivered == [(OLD_MESSAGE, LEGACY_CONTENT_TYPE)]
    finally:
        conn.close()

def test_accept_is_scoped_to_one_integration_on_shared_connection():
    """Two consumers on one connection enforce different accept lists."""
    conn = _connection()
    try:
        old_queue = _queue('migration-scope-old')
        new_queue = _queue('migration-scope-new')
        _publish(conn, old_queue, OLD_MESSAGE, 'pickle')
        _publish(conn, new_queue, NEW_MESSAGE, TASK_V2)

        legacy_seen = []
        new_seen = []
        legacy_rejected = []

        def legacy_message(body, message):
            legacy_seen.append(body)
            message.ack()

        def new_message(body, message):
            new_seen.append(body)
            message.ack()

        def new_decode_error(message, exc):
            legacy_rejected.append(type(exc))
            message.reject(requeue=False)

        with Consumer(conn, [old_queue], callbacks=[legacy_message],
                      accept=['pickle']), \
                Consumer(conn, [new_queue], callbacks=[new_message],
                         accept=[TASK_V2],
                         on_decode_error=new_decode_error):
            # Drain until each consumer has made a decision.
            for _ in range(2):
                conn.drain_events(timeout=1)

        assert legacy_seen == [OLD_MESSAGE]
        assert new_seen == [NEW_MESSAGE]
        assert legacy_rejected == []
    finally:
        conn.close()

"""Tests for service activity reporting and statistics

The handlers and ORM are exercised directly against an in-memory
database so the core semantics can be verified independently of
an HTTP server.
"""
import json
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

import pytest
from tornado.httputil import HTTPHeaders
from tornado.web import HTTPError

from jupyterhub import orm, scopes
from jupyterhub.apihandlers.service_activity import (
    ServiceActivityAPIHandler,
    ServiceActivitySummaryAPIHandler,
    _parse_duration,
    _parse_timestamp,
)
from jupyterhub.roles import create_role, get_default_roles
from jupyterhub.utils import isoformat, utcnow


def make_db():
    factory = orm.new_session_factory('sqlite:///:memory:', reset=True)
    db = factory()
    for role in get_default_roles():
        create_role(db, role)
    return db


def make_handler(cls, db, user, scopes_list, body=None, query=None):
    """Create a handler instance without starting an HTTP server"""
    services = {}
    for svc in db.query(orm.Service):
        services[svc.name] = SimpleNamespace(name=svc.name)
    handler = cls.__new__(cls)
    handler.application = SimpleNamespace(
        settings={'db': db, 'log': mock.Mock(), 'services': services}
    )
    handler.request = SimpleNamespace(
        path='/api/x',
        method='POST' if body is not None else 'GET',
        headers=HTTPHeaders(),
        arguments=query or {},
        body=json.dumps(body).encode() if body is not None else b'',
    )
    handler._jupyterhub_user = user
    handler.expanded_scopes = set(scopes_list)
    handler.parsed_scopes = scopes.parse_scopes(handler.expanded_scopes)
    handler._write_buffer = []
    handler._status_code = 200
    handler.write = handler._write_buffer.append
    handler.get_status = lambda: handler._status_code
    handler.set_status = lambda code: setattr(handler, '_status_code', code)
    if body is not None:
        handler.get_json_body = lambda: body
    return handler


def read_payload(handler):
    return json.loads(''.join(handler._write_buffer))


def test_parse_duration_and_timestamp():
    assert _parse_duration('24h') == 86400
    assert _parse_duration('7d') == 7 * 86400
    assert _parse_duration('90') == 90
    assert _parse_duration('1.5h') == 5400
    now = utcnow(with_tz=False)
    t = now - timedelta(hours=1)
    assert _parse_timestamp(isoformat(t)) == t
    with pytest.raises(ValueError):
        _parse_duration('bogus')


def test_default_scopes_are_distinct():
    expanded = scopes.expand_scopes({'read:services'})
    assert 'read:services:activity' not in expanded
    assert 'services:activity' not in expanded
    defaults = {role['name']: set(role['scopes']) for role in get_default_roles()}
    assert 'read:services:activity' in defaults['admin']
    # reporting is separate from reading details
    assert 'services:activity' in defaults['admin']


def test_report_dedupe_and_watermark():
    db = make_db()
    svc = orm.Service(name='svc-a', from_config=False)
    db.add(svc)
    db.commit()

    now = utcnow(with_tz=False)
    newer = now - timedelta(hours=1)
    older = now - timedelta(hours=2)

    for ts in (older, older, older):
        handler = make_handler(
            ServiceActivityAPIHandler,
            db,
            svc,
            ['services:activity!service=svc-a'],
            body={'activity_id': 'a1', 'last_activity': isoformat(ts)},
        )
        handler.post('svc-a')
        assert handler._status_code == 200
    assert db.query(orm.ServiceActivity).count() == 1

    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        svc,
        ['services:activity!service=svc-a'],
        body={'activity_id': 'a1', 'last_activity': isoformat(newer)},
    )
    handler.post('svc-a')
    payload = read_payload(handler)
    assert payload['updated'] is True
    record = db.query(orm.ServiceActivity).one()
    assert record.last_activity == newer

    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        svc,
        ['services:activity!service=svc-a'],
        body={'activity_id': 'a1', 'last_activity': isoformat(older)},
    )
    handler.post('svc-a')
    payload = read_payload(handler)
    assert payload['created'] is False
    assert payload['updated'] is False
    db.refresh(record)
    assert record.last_activity == newer
    assert db.query(orm.ServiceActivity).count() == 1
    db.close()


def test_batch_out_of_order_submission():
    db = make_db()
    svc = orm.Service(name='svc-a', from_config=False)
    db.add(svc)
    db.commit()

    now = utcnow(with_tz=False)
    newer = now - timedelta(minutes=5)
    older = now - timedelta(hours=2)
    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        svc,
        ['services:activity!service=svc-a'],
        body={
            'activities': [
                {'activity_id': 'a1', 'last_activity': isoformat(newer)},
                {'activity_id': 'a2', 'last_activity': isoformat(older)},
            ]
        },
    )
    handler.post('svc-a')
    payload = read_payload(handler)
    assert payload['count'] == 2
    assert db.query(orm.ServiceActivity).count() == 2

    # reverse-order re-submission changes nothing
    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        svc,
        ['services:activity!service=svc-a'],
        body={
            'activities': [
                {'activity_id': 'a2', 'last_activity': isoformat(older)},
                {'activity_id': 'a1', 'last_activity': isoformat(newer)},
            ]
        },
    )
    handler.post('svc-a')
    assert db.query(orm.ServiceActivity).count() == 2
    db.close()


def test_identity_cannot_cross_services():
    db = make_db()
    a = orm.Service(name='svc-a', from_config=False)
    b = orm.Service(name='svc-b', from_config=False)
    db.add_all([a, b])
    db.commit()

    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        a,
        ['services:activity!service=svc-a'],
        body={'last_activity': isoformat(utcnow(with_tz=False))},
    )
    with pytest.raises(HTTPError) as exc:
        handler.post('svc-b')
    assert exc.value.status_code == 403
    db.close()


def test_detail_scoped_to_service():
    db = make_db()
    a = orm.Service(name='svc-a', from_config=False)
    b = orm.Service(name='svc-b', from_config=False)
    db.add_all([a, b])
    db.commit()
    now = utcnow(with_tz=False)
    db.add_all(
        [
            orm.ServiceActivity(service_id=a.id, activity_id='a1', last_activity=now),
            orm.ServiceActivity(service_id=b.id, activity_id='b1', last_activity=now),
        ]
    )
    db.commit()

    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        a,
        ['read:services:activity!service=svc-a'],
    )
    handler.get('svc-a')
    payload = read_payload(handler)
    assert payload['count'] == 1
    assert payload['activity'][0]['activity_id'] == 'a1'
    assert 'b1' not in json.dumps(payload)

    with pytest.raises(HTTPError):
        handler.get('svc-b')

    # the owning service may read its own details
    owner_handler = make_handler(ServiceActivityAPIHandler, db, a, [])
    owner_handler.get('svc-a')
    assert read_payload(owner_handler)['count'] == 1
    db.close()


def test_summary_totals_complete_but_anonymous():
    db = make_db()
    a = orm.Service(name='svc-a', from_config=False)
    b = orm.Service(name='svc-b', from_config=False)
    db.add_all([a, b])
    db.commit()
    now = utcnow(with_tz=False)
    db.add_all(
        [
            orm.ServiceActivity(
                service_id=a.id,
                activity_id='a1',
                last_activity=now - timedelta(hours=1),
            ),
            orm.ServiceActivity(
                service_id=a.id,
                activity_id='a2',
                last_activity=now - timedelta(hours=2),
            ),
            orm.ServiceActivity(
                service_id=b.id,
                activity_id='b1',
                last_activity=now - timedelta(days=10),
            ),
        ]
    )
    db.commit()

    user = orm.User(name='public')
    db.add(user)
    db.commit()

    handler = make_handler(
        ServiceActivitySummaryAPIHandler,
        db,
        user,
        ['list:services'],
        query={'period': ['24h']},
    )
    handler.get()
    payload = read_payload(handler)
    # totals are complete: restricted svc-b is included
    assert payload['active_services'] == 1
    assert payload['activity_count'] == 2
    # counts for the caller's public list; restricted svc-b is still in totals
    assert payload['services'] == {'svc-a': 2, 'svc-b': 0}
    # no activity identifiers or per-activity timestamps leak
    blob = json.dumps(payload)
    for secret in ('a1', 'a2', 'b1', 'last_activity'):
        assert secret not in blob

    handler = make_handler(
        ServiceActivitySummaryAPIHandler,
        db,
        user,
        ['list:services'],
        query={'period': ['30d']},
    )
    handler.get()
    payload = read_payload(handler)
    assert payload['active_services'] == 2
    assert payload['activity_count'] == 3

    # out-of-window activity is excluded from both totals
    handler = make_handler(
        ServiceActivitySummaryAPIHandler,
        db,
        user,
        ['list:services'],
        query={'window': ['150m']},
    )
    handler.get()
    payload = read_payload(handler)
    assert payload['activity_count'] == 2
    db.close()


def test_batch_rejects_invalid_entry_without_partial_write():
    db = make_db()
    svc = orm.Service(name='svc-a', from_config=False)
    db.add(svc)
    db.commit()

    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        svc,
        ['services:activity!service=svc-a'],
        body={
            'activities': [
                {
                    'activity_id': 'a1',
                    'last_activity': isoformat(utcnow(with_tz=False)),
                },
                {'activity_id': 'a2'},
            ]
        },
    )
    with pytest.raises(HTTPError) as exc:
        handler.post('svc-a')
    assert exc.value.status_code == 400
    assert db.query(orm.ServiceActivity).count() == 0
    db.close()


def test_report_uses_timestamp_as_default_identity():
    db = make_db()
    svc = orm.Service(name='svc-a', from_config=False)
    db.add(svc)
    db.commit()
    t = utcnow(with_tz=False) - timedelta(minutes=10)

    for _ in range(2):
        handler = make_handler(
            ServiceActivityAPIHandler,
            db,
            svc,
            ['services:activity!service=svc-a'],
            body={'last_activity': isoformat(t)},
        )
        handler.post('svc-a')
    # identical timestamp reports collapse to one activity
    assert db.query(orm.ServiceActivity).count() == 1

    handler = make_handler(
        ServiceActivityAPIHandler,
        db,
        svc,
        ['services:activity!service=svc-a'],
        body={'last_activity': isoformat(t + timedelta(minutes=1))},
    )
    handler.post('svc-a')
    assert db.query(orm.ServiceActivity).count() == 2
    db.close()

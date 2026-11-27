import asyncio
import json
import time
from unittest import IsolatedAsyncioTestCase

from celery.events import Event
from tornado.web import create_signed_value

from flower.events import EventsState
from flower.urls import settings
from tests.unit import AsyncHTTPTestCase

DETAIL_AUTH = 'admin@example.com'
ADMIN = 'admin@example.com'
VIEWER = 'viewer@example.com'

# Everything the in-memory fake worker would return from a Celery inspection.
FAKE_WORKER_INFO = {
    'stats': {
        'pid': 4242,
        'total': {'tasks.add': 7},
        'broker': {'hostname': 'redis', 'userid': None,
                   'virtual_host': '/', 'port': 6379},
    },
    'active_queues': [{'name': 'celery', 'durable': True}],
    'registered': ['tasks.add', 'tasks.sleep'],
    'conf': {'CELERY_TIMEZONE': 'UTC'},
    'active': [{'id': 'task-active', 'name': 'tasks.add', 'args': '(1, 2)'}],
    'scheduled': [{'request': {'id': 'task-scheduled', 'args': '(3,)'}}],
    'reserved': [{'id': 'task-reserved'}],
    'revoked': ['task-revoked'],
    'timestamp': 1000.0,
}


class WorkerPermissionTestCase(AsyncHTTPTestCase):
    def setUp(self):
        super().setUp()
        # In-memory fake worker drives both the list and detail code paths;
        # no broker connection is opened.
        self._app.inspector.workers['celery@worker1'] = dict(FAKE_WORKER_INFO)
        state = EventsState()
        state.get_or_create_worker('celery@worker1')
        state.event(Event('worker-online', hostname='celery@worker1',
                          local_received=time.time()))
        self._app.events.state = state

    def session(self, email):
        signed = create_signed_value(
            settings['cookie_secret'], 'user', email)
        return {'Cookie': 'user=' + signed.decode()}

    def fetch_as(self, path, email):
        with self.mock_option('auth', '.*@example.com'), \
                self.mock_option('worker_details_auth', DETAIL_AUTH):
            return self.fetch(path, headers=self.session(email))


class WorkerListApiPermissionTests(WorkerPermissionTestCase):
    def test_privileged_account_receives_every_inspected_field(self):
        r = self.fetch_as('/api/workers', ADMIN)
        self.assertEqual(200, r.code)
        worker = json.loads(r.body)['celery@worker1']
        for field in ('stats', 'active_queues', 'registered', 'conf',
                      'active', 'scheduled', 'reserved', 'revoked',
                      'timestamp'):
            self.assertIn(field, worker)

    def test_status_only_account_keeps_liveness_but_loses_queues_and_tasks(self):
        r = self.fetch_as('/api/workers', VIEWER)
        self.assertEqual(200, r.code)
        worker = json.loads(r.body)['celery@worker1']
        self.assertIn('timestamp', worker)
        for secret in ('stats', 'active_queues', 'registered', 'conf',
                       'active', 'scheduled', 'reserved', 'revoked'):
            self.assertNotIn(secret, worker)

    def test_status_endpoint_stays_available_to_status_only_accounts(self):
        r = self.fetch_as('/api/workers?status=true', VIEWER)
        self.assertEqual(200, r.code)
        self.assertEqual({'celery@worker1': True}, json.loads(r.body))

    def test_single_worker_detail_requires_the_detail_view(self):
        viewer = self.fetch_as(
            '/api/workers?workername=celery@worker1', VIEWER)
        self.assertEqual(403, viewer.code)

        admin = self.fetch_as(
            '/api/workers?workername=celery@worker1', ADMIN)
        self.assertEqual(200, admin.code)
        worker = json.loads(admin.body)['celery@worker1']
        self.assertIn('active_queues', worker)

    def test_cached_single_worker_path_goes_through_the_same_gate(self):
        # the fast cache branch must not bypass the detail authorization
        viewer = self.fetch_as(
            '/api/workers?workername=celery@worker1', VIEWER)
        self.assertEqual(403, viewer.code)

    def test_without_restriction_every_account_sees_full_details(self):
        with self.mock_option('auth', '.*@example.com'):
            r = self.fetch('/api/workers', headers=self.session(VIEWER))
        worker = json.loads(r.body)['celery@worker1']
        self.assertIn('active_queues', worker)


class WorkerPagePermissionTests(WorkerPermissionTestCase):
    def test_status_only_account_cannot_open_the_worker_page(self):
        r = self.fetch_as('/worker/celery@worker1', VIEWER)
        self.assertEqual(403, r.code)

    def test_privileged_account_opens_the_worker_page(self):
        r = self.fetch_as('/worker/celery@worker1', ADMIN)
        self.assertEqual(200, r.code)
        self.assertIn('<title>celery@worker1 · Flower</title>',
                      r.body.decode('utf-8'))

    def test_workers_list_page_renders_for_both_tiers(self):
        viewer = self.fetch_as('/workers', VIEWER)
        self.assertEqual(200, viewer.code)
        admin = self.fetch_as('/workers', ADMIN)
        self.assertEqual(200, admin.code)

    def test_list_page_flags_detail_navigation_per_account(self):
        viewer = self.fetch_as('/workers', VIEWER).body.decode('utf-8')
        admin = self.fetch_as('/workers', ADMIN).body.decode('utf-8')
        self.assertIn('canViewWorkerDetails = false', viewer)
        self.assertIn('canViewWorkerDetails = true', admin)
        # status-only sessions must not get a link to the tasks/broker views
        self.assertNotIn('href="/tasks"', viewer)
        self.assertIn('href="/tasks"', admin)

    def test_broker_and_task_views_are_gated(self):
        self.assertEqual(403, self.fetch_as('/broker', VIEWER).code)
        self.assertEqual(403, self.fetch_as('/tasks', VIEWER).code)
        self.assertEqual(
            403, self.fetch_as('/api/queues/length', VIEWER).code)
        self.assertEqual(
            403, self.fetch_as('/api/tasks', VIEWER).code)
        self.assertEqual(
            403, self.fetch_as('/api/task/types', VIEWER).code)
        self.assertEqual(
            403, self.fetch_as('/api/task/info/whatever', VIEWER).code)
        self.assertEqual(
            403, self.fetch_as('/tasks/datatable?draw=1&start=0&length=10',
                               VIEWER).code)


class StaleInspectionAuthorizationTests(IsolatedAsyncioTestCase):
    """Authorization is re-evaluated when each response is serialized.

    The fake inspection fills an in-memory worker while the authorization
    option changes in between; the response is then filtered with whatever
    permission applies at serialization time.
    """

    async def test_inspection_started_privileged_is_filtered_after_revocation(self):
        from flower.utils.permissions import (
            STATUS_ONLY_INSPECT_FIELDS,
            can_view_worker_details,
            filter_worker_info,
        )

        detail_auth = ''
        self.assertTrue(can_view_worker_details(ADMIN, detail_auth))

        async def slow_inspection():
            nonlocal detail_auth
            # The detail result lands one step after the permission change,
            # mirroring an inspect reply still on the wire.
            await asyncio.sleep(0)
            detail_auth = 'someone-else@example.com'
            await asyncio.sleep(0)
            return dict(FAKE_WORKER_INFO)

        info = await slow_inspection()
        self.assertFalse(can_view_worker_details(ADMIN, detail_auth))

        restricted = filter_worker_info(info, STATUS_ONLY_INSPECT_FIELDS)
        self.assertNotIn('active_queues', restricted)
        self.assertNotIn('active', restricted)
        self.assertEqual({'timestamp': 1000.0}, restricted)
        # the payload that was inspected under the old permission is untouched
        self.assertIn('active_queues', info)

    async def test_inspection_started_status_only_is_released_after_grant(self):
        from flower.utils.permissions import can_view_worker_details

        detail_auth = DETAIL_AUTH
        self.assertFalse(can_view_worker_details(VIEWER, detail_auth))

        async def slow_inspection():
            nonlocal detail_auth
            await asyncio.sleep(0)
            # an admin widens this account's permissions before the reply lands
            detail_auth = '.*@example.com'
            await asyncio.sleep(0)
            return dict(FAKE_WORKER_INFO)

        info = await slow_inspection()
        self.assertTrue(can_view_worker_details(VIEWER, detail_auth))
        self.assertIn('active_queues', info)


class AccessAuditLogTests(WorkerPermissionTestCase):
    def test_denial_is_logged_with_a_checkable_reason(self):
        with self.assertLogs('flower.utils.permissions', level='WARNING') as logs:
            self.fetch_as('/api/workers?workername=celery@worker1', VIEWER)
        self.assertTrue(any(
            'denied' in line and VIEWER in line and
            'online status' in line
            for line in logs.output))

    def test_grant_is_logged_with_the_matching_reason(self):
        with self.assertLogs('flower.utils.permissions', level='INFO') as logs:
            self.fetch_as('/api/workers?workername=celery@worker1', ADMIN)
        self.assertTrue(any(
            'granted' in line and ADMIN in line and
            'worker_details_auth' in line
            for line in logs.output))

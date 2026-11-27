"""End-to-end checks for operator-scoped control approvals.

These use the in-process handler client so they run where the sandbox forbids
local port binding.  They exercise the same handler classes the real router
selects and assert on the actual Celery control calls.
"""
import threading
import unittest
from unittest.mock import MagicMock, patch

import celery
from tornado.ioloop import IOLoop
from tornado.options import options

from flower.app import Flower
from flower.events import Events
from flower.urls import handlers, settings
from tests.unit.inprocess import InProcessClient


def quiet_inspector(app):
    """Detached inspections try to reach a broker this fixture does not have."""
    stop = patch.object(app, 'update_workers', return_value=None)
    stop.start()
    return stop

DUTY = 'duty=worker.queue_cancel_consumer,worker.pool_grow,worker.shutdown'
POOL = 'pool=worker.queue_add_consumer,worker.pool_grow'
USERS = ['alice:wonderland', 'bob:builder']


class InProcessHeadlessApp(unittest.TestCase):
    groups = []
    operators = []

    def setUp(self):
        options.control_groups = list(self.groups)
        options.control_operators = list(self.operators)
        options.basic_auth = USERS
        options.read_only = False
        capp = celery.Celery()
        self._app = Flower(
            capp=capp,
            events=Events(capp, IOLoop.current(),
                          max_tasks_in_memory=10),
            options=options, handlers=handlers, **settings)
        self._inspector_patch = quiet_inspector(self._app)
        self.client = InProcessClient(self._app)
        self.service = self._app.control
        self.service.registry.clear()
        self.service.ledger._approvals.clear()
        self.service.ledger._responses.clear()

    def tearDown(self):
        self._inspector_patch.stop()
        options.control_groups = []
        options.control_operators = []
        options.basic_auth = []
        options.read_only = False


class ControlScenarioTests(InProcessHeadlessApp):
    groups = [DUTY, POOL]
    operators = ['alice=duty', 'bob=pool']

    def login(self, user):
        return (user, 'wonderland' if user == 'alice' else 'builder')

    def register(self, pid, queues):
        service = self.service
        service.observe_event('worker-online', 'celery@worker1', {'pid': pid})
        service.observe_inspection('celery@worker1', {
            'stats': {'pid': pid},
            'active_queues': [{'name': queue} for queue in queues]})
        return service.registration_for('celery@worker1')

    def approve(self, user, action, registration, **scope):
        body = dict(scope, action=action,
                    registration_id=registration.registration_id)
        return self.client.post(
            '/api/worker/approve/celery%40worker1', body,
            auth=self.login(user), headers={'X-Flower-Control-Page': '1'})

    def test_old_page_cannot_stop_a_replacement_workers_queue(self):
        calls = []
        control = self._app.capp.control
        control.broadcast = MagicMock(
            side_effect=lambda *args, **kwargs: calls.append(
                (args, kwargs)) or [{'celery@worker1': {'ok': 'done'}}])

        first = self.register(1001, ['q-orders', 'q-email'])
        approved = self.approve('alice', 'queue.cancel', first,
                                queue='q-orders')
        self.assertEqual(200, approved.code)
        approval = approved.json()

        second = self.register(2002, ['q-orders', 'q-email'])
        self.assertNotEqual(first.registration_id, second.registration_id)

        # the old page still carries the registration it rendered
        stale = self.approve('alice', 'queue.cancel', first, queue='q-orders')
        self.assertEqual(409, stale.code)
        self.assertEqual(b"Worker 'celery@worker1' was registered again; "
                         b"reload the page before approving", stale.body)

        late = self.client.post(
            '/api/worker/queue/cancel-consumer/celery%40worker1',
            {'queue': 'q-orders', 'approval': approval['approval_id']},
            auth=self.login('alice'))
        self.assertEqual(409, late.code)
        self.assertEqual([], calls)

        current = self.approve('alice', 'queue.cancel', second,
                               queue='q-orders')
        self.assertEqual(200, current.code)
        executed = self.client.post(
            '/api/worker/queue/cancel-consumer/celery%40worker1',
            {'queue': 'q-orders',
             'approval': current.json()['approval_id']},
            auth=self.login('alice'))
        self.assertEqual(200, executed.code)
        self.assertEqual(1, len(calls))
        args, kwargs = calls[0]
        self.assertEqual(('cancel_consumer',), args)
        self.assertEqual({'queue': 'q-orders'},
                         kwargs['arguments'])
        self.assertEqual(['celery@worker1'], kwargs['destination'])

        responses = self.client.get(
            '/api/control/responses', auth=self.login('alice')).json()
        delivered = [record for record in responses['responses']
                     if record['outcome'] == 'delivered']
        self.assertEqual(1, len(delivered))
        self.assertEqual(second.generation, delivered[0]['generation'])
        self.assertEqual(['celery@worker1'], delivered[0]['destination'])
        self.assertEqual('cancel_consumer', delivered[0]['command'])
        self.assertEqual('page', delivered[0]['origin'])

        rejected = [record for record in responses['responses']
                    if record['outcome'] == 'rejected']
        self.assertEqual(2, len(rejected))
        self.assertTrue(all(record['superseded'] for record in rejected))
        self.assertTrue(all(record['registration_id'] ==
                            first.registration_id for record in rejected))

    def test_groups_cannot_borrow_each_others_actions(self):
        control = self._app.capp.control
        control.broadcast = MagicMock(
            return_value=[{'celery@worker1': {'ok': 'done'}}])
        registration = self.register(1001, ['q-orders'])

        bob_cancel = self.approve('bob', 'queue.cancel', registration,
                                  queue='q-orders')
        self.assertEqual(403, bob_cancel.code)

        alice_add = self.approve('alice', 'queue.add', registration,
                                 queue='q-new')
        self.assertEqual(403, alice_add.code)

        alice_shutdown = self.approve('alice', 'worker.shutdown', registration)
        self.assertEqual(200, alice_shutdown.code)
        control.broadcast.assert_not_called()

    def test_approval_is_single_use_and_bound_to_the_operator(self):
        control = self._app.capp.control
        control.pool_grow = MagicMock(
            return_value=[{'celery@worker1': {'ok': 'done'}}])
        registration = self.register(1001, ['q-orders'])
        approval = self.approve('alice', 'pool.grow', registration, n=2)
        self.assertEqual(200, approval.code)
        approval_id = approval.json()['approval_id']

        by_bob = self.client.post(
            '/api/worker/pool/grow/celery%40worker1',
            {'n': 2, 'approval': approval_id}, auth=self.login('bob'))
        self.assertEqual(403, by_bob.code)
        control.pool_grow.assert_not_called()

        wrong_scope = self.client.post(
            '/api/worker/pool/grow/celery%40worker1',
            {'n': 9, 'approval': approval_id}, auth=self.login('alice'))
        self.assertEqual(409, wrong_scope.code)
        control.pool_grow.assert_not_called()

        reused = self.client.post(
            '/api/worker/pool/grow/celery%40worker1',
            {'n': 2, 'approval': approval_id}, auth=self.login('alice'))
        self.assertEqual(409, reused.code)
        control.pool_grow.assert_not_called()

    def test_late_response_keeps_the_registration_it_targeted(self):
        control = self._app.capp.control
        started = threading.Event()
        release = threading.Event()

        def block(*args, **kwargs):
            started.set()
            release.wait(5)
            return [{'celery@worker1': {'ok': 'done'}}]

        control.broadcast = MagicMock(side_effect=block)
        registration = self.register(1001, ['q-orders'])
        approval = self.approve('alice', 'queue.cancel', registration,
                                queue='q-orders').json()

        responses = []

        def run():
            responses.append(self.client.post(
                '/api/worker/queue/cancel-consumer/celery%40worker1',
                {'queue': 'q-orders', 'approval': approval['approval_id']},
                auth=self.login('alice')))

        worker = threading.Thread(target=run)
        worker.start()
        try:
            self.assertTrue(started.wait(5))
            self.register(2002, ['q-orders'])
        finally:
            release.set()
        worker.join(5)
        self.assertEqual(200, responses[0].code)

        record = self.client.get(
            '/api/control/responses', auth=self.login('alice')
        ).json()['responses'][0]
        self.assertEqual('delivered', record['outcome'])
        self.assertEqual(registration.registration_id,
                         record['registration_id'])
        self.assertEqual(registration.generation, record['generation'])
        self.assertTrue(record['superseded'])


class WorkerPageApprovalTests(InProcessHeadlessApp):
    groups = [DUTY]
    operators = ['alice=duty']

    def test_page_binds_controls_to_the_rendered_registration(self):
        self._app.inspector.workers['celery@worker1'] = {
            'stats': {'pid': 77, 'total': {}, 'broker': {'hostname': 'redis'}},
            'active_queues': []}
        self.service.observe_event(
            'worker-online', 'celery@worker1', {'pid': 77})
        self.service.observe_inspection(
            'celery@worker1',
            {'stats': {'pid': 77},
             'active_queues': [{'name': 'q-orders'}]})
        registration = self.service.registration_for('celery@worker1')
        self.service.approve('alice', 'queue.cancel', 'celery@worker1',
                             registration_id=registration.registration_id,
                             queue='q-orders')

        page = self.client.get('/worker/celery%40worker1',
                               auth=('alice', 'wonderland'))
        html = page.body.decode()
        self.assertEqual(200, page.code)
        self.assertIn('data-control-approvals="required"', html)
        self.assertIn(
            f'data-registration-id="{registration.registration_id}"', html)
        self.assertIn('Approved actions', html)
        self.assertIn('data-action="worker.queue_cancel_consumer"', html)

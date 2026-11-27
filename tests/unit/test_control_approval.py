import asyncio
import unittest
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

from celery.events import Event

from flower.control.policy import (
    OperatorPolicy,
    normalize_action,
    parse_group_actions,
    parse_group_members,
)
from flower.control.service import ControlService
from flower.events import EventsState


def options(groups, operators):
    return SimpleNamespace(control_groups=groups,
                           control_operators=operators)


class PolicyTests(unittest.TestCase):
    def test_parses_group_allowlists(self):
        groups = parse_group_actions(
            ['duty=worker.shutdown,worker.queue_cancel_consumer',
             'pool=worker.pool_grow,worker.pool_shrink',
             'pool=worker.pool_autoscale'])
        self.assertEqual(
            {'duty': frozenset({'worker.shutdown',
                                'worker.queue_cancel_consumer'}),
             'pool': frozenset({'worker.pool_grow',
                                'worker.pool_shrink',
                                'worker.pool_autoscale'})},
            groups)

    def test_parses_members_in_both_styles(self):
        groups = {'duty': frozenset(), 'pool': frozenset()}
        members = parse_group_members(
            ['alice=duty', 'pool=bob,carol'], groups)
        self.assertEqual(
            {'alice': 'duty', 'bob': 'pool', 'carol': 'pool'}, members)

    def test_comma_split_option_values_continue_the_entry(self):
        # Tornado splits a multiple option on commas before Flower sees it
        groups = parse_group_actions(
            ['duty=worker.shutdown', 'worker.queue_cancel_consumer',
             'pool=worker.pool_grow'])
        self.assertEqual(
            {'duty': frozenset({'worker.shutdown',
                                'worker.queue_cancel_consumer'}),
             'pool': frozenset({'worker.pool_grow'})},
            groups)
        members = parse_group_members(
            ['duty=alice', 'bob'], groups)
        self.assertEqual({'alice': 'duty', 'bob': 'duty'}, members)

    def test_actions_are_scoped_per_group(self):
        groups = parse_group_actions(['duty=worker.shutdown',
                                      'pool=worker.pool_grow'])
        policy = OperatorPolicy(
            groups, parse_group_members(['alice=duty', 'bob=pool'], groups))
        self.assertTrue(policy.allows('alice', 'shutdown'))
        self.assertFalse(policy.allows('alice', 'worker.pool_grow'))
        self.assertTrue(policy.allows('bob', 'worker.pool_grow'))
        self.assertFalse(policy.allows('bob', 'worker.shutdown'))
        self.assertFalse(policy.allows('carol', 'worker.shutdown'))

    def test_unknown_group_disables_the_action(self):
        groups = parse_group_actions(['duty=worker.shutdown'])
        policy = OperatorPolicy(
            groups, parse_group_members(['alice=missing'], groups))
        self.assertFalse(policy.allows('alice', 'worker.shutdown'))

    def test_normalizes_action_aliases(self):
        self.assertEqual('worker.queue_cancel_consumer',
                         normalize_action('queue.cancel'))
        self.assertEqual('worker.pool_restart',
                         normalize_action('pool_restart'))


class RegistrationTests(unittest.TestCase):
    def service(self):
        return ControlService(
            options(['duty=worker.shutdown'], ['alice=duty']), MagicMock())

    def test_a_new_pid_is_a_new_generation(self):
        service = self.service()
        first = service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 1})
        second = service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 2})
        self.assertEqual(1, first.generation)
        self.assertEqual(2, second.generation)
        self.assertNotEqual(first.registration_id, second.registration_id)

    def test_repeated_online_event_keeps_the_generation(self):
        service = self.service()
        first = service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 1})
        again = service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 1})
        self.assertEqual(first.registration_id, again.registration_id)

    def test_offline_then_online_restarts_the_generation(self):
        service = self.service()
        first = service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 1})
        service.registry.observe_event('worker-offline', 'celery@w1', {'pid': 1})
        again = service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 1})
        self.assertEqual(first.generation + 1, again.generation)
        self.assertNotEqual(first.registration_id, again.registration_id)

    def test_inspection_records_queue_ownership(self):
        service = self.service()
        service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 1})
        registration = service.registry.observe_inspection(
            'celery@w1', {'stats': {'pid': 1},
                          'active_queues': [{'name': 'q1'}]})
        self.assertTrue(service.registry.owns_queue('celery@w1', 'q1'))
        self.assertFalse(service.registry.owns_queue('celery@w1', 'q2'))
        self.assertEqual(frozenset({'q1'}), registration.queues)

    def test_events_state_notifies_the_registry(self):
        state = EventsState()
        seen = []
        state.registration_observer = (
            lambda kind, name, fields: seen.append((kind, name)))
        state.event(Event('worker-online', hostname='celery@w1',
                          local_received=time.time()))
        self.assertIn(('worker-online', 'celery@w1'), seen)


class ApprovalTests(unittest.TestCase):
    def service(self, groups=None, operators=None):
        service = ControlService(
            options(groups or ['duty=worker.queue_cancel_consumer,'
                               'worker.pool_grow,worker.shutdown'],
                    operators or ['alice=duty', 'bob=duty']),
            MagicMock())
        service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 1})
        service.registry.observe_inspection(
            'celery@w1', {'stats': {'pid': 1},
                          'active_queues': [{'name': 'q1'},
                                            {'name': 'q2'}]})
        return service

    def invoke(self, service, operator, action, approval_id, queue=None,
               parameters=None):
        async def run_blocking(op, target, func, *args, **kwargs):
            return func(*args, **kwargs)
        return asyncio.run(service.execute(
            operator, action, 'celery@w1', run_blocking,
            approval_id=approval_id, queue=queue, parameters=parameters))

    def test_approval_is_bound_to_the_registration(self):
        service = self.service()
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=registration.registration_id, queue='q1')
        self.assertEqual(registration.registration_id,
                         approval.registration_id)
        self.assertEqual(registration.generation, approval.generation)

    def test_stale_page_cannot_issue_an_approval(self):
        service = self.service()
        first = service.registration_for('celery@w1')
        service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 2})
        with self.assertRaises(Exception) as raised:
            service.approve('alice', 'queue.cancel', 'celery@w1',
                            registration_id=first.registration_id, queue='q1')
        self.assertEqual(409, raised.exception.status_code)
        record = service.responses()[0]
        self.assertEqual('rejected', record['outcome'])
        self.assertEqual(first.registration_id, record['registration_id'])
        self.assertTrue(record['superseded'])

    def test_unapproved_action_is_refused(self):
        service = self.service(['duty=worker.shutdown', 'pool=worker.pool_grow'],
                               ['alice=duty', 'bob=pool'])
        registration = service.registration_for('celery@w1')
        with self.assertRaises(Exception) as raised:
            service.approve('alice', 'worker.pool_grow', 'celery@w1',
                            registration_id=registration.registration_id)
        self.assertEqual(403, raised.exception.status_code)

    def test_approval_cannot_be_reused(self):
        service = self.service()
        service.capp.control.broadcast = MagicMock(
            return_value=[{'celery@w1': {'ok': ''}}])
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=registration.registration_id, queue='q1')
        self.invoke(service, 'alice', 'queue.cancel', approval.approval_id,
                    queue='q1')
        with self.assertRaises(Exception) as raised:
            self.invoke(service, 'alice', 'queue.cancel',
                        approval.approval_id, queue='q1')
        self.assertEqual(409, raised.exception.status_code)

    def test_another_operator_cannot_use_the_approval(self):
        service = self.service()
        service.capp.control.broadcast = MagicMock(
            return_value=[{'celery@w1': {'ok': ''}}])
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=registration.registration_id, queue='q1')
        with self.assertRaises(Exception) as raised:
            self.invoke(service, 'bob', 'queue.cancel',
                        approval.approval_id, queue='q1')
        self.assertEqual(403, raised.exception.status_code)
        service.capp.control.broadcast.assert_not_called()

    def test_queue_moved_off_the_worker_is_rejected(self):
        service = self.service()
        service.capp.control.broadcast = MagicMock()
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=registration.registration_id, queue='q2')
        service.registry.observe_inspection(
            'celery@w1', {'stats': {'pid': 1},
                          'active_queues': [{'name': 'q1'}]})
        with self.assertRaises(Exception) as raised:
            self.invoke(service, 'alice', 'queue.cancel',
                        approval.approval_id, queue='q2')
        self.assertEqual(409, raised.exception.status_code)
        service.capp.control.broadcast.assert_not_called()

    def test_queue_scope_must_match(self):
        service = self.service()
        service.capp.control.broadcast = MagicMock(
            return_value=[{'celery@w1': {'ok': ''}}])
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=registration.registration_id, queue='q1')
        with self.assertRaises(Exception) as raised:
            self.invoke(service, 'alice', 'queue.cancel',
                        approval.approval_id, queue='q2')
        self.assertEqual(409, raised.exception.status_code)
        service.capp.control.broadcast.assert_not_called()

    def test_missing_approval_is_recorded_with_the_current_registration(self):
        service = self.service()
        service.capp.control.broadcast = MagicMock()
        registration = service.registration_for('celery@w1')
        with self.assertRaises(Exception) as raised:
            self.invoke(service, 'alice', 'queue.cancel', None, queue='q1')
        self.assertEqual(403, raised.exception.status_code)
        record = service.responses()[0]
        self.assertEqual('rejected', record['outcome'])
        self.assertEqual(registration.registration_id,
                         record['registration_id'])
        service.capp.control.broadcast.assert_not_called()

    def test_execute_targets_the_actual_celery_command(self):
        service = self.service()
        service.capp.control.broadcast = MagicMock(
            return_value=[{'celery@w1': {'ok': ''}}])
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=registration.registration_id, queue='q1')
        self.invoke(service, 'alice', 'queue.cancel', approval.approval_id,
                    queue='q1')
        service.capp.control.broadcast.assert_called_once_with(
            'cancel_consumer', arguments={'queue': 'q1'},
            destination=['celery@w1'], reply=True)

    def test_task_limits_use_their_scope(self):
        service = self.service(['duty=task.time_limit'], ['alice=duty'])
        service.capp.control.time_limit = MagicMock(
            return_value=[{'celery@w1': {'ok': 'limits set'}}])
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'task.time_limit', 'celery@w1',
            registration_id=registration.registration_id,
            parameters={'taskname': 'tasks.add', 'soft': 1,
                        'hard': 2})
        self.invoke(service, 'alice', 'task.time_limit', approval.approval_id,
                    parameters={'taskname': 'tasks.add', 'soft': 1,
                                'hard': 2})
        service.capp.control.time_limit.assert_called_once_with(
            'tasks.add', reply=True, hard=2, soft=1,
            destination=['celery@w1'])

    def test_task_limit_scope_change_is_rejected(self):
        service = self.service(['duty=task.time_limit'], ['alice=duty'])
        service.capp.control.time_limit = MagicMock(
            return_value=[{'celery@w1': {'ok': 'limits set'}}])
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'task.time_limit', 'celery@w1',
            registration_id=registration.registration_id,
            parameters={'taskname': 'tasks.add', 'soft': 1,
                        'hard': 2})
        with self.assertRaises(Exception) as raised:
            self.invoke(service, 'alice', 'task.time_limit',
                        approval.approval_id,
                        parameters={'taskname': 'tasks.add', 'soft': 1,
                                    'hard': 9})
        self.assertEqual(409, raised.exception.status_code)
        service.capp.control.time_limit.assert_not_called()

    def test_replacement_between_approval_and_execution_is_rejected(self):
        service = self.service()
        service.capp.control.broadcast = MagicMock(
            return_value=[{'celery@w1': {'ok': ''}}])
        first = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=first.registration_id, queue='q1')
        service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 2})
        with self.assertRaises(Exception) as raised:
            self.invoke(service, 'alice', 'queue.cancel',
                        approval.approval_id, queue='q1')
        self.assertEqual(409, raised.exception.status_code)
        service.capp.control.broadcast.assert_not_called()

    def test_late_response_keeps_its_original_attribution(self):
        service = self.service()
        started = threading.Event()
        release = threading.Event()

        def block(*_args, **_kwargs):
            started.set()
            release.wait(2)
            return [{'celery@w1': {'ok': ''}}]

        service.capp.control.broadcast = MagicMock(side_effect=block)
        registration = service.registration_for('celery@w1')
        approval = service.approve(
            'alice', 'queue.cancel', 'celery@w1',
            registration_id=registration.registration_id, queue='q1')

        result = {}

        def run():
            async def run_blocking(op, target, func, *args, **kwargs):
                return func(*args, **kwargs)
            result['value'] = asyncio.run(service.execute(
                'alice', 'queue.cancel', 'celery@w1', run_blocking,
                approval_id=approval.approval_id, queue='q1'))

        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(started.wait(2))
        service.registry.observe_event(
            'worker-online', 'celery@w1', {'pid': 2})
        release.set()
        worker.join(2)

        record = service.responses()[0]
        self.assertEqual('delivered', record['outcome'])
        self.assertEqual(first_registration(service, approval),
                         record['registration_id'])
        self.assertTrue(record['superseded'])
        self.assertEqual(['celery@w1'], record['destination'])
        self.assertEqual('cancel_consumer', record['command'])


def first_registration(service, approval):
    return service.registry.lookup(approval.registration_id).registration_id

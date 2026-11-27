import asyncio
import dbm
import dbm.dumb
import json
import os
import pickle
import shelve
import tempfile
import time
from unittest.mock import Mock, patch

from celery.events.state import State
from kombu.exceptions import OperationalError
from tornado.testing import AsyncTestCase, gen_test

from flower.events import Events
from tests.unit.utils import task_succeeded_events


class Unpicklable:
    # local lambdas raise different errors per Python version, this fails the same way everywhere
    def __reduce__(self):
        raise pickle.PicklingError('not picklable')


class PersistenceTests(AsyncTestCase):
    def events(self, db, max_tasks_in_memory=10, **kwargs):
        return Events(Mock(), self.io_loop, db=db, persistent=True,
                      enable_events=False,
                      max_tasks_in_memory=max_tasks_in_memory, **kwargs)

    def generations(self, db):
        root = db + '.checkpoints'
        if not os.path.isdir(root):
            return []
        return sorted(os.listdir(root))

    def thatch(self, directory):
        "Plant a red herring directory where a dbm backend would also write"
        os.makedirs(directory, exist_ok=True)

    def test_recovers_counters_and_continues_counting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 2
            events.state.counter['worker1']['task-succeeded'] = 1
            events.state.counter['worker2']['task-failed'] = 3
            events.save_state()

            restored = self.events(db)

            self.assertEqual(
                2, restored.state.counter['worker1']['task-received'])
            self.assertEqual(
                1, restored.state.counter['worker1']['task-succeeded'])
            self.assertEqual(
                3, restored.state.counter['worker2']['task-failed'])

            restored.state.counter['worker1']['task-succeeded'] += 1
            restored.state.counter['worker3']['task-received'] += 1
            restored.save_state()

            restored_again = self.events(db)
            self.assertEqual(
                2, restored_again.state.counter['worker1']['task-succeeded'])
            self.assertEqual(
                1, restored_again.state.counter['worker3']['task-received'])

    def test_save_publishes_a_generation_with_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            manifest = events.checkpoints.save(events.state)

            self.assertEqual(1, manifest['generation'])
            self.assertEqual(
                [f'gen-{manifest["generation"]:012d}'], self.generations(db))
            directory = events.checkpoints.generation_path(manifest['generation'])
            self.assertEqual(
                {'manifest.json', 'events.pkl', 'counters.json'},
                set(os.listdir(directory)))
            # The flat legacy path is not written any more.
            for suffix in ('', '.db', '.dat', '.dir', '.bak'):
                self.assertFalse(os.path.exists(db + suffix))

    def test_failed_save_publishes_no_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 2
            events.save_state()

            events.state.counter['worker1']['task-received'] = 5
            events.state.tasks['bad-task'] = Unpicklable()
            with self.assertRaises(pickle.PicklingError):
                events.save_state()

            restored = self.events(db)
            self.assertEqual(
                2, restored.state.counter['worker1']['task-received'])
            # The half written generation is still on disk, but rejected.
            rejected = [c for c in restored.recovery.report['candidates']
                        if c['status'] == 'rejected']
            self.assertTrue(rejected)
            self.assertIn('manifest is missing', rejected[0]['reason'])

    def test_save_leaves_no_temporary_fragments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            events.save_state()

            leftovers = [name for name in os.listdir(tmpdir)
                         if '.tmp' in name or '.staging' in name]
            self.assertEqual([], leftovers)
            generation = events.checkpoints.generation_path(1)
            self.assertEqual([], [name for name in os.listdir(generation)
                                  if '.tmp' in name])

    def test_recovers_from_corrupt_legacy_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            with open(db + '.db', 'wb') as f:
                f.write(b'garbage' * 100)

            events = self.events(db)

            self.assertEqual({}, dict(events.state.counter))
            self.assertEqual(0, len(events.state.tasks))
            self.assertEqual('fresh', events.recovery.selected.source)
            selected = events.recovery.report['selected']
            self.assertEqual('no checkpoint passed admission',
                             selected['reason'])
            # Corrupt storage is evidence, not something to rename or delete.
            self.assertTrue(os.path.exists(db + '.db'))

    def test_legacy_db_is_admitted_when_no_generation_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 3
            with shelve.open(db, flag='n') as state:
                state['events'] = events.state
                state['counter'] = dict(events.state.counter)

            restored = self.events(db)

            self.assertEqual(
                3, restored.state.counter['worker1']['task-received'])
            self.assertEqual('legacy', restored.recovery.selected.source)
            self.assertEqual(0, restored.recovery.selected.format_version)
            self.assertNotIn('generation', restored.recovery.report['selected'])

    def test_legacy_recognition_works_for_suffixed_dbm_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            with patch.object(dbm, '_defaultmod', dbm.dumb):
                events = self.events(db)
                events.state.counter['worker1']['task-received'] = 3
                with shelve.open(db, flag='n') as state:
                    state['events'] = events.state
                    state['counter'] = dict(events.state.counter)
                self.assertTrue(os.path.exists(db + '.dat'))

                restored = self.events(db)
                self.assertEqual(
                    3, restored.state.counter['worker1']['task-received'])
                self.assertEqual('legacy', restored.recovery.selected.source)

    def test_legacy_containing_a_partial_generation_is_not_mistaken(self):
        # A dbm shelf that a *new* writer left half materialized next to a
        # complete one must not be preferred over the complete checkpoint.
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 2
            events.save_state()

            with shelve.open(db, flag='n') as state:
                state['events'] = events.state
                state['counter'] = {'worker1': {'task-received': 99}}

            restored = self.events(db)
            self.assertEqual(
                2, restored.state.counter['worker1']['task-received'])
            self.assertEqual('generation', restored.recovery.selected.source)

    def test_rejects_generation_with_partial_fragment_set(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 4
            events.save_state()

            directory = events.checkpoints.generation_path(1)
            os.remove(os.path.join(directory, 'counters.json'))

            restored = self.events(db)

            self.assertEqual('fresh', restored.recovery.selected.source)
            self.assertEqual({}, dict(restored.state.counter))
            rejected = [c for c in restored.recovery.report['candidates']
                        if c['status'] == 'rejected']
            self.assertEqual(1, len(rejected))
            self.assertIn("fragment 'counters' is missing", rejected[0]['reason'])
            self.assertEqual(
                {'expected': 2, 'present': 1}, rejected[0]['fragments'])

    def test_rejects_generation_with_tampered_fragment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            events.save_state()

            counters = os.path.join(
                events.checkpoints.generation_path(1), 'counters.json')
            with open(counters, 'rb') as f:
                original = f.read()
            # Same length, different bytes: only the digest can catch it.
            tampered = original.replace(b'1', b'7', 1)
            self.assertEqual(len(original), len(tampered))
            with open(counters, 'wb') as f:
                f.write(tampered)

            restored = self.events(db)
            self.assertEqual('fresh', restored.recovery.selected.source)
            rejected = [c for c in restored.recovery.report['candidates']
                        if c['status'] == 'rejected']
            self.assertIn('sha256 mismatch', rejected[0]['reason'])

    def test_falls_back_to_previous_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            events.save_state()
            events.state.counter['worker1']['task-received'] = 2
            events.save_state()

            # Damage the newest complete generation only.
            newest = events.checkpoints.generation_path(2)
            os.remove(os.path.join(newest, 'events.pkl'))

            restored = self.events(db)

            self.assertEqual('generation', restored.recovery.selected.source)
            self.assertEqual(1, restored.recovery.selected.generation)
            self.assertEqual(
                1, restored.state.counter['worker1']['task-received'])
            retrieval = restored.recovery.report['retrieval']
            self.assertEqual(1, retrieval['counter_total'])
            self.assertEqual(0, retrieval['task_count'])

    def test_stricter_admission_declines_older_generations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            events.save_state()

            strict = self.events(
                db, checkpoint_min_format_version=2)

            self.assertEqual('fresh', strict.recovery.selected.source)
            reason = strict.recovery.report['selected']['reason']
            self.assertEqual('no checkpoint passed admission', reason)
            rejected = [c for c in strict.recovery.report['candidates']
                        if c['status'] == 'rejected']
            self.assertTrue(any('below the admitted minimum 2' in c['reason']
                                for c in rejected))

    def test_stricter_admission_can_also_refuse_legacy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            with shelve.open(db, flag='n') as state:
                state['events'] = events.state
                state['counter'] = {}

            strict = self.events(
                db, checkpoint_min_format_version=1, checkpoint_allow_legacy=False)

            self.assertEqual('fresh', strict.recovery.selected.source)
            rejected = [c for c in strict.recovery.report['candidates']
                        if c['status'] == 'rejected']
            self.assertTrue(any('legacy storage is disabled' in c['reason']
                                for c in rejected))

    def test_recovery_record_is_written_for_operations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-succeeded'] = 1
            events.save_state()

            restored = self.events(db)

            latest = os.path.join(db + '.recovery', 'latest.json')
            history = os.path.join(db + '.recovery', 'recovery.jsonl')
            self.assertTrue(os.path.isfile(latest))
            with open(latest, encoding='utf-8') as f:
                report = json.load(f)
            with open(history, encoding='utf-8') as f:
                records = [json.loads(line) for line in f if line.strip()]

            self.assertEqual('flower.recovery/1', report['schema'])
            self.assertEqual(report, records[-1])
            self.assertEqual('generation', report['selected']['source'])
            self.assertEqual(1, report['selected']['generation'])
            self.assertEqual(
                {'open': True, 'source': 'state'},
                {key: report['retrieval'][key] for key in ('open', 'source')})
            self.assertEqual(1, report['retrieval']['counter_total'])

    def test_recovery_record_lists_the_rejected_save(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            events.save_state()
            events.state.tasks['bad-task'] = Unpicklable()
            with self.assertRaises(pickle.PicklingError):
                events.save_state()

            restored = self.events(db)

            with open(os.path.join(db + '.recovery', 'latest.json'),
                      encoding='utf-8') as f:
                report = json.load(f)
            statuses = [candidate['status']
                        for candidate in report['candidates']]
            self.assertIn('rejected', statuses)
            self.assertEqual(1, report['selected']['generation'])
            self.assertEqual(0, report['retrieval']['task_count'])
            self.assertEqual(1, report['retrieval']['counter_total'])

    def test_manifest_counts_must_match_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            events.save_state()

            manifest_path = os.path.join(
                events.checkpoints.generation_path(1), 'manifest.json')
            with open(manifest_path, encoding='utf-8') as f:
                manifest = json.load(f)
            manifest['task_count'] = 5
            with open(manifest_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f)

            restored = self.events(db)
            self.assertEqual('fresh', restored.recovery.selected.source)
            rejected = [c for c in restored.recovery.report['candidates']
                        if c['status'] == 'rejected']
            self.assertIn('manifest task_count', rejected[0]['reason'])

    def test_selection_is_decided_and_recorded_before_the_state_is_open(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-received'] = 1
            events.save_state()

            seen = []

            def observe(report):
                seen.append(report['selected'])

            recovery = events.checkpoints.recover(before_open=observe)

            self.assertEqual(1, len(seen))
            self.assertEqual('generation', seen[0]['source'])
            self.assertEqual(1, seen[0]['generation'])
            self.assertEqual(
                'highest admitted generation', seen[0]['reason'])
            self.assertEqual(1, recovery.report['retrieval']['counter_total'])

    def test_retention_keeps_only_recent_complete_generations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db, checkpoint_retention=2)
            for counter in (1, 2, 3):
                events.state.counter['worker1']['task-received'] = counter
                events.save_state()

            self.assertEqual(
                ['gen-000000000002', 'gen-000000000003'],
                self.generations(db))
            restored = self.events(db, checkpoint_retention=2)
            self.assertEqual(
                3, restored.state.counter['worker1']['task-received'])
            self.assertEqual(3, restored.recovery.selected.generation)

    def test_fresh_recovery_keeps_the_configured_worker_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')

            restored = Events(
                Mock(), self.io_loop, db=db, persistent=True,
                enable_events=False, max_tasks_in_memory=10,
                max_workers_in_memory=7)

            self.assertEqual('fresh', restored.recovery.selected.source)
            self.assertEqual(7, restored.state.workers.limit)
            self.assertEqual(10, restored.state.tasks.limit)

    def test_warns_when_save_dominates_interval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db, state_save_interval=1000)

            with self.assertLogs('flower.events', level='WARNING') as logs:
                for _ in range(3):
                    with patch('flower.events.time.monotonic', side_effect=[0, 60]):
                        events.save_state()

            self.assertEqual(3, len(logs.output))
            self.assertIn('--state-save-interval', logs.output[0])

    def test_no_warning_for_fast_saves(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db, state_save_interval=1000)

            with (
                patch('flower.events.time.monotonic', side_effect=[0, 0.01]),
                self.assertNoLogs('flower.events', level='WARNING'),
            ):
                events.save_state()

    def test_no_warning_without_save_timer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)

            with (
                patch('flower.events.time.monotonic', side_effect=[0, 60]),
                self.assertNoLogs('flower.events', level='WARNING'),
            ):
                events.save_state()

    def receive_tasks(self, events, count):
        for _ in range(count):
            for event in task_succeeded_events('worker1'):
                event['clock'] = len(events.state.tasks)
                event['local_received'] = time.time()
                events.state.event(event)

    def test_raises_task_limit_on_restore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db, max_tasks_in_memory=2)
            self.receive_tasks(events, 2)
            events.save_state()

            restored = self.events(db, max_tasks_in_memory=4)
            self.receive_tasks(restored, 2)

            self.assertEqual(4, len(restored.state.tasks))

    def test_shrinks_task_limit_on_restore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db, max_tasks_in_memory=4)
            self.receive_tasks(events, 4)
            events.save_state()

            restored = self.events(db, max_tasks_in_memory=2)

            self.assertEqual(2, len(restored.state.tasks))
            self.receive_tasks(restored, 1)
            self.assertEqual(2, len(restored.state.tasks))

    def test_restores_index_and_counters_from_one_generation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db, max_tasks_in_memory=10)
            self.receive_tasks(events, 3)
            events.state.counter['worker1']['task-received'] = 3
            events.save_state()

            restored = self.events(db, max_tasks_in_memory=10)

            self.assertEqual(
                set(restored.state.tasks),
                set(restored.state.search_engine.documents))
            self.assertEqual(3, len(restored.state.search_engine.documents))
            self.assertEqual(
                3, restored.state.counter['worker1']['task-received'])
            self.assertEqual(
                3, restored.recovery.report['retrieval']['indexed_task_count'])

    def test_admits_plain_celery_state_and_rebuilds_the_index(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            for event in task_succeeded_events('worker1'):
                event['clock'] = 1
                event['local_received'] = time.time()
                events.state.event(event)
            plain = State(
                workers=events.state.workers, tasks=events.state.tasks)
            with shelve.open(db, flag='n') as state:
                state['events'] = plain

            restored = self.events(db)

            self.assertEqual('legacy', restored.recovery.selected.source)
            task_id = next(iter(restored.state.tasks))
            self.assertEqual(
                {task_id},
                restored.state.search_engine.matching_ids('state:SUCCESS'))

    def test_loads_database_without_persisted_counters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = os.path.join(tmpdir, 'flower')
            events = self.events(db)
            events.state.counter['worker1']['task-succeeded'] = 1
            with shelve.open(db, flag='n') as state:
                state['events'] = events.state

            restored = self.events(db)

            self.assertEqual({}, dict(restored.state.counter))


class EnableEventsTests(AsyncTestCase):
    def setUp(self):
        super().setUp()
        self.events = Events.__new__(Events)
        self.events.io_loop = Mock()
        self.events.capp = Mock()

    @gen_test
    async def test_awaits_enable_events_call(self):
        future = asyncio.Future()
        self.events.io_loop.run_in_executor.return_value = future

        operation = asyncio.create_task(self.events.on_enable_events())
        await asyncio.sleep(0)

        self.events.io_loop.run_in_executor.assert_called_once_with(
            None, self.events.capp.control.enable_events)
        self.assertFalse(operation.done())

        future.set_result(None)
        await operation

    @gen_test
    async def test_logs_enable_events_failure_without_traceback(self):
        future = asyncio.Future()
        self.events.io_loop.run_in_executor.return_value = future

        operation = asyncio.create_task(self.events.on_enable_events())
        await asyncio.sleep(0)
        future.set_exception(OperationalError('broker is down'))

        with self.assertLogs('flower.events', level='WARNING') as logs:
            await operation

        self.assertEqual(
            'WARNING:flower.events:Failed to enable events: broker is down',
            logs.output[0])

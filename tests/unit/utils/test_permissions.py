from unittest import TestCase

from flower.utils.permissions import (
    STATUS_ONLY_EVENT_FIELDS,
    STATUS_ONLY_INSPECT_FIELDS,
    can_view_worker_details,
    filter_event_workers,
    filter_worker_info,
    filter_workers,
)


class CanViewWorkerDetailsTests(TestCase):
    def test_no_restriction_grants_every_account(self):
        self.assertTrue(can_view_worker_details('viewer@example.com', ''))
        # unauthenticated API sessions carry the placeholder identity True
        self.assertTrue(can_view_worker_details(True, ''))
        self.assertTrue(can_view_worker_details(None, ''))

    def test_matching_email_is_allowed(self):
        self.assertTrue(
            can_view_worker_details('admin@example.com', 'admin@example.com'))
        self.assertTrue(
            can_view_worker_details('one@example.com', '.*@example.com'))

    def test_non_matching_email_is_status_only(self):
        self.assertFalse(
            can_view_worker_details('viewer@example.com', 'admin@example.com'))
        self.assertFalse(
            can_view_worker_details('attacker@example.net', '.*@example.com'))

    def test_basic_auth_identity_stays_status_only(self):
        # Basic auth authenticates but never produces an email identity
        self.assertFalse(can_view_worker_details(True, '.*@example.com'))
        self.assertFalse(can_view_worker_details(None, '.*@example.com'))


class FilterWorkerInfoTests(TestCase):
    def setUp(self):
        self.worker = {
            'stats': {'pid': 1, 'total': {'tasks.add': 3}},
            'active_queues': [{'name': 'celery'}],
            'registered': ['tasks.add'],
            'conf': {'CELERY_TIMEZONE': 'UTC'},
            'active': [{'id': 'task-1', 'args': '(1, 2)'}],
            'scheduled': [],
            'reserved': [],
            'revoked': [],
            'timestamp': 1234.5,
        }

    def test_status_only_keeps_liveness_fields_and_drops_details(self):
        visible = filter_worker_info(self.worker, STATUS_ONLY_INSPECT_FIELDS)
        self.assertEqual({'timestamp': 1234.5}, visible)
        for secret in ('stats', 'active_queues', 'registered', 'conf',
                       'active', 'scheduled', 'reserved', 'revoked'):
            self.assertNotIn(secret, visible)

    def test_filtering_does_not_mutate_the_shared_cache(self):
        filter_worker_info(self.worker, STATUS_ONLY_INSPECT_FIELDS)
        self.assertIn('active_queues', self.worker)
        self.assertIn('stats', self.worker)

    def test_filter_workers_applies_to_every_worker(self):
        result = filter_workers(
            {'worker1': self.worker, 'worker2': {'stats': {}, 'timestamp': 9}},
            STATUS_ONLY_INSPECT_FIELDS)
        self.assertEqual({'timestamp': 1234.5}, result['worker1'])
        self.assertEqual({'timestamp': 9}, result['worker2'])

    def test_event_rows_keep_status_counters_without_payload_fields(self):
        rows = filter_event_workers({
            'worker1': {
                'hostname': 'worker1',
                'status': True,
                'active': 0,
                'task-received': 3,
                'loadavg': [1, 2, 3],
                'active_queues': [{'name': 'celery'}],
                'conf': {'secret': 'value'},
            }
        })
        row = rows['worker1']
        for field in ('hostname', 'status', 'active', 'task-received', 'loadavg'):
            self.assertIn(field, row)
        for secret in ('active_queues', 'conf'):
            self.assertNotIn(secret, row)

    def test_event_allowlist_covers_the_list_page_columns(self):
        for column in ('hostname', 'status', 'active', 'task-received',
                       'task-failed', 'task-succeeded', 'loadavg'):
            self.assertIn(column, STATUS_ONLY_EVENT_FIELDS)

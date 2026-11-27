"""Replay a small fixed set of task events in different orders.

Shows which observations prove a task state occurred and which only
prove that a notification arrived:

- ``state.counter`` counts every delivered event, duplicates included.
- ``task.<state>`` fields (``task.succeeded`` etc.) are set from the
  worker-reported timestamp of the last applied event of that type.
- ``task.state`` only moves forward in precedence, so it is stable
  under delayed and duplicate deliveries.
- ``task.timestamp`` (the default page ordering) is overwritten by any
  event that merges without a field filter, so a delayed ``task-started``
  moves a succeeded task backwards on the tasks page.
"""
import copy
import unittest

from flower.events import EventsState

WORKER = 'worker1'
RECEIVED_AT = 1000.0
STARTED_AT = 1010.0
SUCCEEDED_AT = 1020.0


def task_events(uuid='task-1', succeeded_at=SUCCEEDED_AT):
    """One small reusable event set: received -> started -> succeeded."""
    return {
        'received': dict(type='task-received', uuid=uuid, hostname=WORKER,
                         name='sometask', args='(2, 2)',
                         kwargs="{'foo': 'bar'}", retries=0, eta=None,
                         timestamp=RECEIVED_AT, clock=1),
        'started': dict(type='task-started', uuid=uuid, hostname=WORKER,
                        timestamp=STARTED_AT, clock=2),
        'succeeded': dict(type='task-succeeded', uuid=uuid, hostname=WORKER,
                          result='4', runtime=10.0,
                          timestamp=succeeded_at, clock=3),
    }


def replay(deliveries):
    """Feed events into a fresh EventsState in arrival order.

    ``deliveries`` is a list of (event_set, event_name) pairs. Every
    delivery gets a fresh dict copy (like broker redelivery) and a
    strictly increasing ``local_received`` receiver-side timestamp.
    """
    state = EventsState(max_tasks_in_memory=100)
    arrival = 2000.0
    for events, name in deliveries:
        event = copy.deepcopy(events[name])
        event['local_received'] = arrival
        arrival += 1.0
        state.event(event)
    return state


def lifecycle(events):
    return [(events, 'received'), (events, 'started'), (events, 'succeeded')]


class EventReplayTests(unittest.TestCase):
    def test_normal_order(self):
        events = task_events()
        state = replay(lifecycle(events))
        task = state.tasks['task-1']
        self.assertEqual('SUCCESS', task.state)
        self.assertEqual(SUCCEEDED_AT, task.timestamp)
        self.assertEqual(RECEIVED_AT, task.received)
        self.assertEqual(STARTED_AT, task.started)
        self.assertEqual(SUCCEEDED_AT, task.succeeded)
        self.assertEqual(1, state.counter[WORKER]['task-succeeded'])

    def test_delayed_started_keeps_state_but_moves_timestamp_back(self):
        events = task_events()
        state = replay([(events, 'received'),
                        (events, 'succeeded'),
                        (events, 'started')])
        task = state.tasks['task-1']
        # state is precedence-guarded: late STARTED cannot roll it back
        self.assertEqual('SUCCESS', task.state)
        # but the unfiltered merge copies the event's own timestamp
        self.assertEqual(STARTED_AT, task.timestamp)
        self.assertEqual(SUCCEEDED_AT, task.succeeded)

    def test_duplicate_succeeded_only_inflates_the_counter(self):
        events = task_events()
        state = replay(lifecycle(events) + [(events, 'succeeded')])
        task = state.tasks['task-1']
        self.assertEqual(2, state.counter[WORKER]['task-succeeded'])
        self.assertEqual('SUCCESS', task.state)
        self.assertEqual(SUCCEEDED_AT, task.timestamp)
        self.assertEqual(SUCCEEDED_AT, task.succeeded)

    def test_duplicate_and_delayed_still_prove_terminal_state(self):
        events = task_events()
        state = replay([(events, 'received'),
                        (events, 'succeeded'),
                        (events, 'started'),
                        (events, 'succeeded')])
        task = state.tasks['task-1']
        # reliable: the task reached SUCCESS, and a succeeded notification
        # carrying worker time SUCCEEDED_AT was applied
        self.assertEqual('SUCCESS', task.state)
        self.assertEqual(SUCCEEDED_AT, task.succeeded)
        # the late duplicate also restores the page timestamp
        self.assertEqual(SUCCEEDED_AT, task.timestamp)
        # not reliable: the counter only proves two notifications arrived
        self.assertEqual(2, state.counter[WORKER]['task-succeeded'])

    def test_delayed_duplicate_received_preserves_merge(self):
        events = task_events()
        state = replay(lifecycle(events) + [(events, 'received')])
        task = state.tasks['task-1']
        self.assertEqual(2, state.counter[WORKER]['task-received'])
        self.assertEqual('SUCCESS', task.state)
        self.assertEqual(SUCCEEDED_AT, task.timestamp)
        self.assertEqual(RECEIVED_AT, task.received)

    def test_delayed_started_changes_page_order(self):
        first = task_events('task-1')
        second = task_events('task-2', succeeded_at=1015.0)
        both = lifecycle(first) + lifecycle(second)

        state = replay(both)
        page = state.search_engine.search(state.tasks)
        self.assertEqual(['task-1', 'task-2'], page.task_ids)

        delayed = replay(both + [(first, 'started')])
        page = delayed.search_engine.search(delayed.tasks)
        self.assertEqual(['task-2', 'task-1'], page.task_ids)


if __name__ == '__main__':
    unittest.main()

"""Walk through checkpoint admission in a temporary directory.

Run ``python -m flower.recovery_demo`` (optionally ``--keep``) to produce a
recovery record that shows, in order:

1. a normal save that publishes a complete generation;
2. a save interrupted after only part of the generation was written;
3. a tightened admission policy started on the same directory.

Each startup writes ``<db>.recovery/latest.json`` and appends to
``<db>.recovery/recovery.jsonl``.  The script prints what startup selected and
what the query paths can see afterwards.

``--from-legacy`` also plants an old flat dbm shelf, so the run shows the
legacy storage being admitted first and replaced by a versioned checkpoint.
"""

import argparse
import json
import logging
import os
import pickle
import shelve
import shutil
import sys
import tempfile
import time

from celery.events import Event

from .checkpoints import CheckpointStore
from .events import Events


class _Loop:
    def add_callback(self, callback, *args):
        callback(*args)

    def run_in_executor(self, *_args, **_kwargs):  # pragma: no cover
        raise NotImplementedError


class _App:
    def connection(self):  # pragma: no cover - only used by the event thread
        raise NotImplementedError


COUNTER_EVENT = {'SUCCESS': 'task-succeeded', 'FAILURE': 'task-failed'}


def _task_events(worker, task_id, name, state, clock):
    received = Event(
        'task-received', uuid=task_id, name=name, args='(2, 2)',
        kwargs="{'order': 42}", retries=0, eta=None, hostname=worker,
        clock=clock, local_received=time.time())
    if state == 'SUCCESS':
        finished = Event(
            'task-succeeded', uuid=task_id, result='4', runtime=0.01,
            hostname=worker, clock=clock + 1, local_received=time.time())
    elif state == 'FAILURE':
        finished = Event(
            'task-failed', uuid=task_id, exception="KeyError('order')",
            traceback='line 1', hostname=worker, clock=clock + 1,
            local_received=time.time())
    else:
        finished = Event(
            'task-started', uuid=task_id, hostname=worker, clock=clock + 1,
            local_received=time.time())
    return [received, finished]


def seed(events, tasks):
    clock = 1
    for worker, task_id, name, state in tasks:
        for event in _task_events(worker, task_id, name, state, clock):
            events.state.event(event)
            clock += 1
        events.state.counter[worker][COUNTER_EVENT.get(state, 'task-started')] += 1


def startup(db, *, min_format_version=0, allow_legacy=True):
    return Events(
        _App(), _Loop(), db=db, persistent=True, enable_events=False,
        max_tasks_in_memory=100, checkpoint_min_format_version=min_format_version,
        checkpoint_allow_legacy=allow_legacy)


def query_view(events, query):
    state = events.state
    try:
        return sorted(state.search_engine.matching_ids(query))
    except ValueError as exc:
        return {'error': str(exc)}


def print_startup(title, events):
    recovery = events.recovery
    selected = recovery.report['selected']
    retrieval = recovery.report['retrieval']
    print(f'\n## {title}')
    print(f"selected source: {selected['source']}"
          + (f" (generation {selected.get('generation')})"
             if 'generation' in selected else ''))
    detail = selected['detail']
    if detail and detail != selected['reason']:
        print(f"reason: {selected['reason']} / {detail}")
    else:
        print(f"reason: {selected['reason']}")
    print(f"candidates: " + json.dumps(
        [{'source': c['source'], 'status': c['status'], 'reason': c['reason']}
         for c in recovery.report['candidates']], ensure_ascii=False))
    print(f"retrieval: tasks={retrieval['task_count']} "
          f"indexed={retrieval['indexed_task_count']} "
          f"counters={retrieval['counter_total']} states={retrieval['states']}")
    print(f"record: {recovery.report_path}")
    for query in ('state:SUCCESS', 'state:FAILURE', 'name:billing'):
        print(f"  {query!r} -> {query_view(events, query)}")


def simulate_partial_save(store, state):
    """Write a generation the way a crashed process would have left it.

    Only the events fragment is durable; the counters fragment and the
    manifest were never written, and a staging scratch file remains.
    """
    generation = store.next_generation()
    directory = store.generation_path(generation)
    os.mkdir(directory)
    with open(os.path.join(directory, 'events.pkl'), 'wb') as f:
        pickle.dump(state, f, protocol=pickle.HIGHEST_PROTOCOL)
    with open(os.path.join(directory, 'counters.json.tmp-999'), 'wb') as f:
        f.write(b'{"celery@worker1": ')
    return directory


def main(argv=None):
    logging.basicConfig(level=logging.WARNING, format='log: %(levelname)s %(message)s')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep', action='store_true',
                        help='keep the temporary directory instead of removing it')
    parser.add_argument('--dir', default=None,
                        help='use this directory instead of a fresh temporary one')
    parser.add_argument('--from-legacy', action='store_true',
                        help='start from a legacy flat dbm shelf')
    args = parser.parse_args(argv)

    workdir = args.dir or tempfile.mkdtemp(prefix='flower-recovery-')
    os.makedirs(workdir, exist_ok=True)
    db = os.path.join(workdir, 'flower')
    print(f'workdir: {workdir}')

    try:
        # 0. First startup: nothing to recover, retrieval opens on empty state.
        if args.from_legacy:
            legacy = startup(db)
            seed(legacy, [('celery@legacy', 'task-old-1', 'billing.charge',
                           'SUCCESS')])
            with shelve.open(db, flag='n') as shelf:
                shelf['events'] = legacy.state
                shelf['counter'] = dict(legacy.state.counter)
            print(f'\nplanted legacy shelf at: {db}')

        first = startup(db)
        print_startup(
            'startup 0: ' + ('legacy shelf' if args.from_legacy else 'empty directory'),
            first)

        # 1. A normal save publishes a complete, admitted generation.
        seed(first, [
            ('celery@worker1', 'task-ok-1', 'billing.charge', 'SUCCESS'),
            ('celery@worker1', 'task-ok-2', 'billing.refund', 'SUCCESS'),
            ('celery@worker2', 'task-ok-3', 'orders.pick', 'FAILURE'),
        ])
        first.state.counter['celery@worker1']['task-succeeded'] = 2
        first.save_state()
        print(f'\nnormal save published: {first.checkpoints.generation_path(1)}')

        # 2. Restart: the complete generation is admitted, queries see it.
        second = startup(db)
        print_startup('startup 1: after a normal save', second)

        # 3. A save that wrote only part of the generation before dying.
        partial = simulate_partial_save(second.checkpoints, second.state)
        print(f'\npartial save left at: {partial}')

        # 4. Restart: the partial generation is rejected, generation 1 is used.
        third = startup(db)
        print_startup('startup 2: after a partial save', third)

        # 5. Admission tightens: format 1 is no longer enough, legacy is refused.
        strict = startup(db, min_format_version=2, allow_legacy=False)
        print_startup('startup 3: tightened admission', strict)

        record = strict.recovery.report_path
        print(f'\nrecovery record: {record}')
        with open(record, encoding='utf-8') as f:
            print(f.read())
    finally:
        if not args.keep and not args.dir:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f'left in place: {workdir}')

    return 0


if __name__ == '__main__':  # pragma: no cover
    sys.exit(main())

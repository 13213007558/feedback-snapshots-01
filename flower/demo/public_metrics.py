"""Local walkthrough of the public metrics view.

Run with ``python -m flower.demo.public_metrics``. It feeds two task names
that share a public category and takes one worker offline, then prints the
public and internal views after the label mapping is tightened.
"""

import time
from unittest.mock import patch

from celery.events import Event
from tornado.options import options

from flower.events import EventsState

TASK_METRICS = (
    'events',
    'runtime',
    'prefetch_time',
    'number_of_prefetched_tasks',
    'worker_online',
    'worker_number_of_currently_executing_tasks',
)


def _task_events(worker, name, task_id):
    return [
        Event('task-received', uuid=task_id, name=name, args='()',
              kwargs='{}', retries=0, eta=None, hostname=worker),
        Event('task-started', uuid=task_id, hostname=worker),
        Event('task-succeeded', uuid=task_id, result='4', runtime=0.25,
              hostname=worker),
    ]


def _feed(state, worker, task_name, task_id, clock):
    state.get_or_create_worker(worker)
    state.event(Event('worker-online', hostname=worker, clock=clock,
                      local_received=time.time()))
    for offset, event in enumerate(_task_events(worker, task_name, task_id)):
        event['clock'] = clock + offset + 1
        event['local_received'] = time.time()
        state.event(event)


def _public_lines(text):
    return [line for line in text.splitlines()
            if line.startswith('flower_public_')]


def _internal(state):
    lines = []
    for attribute in TASK_METRICS:
        metric = getattr(state.metrics, attribute)
        for family in metric.collect():
            lines.append(f'# HELP {family.name} {family.documentation}')
            lines.append(f'# TYPE {family.name} {family.type}')
            for sample in family.samples:
                labels = ','.join(f'{key}="{value}"'
                                  for key, value in sample.labels.items())
                suffix = f'{{{labels}}}' if labels else ''
                lines.append(f'{sample.name}{suffix} {sample.value}')
    return lines


def _show(title, lines):
    print(f'=== {title} ===')
    print('\n'.join(lines))
    print()


def main():
    state = EventsState()
    _feed(state, 'celery@team-a', 'tasks.add', 'add-1', 0)
    _feed(state, 'celery@team-b', 'tasks.multiply', 'mul-1', 10)
    public = state.metrics.public

    mapping = {'tasks.add': 'batch', 'tasks.multiply': 'batch',
               'tasks.internal': 'internal'}
    with patch.object(options.mockable(), 'public_metrics_task_categories',
                      mapping), \
            patch.object(options.mockable(), 'public_metrics_retire_seconds',
                         0.0):
        _show('public view, both workers online',
              _public_lines(public.render().decode()))

        state.event(Event('worker-offline', hostname='celery@team-b',
                          clock=20, local_received=time.time()))
        _show('public view, team-b offline',
              _public_lines(public.render().decode()))

        _show('internal view keeps task and worker names',
              _internal(state))

        _show('public view, tasks.multiply withdrawn',
              _public_lines(public.render().decode()))

        with patch.object(options.mockable(), 'public_metrics_task_categories',
                          {'tasks.add': 'batch'}):
            _show('public view, only tasks.add approved',
                  _public_lines(public.render().decode()))

        with patch.object(options.mockable(), 'public_metrics_task_categories',
                          {'tasks.internal': 'internal'}):
            _show('next scrape, batch retired and gone',
                  _public_lines(public.render().decode()))


if __name__ == '__main__':
    main()

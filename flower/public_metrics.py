import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.metrics_core import (
    CounterMetricFamily,
    GaugeMetricFamily,
    HistogramMetricFamily,
)

from .options import options

logger = logging.getLogger(__name__)

TASK_CATEGORIES_OPTION = 'public_metrics_task_categories'
RETIRE_SECONDS_OPTION = 'public_metrics_retire_seconds'

TASK_CATEGORY_LABEL = 'task_category'

EVENTS_DOC = "Number of task events grouped by public task category"
RUNTIME_DOC = "Task runtime grouped by public task category"
PREFETCHED_DOC = "Number of tasks prefetched at online workers grouped by public task category"
WORKERS_ONLINE_DOC = "Number of online workers"
EXECUTING_DOC = "Number of tasks currently executing at online workers"
RETIRED_DOC = "Number of public metric series retired after the label policy changed"


def _category_pairs(value):
    if isinstance(value, dict):
        return list(value.items())
    if value is None:
        return []
    if isinstance(value, str):
        parts = re.split(r'[,\n;]+', value)
    elif isinstance(value, (list, tuple, set)):
        parts = value
    else:
        return []

    pairs = []
    for part in parts:
        if not isinstance(part, str):
            continue
        task, separator, category = part.partition('=')
        if separator:
            pairs.append((task, category))
    return pairs


def parse_task_categories(value):
    "Parse the public task category mapping from a string or mapping"
    categories = {}
    for task, category in _category_pairs(value):
        task = str(task).strip()
        category = str(category).strip()
        if task and category:
            categories[task] = category
    return categories


@dataclass(frozen=True)
class PublicLabelPolicy:
    task_categories: dict

    @classmethod
    def from_options(cls):
        return cls(parse_task_categories(
            getattr(options, TASK_CATEGORIES_OPTION, '')))

    @property
    def categories(self):
        return frozenset(self.task_categories.values())

    def category_for(self, task):
        return self.task_categories.get(task)


@dataclass
class _PublicSeries:
    kind: str
    name: str
    documentation: str
    labelnames: tuple
    labelvalues: tuple
    value: float = 0.0
    buckets: tuple = ()
    sum_value: float = 0.0

    @property
    def key(self):
        return self.name, self.labelvalues

    @property
    def category(self):
        if TASK_CATEGORY_LABEL not in self.labelnames:
            return None
        return self.labelvalues[self.labelnames.index(TASK_CATEGORY_LABEL)]


class PublicMetricsCollector:
    "Project the internal metrics into the labels approved for sharing"

    def __init__(self, metrics):
        self._metrics = metrics
        self.registry = CollectorRegistry()
        self.registry.register(self)
        self._lock = threading.Lock()
        self._policy = None
        self._active = {}
        self._retired = {}
        self._retired_total = 0

    def collect(self):
        with self._lock:
            policy = PublicLabelPolicy.from_options()
            current = self._project(policy)
            now = time.monotonic()

            if self._policy is None:
                self._policy = policy
            elif policy != self._policy:
                self._retire_withdrawn(policy, current, now)
                self._policy = policy

            self._drop_readopted(policy)
            self._expire_retired(now)
            self._active = current

            emitted = dict(current)
            for key, (series, _) in self._retired.items():
                emitted.setdefault(key, series)
            return list(self._families(emitted.values()))

    def render(self):
        return generate_latest(self.registry)

    @property
    def retired_total(self):
        with self._lock:
            return self._retired_total

    @property
    def retired_series(self):
        with self._lock:
            return {key: series for key, (series, _) in self._retired.items()}

    def _retire_withdrawn(self, policy, current, now):
        # Series already formed under the previous policy keep their last
        # value for the grace period, then leave the public view for good.
        retired = 0
        for key, series in self._active.items():
            category = series.category
            if category is None:
                continue
            if category in policy.categories or key in current:
                continue
            if key in self._retired:
                continue
            self._retired[key] = (series, now)
            self._retired_total += 1
            retired += 1

        if retired:
            logger.info(
                "Public metric label policy changed; %d series are leaving the view",
                retired)

    def _drop_readopted(self, policy):
        for key in list(self._retired):
            series, _ = self._retired[key]
            if series.category in policy.categories:
                del self._retired[key]

    def _expire_retired(self, now):
        try:
            grace = float(getattr(options, RETIRE_SECONDS_OPTION, 0) or 0)
        except (TypeError, ValueError):
            grace = 0.0
        grace = max(0.0, grace)

        for key, (_, retired_at) in list(self._retired.items()):
            if now - retired_at >= grace:
                del self._retired[key]

    def _project(self, policy):
        online = self._online_workers()
        series = {}
        self._add_task_events(policy, series)
        self._add_task_runtime(policy, series)
        self._add_prefetched_tasks(policy, online, series)
        self._add_aggregate(
            series, 'flower_public_workers_online', WORKERS_ONLINE_DOC,
            float(len(online)))
        self._add_aggregate(
            series, 'flower_public_tasks_executing', EXECUTING_DOC,
            self._executing_tasks(online))
        return series

    @staticmethod
    def _add_aggregate(series, name, documentation, value):
        item = _PublicSeries(
            kind='gauge', name=name, documentation=documentation,
            labelnames=(), labelvalues=(), value=value)
        series[item.key] = item

    def _online_workers(self):
        online = set()
        for family in self._metrics.worker_online.collect():
            for sample in family.samples:
                if sample.name == 'flower_worker_online' and sample.value > 0:
                    worker = sample.labels.get('worker')
                    if worker is not None:
                        online.add(worker)
        return online

    def _add_task_events(self, policy, series):
        totals = defaultdict(float)
        for family in self._metrics.events.collect():
            for sample in family.samples:
                if sample.name != 'flower_events_total':
                    continue
                category = policy.category_for(sample.labels.get('task', ''))
                if category is None:
                    continue
                key = sample.labels.get('type', ''), category
                totals[key] += sample.value

        for (event_type, category), value in totals.items():
            item = _PublicSeries(
                kind='counter', name='flower_public_events_total',
                documentation=EVENTS_DOC,
                labelnames=('type', TASK_CATEGORY_LABEL),
                labelvalues=(event_type, category), value=value)
            series[item.key] = item

    def _add_task_runtime(self, policy, series):
        totals = {}
        for family in self._metrics.runtime.collect():
            for sample in family.samples:
                category = policy.category_for(sample.labels.get('task', ''))
                if category is None:
                    continue
                data = totals.setdefault(
                    category, {'buckets': defaultdict(float), 'sum': 0.0})
                if sample.name.endswith('_bucket'):
                    data['buckets'][sample.labels.get('le')] += sample.value
                elif sample.name.endswith('_sum'):
                    data['sum'] += sample.value

        for category, data in totals.items():
            buckets = tuple(sorted(
                data['buckets'].items(), key=lambda item: float(item[0])))
            item = _PublicSeries(
                kind='histogram', name='flower_public_task_runtime_seconds',
                documentation=RUNTIME_DOC,
                labelnames=(TASK_CATEGORY_LABEL,),
                labelvalues=(category,), buckets=buckets,
                sum_value=data['sum'])
            series[item.key] = item

    def _add_prefetched_tasks(self, policy, online, series):
        totals = defaultdict(float)
        for family in self._metrics.number_of_prefetched_tasks.collect():
            for sample in family.samples:
                if sample.labels.get('worker') not in online:
                    continue
                category = policy.category_for(sample.labels.get('task', ''))
                if category is None:
                    continue
                totals[category] += sample.value

        for category, value in totals.items():
            item = _PublicSeries(
                kind='gauge', name='flower_public_prefetched_tasks',
                documentation=PREFETCHED_DOC,
                labelnames=(TASK_CATEGORY_LABEL,),
                labelvalues=(category,), value=value)
            series[item.key] = item

    def _executing_tasks(self, online):
        total = 0.0
        for family in self._metrics.worker_number_of_currently_executing_tasks.collect():
            for sample in family.samples:
                if sample.labels.get('worker') in online:
                    total += sample.value
        return total

    def _families(self, series):
        series = list(series)
        counters = defaultdict(list)
        gauges = defaultdict(list)
        histograms = defaultdict(list)
        for item in series:
            if item.kind == 'counter':
                counters[item.name].append(item)
            elif item.kind == 'histogram':
                histograms[item.name].append(item)
            else:
                gauges[item.name].append(item)

        for name, items in sorted(counters.items()):
            family = CounterMetricFamily(
                name, items[0].documentation,
                labels=list(items[0].labelnames))
            for item in sorted(items, key=lambda entry: entry.labelvalues):
                family.add_metric(item.labelvalues, item.value)
            yield family

        for name, items in sorted(gauges.items()):
            family = GaugeMetricFamily(
                name, items[0].documentation,
                labels=list(items[0].labelnames))
            for item in sorted(items, key=lambda entry: entry.labelvalues):
                family.add_metric(item.labelvalues, item.value)
            yield family

        for name, items in sorted(histograms.items()):
            family = HistogramMetricFamily(name, items[0].documentation)
            for item in sorted(items, key=lambda entry: entry.labelvalues):
                family.add_metric(
                    item.labelvalues, list(item.buckets), item.sum_value)
            yield family

        yield CounterMetricFamily(
            'flower_public_series_retired_total', RETIRED_DOC,
            value=float(self._retired_total))

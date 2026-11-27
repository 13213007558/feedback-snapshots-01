"""Event checkpoint storage, admission and recovery reporting.

A checkpoint is an immutable generation directory::

    <db>.checkpoints/gen-000000000001/
        manifest.json
        events.pkl
        counters.json

Fragments are written first and the manifest is published last.  The
manifest lists the exact bytes of every fragment, so a generation that was
only partially written, was truncated, or was assembled by hand cannot be
mistaken for a complete one.  Recovery evaluates every candidate against the
local admission policy before any of them is exposed to the query paths.
"""

import collections
import copy
import dbm
import hashlib
import json
import logging
import os
import pickle
import re
import shelve
import shutil
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from celery.events.state import State

from . import __version__

logger = logging.getLogger(__name__)

CHECKPOINT_FORMAT = 'flower-events-checkpoint'
CHECKPOINT_FORMAT_VERSION = 1
RECOVERY_SCHEMA = 'flower.recovery/1'

CHECKPOINTS_DIR_SUFFIX = '.checkpoints'
RECOVERY_DIR_SUFFIX = '.recovery'
GENERATION_PREFIX = 'gen-'
GENERATION_RE = re.compile(r'^gen-(\d{1,18})$')

MANIFEST_NAME = 'manifest.json'
FRAGMENT_ROLES = ('events', 'counters')
FRAGMENT_NAMES = {
    'events': 'events.pkl',
    'counters': 'counters.json',
}

STAGING_SUFFIXES = (
    '.tmp',
    '.tmp.db',
    '.tmp.dat',
    '.tmp.dir',
    '.tmp.bak',
    '.staging',
)

MAX_TASK_SAMPLE = 20


class CheckpointError(Exception):
    """A checkpoint could not be written or admitted."""


@dataclass(frozen=True)
class AdmissionPolicy:
    """Local rules a checkpoint must satisfy before it becomes visible."""

    min_format_version: int = CHECKPOINT_FORMAT_VERSION
    allow_legacy: bool = True

    def admits_manifest(self, manifest):
        version = manifest.get('format_version')
        if not isinstance(version, int) or isinstance(version, bool):
            return False, 'manifest has no integer format_version'
        if version < self.min_format_version:
            return False, (
                f'checkpoint format version {version} is below the '
                f'admitted minimum {self.min_format_version}')
        return True, ''

    def to_dict(self):
        return {
            'min_format_version': self.min_format_version,
            'allow_legacy': self.allow_legacy,
        }


@dataclass
class Candidate:
    """One storage location recovery considered, admitted or rejected."""

    source: str
    path: str
    generation: Optional[int] = None
    status: str = 'rejected'
    reason: str = ''
    format_version: Optional[int] = None
    created_at: Optional[float] = None
    task_count: Optional[int] = None
    counter_total: Optional[int] = None
    fragments_expected: int = 0
    fragments_present: int = 0
    state: Any = field(default=None, repr=False)
    counters: Any = field(default=None, repr=False)

    @property
    def admitted(self):
        return self.status == 'admitted'

    def to_dict(self):
        data = {
            'source': self.source,
            'path': self.path,
            'status': self.status,
            'reason': self.reason,
        }
        if self.generation is not None:
            data['generation'] = self.generation
        if self.format_version is not None:
            data['format_version'] = self.format_version
        if self.created_at is not None:
            data['created_at'] = self.created_at
        if self.task_count is not None:
            data['task_count'] = self.task_count
        if self.counter_total is not None:
            data['counter_total'] = self.counter_total
        if self.fragments_expected:
            data['fragments'] = {
                'expected': self.fragments_expected,
                'present': self.fragments_present,
            }
        return data


@dataclass
class RecoveryResult:
    """The admitted state plus the evidence behind the selection."""

    state: Any
    counters: collections.defaultdict
    selected: Candidate
    report: dict
    report_path: Optional[str] = None


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path, data):
    tmp = f'{path}.tmp-{os.getpid()}'
    try:
        with open(tmp, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _counters_from_mapping(raw):
    """Validate and rebuild the counters mapping kept with a state."""
    if raw is None:
        return collections.defaultdict(collections.Counter)
    if not isinstance(raw, dict):
        raise CheckpointError('counters are not a JSON object')
    counter = collections.defaultdict(collections.Counter)
    for worker, events in raw.items():
        if not isinstance(worker, str) or not isinstance(events, dict):
            raise CheckpointError('counters have a malformed worker entry')
        for event_type, value in events.items():
            if not isinstance(event_type, str):
                raise CheckpointError('counters have a malformed event type')
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise CheckpointError(
                    f"counter {worker}/{event_type} is not a non-negative integer")
        counter[worker].update(events)
    return counter


def _counter_total(counter):
    return sum(sum(events.values()) for events in counter.values())


def _coerce_state(value, max_tasks_in_memory):
    from .events import EventsState

    if isinstance(value, EventsState):
        return value
    if not isinstance(value, State):
        return None
    # A checkpoint may have been produced before EventsState grew its index,
    # or by a tool that stored a plain Celery State.  Rebuild the index from
    # the very tasks in this payload.
    state = EventsState(
        workers=value.workers,
        tasks=value.tasks,
        taskheap=value._taskheap,  # pylint: disable=protected-access
        max_workers_in_memory=value.max_workers_in_memory,
        max_tasks_in_memory=max_tasks_in_memory,
    )
    state._seen_types.update(value._seen_types)  # pylint: disable=protected-access
    state.event_count = value.event_count
    state.task_count = value.task_count
    return state


class CheckpointStore:
    """Read and write generation checkpoints below a Flower ``db`` path."""

    def __init__(self, db, *, min_format_version=CHECKPOINT_FORMAT_VERSION,
                 allow_legacy=True, retention=5, max_workers_in_memory=5000,
                 max_tasks_in_memory=10000):
        self.db = db
        self.root = db + CHECKPOINTS_DIR_SUFFIX
        self.recovery_dir = db + RECOVERY_DIR_SUFFIX
        self.policy = AdmissionPolicy(
            min_format_version=min_format_version,
            allow_legacy=allow_legacy)
        self.retention = retention
        self.max_workers_in_memory = max_workers_in_memory
        self.max_tasks_in_memory = max_tasks_in_memory

    # -- paths ---------------------------------------------------------

    def generation_path(self, generation):
        return os.path.join(self.root, f'{GENERATION_PREFIX}{generation:012d}')

    def generations(self):
        """Yield ``(generation, path)`` for well formed generation directories."""
        try:
            entries = os.listdir(self.root)
        except FileNotFoundError:
            return
        for name in entries:
            match = GENERATION_RE.match(name)
            if match:
                yield int(match.group(1)), os.path.join(self.root, name)

    def next_generation(self):
        return max((generation for generation, _ in self.generations()), default=0) + 1

    # -- writing -------------------------------------------------------

    def _fragment_bytes(self, role, state, counters):
        if role == 'events':
            return pickle.dumps(state, protocol=pickle.HIGHEST_PROTOCOL)
        if role == 'counters':
            return json.dumps(
                {worker: dict(events) for worker, events in counters.items()},
                sort_keys=True, separators=(',', ':'), ensure_ascii=False,
            ).encode('utf-8')
        raise CheckpointError(f'unknown fragment role {role!r}')

    def _write_fragment(self, role, data, directory):
        name = FRAGMENT_NAMES[role]
        path = os.path.join(directory, name)
        _atomic_write(path, data)
        return {
            'role': role,
            'name': name,
            'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
        }

    def save(self, state):
        """Publish one generation, or leave a visibly incomplete one.

        Fragments are durable before the manifest is published.  A process
        that dies midway leaves a generation directory that admission will
        reject; previously published generations are never touched.
        """
        counters = _counters_from_mapping(dict(state.counter))
        os.makedirs(self.root, exist_ok=True)
        generation = self.next_generation()
        directory = self.generation_path(generation)
        try:
            os.mkdir(directory)
        except FileExistsError as exc:
            raise CheckpointError(
                f'checkpoint generation {generation} already exists') from exc
        fragments = []
        # ``events`` is serialized first so an unserializable state fails
        # before any counter payload is considered.
        for role in ('events', 'counters'):
            data = self._fragment_bytes(role, state, counters)
            fragments.append(self._write_fragment(role, data, directory))
        _fsync_dir(directory)

        manifest = {
            'format': CHECKPOINT_FORMAT,
            'format_version': CHECKPOINT_FORMAT_VERSION,
            'generation': generation,
            'created_at': time.time(),
            'created_by': f'flower/{__version__}',
            'task_count': len(state.tasks),
            'counter_total': _counter_total(counters),
            'fragments': fragments,
        }
        manifest_bytes = json.dumps(
            manifest, sort_keys=True, indent=2, ensure_ascii=False).encode('utf-8')
        # The manifest is the admission point: until it exists the generation
        # is only a pile of physical fragments.
        _atomic_write(os.path.join(directory, MANIFEST_NAME), manifest_bytes)
        _fsync_dir(directory)
        _fsync_dir(self.root)

        self.prune()
        return manifest

    def prune(self):
        """Drop old complete generations, keeping incomplete ones as evidence."""
        if not self.retention or self.retention < 1:
            return
        complete = []
        for generation, path in self.generations():
            manifest_path = os.path.join(path, MANIFEST_NAME)
            if not os.path.isfile(manifest_path):
                continue
            try:
                with open(manifest_path, encoding='utf-8') as f:
                    manifest = json.load(f)
            except (OSError, ValueError):
                continue
            if manifest.get('format') == CHECKPOINT_FORMAT:
                complete.append((generation, path))
        complete.sort(reverse=True)
        keep = max(1, self.retention)
        for _, path in complete[keep:]:
            try:
                shutil.rmtree(path)
            except OSError as exc:
                logger.warning("Could not remove old checkpoint '%s': %s", path, exc)

    # -- reading -------------------------------------------------------

    def _load_manifest(self, directory):
        manifest_path = os.path.join(directory, MANIFEST_NAME)
        if not os.path.isfile(manifest_path):
            raise CheckpointError(
                'manifest is missing: the generation was never completed')
        try:
            with open(manifest_path, encoding='utf-8') as f:
                manifest = json.load(f)
        except (OSError, ValueError) as exc:
            raise CheckpointError(f'manifest is not valid JSON: {exc}') from exc
        if not isinstance(manifest, dict):
            raise CheckpointError('manifest is not a JSON object')
        if manifest.get('format') != CHECKPOINT_FORMAT:
            raise CheckpointError(
                f"unsupported checkpoint format {manifest.get('format')!r}")
        return manifest

    def _fragment_entry(self, manifest, role):
        fragments = manifest.get('fragments')
        if not isinstance(fragments, list):
            raise CheckpointError('manifest does not list checkpoint fragments')
        matches = [item for item in fragments
                   if isinstance(item, dict) and item.get('role') == role]
        if not matches:
            raise CheckpointError(f"manifest does not declare a '{role}' fragment")
        if len(matches) > 1:
            raise CheckpointError(f"manifest declares '{role}' more than once")
        return matches[0]

    def _check_fragment(self, directory, role, entry):
        name = entry.get('name')
        if not isinstance(name, str) or not name:
            raise CheckpointError(f"fragment '{role}' has no file name")
        if name in ('.', '..') or os.path.sep in name or (
                os.path.altsep and os.path.altsep in name):
            raise CheckpointError(f"fragment '{role}' has an unsafe file name")
        path = os.path.join(directory, name)
        try:
            info = os.lstat(path)
        except FileNotFoundError as exc:
            raise CheckpointError(
                f"fragment '{role}' is missing ({name})") from exc
        if not stat.S_ISREG(info.st_mode):
            raise CheckpointError(f"fragment '{role}' is not a regular file")
        expected_size = entry.get('size')
        if not isinstance(expected_size, int) or expected_size < 0:
            raise CheckpointError(f"fragment '{role}' has no valid size")
        if info.st_size != expected_size:
            raise CheckpointError(
                f"fragment '{role}' size mismatch: "
                f"manifest {expected_size}, actual {info.st_size}")
        expected_digest = entry.get('sha256')
        if not isinstance(expected_digest, str) or not re.match(
                r'^[0-9a-f]{64}$', expected_digest):
            raise CheckpointError(f"fragment '{role}' has no valid sha256")
        actual_digest = _sha256(path)
        if actual_digest != expected_digest:
            raise CheckpointError(f"fragment '{role}' sha256 mismatch")
        return path

    def _read_generation(self, candidate, directory):
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode):
            raise CheckpointError('generation path is not a directory')

        manifest = self._load_manifest(directory)
        admitted, reason = self.policy.admits_manifest(manifest)
        version = manifest.get('format_version')
        if isinstance(version, int) and not isinstance(version, bool):
            candidate.format_version = version
        created_at = manifest.get('created_at')
        if isinstance(created_at, (int, float)) and not isinstance(created_at, bool):
            candidate.created_at = float(created_at)
        task_count = manifest.get('task_count')
        if isinstance(task_count, int) and not isinstance(task_count, bool):
            candidate.task_count = task_count
        counter_total = manifest.get('counter_total')
        if isinstance(counter_total, int) and not isinstance(counter_total, bool):
            candidate.counter_total = counter_total

        fragments = manifest.get('fragments')
        if isinstance(fragments, list):
            candidate.fragments_expected = len(fragments)
            candidate.fragments_present = sum(
                1 for item in fragments
                if isinstance(item, dict)
                and isinstance(item.get('name'), str)
                and os.path.isfile(os.path.join(directory, item['name'])))
        if not admitted:
            raise CheckpointError(reason)
        if candidate.fragments_expected != len(FRAGMENT_ROLES):
            raise CheckpointError(
                f'manifest declares {candidate.fragments_expected} fragment(s), '
                f'expected {len(FRAGMENT_ROLES)}')

        generation = manifest.get('generation')
        if generation != candidate.generation:
            raise CheckpointError(
                f'manifest generation {generation!r} does not match '
                f'directory generation {candidate.generation}')

        paths = {}
        for role in FRAGMENT_ROLES:
            entry = self._fragment_entry(manifest, role)
            paths[role] = self._check_fragment(directory, role, entry)

        try:
            with open(paths['events'], 'rb') as f:
                state = pickle.load(f)
        except Exception as exc:
            raise CheckpointError(f'events fragment cannot be loaded: {exc}') from exc
        state = _coerce_state(state, self.max_tasks_in_memory)
        if state is None:
            raise CheckpointError('events fragment is not a Celery State')

        try:
            with open(paths['counters'], 'rb') as f:
                raw_counters = json.load(f)
            counters = _counters_from_mapping(raw_counters)
        except CheckpointError:
            raise
        except Exception as exc:
            raise CheckpointError(f'counters fragment is not valid JSON: {exc}') from exc

        if candidate.task_count is not None and candidate.task_count != len(state.tasks):
            raise CheckpointError(
                f'manifest task_count {candidate.task_count} does not match '
                f'payload task_count {len(state.tasks)}')
        if candidate.counter_total is not None and \
                candidate.counter_total != _counter_total(counters):
            raise CheckpointError(
                f'manifest counter_total {candidate.counter_total} does not match '
                f'payload counter_total {_counter_total(counters)}')

        candidate.state = state
        candidate.counters = counters
        candidate.task_count = len(state.tasks)
        candidate.counter_total = _counter_total(counters)

    def _legacy_files(self):
        base = self.db
        names = [base, base + '.db', base + '.dat', base + '.dir', base + '.bak']
        return [name for name in names if os.path.exists(name)]

    def _read_legacy(self, candidate):
        if not self.policy.allow_legacy:
            raise CheckpointError('legacy storage is disabled by the admission policy')
        if self.policy.min_format_version > 0:
            raise CheckpointError(
                f'legacy storage is format version 0, below the admitted '
                f'minimum {self.policy.min_format_version}')
        files = self._legacy_files()
        if not files:
            raise CheckpointError('legacy storage is not present')
        try:
            kind = dbm.whichdb(self.db)
        except Exception as exc:
            raise CheckpointError(f'legacy storage cannot be identified: {exc}') from exc
        if not kind:
            raise CheckpointError('legacy storage is not a recognized dbm database')
        try:
            with shelve.open(self.db, flag='r') as shelf:
                if 'events' not in shelf:
                    raise CheckpointError("legacy shelf has no 'events' entry")
                state = shelf['events']
                raw_counters = shelf.get('counter')
        except CheckpointError:
            raise
        except Exception as exc:
            raise CheckpointError(f'legacy shelf cannot be read: {exc}') from exc
        state = _coerce_state(state, self.max_tasks_in_memory)
        if state is None:
            raise CheckpointError('legacy events entry is not a Celery State')
        counters = _counters_from_mapping(raw_counters)
        candidate.format_version = 0
        candidate.state = state
        candidate.counters = counters
        candidate.task_count = len(state.tasks)
        candidate.counter_total = _counter_total(counters)
        candidate.fragments_expected = 2 if raw_counters is not None else 1
        candidate.fragments_present = candidate.fragments_expected
        candidate.reason = 'legacy dbm shelf'

    def candidates(self):
        """Evaluate every generation, staging artifact and legacy shelf."""
        found = []
        for generation, path in sorted(self.generations(), reverse=True):
            candidate = Candidate(
                source='generation', path=path, generation=generation)
            try:
                self._read_generation(candidate, path)
            except CheckpointError as exc:
                candidate.status = 'rejected'
                candidate.reason = str(exc)
            except Exception as exc:  # defensive: admission must never crash startup
                candidate.status = 'rejected'
                candidate.reason = f'unexpected checkpoint error: {exc}'
            else:
                candidate.status = 'admitted'
                candidate.reason = 'complete and admitted'
            found.append(candidate)

        for path in self._staging_artifacts():
            found.append(Candidate(
                source='staging', path=path, status='rejected',
                reason='incomplete staging left by an interrupted save'))

        legacy = Candidate(source='legacy', path=self.db)
        if self._legacy_files():
            try:
                self._read_legacy(legacy)
            except CheckpointError as exc:
                legacy.status = 'rejected'
                legacy.reason = str(exc)
                logger.error("Failed to admit legacy event state at '%s': %s",
                             self.db, exc)
            except Exception as exc:
                legacy.status = 'rejected'
                legacy.reason = f'unexpected legacy error: {exc}'
                logger.error("Failed to admit legacy event state at '%s': %s",
                             self.db, exc)
            else:
                legacy.status = 'admitted'
            found.append(legacy)
        else:
            legacy.status = 'absent'
            legacy.reason = 'no legacy dbm shelf found'
            found.append(legacy)
        return found

    def _staging_artifacts(self):
        """Return scratch files a save may leave behind, never a valid shelf."""
        paths = []
        parent = os.path.dirname(os.path.abspath(self.db)) or '.'
        base = os.path.basename(self.db)
        try:
            entries = os.listdir(parent)
        except FileNotFoundError:
            entries = []
        for name in entries:
            if not name.startswith(base + '.'):
                continue
            suffix = name[len(base):]
            if any(suffix == item or suffix.startswith(item + '.')
                   for item in STAGING_SUFFIXES):
                paths.append(os.path.join(parent, name))
        try:
            entries = os.listdir(self.root)
        except FileNotFoundError:
            entries = []
        for name in entries:
            path = os.path.join(self.root, name)
            if name.startswith('.staging'):
                paths.append(path)
            elif GENERATION_RE.match(name):
                try:
                    files = os.listdir(path)
                except OSError:
                    continue
                for filename in files:
                    if '.tmp-' in filename:
                        paths.append(os.path.join(path, filename))
        return sorted(paths)

    def recover(self, before_open=None):
        """Admit one generation and only then hand back a readable state.

        ``before_open`` runs after the selection is made and recorded but
        before the state is returned, so a caller can assert that nothing is
        published while admission is still in progress.
        """
        candidates = self.candidates()
        admitted = [c for c in candidates if c.admitted]
        if admitted:
            # New generations always outrank legacy, which has generation 0.
            selected = max(
                admitted,
                key=lambda c: (c.generation if c.generation is not None else 0))
            reason = (
                'highest admitted generation'
                if selected.source == 'generation'
                else 'legacy fallback: no admitted generation')
        else:
            considered = [c for c in candidates
                          if c.source == 'generation'
                          or (c.source == 'legacy' and c.status == 'rejected')]
            reason = ('no checkpoint passed admission' if considered
                      else 'no checkpoint present')
            selected = Candidate(
                source='fresh', path=self.db, status='selected',
                reason=reason)

        if selected.state is None:
            from .events import EventsState
            state = EventsState(
                max_workers_in_memory=self.max_workers_in_memory,
                max_tasks_in_memory=self.max_tasks_in_memory)
            counters = collections.defaultdict(collections.Counter)
        else:
            state = selected.state
            counters = selected.counters
        state.max_workers_in_memory = max(
            getattr(state.workers, 'limit', 0), self.max_workers_in_memory)
        state.set_max_tasks(self.max_tasks_in_memory)
        # The live state must not share mutable payloads with the candidate
        # bookkeeping that admission evaluated.
        state.counter = copy.deepcopy(counters)

        report = {
            'schema': RECOVERY_SCHEMA,
            'timestamp': time.time(),
            'db': self.db,
            'policy': self.policy.to_dict(),
            'checkpoints_dir': self.root,
            'candidates': [candidate.to_dict() for candidate in candidates],
            'selected': {
                'source': selected.source,
                'status': selected.status,
                'reason': reason,
                'detail': selected.reason,
            },
        }
        if selected.generation is not None:
            report['selected']['generation'] = selected.generation
            report['selected']['path'] = selected.path
        if selected.format_version is not None:
            report['selected']['format_version'] = selected.format_version

        if before_open is not None:
            before_open(report)
        report['retrieval'] = retrieval_summary(state, counters)
        return RecoveryResult(
            state=state, counters=counters, selected=selected, report=report)


def retrieval_summary(state, counters):
    states = collections.Counter(
        task.state or 'PENDING' for task in state.tasks.values())
    task_ids = list(state.tasks)[:MAX_TASK_SAMPLE]
    return {
        'open': True,
        'source': 'state',
        'task_count': len(state.tasks),
        'indexed_task_count': len(state.search_engine.documents),
        'counter_total': _counter_total(counters),
        'states': dict(sorted(states.items())),
        'task_ids': task_ids,
        'task_ids_truncated': max(0, len(state.tasks) - len(task_ids)),
    }


def write_recovery_record(recovery_dir, report):
    """Append the startup record and refresh ``latest.json``."""
    os.makedirs(recovery_dir, exist_ok=True)
    latest = os.path.join(recovery_dir, 'latest.json')
    line = json.dumps(report, sort_keys=True, ensure_ascii=False)
    history = os.path.join(recovery_dir, 'recovery.jsonl')
    with open(history, 'a', encoding='utf-8') as f:
        f.write(line + '\n')
        f.flush()
        os.fsync(f.fileno())
    _atomic_write(
        latest,
        (json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + '\n')
        .encode('utf-8'))
    _fsync_dir(recovery_dir)
    return latest

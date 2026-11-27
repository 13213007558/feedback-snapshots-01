import collections
import secrets
import threading
import time


class Registration:
    """One concrete incarnation of a worker name.

    A worker name can be reused by a new process.  The registration id is
    opaque and changes whenever the name is registered again, so approvals
    can bind to the incarnation instead of the name shown in a list.
    """

    __slots__ = ('name', 'registration_id', 'generation', 'pid', 'source',
                 'created_at', 'last_seen', 'online', 'queues')

    def __init__(self, name, generation, pid=None, source='event',
                 online=True, now=None):
        self.name = name
        self.registration_id = secrets.token_hex(12)
        self.generation = generation
        self.pid = pid
        self.source = source
        self.created_at = now if now is not None else time.time()
        self.last_seen = self.created_at
        self.online = online
        self.queues = frozenset()

    def as_dict(self):
        return {
            'worker': self.name,
            'registration_id': self.registration_id,
            'generation': self.generation,
            'pid': self.pid,
            'source': self.source,
            'since': self.created_at,
            'last_seen': self.last_seen,
            'online': self.online,
            'queues': sorted(self.queues),
        }


class WorkerRegistry:
    """Tracks worker incarnations from events and inspections.

    The registry is the server-side authority for "the object that was
    approved".  Names are only used to find the current incarnation; they are
    never accepted on their own as proof that a control command still targets
    the worker an operator saw.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._registrations = {}
        self._history = {}
        self._queue_owners = collections.defaultdict(set)

    def _replace(self, name, generation, pid, source, online):
        registration = Registration(name, generation, pid=pid, source=source,
                                    online=online)
        self._registrations[name] = registration
        self._history[registration.registration_id] = registration
        self._reindex_queues()
        return registration

    def _reindex_queues(self):
        owners = collections.defaultdict(set)
        for registration in self._registrations.values():
            for queue in registration.queues:
                owners[queue].add(registration.registration_id)
        self._queue_owners = owners

    def observe_event(self, event_type, name, fields=None, now=None):
        fields = fields or {}
        pid = fields.get('pid')
        now = now if now is not None else time.time()
        with self._lock:
            registration = self._registrations.get(name)
            if registration is None:
                return self._replace(
                    name, 1, pid, 'event', event_type != 'worker-offline')
            restarted = pid is not None and registration.pid is not None \
                and pid != registration.pid
            if event_type == 'worker-online' and not registration.online:
                # the name went offline and came back: a new incarnation
                restarted = True
            if restarted:
                registration = self._replace(
                    name, registration.generation + 1, pid, 'event',
                    event_type != 'worker-offline')
            registration.last_seen = now
            registration.online = event_type != 'worker-offline'
            if pid is not None:
                registration.pid = pid
            return registration

    def ensure(self, name, now=None):
        """Return the current registration, creating generation 1 if needed."""
        with self._lock:
            registration = self._registrations.get(name)
            if registration is None:
                registration = self._replace(name, 1, None, 'local', True)
            return registration

    def observe_inspection(self, name, info, now=None):
        info = info or {}
        stats = info.get('stats') or {}
        pid = stats.get('pid')
        queues = info.get('active_queues')
        now = now if now is not None else time.time()
        with self._lock:
            registration = self._registrations.get(name)
            if registration is None:
                registration = self._replace(name, 1, pid, 'inspect', True)
            elif pid is not None and registration.pid is not None \
                    and pid != registration.pid:
                registration = self._replace(
                    name, registration.generation + 1, pid, 'inspect', True)
            registration.last_seen = now
            if pid is not None:
                registration.pid = pid
            if isinstance(queues, list):
                registration.queues = frozenset(
                    queue.get('name') for queue in queues
                    if isinstance(queue, dict) and queue.get('name'))
                self._reindex_queues()
            return registration

    def current(self, name):
        with self._lock:
            return self._registrations.get(name)

    def queue_owners(self, queue):
        with self._lock:
            return set(self._queue_owners.get(queue, ()))

    def owns_queue(self, name, queue):
        registration = self.current(name)
        return bool(registration and queue in registration.queues)

    def snapshot(self):
        with self._lock:
            return dict(self._registrations)

    def lookup(self, registration_id):
        """Return a registration by id, including superseded generations."""
        if not registration_id:
            return None
        with self._lock:
            return self._history.get(registration_id)

    def clear(self):
        with self._lock:
            self._registrations.clear()
            self._history.clear()
            self._queue_owners.clear()

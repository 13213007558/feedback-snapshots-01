import collections
import secrets
import threading
import time


class Approval:
    """A grant for one operator, one action and its concrete target scope."""

    __slots__ = ('approval_id', 'operator', 'group', 'action', 'worker',
                 'registration_id', 'generation', 'queue', 'parameters',
                 'created_at', 'consumed_at', 'consumed_by', 'origin',
                 'audit_id')

    def __init__(self, operator, group, action, worker, registration_id,
                 generation, queue=None, parameters=None, origin=None,
                 now=None):
        self.approval_id = secrets.token_hex(12)
        self.audit_id = secrets.token_hex(8)
        self.operator = operator
        self.group = group
        self.action = action
        self.worker = worker
        self.registration_id = registration_id
        self.generation = generation
        self.queue = queue
        self.parameters = dict(parameters or {})
        self.created_at = now if now is not None else time.time()
        self.consumed_at = None
        self.consumed_by = None
        self.origin = origin

    def as_dict(self):
        return {
            'approval_id': self.approval_id,
            'audit_id': self.audit_id,
            'operator': self.operator,
            'group': self.group,
            'action': self.action,
            'worker': self.worker,
            'registration_id': self.registration_id,
            'generation': self.generation,
            'queue': self.queue,
            'parameters': dict(self.parameters),
            'created_at': self.created_at,
            'consumed_at': self.consumed_at,
            'consumed_by': self.consumed_by,
            'origin': self.origin,
        }


class ResponseRecord:
    __slots__ = ('record_id', 'audit_id', 'approval_id', 'operator',
                 'action', 'worker', 'registration_id', 'generation',
                 'outcome', 'status', 'destination', 'command', 'message',
                 'received_at', 'superseded', 'origin')

    def __init__(self, entry, outcome, status=None, destination=None,
                 command=None, message=None, now=None):
        self.record_id = secrets.token_hex(10)
        self.audit_id = entry['audit_id']
        self.approval_id = entry['approval_id']
        self.operator = entry['operator']
        self.action = entry['action']
        self.worker = entry['worker']
        self.registration_id = entry['registration_id']
        self.generation = entry['generation']
        self.outcome = outcome
        self.status = status
        self.destination = list(destination or ())
        self.command = command
        self.message = message
        self.received_at = now if now is not None else time.time()
        self.superseded = bool(entry.get('superseded'))
        self.origin = entry.get('origin')

    def as_dict(self):
        return {
            'record_id': self.record_id,
            'audit_id': self.audit_id,
            'approval_id': self.approval_id,
            'operator': self.operator,
            'action': self.action,
            'worker': self.worker,
            'registration_id': self.registration_id,
            'generation': self.generation,
            'outcome': self.outcome,
            'status': self.status,
            'destination': list(self.destination),
            'command': self.command,
            'message': self.message,
            'received_at': self.received_at,
            'superseded': self.superseded,
            'origin': self.origin,
        }


class ControlLedger:
    """Single-use approvals and the responses attributed to them."""

    max_records = 1000

    def __init__(self, max_records=None):
        if max_records is not None:
            self.max_records = max_records
        self._lock = threading.Lock()
        self._approvals = collections.OrderedDict()
        self._responses = collections.OrderedDict()

    def approve(self, operator, group, action, registration, queue=None,
                parameters=None, origin=None):
        approval = Approval(
            operator, group, action, registration.name,
            registration.registration_id, registration.generation,
            queue=queue, parameters=parameters, origin=origin)
        with self._lock:
            self._approvals[approval.approval_id] = approval
            self._trim(self._approvals)
        return approval

    def get(self, approval_id):
        with self._lock:
            return self._approvals.get(approval_id)

    @staticmethod
    def rejection(approval, operator, group, allowed_actions, registration):
        if approval is None:
            return 'unknown-approval'
        if approval.consumed_at is not None:
            return 'already-consumed'
        if approval.operator != operator:
            return 'wrong-operator'
        if approval.group != group:
            return 'wrong-group'
        if approval.action not in allowed_actions:
            return 'action-not-allowed'
        if registration is None \
                or approval.registration_id != registration.registration_id:
            return 'registration-changed'
        if approval.action == 'worker.queue_cancel_consumer' \
                and approval.queue not in registration.queues:
            return 'queue-moved'
        return None

    def consume(self, approval_id, operator, group, allowed_actions,
                registration):
        """Atomically validate and consume an approval.

        Returns ``(approval, None)`` on success or ``(None, reason)`` where
        reason is one of the stable strings used by the API and page.
        """
        with self._lock:
            approval = self._approvals.get(approval_id)
            reason = self.rejection(
                approval, operator, group, allowed_actions, registration)
            if reason is not None:
                return None, reason
            approval.consumed_at = time.time()
            approval.consumed_by = operator
            return approval, None

    def record(self, entry, outcome, **kwargs):
        record = ResponseRecord(entry, outcome, **kwargs)
        with self._lock:
            self._responses[record.record_id] = record
            self._trim(self._responses)
        return record

    def responses(self, limit=None):
        with self._lock:
            records = list(self._responses.values())
        if limit:
            records = records[-limit:]
        return list(reversed(records))

    def pending(self):
        with self._lock:
            return [approval for approval in self._approvals.values()
                    if approval.consumed_at is None]

    def _trim(self, mapping):
        while len(mapping) > self.max_records:
            mapping.popitem(last=False)

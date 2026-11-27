import logging
import secrets

from tornado.web import HTTPError

from .ledger import ControlLedger
from .policy import ACTION_COMMANDS, OperatorPolicy, normalize_action
from .registry import WorkerRegistry

logger = logging.getLogger(__name__)


REJECTION_STATUS = {
    'unknown-approval': 404,
    'already-consumed': 409,
    'wrong-operator': 403,
    'wrong-group': 403,
    'action-not-allowed': 403,
    'registration-changed': 409,
    'queue-moved': 409,
    'approval-scope-mismatch': 409,
    'missing-approval': 403,
}


class ApprovalError(HTTPError):
    def __init__(self, reason, message=None):
        super().__init__(
            REJECTION_STATUS.get(reason, 403),
            message or f"Control action is not approved: {reason}")
        self.reason = reason


class ControlService:
    """The only path that turns an operator intent into a Celery command.

    Both the HTML page and the API call :meth:`execute`; the page never builds
    a control URL with a bare worker name.
    """

    def __init__(self, options, capp):
        self.options = options
        self.capp = capp
        self.policy = OperatorPolicy.from_options(options)
        self.registry = WorkerRegistry()
        self.ledger = ControlLedger()

    @property
    def approvals_required(self):
        return self.policy.enabled

    def registration_for(self, name):
        return self.registry.current(name)

    @staticmethod
    def action_allowlist():
        return set(ACTION_COMMANDS)

    def ensure_registration(self, name, info=None):
        if info is not None:
            return self.registry.observe_inspection(name, info)
        return self.registry.ensure(name)

    def observe_event(self, event_type, name, fields=None):
        return self.registry.observe_event(event_type, name, fields)

    def observe_inspection(self, name, info):
        return self.registry.observe_inspection(name, info)

    def approve(self, operator, action, workername, registration_id=None,
                queue=None, parameters=None, origin='api'):
        action = normalize_action(action)
        if action is None:
            raise HTTPError(400, "Missing control action")
        if action not in ACTION_COMMANDS:
            raise HTTPError(400, f"Unknown control action '{action}'")
        if self.approvals_required and not self.policy.allows(operator, action):
            self._record_attempt(
                operator, action, workername, None,
                'action-not-allowed', status=403,
                message=f"operator '{operator}' may not request it",
                origin=origin)
            raise HTTPError(
                403, f"Operator '{operator}' may not request '{action}'")

        registration = self.registry.current(workername)
        if registration is None:
            raise HTTPError(404, f"Unknown worker '{workername}'")
        if registration_id is not None \
                and registration_id != registration.registration_id:
            self._record_attempt(
                operator, action, workername, registration_id,
                'registration-changed', status=409,
                message='worker registration changed', origin=origin)
            raise HTTPError(
                409,
                f"Worker '{workername}' was registered again; "
                "reload the page before approving")
        parameters = self._validate_parameters(action, queue, parameters)
        if action == 'worker.queue_cancel_consumer' \
                and parameters.get('queue') not in registration.queues:
            self._record_attempt(
                operator, action, workername, registration_id,
                'queue-moved', status=409,
                message=f"queue '{parameters.get('queue')}' not registered",
                origin=origin)
            raise HTTPError(
                409,
                f"Queue '{parameters.get('queue')}' is not registered on "
                f"'{workername}'")
        approval = self.ledger.approve(
            operator, self.policy.group_for(operator) or operator, action,
            registration, queue=parameters.get('queue'), parameters=parameters,
            origin=origin)
        logger.info(
            "Approved control action %s for %s registration=%s approval=%s "
            "operator=%s origin=%s", action, workername,
            registration.registration_id, approval.approval_id, operator,
            origin)
        return approval

    def _attempt_entry(self, operator, action, workername, registration_id,
                       origin='api'):
        previous = self.registry.lookup(registration_id)
        registration_id = registration_id or self._current_id(workername)
        return {
            'audit_id': secrets.token_hex(8),
            'approval_id': None,
            'operator': operator,
            'action': action,
            'worker': workername,
            'registration_id': registration_id,
            'generation': previous.generation if previous else None,
            'origin': origin,
        }

    def _record_attempt(self, operator, action, workername, registration_id,
                        reason, status=None, message=None, origin='api'):
        entry = self._attempt_entry(
            operator, action, workername, registration_id, origin=origin)
        if entry['generation'] is None:
            current = self.registry.lookup(entry['registration_id'])
            entry['generation'] = current.generation if current else None
        entry['superseded'] = self._is_superseded(
            entry['registration_id'], workername)
        self.ledger.record(entry, 'rejected', status=status,
                           message=f'{reason}: {message}' if message else reason)

    def _current_id(self, workername):
        registration = self.registry.current(workername)
        return registration.registration_id if registration else None

    def _is_superseded(self, registration_id, workername=None):
        registration = self.registry.lookup(registration_id)
        if registration is None:
            return False
        current = self.registry.current(workername or registration.name)
        return (current is None
                or current.registration_id != registration.registration_id)

    def _validate_parameters(self, action, queue, parameters):
        parameters = dict(parameters or {})
        if queue is not None:
            parameters['queue'] = queue
        queue = parameters.get('queue')
        if action in ('worker.queue_add_consumer',
                      'worker.queue_cancel_consumer'):
            if not queue:
                raise HTTPError(400, "Missing argument queue")
            parameters['queue'] = str(queue)
        elif action in ('worker.pool_grow', 'worker.pool_shrink'):
            try:
                n = int(parameters.get('n', 1))
            except (TypeError, ValueError) as exc:
                raise HTTPError(400, "Invalid argument 'n'") from exc
            if n < 1:
                raise HTTPError(400, "Invalid argument 'n'")
            parameters['n'] = n
        elif action == 'worker.pool_autoscale':
            try:
                low = int(parameters.get('min'))
                high = int(parameters.get('max'))
            except (TypeError, ValueError) as exc:
                raise HTTPError(400, "Invalid autoscale range") from exc
            if low < 1 or high < low:
                raise HTTPError(400, "Invalid autoscale range")
            parameters.update(min=low, max=high)
        elif action == 'task.time_limit':
            if not parameters.get('taskname'):
                raise HTTPError(400, "Missing argument taskname")
            for name in ('hard', 'soft'):
                value = parameters.get(name)
                if value in (None, ''):
                    parameters[name] = None
                    continue
                try:
                    parameters[name] = float(value)
                except (TypeError, ValueError) as exc:
                    raise HTTPError(
                        400, f"Invalid argument '{name}'") from exc
        elif action == 'task.rate_limit':
            if not parameters.get('taskname'):
                raise HTTPError(400, "Missing argument taskname")
            if not parameters.get('ratelimit'):
                raise HTTPError(400, "Missing argument ratelimit")
            parameters['ratelimit'] = str(parameters['ratelimit'])
        return parameters

    def _check_approval(self, operator, action, workername, approval_id,
                        queue=None, parameters=None):
        registration = self.registry.current(workername)
        group = self.policy.group_for(operator) or operator
        allowed = (self.policy.actions_for(operator)
                   if self.approvals_required else {normalize_action(action)})
        # Consume first so a mismatched request cannot be retried against the
        # same single-use approval; every later check fails closed.
        approval, reason = self.ledger.consume(
            approval_id, operator, group, allowed, registration)
        if approval is None:
            raise ApprovalError(reason)
        if approval.action != normalize_action(action):
            raise ApprovalError('approval-scope-mismatch')
        if approval.worker != workername:
            raise ApprovalError('approval-scope-mismatch')
        if action in ('worker.queue_add_consumer',
                      'worker.queue_cancel_consumer') \
                and approval.parameters.get('queue') != queue:
            raise ApprovalError('approval-scope-mismatch')
        for key, value in (parameters or {}).items():
            if key in approval.parameters and approval.parameters[key] != value:
                raise ApprovalError('approval-scope-mismatch')
        return approval, registration

    async def execute(self, operator, action, workername, run_blocking,
                      approval_id=None, queue=None, parameters=None,
                      origin='api'):
        """Validate the approval against the current registration and run it."""
        action = normalize_action(action)
        entry = None
        if self.approvals_required:
            approval = self.ledger.get(approval_id)
            if approval is not None:
                entry = approval.as_dict()
            else:
                entry = self._attempt_entry(
                    operator, action, workername, approval_id,
                    origin=origin)
            try:
                if not approval_id:
                    raise ApprovalError('missing-approval')
                approval, registration = self._check_approval(
                    operator, action, workername, approval_id,
                    queue=queue, parameters=parameters)
            except ApprovalError as exc:
                entry['superseded'] = self._is_superseded(
                    entry['registration_id'], workername)
                self.ledger.record(
                    entry, 'rejected', status=exc.status_code,
                    message=str(exc.reason))
                raise
        else:
            registration = self.registry.current(workername)
            if registration is None:
                # Legacy mode has no operator approvals; the handler's own
                # worker check still gates the command.
                registration = self.registry.ensure(workername)
            entry = {
                'audit_id': f'legacy-{secrets.token_hex(8)}',
                'approval_id': None,
                'operator': operator,
                'action': action,
                'worker': workername,
                'registration_id': registration.registration_id,
                'generation': registration.generation,
                'origin': origin,
            }

        command, destination, func, args, kwargs = self._plan(
            action, workername, queue=queue, parameters=parameters or {})
        try:
            response = await run_blocking(
                action, f"{workername}@{entry['registration_id']}",
                func, *args, **kwargs)
        except Exception as exc:
            current = self.registry.current(workername)
            entry['superseded'] = bool(
                current is None
                or current.registration_id != entry['registration_id'])
            self.ledger.record(
                entry, 'error', status=getattr(exc, 'status_code', 500),
                destination=destination, command=command,
                message=str(exc))
            raise
        current = self.registry.current(workername)
        entry['superseded'] = bool(
            current is None
            or current.registration_id != entry['registration_id'])
        self.ledger.record(
            entry, 'delivered', status=200, destination=destination,
            command=command, message=self._message(
                action, workername, queue=queue,
                parameters=parameters or {}, response=response))
        return response, entry

    def _plan(self, action, workername, queue=None, parameters=None):
        """Return (command, destination, control callable, args, kwargs)."""
        parameters = parameters or {}
        control = self.capp.control
        destination = [workername]
        if action == 'worker.shutdown':
            return ('shutdown', destination, control.broadcast,
                    ('shutdown',), {'destination': destination})
        if action == 'worker.pool_restart':
            return ('pool_restart', destination, control.broadcast,
                    ('pool_restart',),
                    {'arguments': {'reload': False},
                     'destination': destination, 'reply': True})
        if action == 'worker.pool_grow':
            return ('pool_grow', destination, control.pool_grow, (),
                    {'n': parameters.get('n', 1), 'reply': True,
                     'destination': destination})
        if action == 'worker.pool_shrink':
            return ('pool_shrink', destination, control.pool_shrink, (),
                    {'n': parameters.get('n', 1), 'reply': True,
                     'destination': destination})
        if action == 'worker.pool_autoscale':
            return ('autoscale', destination, control.broadcast,
                    ('autoscale',),
                    {'arguments': {'min': parameters.get('min'),
                                   'max': parameters.get('max')},
                     'destination': destination, 'reply': True})
        if action == 'worker.queue_add_consumer':
            return ('add_consumer', destination, control.broadcast,
                    ('add_consumer',),
                    {'arguments': {'queue': parameters.get('queue', queue)},
                     'destination': destination, 'reply': True})
        if action == 'worker.queue_cancel_consumer':
            return ('cancel_consumer', destination, control.broadcast,
                    ('cancel_consumer',),
                    {'arguments': {'queue': parameters.get('queue', queue)},
                     'destination': destination, 'reply': True})
        if action == 'task.time_limit':
            return ('time_limit', destination, control.time_limit,
                    (parameters.get('taskname'),),
                    {'reply': True, 'hard': parameters.get('hard'),
                     'soft': parameters.get('soft'),
                     'destination': destination})
        if action == 'task.rate_limit':
            return ('rate_limit', destination, control.rate_limit,
                    (parameters.get('taskname'), parameters.get('ratelimit')),
                    {'reply': True, 'destination': destination})
        raise HTTPError(400, f"Unknown control action '{action}'")

    @staticmethod
    def _message(action, workername, queue=None, parameters=None,
                 response=None):
        parameters = parameters or {}
        if action == 'worker.shutdown':
            return 'Shutting down!'
        if action == 'worker.pool_restart':
            return f"Restarting '{workername}' worker's pool"
        if action == 'worker.pool_grow':
            return (f"Growing '{workername}' worker's pool by "
                    f"{parameters.get('n', 1)}")
        if action == 'worker.pool_shrink':
            return (f"Shrinking '{workername}' worker's pool by "
                    f"{parameters.get('n', 1)}")
        if action == 'worker.pool_autoscale':
            return (f"Autoscaling '{workername}' worker "
                    f"(min={parameters.get('min')}, "
                    f"max={parameters.get('max')})")
        if action == 'worker.queue_add_consumer':
            return f"add consumer {parameters.get('queue', queue)}"
        if action == 'worker.queue_cancel_consumer':
            return f"no longer consuming from {parameters.get('queue', queue)}"
        return 'ok'

    def responses(self, limit=None):
        records = self.ledger.responses(limit)
        payload = []
        for record in records:
            item = record.as_dict()
            current = self.registry.current(record.worker)
            item['current_registration_id'] = (
                current.registration_id if current else None)
            item['superseded'] = (
                item['superseded']
                or current is None
                or current.registration_id != record.registration_id)
            payload.append(item)
        return payload

    def pending_approvals(self, operator=None):
        approvals = []
        for approval in self.ledger.pending():
            if operator is not None and approval.operator != operator:
                continue
            approvals.append(approval.as_dict())
        return approvals

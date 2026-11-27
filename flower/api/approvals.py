import logging

from tornado import web

from ..control.policy import normalize_action
from . import BaseApiHandler

logger = logging.getLogger(__name__)


class ApprovalMixin(BaseApiHandler):
    @property
    def control(self):
        return self.application.control


class WorkerApproval(ApprovalMixin):
    @web.authenticated
    async def post(self, workername):
        """
Approve one control action for one worker registration

The approval is bound to the worker's current registration id.  It is a
single-use grant for the named action and its scope (queue, pool size or
autoscale range).

**Example request**:

.. sourcecode:: http

  POST /api/worker/approve/celery@worker2 HTTP/1.1
  Content-Length: 41
  Content-Type: application/x-www-form-urlencoded; charset=utf-8
  Host: localhost:5555

  action=queue.cancel&queue=sample-queue&registration_id=...

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Type: application/json; charset=UTF-8

  {
      "approval_id": "...",
      "audit_id": "...",
      "worker": "celery@worker2",
      "action": "worker.queue_cancel_consumer",
      "registration_id": "...",
      "generation": 2,
      "queue": "sample-queue"
  }

:query action: control action to approve
:query registration_id: registration the operator saw; rejected if the
                        worker has been registered again since
:query queue: queue for consumer actions
:query n: pool size for grow/shrink
:query min: minimum pool size for autoscale
:query max: maximum pool size for autoscale
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: approval issued
:statuscode 400: missing or invalid action scope
:statuscode 401: unauthorized request
:statuscode 403: operator group may not perform the action
:statuscode 404: unknown worker
:statuscode 409: worker was registered again since the page was loaded
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        action = normalize_action(self.get_argument('action', required=True))
        registration_id = self.get_argument(
            'registration_id', default=None)
        parameters = {}
        for name in ('queue', 'n', 'min', 'max', 'taskname', 'ratelimit',
                     'hard', 'soft'):
            value = self.get_argument(name, default=None)
            if value is not None:
                parameters[name] = value
        approval = self.control.approve(
            self.operator(), action, workername,
            registration_id=registration_id,
            parameters=parameters, origin=self.entry_origin())
        self.write(approval.as_dict())


class WorkerRegistrations(ApprovalMixin):
    @web.authenticated
    async def get(self, workername=None):
        """
Return the current worker registration ids

:query workername: restrict the response to one worker
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 404: unknown worker
        """
        workername = workername or self.get_argument(
            'workername', default=None)
        if workername:
            registration = self.control.registration_for(workername)
            if registration is None:
                raise web.HTTPError(404, f"Unknown worker '{workername}'")
            self.write({workername: registration.as_dict()})
            return
        self.write({
            name: registration.as_dict()
            for name, registration in
            self.control.registry.snapshot().items()
        })


class ControlResponses(ApprovalMixin):
    @web.authenticated
    async def get(self):
        """
Return control responses with their approval attribution

Each record keeps the worker name, registration id and action it was issued
for, even when the worker has since been registered again.  ``superseded``
marks records whose target registration is no longer current.

:query limit: return at most this many most recent records
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
        """
        limit = self.get_argument('limit', default=None, type=int)
        responses = self.control.responses(limit=limit)
        self.write({
            'approvals_required': self.control.approvals_required,
            'responses': responses,
        })


class PendingApprovals(ApprovalMixin):
    @web.authenticated
    async def get(self):
        """
Return the operator's unconsumed approvals

:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
        """
        operator = self.operator()
        if operator is None:
            raise web.HTTPError(
                403, "Approvals are only listed for a named operator")
        self.write({
            'approvals': self.control.pending_approvals(operator=operator),
        })

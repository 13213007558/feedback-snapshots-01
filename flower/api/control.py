import logging

from tornado import web

from . import BaseApiHandler

logger = logging.getLogger(__name__)


class ControlHandler(BaseApiHandler):
    def is_worker(self, workername):
        return workername and workername in self.application.workers

    def error_reason(self, workername, response):
        "extracts error message from response"
        for res in response:
            try:
                return res[workername].get('error', 'Unknown reason')
            except KeyError:
                pass
        logger.error("Failed to extract error reason from '%s'", response)
        return 'Unknown reason'

    @property
    def control(self):
        return self.application.control

    def check_worker(self, workername):
        if not self.is_worker(workername) \
                and self.control.registration_for(workername) is None:
            raise web.HTTPError(404, f"Unknown worker '{workername}'")

    def approval_argument(self):
        return self.get_argument('approval', default=None)

    async def execute(self, action, workername, approval_id=None,
                      queue=None, parameters=None):
        response, entry = await self.control.execute(
            self.operator(), action, workername, self.run_blocking,
            approval_id=approval_id, queue=queue, parameters=parameters,
            origin=self.entry_origin())
        return response, entry

    def reply_for(self, workername, response):
        if response and workername in response[0]:
            return response[0][workername]
        return None

    def failed_reply(self, workername, response):
        reply = self.reply_for(workername, response) or {}
        return 'error' in reply


class WorkerShutDown(ControlHandler):
    @web.authenticated
    async def post(self, workername):
        """
Shut down a worker

**Example request**:

.. sourcecode:: http

  POST /api/worker/shutdown/celery@worker2 HTTP/1.1
  Content-Length: 0
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 29
  Content-Type: application/json; charset=UTF-8

  {
      "message": "Shutting down!"
  }

The ``approval`` query parameter is required when operator groups are
configured.  It must name the approval issued for this action and this
worker registration.

:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: read only mode is enabled or action not approved
:statuscode 404: unknown worker or unknown approval
:statuscode 409: worker re-registered or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        self.check_worker(workername)

        logger.info("Shutting down '%s' worker", workername)
        await self.execute('worker.shutdown', workername,
                           approval_id=self.approval_argument())
        self.write({"message": "Shutting down!"})


class WorkerPoolRestart(ControlHandler):
    @web.authenticated
    async def post(self, workername):
        """
Restart worker's pool

**Example request**:

.. sourcecode:: http

  POST /api/worker/pool/restart/celery@worker2 HTTP/1.1
  Content-Length: 0
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 56
  Content-Type: application/json; charset=UTF-8

  {
      "message": "Restarting 'celery@worker2' worker's pool"
  }

:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: pool restart is not enabled (see CELERYD_POOL_RESTARTS) or read only mode is enabled or action not approved
:statuscode 404: unknown worker or unknown approval
:statuscode 409: worker re-registered or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        self.check_worker(workername)

        logger.info("Restarting '%s' worker's pool", workername)
        response, _ = await self.execute(
            'worker.pool_restart', workername,
            approval_id=self.approval_argument())
        if not self.failed_reply(workername, response):
            self.write({"message": f"Restarting '{workername}' worker's pool"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to restart the '{workername}' pool: {reason}")


class WorkerPoolGrow(ControlHandler):
    @web.authenticated
    async def post(self, workername):
        """
Grow worker's pool

**Example request**:

.. sourcecode:: http

  POST /api/worker/pool/grow/celery@worker2?n=3 HTTP/1.1
  Content-Length: 0
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 58
  Content-Type: application/json; charset=UTF-8

  {
      "message": "Growing 'celery@worker2' worker's pool by 3"
  }

:query n: number of pool processes to grow, default is 1
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: failed to grow or read only mode is enabled or action not approved
:statuscode 404: unknown worker or unknown approval
:statuscode 409: worker re-registered, pool size differs from the approval, or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        self.check_worker(workername)

        n = self.get_argument('n', default=1, type=int)

        logger.info("Growing '%s' worker's pool by '%s'", workername, n)
        response, _ = await self.execute(
            'worker.pool_grow', workername,
            approval_id=self.approval_argument(),
            parameters={'n': n})
        if not self.failed_reply(workername, response):
            self.write({"message": f"Growing '{workername}' worker's pool by {n}"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to grow '{workername}' worker's pool: {reason}")


class WorkerPoolShrink(ControlHandler):
    @web.authenticated
    async def post(self, workername):
        """
Shrink worker's pool

**Example request**:

.. sourcecode:: http

  POST /api/worker/pool/shrink/celery@worker2 HTTP/1.1
  Content-Length: 0
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 60
  Content-Type: application/json; charset=UTF-8

  {
      "message": "Shrinking 'celery@worker2' worker's pool by 1"
  }

:query n: number of pool processes to shrink, default is 1
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: failed to shrink or read only mode is enabled or action not approved
:statuscode 404: unknown worker or unknown approval
:statuscode 409: worker re-registered, pool size differs from the approval, or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        self.check_worker(workername)

        n = self.get_argument('n', default=1, type=int)

        logger.info("Shrinking '%s' worker's pool by '%s'", workername, n)
        response, _ = await self.execute(
            'worker.pool_shrink', workername,
            approval_id=self.approval_argument(),
            parameters={'n': n})
        if not self.failed_reply(workername, response):
            self.write({"message": f"Shrinking '{workername}' worker's pool by {n}"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to shrink '{workername}' worker's pool: {reason}")


class WorkerPoolAutoscale(ControlHandler):
    @web.authenticated
    async def post(self, workername):
        """
Autoscale worker pool

**Example request**:

.. sourcecode:: http

  POST /api/worker/pool/autoscale/celery@worker2?min=3&max=10 HTTP/1.1
  Content-Length: 0
  Content-Type: application/x-www-form-urlencoded; charset=utf-8
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 66
  Content-Type: application/json; charset=UTF-8

  {
      "message": "Autoscaling 'celery@worker2' worker (min=3, max=10)"
  }

:query min: minimum number of pool processes
:query max: maximum number of pool processes
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: autoscaling is not enabled (see CELERYD_AUTOSCALER) or read only mode is enabled or action not approved
:statuscode 404: unknown worker or unknown approval
:statuscode 409: worker re-registered, range differs from the approval, or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        self.check_worker(workername)

        min = self.get_argument('min', type=int, required=True)
        max = self.get_argument('max', type=int, required=True)

        logger.info("Autoscaling '%s' worker by '%s'",
                    workername, (min, max))
        response, _ = await self.execute(
            'worker.pool_autoscale', workername,
            approval_id=self.approval_argument(),
            parameters={'min': min, 'max': max})
        if not self.failed_reply(workername, response):
            self.write({"message": f"Autoscaling '{workername}' worker "
                                    f"(min={min}, max={max})"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to autoscale '{workername}' worker: {reason}")


class WorkerQueueAddConsumer(ControlHandler):
    @web.authenticated
    async def post(self, workername):
        """
Start consuming from a queue

**Example request**:

.. sourcecode:: http

  POST /api/worker/queue/add-consumer/celery@worker2?queue=sample-queue HTTP/1.1
  Content-Length: 0
  Content-Type: application/x-www-form-urlencoded; charset=utf-8
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 40
  Content-Type: application/json; charset=UTF-8

  {
      "message": "add consumer sample-queue"
  }

:query queue: the name of a new queue
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: failed to add consumer or read only mode is enabled or action not approved
:statuscode 404: unknown worker or unknown approval
:statuscode 409: worker re-registered, queue differs from the approval, or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        self.check_worker(workername)

        queue = self.get_argument('queue', required=True)

        logger.info("Adding consumer '%s' to worker '%s'",
                    queue, workername)
        response, _ = await self.execute(
            'worker.queue_add_consumer', workername,
            approval_id=self.approval_argument(), queue=queue)
        if not self.failed_reply(workername, response):
            reply = self.reply_for(workername, response) or {}
            self.write({"message": reply.get('ok') or f"add consumer {queue}"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to add '{queue}' consumer to '{workername}' worker: {reason}")


class WorkerQueueCancelConsumer(ControlHandler):
    @web.authenticated
    async def post(self, workername):
        """
Stop consuming from a queue

**Example request**:

.. sourcecode:: http

  POST /api/worker/queue/cancel-consumer/celery@worker2?queue=sample-queue HTTP/1.1
  Content-Length: 0
  Content-Type: application/x-www-form-urlencoded; charset=utf-8
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 52
  Content-Type: application/json; charset=UTF-8

  {
      "message": "no longer consuming from sample-queue"
  }

:query queue: the name of queue
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: failed to cancel consumer or read only mode is enabled or action not approved
:statuscode 404: unknown worker or unknown approval
:statuscode 409: worker re-registered, queue moved, or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        self.check_worker(workername)

        queue = self.get_argument('queue', required=True)

        logger.info("Canceling consumer '%s' from worker '%s'",
                    queue, workername)
        response, _ = await self.execute(
            'worker.queue_cancel_consumer', workername,
            approval_id=self.approval_argument(), queue=queue)
        if not self.failed_reply(workername, response):
            reply = self.reply_for(workername, response) or {}
            self.write({"message": reply.get('ok') or f"no longer consuming from {queue}"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to cancel '{queue}' consumer from '{workername}' worker: {reason}")


class TaskRevoke(ControlHandler):
    @web.authenticated
    async def post(self, taskid):
        """
Revoke a task

**Example request**:

.. sourcecode:: http

  POST /api/task/revoke/1480b55c-b8b2-462c-985e-24af3e9158f9?terminate=true HTTP/1.1
  Content-Length: 0
  Content-Type: application/x-www-form-urlencoded; charset=utf-8
  Host: localhost:5555

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 61
  Content-Type: application/json; charset=UTF-8

  {
      "message": "Revoked '1480b55c-b8b2-462c-985e-24af3e9158f9'"
  }

:query terminate: terminate the task if it is running
:query signal: name of signal to send to process if terminate (default: 'SIGTERM')
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: read only mode is enabled
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        logger.info("Revoking task '%s'", taskid)
        terminate = self.get_argument('terminate', default=False, type=bool)
        signal = self.get_argument('signal', default='SIGTERM', type=str)
        await self.run_blocking(
            'task.revoke', taskid, self.capp.control.revoke,
            taskid, terminate=terminate, signal=signal)
        self.write({"message": f"Revoked '{taskid}'"})


class TaskTimout(ControlHandler):
    @web.authenticated
    async def post(self, taskname):
        """
Change soft and hard time limits for a task

**Example request**:

.. sourcecode:: http

    POST /api/task/timeout/tasks.sleep HTTP/1.1
    Content-Length: 44
    Content-Type: application/x-www-form-urlencoded; charset=utf-8
    Host: localhost:5555

    soft=30&hard=100&workername=celery%40worker1

**Example response**:

.. sourcecode:: http

    HTTP/1.1 200 OK
    Content-Length: 46
    Content-Type: application/json; charset=UTF-8

    {
        "message": "time limits set successfully"
    }

:query workername: worker name
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: read only mode is enabled or action not approved
:statuscode 404: unknown task/worker or unknown approval
:statuscode 409: worker re-registered or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        workername = self.get_argument('workername', required=True)
        hard = self.get_argument('hard', default=None, type=float)
        soft = self.get_argument('soft', default=None, type=float)

        if taskname not in self.capp.tasks:
            raise web.HTTPError(404, f"Unknown task '{taskname}'")
        self.check_worker(workername)

        logger.info("Setting timeouts for '%s' task (%s, %s)",
                    taskname, soft, hard)
        parameters = {'taskname': taskname, 'hard': hard, 'soft': soft}
        response, _ = await self.execute(
            'task.time_limit', workername,
            approval_id=self.approval_argument(), parameters=parameters)

        if not self.failed_reply(workername, response):
            reply = self.reply_for(workername, response) or {}
            self.write({"message": reply.get('ok') or "time limits set successfully"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to set timeouts: '{reason}'")


class TaskRateLimit(ControlHandler):
    @web.authenticated
    async def post(self, taskname):
        """
Change rate limit for a task

**Example request**:

.. sourcecode:: http

    POST /api/task/rate-limit/tasks.sleep HTTP/1.1
    Content-Length: 41
    Content-Type: application/x-www-form-urlencoded; charset=utf-8
    Host: localhost:5555

    ratelimit=200&workername=celery%40worker1

**Example response**:

.. sourcecode:: http

  HTTP/1.1 200 OK
  Content-Length: 61
  Content-Type: application/json; charset=UTF-8

  {
      "message": "new rate limit set successfully"
  }

:query workername: worker name
:reqheader Authorization: optional OAuth token to authenticate
:statuscode 200: no error
:statuscode 401: unauthorized request
:statuscode 403: read only mode is enabled or action not approved
:statuscode 404: unknown task/worker or unknown approval
:statuscode 409: worker re-registered or approval already consumed
        """
        if self.application.options.read_only:
            raise web.HTTPError(403, "Read only mode is enabled")

        workername = self.get_argument('workername', required=True)
        ratelimit = self.get_argument('ratelimit', required=True)

        if taskname not in self.capp.tasks:
            raise web.HTTPError(404, f"Unknown task '{taskname}'")
        self.check_worker(workername)

        logger.info("Setting '%s' rate limit for '%s' task",
                    ratelimit, taskname)
        response, _ = await self.execute(
            'task.rate_limit', workername,
            approval_id=self.approval_argument(),
            parameters={'taskname': taskname, 'ratelimit': ratelimit})
        if not self.failed_reply(workername, response):
            reply = self.reply_for(workername, response) or {}
            self.write({"message": reply.get('ok') or "new rate limit set successfully"})
        else:
            logger.error(response)
            self.set_status(403)
            reason = self.error_reason(workername, response)
            self.write(f"Failed to set rate limit: '{reason}'")

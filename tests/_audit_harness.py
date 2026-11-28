"""Shared fixtures for the authorization-audit verification suite.

The audit middleware in this module records *stage facts*: a fact is appended
at the moment a stage is actually reached, so the resulting trail cannot be
rewritten by a later stage (such as an ``after`` hook changing the response,
or an error handler converting a raised exception into an error page).

A request is only registered as *granted* once it has both passed the
resource ``before`` hook (real authorization) and completed its business
operation. Middleware short-circuits, resource-hook denials, and responder
failures are recorded with the stages they really traversed -- including a
business operation that started but then failed -- yet they are never
registered as grants.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field

import falcon

# Stage names emitted into the per-request fact trail. They double as the
# authoritative, ordered enumeration of every pipeline stage a request may
# reach on either the WSGI or the ASGI surface.
STAGE_REQUEST_MW = 'middleware.process_request'
STAGE_RESOURCE_MW = 'middleware.process_resource'
STAGE_BEFORE_HOOK = 'resource.before_hook'
STAGE_BUSINESS = 'resource.responder'
STAGE_AFTER_HOOK = 'resource.after_hook'
STAGE_RESPONSE_MW = 'middleware.process_response'
STAGE_ERROR_HANDLER = 'error_handler'

CONTEXT_KEY = 'audit_trail'


class BusinessFailure(Exception):
    """Raised by the responder to model a business operation that fails."""


@dataclass
class AuditRecord:
    """Verifiable facts collected for a single request, in traversal order.

    Attributes:
        request_id: Stable identifier copied from the ``X-Request-Id`` header.
        stages: Ordered stage facts; appended only when a stage really runs.
        resource_ops: Number of business operations actually started.
        authorized: ``True`` once the before hook admits the request.
        entered_business: ``True`` once the responder actually starts.
        granted: ``True`` only when authorization passed and the business
            operation completed; the durable audit decision.
        business_completed: ``True`` when the responder returns normally.
        final_status: Response status observed in ``process_response``.
        response_succeeded: ``req_succeeded`` flag observed by the middleware.
        error_handled: ``True`` when a registered error handler converted an
            exception into an error page.
        after_hook_rewrote_response: ``True`` when the after hook changed the
            response status after the business call.
    """

    request_id: str
    stages: list[str] = field(default_factory=list)
    resource_ops: int = 0
    authorized: bool = False
    entered_business: bool = False
    granted: bool = False
    business_completed: bool = False
    final_status: int | None = None
    response_succeeded: bool | None = None
    error_handled: bool = False
    after_hook_rewrote_response: bool = False

    def record(self, stage: str) -> None:
        self.stages.append(stage)


class AuditJournal:
    """Process-wide collector of :class:`AuditRecord` instances."""

    def __init__(self) -> None:
        self._records: dict[str, AuditRecord] = {}

    def start(self, request_id: str) -> AuditRecord:
        record = AuditRecord(request_id=request_id)
        self._records[request_id] = record
        return record

    def get(self, request_id: str) -> AuditRecord:
        return self._records[request_id]

    @property
    def records(self) -> dict[str, AuditRecord]:
        """Mapping of every recorded request id to its audit record."""
        return self._records

    def reset(self) -> None:
        self._records.clear()


def _record_for(req) -> AuditRecord:
    return req.context[CONTEXT_KEY]


def _record_for_mw(middleware: AuditMiddleware, req) -> AuditRecord:
    # An upstream middleware may short-circuit before this component's
    # process_request ran. In that case lazily open the record here so the
    # response stage still leaves a verifiable (empty) trail.
    if CONTEXT_KEY not in req.context:
        record = middleware._journal.start(req.get_header('X-Request-Id'))
        req.context[CONTEXT_KEY] = record
    return req.context[CONTEXT_KEY]


class AuditMiddleware:
    """Middleware that leaves an independent fact at every pipeline stage.

    The authorization/grant decision is written eagerly at the stage where it
    happens. ``process_response`` only snapshots the final response; it never
    recomputes the grant, so a later status change cannot rewrite history.
    """

    def __init__(self, journal: AuditJournal) -> None:
        self._journal = journal

    def process_request(self, req, resp) -> None:
        record = self._journal.start(req.get_header('X-Request-Id'))
        req.context[CONTEXT_KEY] = record
        record.record(STAGE_REQUEST_MW)

    def process_resource(self, req, resp, resource, params) -> None:
        _record_for(req).record(STAGE_RESOURCE_MW)

    def process_response(self, req, resp, resource, req_succeeded) -> None:
        record = _record_for_mw(self, req)
        record.record(STAGE_RESPONSE_MW)
        record.final_status = resp.status_code
        record.response_succeeded = req_succeeded

    async def process_request_async(self, req, resp) -> None:
        self.process_request(req, resp)

    async def process_resource_async(self, req, resp, resource, params) -> None:
        self.process_resource(req, resp, resource, params)

    async def process_response_async(self, req, resp, resource, req_succeeded) -> None:
        self.process_response(req, resp, resource, req_succeeded)


def authorize_before(req, resp, resource, params) -> None:
    """Resource ``before`` hook performing the real authorization decision.

    Requests carrying ``X-Deny: 1`` are rejected here with ``400``; every
    other request is admitted and marked authorized before business code runs.
    """
    record = _record_for(req)
    record.record(STAGE_BEFORE_HOOK)
    if req.get_header('X-Deny') == '1':
        raise falcon.HTTPBadRequest(
            title='Denied by resource hook',
            description='The before hook refused to authorize this request.',
        )
    record.authorized = True


async def authorize_before_async(req, resp, resource, params) -> None:
    authorize_before(req, resp, resource, params)


def mutate_after(req, resp, resource) -> None:
    """Resource ``after`` hook that rewrites the response status.

    This models a post-processing step that alters the response. The audit
    trail keeps the authorization and business facts recorded earlier; the
    rewrite only flags that the response was changed after the fact.
    """
    record = _record_for(req)
    record.record(STAGE_AFTER_HOOK)
    record.after_hook_rewrote_response = True
    resp.status = falcon.HTTP_400


async def mutate_after_async(req, resp, resource) -> None:
    mutate_after(req, resp, resource)


def handle_business_failure(req, resp, ex, params) -> None:
    """Convert a :class:`BusinessFailure` into a ``400`` error page."""
    record = _record_for(req)
    record.record(STAGE_ERROR_HANDLER)
    record.error_handled = True
    raise falcon.HTTPBadRequest(
        title='Business operation failed',
        description='The responder raised and the error page converted it.',
    )


async def handle_business_failure_async(req, resp, ex, params) -> None:
    handle_business_failure(req, resp, ex, params)


@falcon.before(authorize_before)
@falcon.after(mutate_after)
class AuditResource:
    """Resource exercising before/after hooks and a real business operation."""

    def on_post(self, req, resp) -> None:
        record = _record_for(req)
        # The responder starts: authorization has genuinely been passed and
        # the business operation is really entered (and counted once).
        record.record(STAGE_BUSINESS)
        record.entered_business = True
        record.resource_ops += 1

        if req.get_header('X-Fail-Business') == '1':
            raise BusinessFailure('the business operation failed')

        # A request approved in preprocessing may still fail to decode.
        _ = req.media
        record.business_completed = True
        # The durable grant is only registered now that the op completed.
        record.granted = True
        resp.status = falcon.HTTP_200
        resp.media = {'outcome': 'business-complete'}


@falcon.before(authorize_before_async)
@falcon.after(mutate_after_async)
class AuditResourceAsync:
    """ASGI counterpart of :class:`AuditResource`."""

    async def on_post(self, req, resp) -> None:
        record = _record_for(req)
        record.record(STAGE_BUSINESS)
        record.entered_business = True
        record.resource_ops += 1

        if req.get_header('X-Fail-Business') == '1':
            raise BusinessFailure('the business operation failed')

        _ = await req.get_media()
        record.business_completed = True
        record.granted = True
        resp.status = falcon.HTTP_200
        resp.media = {'outcome': 'business-complete'}


class EarlyReturnMiddleware:
    """Middleware that short-circuits before routing with a ``400`` response."""

    def process_request(self, req, resp) -> None:
        resp.status = falcon.HTTP_400
        resp.media = {'outcome': 'middleware-short-circuit'}
        resp.complete = True

    async def process_request_async(self, req, resp) -> None:
        self.process_request(req, resp)


JSON_HEADERS = {'Content-Type': 'application/json'}

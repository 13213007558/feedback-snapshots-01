"""Service activity reporting, details, and aggregate statistics

Services report activity to the Hub. Reports are idempotent:
re-sending an activity does not increase the recorded counts,
and an older observation never replaces a newer one.

Activity details are only visible to principals with
``read:services:activity`` (optionally filtered by ``!service=``),
or to the service that owns the activity.

The aggregate summary is available to any authenticated principal
and contains only totals, never service names or activity identifiers.
"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
import json
import re
from datetime import timedelta, timezone

from dateutil.parser import parse as parse_date
from sqlalchemy import func
from tornado import web

from .. import orm
from ..scopes import Scope
from ..utils import isoformat, utcnow
from .base import APIHandler

# default statistics window: 30 days
DEFAULT_WINDOW_SECONDS = 30 * 24 * 60 * 60

_DURATION_RE = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$", re.IGNORECASE
)
_DURATION_UNITS = {
    "": 1,
    "ms": 0.001,
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 24 * 60 * 60,
    "w": 7 * 24 * 60 * 60,
}
_PERIODS = {
    "24h": 24 * 60 * 60,
    "1d": 24 * 60 * 60,
    "day": 24 * 60 * 60,
    "daily": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "1w": 7 * 24 * 60 * 60,
    "week": 7 * 24 * 60 * 60,
    "weekly": 7 * 24 * 60 * 60,
    "30d": 30 * 24 * 60 * 60,
    "month": 30 * 24 * 60 * 60,
    "monthly": 30 * 24 * 60 * 60,
}


def _parse_timestamp(timestamp):
    """Parse and return a naive UTC timestamp.

    Raises HTTPError(400) for invalid or implausibly future timestamps.
    """
    try:
        dt = parse_date(timestamp)
    except Exception:
        raise web.HTTPError(400, "Not a valid timestamp: %r" % (timestamp,))
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)

    now = utcnow(with_tz=False)
    if (dt - now) > timedelta(minutes=59):
        raise web.HTTPError(
            400,
            "Rejecting activity from more than an hour in the future: %s"
            % isoformat(dt),
        )
    return dt


def _parse_duration(value):
    """Parse a duration string (e.g. "24h", "7d", "3600") into seconds"""
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and not value.strip():
        raise ValueError(f"Invalid duration: {value!r}")
    match = _DURATION_RE.match(str(value))
    if not match:
        raise ValueError(f"Invalid duration: {value!r}")
    number, unit = match.groups()
    return int(float(number) * _DURATION_UNITS[(unit or "").lower()])


def _get_window(handler):
    """Resolve the requested statistics window from query parameters

    Supported forms:
      - period=24h|7d|30d (aliases: day, week, month)
      - window=<seconds or duration, e.g. 3600 or "6h">
      - hours=<number>, days=<number>
      - since=<timestamp>, until=<timestamp>
    """
    now = utcnow(with_tz=False)
    arguments = handler.request.arguments

    until = now
    if "until" in arguments:
        until = _parse_timestamp(handler.get_argument("until"))

    window_seconds = None
    if "period" in arguments:
        period = handler.get_argument("period")
        if period not in _PERIODS:
            raise web.HTTPError(400, f"Invalid period: {period!r}")
        window_seconds = _PERIODS[period]
    elif "window" in arguments:
        try:
            window_seconds = _parse_duration(handler.get_argument("window"))
        except ValueError as e:
            raise web.HTTPError(400, str(e))
    elif "hours" in arguments:
        try:
            window_seconds = int(float(handler.get_argument("hours")) * 3600)
        except ValueError:
            raise web.HTTPError(400, "`hours` must be a number")
    elif "days" in arguments:
        try:
            window_seconds = int(float(handler.get_argument("days")) * 24 * 3600)
        except ValueError:
            raise web.HTTPError(400, "`days` must be a number")

    if window_seconds is not None and window_seconds < 0:
        raise web.HTTPError(400, "window must not be negative")

    if "since" in arguments:
        since = _parse_timestamp(handler.get_argument("since"))
    elif window_seconds is not None:
        since = until - timedelta(seconds=window_seconds)
    else:
        since = until - timedelta(seconds=DEFAULT_WINDOW_SECONDS)

    if since > until:
        raise web.HTTPError(400, "`since` must not be after `until`")

    return since, until


def _get_report_timestamp(body):
    for key in ("last_activity", "timestamp", "time", "at"):
        value = body.get(key)
        if value:
            return _parse_timestamp(value)
    raise web.HTTPError(400, "body must contain `last_activity`")


def _get_activity_id(body, last_activity):
    """Identify a single activity

    Prefer an explicit stable identifier from the report.
    Otherwise, the normalized activity timestamp identifies the event,
    so re-sending the same event is idempotent.
    """
    for key in ("activity_id", "event_id", "id"):
        value = body.get(key)
        if value is not None:
            if not isinstance(value, str) or not value:
                raise web.HTTPError(400, f"`{key}` must be a non-empty string")
            if len(value) > 255:
                raise web.HTTPError(400, f"`{key}` must be at most 255 characters")
            return value
    return isoformat(last_activity)


def _activity_model(record):
    return {
        "activity_id": record.activity_id,
        "last_activity": isoformat(record.last_activity),
        "recorded_at": isoformat(record.recorded_at),
    }


class ServiceActivityAPIHandler(APIHandler):
    """Report or read activity for a single service

    POST /api/services/:service_name/activity
        {"activity_id": "unique-id", "last_activity": "2026-01-01T00:00:00Z"}

        Also accepts a batch:
        {"activities": [{"activity_id": "...", "last_activity": "..."}, ...]}

    GET /api/services/:service_name/activity
        The owning service may read its own details.
        Other principals need an explicit read:services:activity grant
        for this service (optionally via !service= filtering).
        Optional since/until/period/window parameters filter records.

    Repeated reports of the same activity_id are idempotent.
    An older last_activity never replaces a newer one.
    """

    def _report_service(self, service_name):
        """Resolve and authorize a report for service_name

        A service may always report its own activity.
        Other principals need the services:activity scope
        (optionally filtered by !service=).
        """
        current_user = self.current_user
        if current_user is None:
            raise web.HTTPError(403, "Missing or invalid credentials.")

        if isinstance(current_user, orm.Service) and current_user.name == service_name:
            allowed = True
        else:
            allowed = self.has_scope(f"services:activity!service={service_name}")
        if not allowed:
            raise web.HTTPError(
                403,
                "Not authorized to report activity for service %s" % service_name,
            )
        service = orm.Service.find(self.db, name=service_name)
        if service is None:
            raise web.HTTPError(404, "No such service: %r" % (service_name,))
        return service

    def _detail_service(self, service_name):
        """Resolve and authorize a detail read for service_name

        A service may read its own activity details.
        Everyone else needs an explicit read:services:activity grant
        for this service (optionally via !service= filtering).
        """
        service = orm.Service.find(self.db, name=service_name)
        if service is None:
            raise web.HTTPError(404, "No such service: %r" % (service_name,))

        current_user = self.current_user
        is_owner = (
            isinstance(current_user, orm.Service)
            and current_user.name == service_name
        )
        scope_filter = self.get_scope_filter('read:services:activity')
        if not is_owner and not scope_filter(service, kind='service'):
            raise web.HTTPError(
                403,
                "Not authorized to read activity for service %s" % service_name,
            )
        return service

    def _report_one(self, service, body):
        if not isinstance(body, dict):
            raise web.HTTPError(400, "each activity must be a json dict")
        last_activity = _get_report_timestamp(body)
        activity_id = _get_activity_id(body, last_activity)

        record = (
            self.db.query(orm.ServiceActivity)
            .filter_by(service_id=service.id, activity_id=activity_id)
            .one_or_none()
        )
        created = updated = False
        if record is None:
            record = orm.ServiceActivity(
                service_id=service.id,
                activity_id=activity_id,
                last_activity=last_activity,
                recorded_at=utcnow(with_tz=False),
            )
            self.db.add(record)
            created = True
        elif last_activity > record.last_activity:
            # an older observation never replaces a newer one
            record.last_activity = last_activity
            updated = True
        self.db.commit()

        model = _activity_model(record)
        model.update(
            {
                "kind": "service_activity",
                "service": service.name,
                "created": created,
                "updated": updated,
            }
        )
        return model

    def post(self, service_name):
        service = self._report_service(service_name)

        body = self.get_json_body()
        if isinstance(body, list):
            activities = body
        elif isinstance(body, dict):
            activities = body.get("activities")
            if activities is None:
                self.write(json.dumps(self._report_one(service, body)))
                return
        else:
            raise web.HTTPError(400, "body must be a json dict or list")

        if not isinstance(activities, list):
            raise web.HTTPError(400, "`activities` must be a list")
        # validate the whole batch before applying any of it,
        # so a bad entry cannot leave partially-applied state
        for item in activities:
            if not isinstance(item, dict):
                raise web.HTTPError(400, "each activity must be a json dict")
            _get_report_timestamp(item)
        results = [self._report_one(service, item) for item in activities]
        self.write(
            json.dumps(
                {
                    "kind": "service_activity_batch",
                    "service": service.name,
                    "count": len(results),
                    "results": results,
                }
            )
        )

    def get(self, service_name):
        if self.current_user is None:
            raise web.HTTPError(403, "Missing or invalid credentials.")
        service = self._detail_service(service_name)

        since, until = _get_window(self)
        records = (
            self.db.query(orm.ServiceActivity)
            .filter(
                orm.ServiceActivity.service_id == service.id,
                orm.ServiceActivity.last_activity >= since,
                orm.ServiceActivity.last_activity <= until,
            )
            .order_by(orm.ServiceActivity.last_activity, orm.ServiceActivity.id)
            .all()
        )
        last_activity = records[-1].last_activity if records else None
        self.write(
            json.dumps(
                {
                    "kind": "service_activity_list",
                    "service": service.name,
                    "window_seconds": int((until - since).total_seconds()),
                    "since": isoformat(since),
                    "until": isoformat(until),
                    "count": len(records),
                    "last_activity": isoformat(last_activity),
                    "activity": [_activity_model(r) for r in records],
                }
            )
        )


class ServiceActivitySummaryAPIHandler(APIHandler):
    """Read aggregate service activity statistics

    GET /api/service-activity

    Any authenticated principal may read the aggregate.

    The response contains complete totals across every service:
    ``active_services`` counts distinct services with activity in the window,
    and ``activity_count`` counts distinct, de-duplicated activities.

    ``services`` maps each service in the caller's public service list
    (the same set returned by ``GET /api/services``) to its de-duplicated
    activity count in the window.
    It never contains activity identifiers or per-activity timestamps,
    so restricted activity details cannot be reconstructed from it.

    Optional window parameters: period=24h|7d|30d, window=<seconds>,
    hours=<number>, days=<number>, since=<timestamp>, until=<timestamp>.
    """

    def _visible_service_ids(self):
        """Map ORM service ids to names for services in the caller's public list

        Uses the same list:services scope as GET /api/services.
        """
        service_scope = self.parsed_scopes.get('list:services')
        if service_scope is None:
            service_scope = self.parsed_scopes.get('read:services')
        if service_scope is None:
            service_scope = self.parsed_scopes.get('read:services:name')
        if service_scope is None:
            return {}

        visible = {}
        for name in self.services:
            if service_scope is Scope.ALL or (
                isinstance(service_scope, dict)
                and name in service_scope.get("service", set())
            ):
                orm_service = orm.Service.find(self.db, name=name)
                if orm_service is not None:
                    visible[orm_service.id] = name
        return visible

    def get(self):
        if self.current_user is None:
            raise web.HTTPError(403, "Missing or invalid credentials.")

        since, until = _get_window(self)
        window = (
            orm.ServiceActivity.last_activity >= since,
            orm.ServiceActivity.last_activity <= until,
        )

        # complete totals over all services
        active_services = (
            self.db.query(
                func.count(func.distinct(orm.ServiceActivity.service_id))
            )
            .filter(*window)
            .scalar()
        )
        activity_count = (
            self.db.query(func.count(orm.ServiceActivity.id))
            .filter(*window)
            .scalar()
        )

        # per-service counts for services in the caller's public list only
        visible = self._visible_service_ids()
        counts = {}
        if visible:
            rows = (
                self.db.query(
                    orm.ServiceActivity.service_id,
                    func.count(orm.ServiceActivity.id),
                )
                .filter(orm.ServiceActivity.service_id.in_(visible), *window)
                .group_by(orm.ServiceActivity.service_id)
            )
            for service_id, count in rows:
                counts[visible[service_id]] = int(count)
        by_service = {name: counts.get(name, 0) for name in visible.values()}

        self.write(
            json.dumps(
                {
                    "kind": "service_activity_summary",
                    "window_seconds": int((until - since).total_seconds()),
                    "since": isoformat(since),
                    "until": isoformat(until),
                    "active_services": int(active_services or 0),
                    "activity_count": int(activity_count or 0),
                    "services": by_service,
                }
            )
        )


default_handlers = [
    # aggregate statistics
    (r"/api/service-activity", ServiceActivitySummaryAPIHandler),
    (r"/api/services/activity", ServiceActivitySummaryAPIHandler),
    # per-service details, batches, and reports
    (r"/api/services/([^/]+)/activity", ServiceActivityAPIHandler),
]

"""View-level authorization for worker data.

Flower accounts fall into two tiers:

* status-only accounts may see whether a worker is online;
* detail accounts may additionally see queue topology, worker configuration
  and task payloads.

The decision is always taken from the live option value at response time, so a
result that was inspected before an authorization change is still filtered with
the permissions that apply when it reaches the caller.
"""
import logging

from .authentication import authenticate

logger = logging.getLogger(__name__)

# Inspection fields that only describe worker liveness. Everything else exposed
# by the Celery inspector (queues, configuration, task lists, statistics) is
# detail data and requires the worker details permission.
STATUS_ONLY_INSPECT_FIELDS = frozenset(('timestamp',))

# Event-state fields rendered on the workers list, all derived from worker
# heartbeats and task counters rather than task payloads or queue definitions.
STATUS_ONLY_EVENT_FIELDS = frozenset((
    'hostname', 'status', 'timestamp', 'last_heartbeat', 'heartbeats',
    'active', 'processed', 'loadavg', 'alive', 'pid', 'freq', 'clock',
    'sw_ident', 'sw_ver', 'sw_sys',
    'task-received', 'task-started', 'task-succeeded', 'task-failed',
    'task-retried', 'task-revoked',
))


def can_view_worker_details(user, detail_auth):
    """Return whether an authenticated identity may see worker detail data.

    When no detail restriction is configured every authenticated account keeps
    the historical full access. Basic-auth sessions carry no email identity and
    therefore stay status-only once a restriction is enabled.
    """
    if not detail_auth:
        return True
    if not user or user is True:
        return False
    return authenticate(detail_auth, user)


def _filter_mapping(data, allowed_fields):
    return {key: value for key, value in data.items() if key in allowed_fields}


def filter_worker_info(worker, allowed_fields):
    """Strip fields a status-only account is not allowed to read."""
    return _filter_mapping(worker, allowed_fields)


def filter_workers(workers, allowed_fields):
    """Apply :func:`filter_worker_info` to every worker in an inspect cache."""
    return {
        name: _filter_mapping(info, allowed_fields)
        for name, info in workers.items()
    }


def filter_event_workers(workers):
    """Filter the worker rows built from the event state on the list page."""
    return {
        name: _filter_mapping(info, STATUS_ONLY_EVENT_FIELDS)
        for name, info in workers.items()
    }


def log_access_decision(user, granted, resource, reason):
    """Emit an auditable record of why a worker data view was allowed or denied."""
    level = logging.INFO if granted else logging.WARNING
    logger.log(
        level,
        "worker data access %s for user=%s resource=%s reason=%s",
        'granted' if granted else 'denied',
        user,
        resource,
        reason,
    )

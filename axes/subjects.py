"""Subject-aware lockout identity and migration helpers.

Axes historically keyed lockouts on the username plus the network group of the
client IP address.  New deployments key lockouts on a registered subject
identifier such as an institution id.  During a rolling deployment both
generations of workers write records at the same time, so reads, writes and
administrative unlocks have to agree on which legacy window belongs to which
registered subject.

The helpers here keep the two representations comparable:

* a subject window holds records written with ``AccessAttempt.subject`` set;
* a legacy window holds records whose username and network group match one of
  the identities registered for the subject.

Writes are single-homed.  A subject-aware request increments the subject row;
a pre-migration request increments its username/network-group row.  Reads of a
subject evaluate the union of both representations, so each real failure is
counted once and a lockout reached before the migration is not lost.  During
the migration, ``backfill_subject_attempts`` adopts legacy rows into their
subject row in place, preserving the failure count and cool-off deadline.

This module does not import ``axes.helpers`` or ``axes.handlers`` so the
dependency direction stays one-way.
"""

from dataclasses import dataclass
from hashlib import sha256
from logging import getLogger
from typing import Iterable, List, Optional, Set

from django.db.models import Q, QuerySet
from django.utils.module_loading import import_string

from axes.conf import settings

log = getLogger(__name__)

SUBJECT_MAX_LENGTH = 128


@dataclass(frozen=True)
class LegacyIdentity:
    """A window used by pre-subject workers: username plus network group."""

    username: Optional[str] = None
    network_group: Optional[str] = None
    ip_address: Optional[str] = None

    def matches(
        self,
        username: Optional[str],
        ip_address: Optional[str],
        network_group: Optional[str],
    ) -> bool:
        if self.username is not None and self.username != username:
            return False
        if self.ip_address is not None:
            return self.ip_address == ip_address
        if self.network_group is not None:
            return self.network_group == network_group
        return True


def _load_setting(value):
    if value is None:
        return None
    if isinstance(value, str):
        return import_string(value)
    return value


def _call_with_optional_args(func, *args):
    try:
        return func(*args)
    except TypeError:
        if len(args) > 1:
            return func(*args[:1])
        raise


def _normalize_identity(value) -> Optional[LegacyIdentity]:
    if value is None:
        return None
    if isinstance(value, LegacyIdentity):
        return value
    if isinstance(value, dict):
        ip_address = value.get("ip_address")
        network_group = value.get("network_group")
        if network_group is None and ip_address is not None:
            network_group = get_network_group(ip_address)
        return LegacyIdentity(
            username=value.get("username"),
            network_group=network_group,
            ip_address=ip_address,
        )
    if isinstance(value, (tuple, list)):
        username = value[0] if len(value) > 0 else None
        network_group = value[1] if len(value) > 1 else None
        return LegacyIdentity(username=username, network_group=network_group)
    raise TypeError(
        "Subject legacy identities must be dicts, tuples or LegacyIdentity " "instances"
    )


def _normalize_identities(values) -> Set[LegacyIdentity]:
    if values is None:
        return set()
    if isinstance(values, (dict, LegacyIdentity, tuple)):
        values = [values]
    return {
        identity
        for identity in (_normalize_identity(value) for value in values)
        if identity is not None
    }


class SubjectRegistry:
    """Resolve subjects and map legacy username/network-group windows to them."""

    def __init__(self, external=None) -> None:
        self.external = external

    def legacy_identities(self, subject: Optional[str]) -> Set[LegacyIdentity]:
        if not subject:
            return set()

        if self.external is not None and hasattr(self.external, "legacy_identities"):
            values = self.external.legacy_identities(subject) or []
            return _normalize_identities(values)

        raw = _load_setting(getattr(settings, "AXES_SUBJECT_LEGACY_IDENTITIES", None))
        if callable(raw):
            raw = _call_with_optional_args(raw)
        if not isinstance(raw, dict):
            return set()
        return _normalize_identities(raw.get(subject))

    def subjects(self) -> Set[str]:
        subjects: Set[str] = set()
        if self.external is not None and hasattr(self.external, "subjects"):
            subjects.update(str(value) for value in self.external.subjects())
        raw = _load_setting(getattr(settings, "AXES_SUBJECT_LEGACY_IDENTITIES", None))
        if callable(raw):
            raw = _call_with_optional_args(raw)
        if isinstance(raw, dict):
            subjects.update(str(value) for value in raw)
        return subjects

    def subject_for_legacy(
        self,
        username: Optional[str],
        ip_address: Optional[str] = None,
        network_group: Optional[str] = None,
    ) -> Optional[str]:
        if ip_address is not None and network_group is None:
            network_group = get_network_group(ip_address)

        if self.external is not None and hasattr(self.external, "subject_for_legacy"):
            value = self.external.subject_for_legacy(
                username, ip_address, network_group
            )
            return str(value) if value is not None else None

        lookup = _load_setting(
            getattr(settings, "AXES_SUBJECT_LEGACY_LOOKUP_CALLABLE", None)
        )
        if lookup is not None:
            value = _call_with_optional_args(
                lookup, username, ip_address, network_group
            )
            return str(value) if value is not None else None

        for subject in sorted(self.subjects()):
            for identity in self.legacy_identities(subject):
                if identity.matches(username, ip_address, network_group):
                    return subject
        return None


def get_subject_registry() -> SubjectRegistry:
    external = _load_setting(getattr(settings, "AXES_SUBJECT_REGISTRY", None))
    return SubjectRegistry(external=external)


def get_network_group(ip_address: Optional[str]) -> Optional[str]:
    """Return the legacy network group for an IP address.

    Deployments that grouped addresses (for example by /24 or by a VPN pool)
    configure ``settings.AXES_SUBJECT_NETWORK_GROUP_CALLABLE``.  The default
    keeps the previous behaviour and uses the address itself.
    """

    if ip_address is None:
        return None

    network_group_callable = _load_setting(
        getattr(settings, "AXES_SUBJECT_NETWORK_GROUP_CALLABLE", None)
    )
    if network_group_callable is not None:
        value = _call_with_optional_args(network_group_callable, ip_address)
    else:
        value = ip_address
    if value is None:
        return None
    return str(value)


def _normalize_subject(value) -> Optional[str]:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    if len(value) > SUBJECT_MAX_LENGTH:
        log.warning(
            "AXES: Truncating subject of length %s to %s characters.",
            len(value),
            SUBJECT_MAX_LENGTH,
        )
        value = value[:SUBJECT_MAX_LENGTH]
    return value


def get_client_subject(request, credentials: Optional[dict] = None) -> Optional[str]:
    """Resolve the registered subject explicitly supplied by the client."""

    from axes.models import AccessBase

    if isinstance(request, AccessBase):
        return _normalize_subject(request.subject)

    subject_callable = _load_setting(getattr(settings, "AXES_SUBJECT_CALLABLE", None))
    if subject_callable is not None:
        return _normalize_subject(
            _call_with_optional_args(subject_callable, request, credentials)
        )

    value = None
    if credentials is not None:
        try:
            value = credentials.get(settings.AXES_SUBJECT_FORM_FIELD)
        except AttributeError:
            value = None

    # Authentication backends build credentials from the username and password
    # only, so the registered subject also has to be readable from the request
    # payload when it is not part of the credentials.
    if value is None:
        data = getattr(request, "data", None)
        if data is None:
            try:
                data = getattr(request, "POST", None)
            except Exception:  # noqa: BLE001 - malformed multipart bodies
                data = None
        if data is not None:
            try:
                value = data.get(settings.AXES_SUBJECT_FORM_FIELD)
            except AttributeError:
                value = None
    if value is None:
        meta = getattr(request, "META", {})
        value = meta.get("HTTP_X_AXES_SUBJECT")
    if value is None:
        value = getattr(request, "axes_subject", None)
    return _normalize_subject(value)


def get_subject_for_legacy(
    username: Optional[str], ip_address: Optional[str]
) -> Optional[str]:
    """Map a legacy username/network-group window to its registered subject."""

    if ip_address is None:
        return None
    return get_subject_registry().subject_for_legacy(
        username, ip_address, get_network_group(ip_address)
    )


# -- attempt querysets --------------------------------------------------------
def _legacy_identity_queryset(identity: LegacyIdentity) -> Optional[QuerySet]:
    from axes.models import AccessAttempt

    queryset = AccessAttempt.objects.filter(subject="")
    query = Q()
    if identity.username is not None:
        query &= Q(username=identity.username)
    if identity.ip_address is not None:
        query &= Q(ip_address=identity.ip_address)
    if query:
        queryset = queryset.filter(query)

    if identity.network_group is not None and identity.ip_address is None:
        matching = [
            attempt.pk
            for attempt in queryset.only("pk", "username", "ip_address")
            if identity.matches(
                attempt.username,
                attempt.ip_address,
                get_network_group(attempt.ip_address),
            )
        ]
        return AccessAttempt.objects.filter(pk__in=matching)

    return queryset


def subject_legacy_querysets(subject: Optional[str]) -> List[QuerySet]:
    """Legacy windows registered to ``subject`` (pre-migration records).

    The first queryset covers rows the pre-migration workers wrote for the
    subject's own username/network-group windows.  When the migration mapping
    names additional usernames for the same subject, each of those becomes a
    separate window so their counts stay separate instead of being merged.
    """

    if not subject:
        return []
    querysets = []
    for identity in sorted(
        get_subject_registry().legacy_identities(subject),
        key=lambda item: (item.username or "", item.ip_address or ""),
    ):
        queryset = _legacy_identity_queryset(identity)
        if queryset is not None:
            querysets.append(queryset)
    return querysets


def legacy_window_owned_by(
    subject: Optional[str], username: Optional[str], ip_address: Optional[str]
) -> bool:
    """Return whether the current legacy window belongs to ``subject``.

    A subject-aware worker only mirrors a failure into the username/network
    group window when that window is registered for the same subject.  Another
    subject with a coincidentally identical username keeps its own counter.
    """

    if not subject or ip_address is None:
        return False
    network_group = get_network_group(ip_address)
    return any(
        identity.matches(username, ip_address, network_group)
        for identity in get_subject_registry().legacy_identities(subject)
    )


def filter_subject_scope(subject: Optional[str]) -> QuerySet:
    """Union of every attempt window owned by ``subject``."""

    from axes.models import AccessAttempt

    if not subject:
        return AccessAttempt.objects.none()

    scope = AccessAttempt.objects.filter(subject=subject)
    for queryset in subject_legacy_querysets(subject):
        scope = scope | queryset
    return scope


def subject_attempt_querysets(subject: Optional[str]) -> List[QuerySet]:
    """One lockout window covering every row owned by ``subject``.

    Writes are single-homed: a subject-aware request increments the subject
    row, while a pre-migration worker increments its username/network-group
    row.  The two representations are disjoint, so the union counts each real
    failure exactly once.

    The union contains the registered legacy windows for the subject and
    excludes every window registered to another subject, even when usernames
    coincide.
    """

    if not subject:
        return []
    return [filter_subject_scope(subject)]


# -- cache keys ---------------------------------------------------------------
def _cache_key_for_values(values: Iterable) -> str:
    components = "".join(str(value) for value in values if value)
    digest = sha256(components.encode()).hexdigest()
    return f"axes-{digest}"


def subject_cache_keys(subject: Optional[str]) -> List[str]:
    """Cache keys for the complete subject scope.

    Only keys that are unambiguous for the subject are returned.  A
    username-only key is deliberately excluded because another subject with a
    coincidentally identical username must keep its own counter.
    """

    if not subject:
        return []

    keys = [_cache_key_for_values([subject])]
    for identity in get_subject_registry().legacy_identities(subject):
        usernames = [identity.username] if identity.username is not None else [None]
        for username in usernames:
            if username is not None:
                # The username+IP key is unambiguous even if another subject
                # shares the username, because the IP address differs.
                if identity.ip_address is not None:
                    keys.append(_cache_key_for_values([username, identity.ip_address]))
                if identity.network_group is not None:
                    keys.append(
                        _cache_key_for_values([username, identity.network_group])
                    )
            elif identity.ip_address is not None:
                keys.append(_cache_key_for_values([identity.ip_address]))
            elif identity.network_group is not None:
                keys.append(_cache_key_for_values([identity.network_group]))
    return list(dict.fromkeys(keys))


# -- migration ---------------------------------------------------------------
def backfill_subject_attempts(subject: Optional[str] = None) -> int:
    """Adopt pre-migration records into their subject window.

    Each legacy row is renamed in place: only ``subject`` changes.  The failure
    count and ``attempt_time`` are preserved, so a subject that already reached
    the threshold keeps both its count and its cool-off deadline.

    The row stays the same row the pre-migration code used, so old workers keep
    finding it through their username/network-group lookups.  Because the update
    is filtered on ``subject=""`` the command is idempotent, and a row can only
    be adopted by the subject it is registered to; another subject with a
    coincidentally identical username keeps its own rows.
    """

    from axes.models import AccessAttempt

    subjects = [subject] if subject else sorted(get_subject_registry().subjects())
    migrated = 0

    for current_subject in subjects:
        identities = get_subject_registry().legacy_identities(current_subject)
        if not identities:
            continue
        for legacy in AccessAttempt.objects.filter(subject="").order_by("pk"):
            network_group = get_network_group(legacy.ip_address)
            if not any(
                identity.matches(legacy.username, legacy.ip_address, network_group)
                for identity in identities
            ):
                continue

            owner = get_subject_registry().subject_for_legacy(
                legacy.username, legacy.ip_address, network_group
            )
            if owner is not None and owner != current_subject:
                continue

            migrated += AccessAttempt.objects.filter(pk=legacy.pk, subject="").update(
                subject=current_subject
            )

    if migrated:
        log.info("AXES: Adopted %d legacy windows into their subject.", migrated)
    return migrated


# -- failure event identity ---------------------------------------------------
def get_failure_event_key(request, credentials: Optional[dict] = None) -> Optional[str]:
    """Return the idempotency key that identifies one failed login event.

    The key is shared by every worker that observes the same failure, which
    makes a dual write or a backfill count exactly once.
    """

    value = None
    event_callable = _load_setting(
        getattr(settings, "AXES_FAILURE_EVENT_ID_CALLABLE", None)
    )
    if event_callable is not None:
        value = _call_with_optional_args(event_callable, request, credentials)
    else:
        data = credentials
        if data is None:
            data = getattr(request, "data", None)
        if data is None:
            try:
                data = getattr(request, "POST", None)
            except Exception:  # noqa: BLE001 - malformed multipart bodies
                data = None
        if data is not None:
            try:
                value = data.get(settings.AXES_FAILURE_EVENT_ID_FIELD)
            except AttributeError:
                value = None
        if value is None:
            meta = getattr(request, "META", {})
            value = meta.get("HTTP_X_AXES_FAILURE_ID")
        if value is None:
            value = meta.get("HTTP_X_REQUEST_ID")
        if value is None:
            value = getattr(request, "axes_failure_event_id", None)

    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    if len(value) > 64:
        value = sha256(value.encode()).hexdigest()
    return value

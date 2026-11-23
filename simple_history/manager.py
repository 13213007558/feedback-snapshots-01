import datetime

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.db.models import Exists, OuterRef, Q, QuerySet
from django.db.models.functions import Coalesce
from django.utils import timezone

from simple_history.utils import (
    get_app_model_primary_key_name,
    get_change_reason_from_object,
    get_history_recorded_at,
)

# when converting a historical record to an instance, this attribute is added
# to the instance so that code can reverse the instance to its historical record
SIMPLE_HISTORY_REVERSE_ATTR_NAME = "_history"

# Sort key used in place of an unknown (NULL) `history_recorded_at` so that
# rows with a known entry time always sort after legacy rows. Any real
# recorded time is assigned by the trusted recording clock, which never
# produces values this old.
UNKNOWN_RECORDED_AT_SENTINEL = datetime.datetime(1970, 1, 1)


def _recorded_at_sentinel():
    if settings.USE_TZ:
        return UNKNOWN_RECORDED_AT_SENTINEL.replace(tzinfo=datetime.timezone.utc)
    return UNKNOWN_RECORDED_AT_SENTINEL


class HistoricalQuerySet(QuerySet):
    """
    Enables additional functionality when working with historical records.

    For additional history on this topic, see:
        - https://github.com/django-commons/django-simple-history/pull/229
        - https://github.com/django-commons/django-simple-history/issues/354
        - https://github.com/django-commons/django-simple-history/issues/397
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._as_instances = False
        self._as_of = None
        self._pk_attr = self.model.instance_type._meta.pk.attname

    def as_instances(self) -> "HistoricalQuerySet":
        """
        Return a queryset that generates instances instead of historical records.
        Queries against the resulting queryset will translate `pk` into the
        primary key field of the original type.
        """
        if not self._as_instances:
            result = self.exclude(history_type="-")
            result._as_instances = True
        else:
            result = self._clone()
        return result

    def filter(self, *args, **kwargs) -> "HistoricalQuerySet":
        """
        If a `pk` filter arrives and the queryset is returning instances
        then the caller actually wants to filter based on the original
        type's primary key, and not the history_id (historical record's
        primary key); this happens frequently with DRF.
        """
        if self._as_instances and "pk" in kwargs:
            kwargs[self._pk_attr] = kwargs.pop("pk")
        return super().filter(*args, **kwargs)

    def latest_of_each(self) -> "HistoricalQuerySet":
        """
        Ensures results in the queryset are the latest historical record for each
        primary key. This includes deletion records.
        """
        if hasattr(self.model, "history_recorded_at"):
            return self._latest_of_each_bitemporal()
        # Subquery for finding the records that belong to the same history-tracked
        # object as the record from the outer query (identified by `_pk_attr`),
        # and that have a later `history_date` than the outer record.
        # The very latest record of a history-tracked object should be excluded from
        # this query - which will make it included in the `~Exists` query below.
        later_records = self.filter(
            Q(**{self._pk_attr: OuterRef(self._pk_attr)}),
            Q(history_date__gt=OuterRef("history_date")),
        )

        # Filter the records to only include those for which the `later_records`
        # subquery does not return any results.
        return self.filter(~Exists(later_records))

    def _latest_of_each_bitemporal(self) -> "HistoricalQuerySet":
        """
        Bitemporal variant of ``latest_of_each()`` with a deterministic order
        when several records share the same business-effective time
        (``history_date``): the record that entered the audit store later wins,
        records with an unknown (NULL) recorded time lose to any known one, and
        the history primary key is the final tie-breaker.
        """
        history_pk_attr = self.model._meta.pk.attname
        queryset = self.annotate(
            _recorded_at_sort=Coalesce("history_recorded_at", _recorded_at_sentinel())
        )
        same_effective_time = Q(history_date=OuterRef("history_date"))
        later_records = queryset.filter(
            Q(**{self._pk_attr: OuterRef(self._pk_attr)}),
            Q(history_date__gt=OuterRef("history_date"))
            | (
                same_effective_time
                & Q(_recorded_at_sort__gt=OuterRef("_recorded_at_sort"))
            )
            | (
                same_effective_time
                & Q(_recorded_at_sort=OuterRef("_recorded_at_sort"))
                & Q(**{f"{history_pk_attr}__gt": OuterRef(history_pk_attr)})
            ),
        )
        return queryset.filter(~Exists(later_records))

    def as_of_recorded(self, date, *, include_unknown=True) -> "HistoricalQuerySet":
        """
        Return the historical records the audit store actually contained at
        ``date`` -- i.e. filtered by ``history_recorded_at`` (when each row
        truly entered the audit store), not by the business-effective
        ``history_date``.

        Rows whose entry time is unknown (``history_recorded_at`` is NULL,
        e.g. legacy data that predates bitemporal tracking) are included by
        default: they are known to exist now, but no entry time may be
        fabricated for them. Pass ``include_unknown=False`` to restrict the
        result to rows with a known entry time.
        """
        if not hasattr(self.model, "history_recorded_at"):
            raise ImproperlyConfigured(
                "%s has no `history_recorded_at` field; audit-time queries "
                "require `HistoricalRecords(bitemporal=True)`."
                % self.model._meta.object_name
            )
        known = Q(history_recorded_at__lte=date)
        if include_unknown:
            known |= Q(history_recorded_at__isnull=True)
        return self.filter(known)

    def _select_related_history_tracked_objs(self) -> "HistoricalQuerySet":
        """
        A convenience method that calls ``select_related()`` with all the names of
        the model's history-tracked ``ForeignKey`` fields.
        """
        field_names = [
            field.name
            for field in self.model.tracked_fields
            if isinstance(field, models.ForeignKey)
        ]
        return self.select_related(*field_names)

    def _clone(self) -> "HistoricalQuerySet":
        c = super()._clone()
        c._as_instances = self._as_instances
        c._as_of = self._as_of
        c._pk_attr = self._pk_attr
        return c

    def _fetch_all(self) -> None:
        super()._fetch_all()
        self._instanceize()

    def _instanceize(self) -> None:
        """
        Convert the result cache to instances if possible and it has not already been
        done.  If a query extracts `.values(...)` then the result cache will not contain
        historical objects to be converted.
        """
        if (
            self._result_cache
            and self._as_instances
            and isinstance(self._result_cache[0], self.model)
        ):
            self._result_cache = [item.instance for item in self._result_cache]
            for item in self._result_cache:
                historic = getattr(item, SIMPLE_HISTORY_REVERSE_ATTR_NAME)
                setattr(historic, "_as_of", self._as_of)


class HistoryManager(models.Manager):
    def __init__(self, model, instance=None):
        super().__init__()
        self.model = model
        self.instance = instance

    def get_super_queryset(self):
        return super().get_queryset()

    def get_queryset(self):
        qs = self.get_super_queryset()
        if self.instance is None:
            return qs

        key_name = get_app_model_primary_key_name(self.instance)
        return self.get_super_queryset().filter(**{key_name: self.instance.pk})

    def most_recent(self):
        """
        Returns the most recent copy of the instance available in the history.
        """
        if not self.instance:
            raise TypeError(
                "Can't use most_recent() without a {} instance.".format(
                    self.model._meta.object_name
                )
            )
        tmp = []

        for field in self.model.tracked_fields:
            if isinstance(field, models.ForeignKey):
                tmp.append(field.name + "_id")
            else:
                tmp.append(field.name)
        fields = tuple(tmp)
        try:
            values = self.get_queryset().values(*fields)[0]
        except IndexError:
            raise self.instance.DoesNotExist(
                "%s has no historical record." % self.instance._meta.object_name
            )
        return self.instance.__class__(**values)

    def as_of(self, date):
        """
        Get a snapshot as of a specific date.

        When this is used on an instance, it will return the instance based
        on the specific date.  If the instance did not exist yet, or had been
        deleted, then a DoesNotExist error is railed.

        When this is used on a model's history manager, the resulting queryset
        will locate the most recent historical record before the specified date
        for each primary key, generating instances.  If the most recent historical
        record is a deletion, that instance is dropped from the result.

        A common usage pattern for querying is to accept an optional time
        point `date` and then use:

            `qs = <Model>.history.as_of(date) if date else <Model>.objects`

        after which point one can add filters, values - anything a normal
        queryset would support.

        To retrieve historical records, query the model's history directly;
        for example:
            `qs = <Model>.history.filter(history_date__lte=date, pk=...)`

        To retrieve the most recent historical record, including deletions,
        you could then use:
            `qs = qs.latest_of_each()`
        """
        queryset = self.get_queryset().filter(history_date__lte=date)
        if not self.instance:
            if isinstance(queryset, HistoricalQuerySet):
                queryset._as_of = date
            queryset = queryset.latest_of_each().as_instances()
            return queryset

        try:
            # historical records are sorted in reverse chronological order
            history_obj = queryset[0]
        except IndexError:
            raise self.instance.DoesNotExist(
                "%s had not yet been created." % self.instance._meta.object_name
            )
        if history_obj.history_type == "-":
            raise self.instance.DoesNotExist(
                "%s had already been deleted." % self.instance._meta.object_name
            )
        result = history_obj.instance
        historic = getattr(result, SIMPLE_HISTORY_REVERSE_ATTR_NAME)
        setattr(historic, "_as_of", date)
        return result

    def audit_as_of(self, date, *, include_unknown=True):
        """
        Reconstruct the version(s) the system actually held at a specific
        moment, based on when records truly entered the audit store
        (``history_recorded_at``) rather than when they took effect
        (``history_date``).

        Among the records known at ``date``, the latest one per primary key is
        selected by business-effective time (with the deterministic bitemporal
        tie-breaking of ``latest_of_each()``). Rows with an unknown (NULL)
        entry time are treated as known since before any auditable moment and
        are therefore included unless ``include_unknown=False``.

        Like ``as_of()``, this returns a queryset of instances when used on a
        model's history manager, and a single instance (or raises
        ``DoesNotExist``) when used on an instance.
        """
        queryset = self.get_queryset().as_of_recorded(
            date, include_unknown=include_unknown
        )
        if not self.instance:
            return queryset.latest_of_each().as_instances()

        try:
            # historical records are sorted by effective time, then recorded
            # time (unknown last), then history_id
            history_obj = queryset[0]
        except IndexError:
            raise self.instance.DoesNotExist(
                "%s had not yet been recorded." % self.instance._meta.object_name
            )
        if history_obj.history_type == "-":
            raise self.instance.DoesNotExist(
                "%s had already been deleted." % self.instance._meta.object_name
            )
        return history_obj.instance

    def bulk_history_create(
        self,
        objs,
        batch_size=None,
        update=False,
        default_user=None,
        default_change_reason="",
        default_date=None,
        custom_historical_attrs=None,
    ):
        """
        Bulk create the history for the objects specified by objs.
        If called by bulk_update_with_history, use the update boolean and
        save the history_type accordingly.
        """
        if not getattr(settings, "SIMPLE_HISTORY_ENABLED", True):
            return

        history_type = "+"
        if update:
            history_type = "~"

        # All rows of a controlled bulk import share one recorded-at boundary,
        # assigned by the trusted recording side -- the same rule regular saves
        # follow. If the import's transaction rolls back, none of these rows
        # persist, so a failed import is never queryable as recorded.
        has_recorded_at = hasattr(self.model, "history_recorded_at")
        recorded_at = get_history_recorded_at() if has_recorded_at else None

        historical_instances = []
        for instance in objs:
            history_user = getattr(
                instance,
                "_history_user",
                default_user or self.model.get_default_history_user(instance),
            )
            row = self.model(
                history_date=getattr(
                    instance, "_history_date", default_date or timezone.now()
                ),
                history_user=history_user,
                history_change_reason=get_change_reason_from_object(instance)
                or default_change_reason,
                history_type=history_type,
                **{
                    field.attname: getattr(instance, field.attname)
                    for field in self.model.tracked_fields
                },
                **(custom_historical_attrs or {}),
            )
            if hasattr(self.model, "history_relation"):
                row.history_relation_id = instance.pk
            if has_recorded_at:
                # Set after construction so caller-supplied attributes
                # (e.g. via `custom_historical_attrs`) cannot override it.
                row.history_recorded_at = recorded_at
            historical_instances.append(row)

        return self.model.objects.bulk_create(
            historical_instances, batch_size=batch_size
        )


class HistoryDescriptor:
    def __init__(self, model, manager=HistoryManager, queryset=HistoricalQuerySet):
        self.model = model
        self.queryset_class = queryset
        self.manager_class = manager

    def __get__(self, instance, owner):
        return self.manager_class.from_queryset(self.queryset_class)(
            self.model, instance
        )

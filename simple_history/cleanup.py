"""Pluggable policies for the ``clean_old_history`` management command.

A retention policy decides which historical records that are older than the
configured retention window may actually be deleted.  Records that still have
to be kept (for example because the corresponding object is under a compliance
freeze) are returned with a human-readable reason so that dry runs can explain
why they are protected.
"""

from collections import namedtuple

ProtectedRecord = namedtuple("ProtectedRecord", ["record", "reason"])


class HistoryCleanupPolicy:
    """Base class for ``clean_old_history`` retention policies.

    Subclass it and implement :meth:`protect_reason`.  Return ``None`` when the
    historical record may be deleted, or a short human-readable string
    explaining why the record has to be kept.
    """

    def protect_reason(self, history_record):
        """Return the reason the record is protected, or ``None``.

        :param history_record: An instance of the model's historical model.
        :return: A string with the protection reason, or ``None`` when the
            record is allowed to be cleaned up.
        """
        raise NotImplementedError

    def partition(self, history_queryset):
        """Split a queryset of expired records into deletable and protected.

        The policy is evaluated for every record at call time, so rerunning a
        failed cleanup always applies the protection rules currently in force.

        :param history_queryset: A queryset of historical records that are
            older than the retention window.
        :return: A tuple ``(protected, deletable)`` where ``protected`` is a
            list of :class:`ProtectedRecord` and ``deletable`` is a list of
            primary keys of records that may be deleted.
        """
        protected = []
        deletable = []
        for record in history_queryset:
            reason = self.protect_reason(record)
            if reason is None:
                deletable.append(record.pk)
            else:
                protected.append(ProtectedRecord(record=record, reason=reason))
        return protected, deletable

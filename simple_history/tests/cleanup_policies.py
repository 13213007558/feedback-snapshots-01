"""Retention policies used by the ``clean_old_history`` test suite."""

from django.db import router

from simple_history.cleanup import HistoryCleanupPolicy


class ComplianceFreezePolicy(HistoryCleanupPolicy):
    """Keeps every historical record of a compliance-frozen object."""

    def protect_reason(self, history_record):
        instance_type = history_record.instance_type
        object_id = getattr(history_record, instance_type._meta.pk.attname)
        # The historical table can live in a different database than the
        # tracked model, so let the router pick the right alias.
        db_alias = router.db_for_read(instance_type)
        try:
            live_object = instance_type.objects.using(db_alias).get(pk=object_id)
        except instance_type.DoesNotExist:
            # The object was deleted: fall back to the state captured by this
            # historical record itself.
            live_object = None

        if live_object is not None:
            frozen = live_object.compliance_frozen
            reason = live_object.freeze_reason
        else:
            snapshot = history_record.history_object
            frozen = snapshot.compliance_frozen
            reason = snapshot.freeze_reason

        if frozen:
            return reason or "Object is under a compliance freeze"
        return None

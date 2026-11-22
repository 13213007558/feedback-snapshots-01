Utils
=====


clean_duplicate_history
-----------------------

For performance reasons, ``django-simple-history`` always creates an ``HistoricalRecord``
when ``Model.save()`` is called regardless of data having actually changed.
If you find yourself with a lot of history duplicates you can schedule the
``clean_duplicate_history`` command

.. code-block:: bash

    $ python manage.py clean_duplicate_history --auto

You can use ``--auto`` to clean up duplicates for every model
with ``HistoricalRecords`` or enumerate specific models as args.
There is also ``-m/--minutes`` to specify how many minutes to go
back in history while searching (default checks whole history),
so you can schedule, for instance, an hourly cronjob such as

.. code-block:: bash

    $ python manage.py clean_duplicate_history -m 60 --auto

You can also use ``--excluded_fields`` to provide a list of fields to be excluded
from the duplicate check

.. code-block:: bash

    $ python manage.py clean_duplicate_history --auto --excluded_fields field1 field2

You can use Django's base manager to perform the cleanup over all records,
including those that would otherwise be filtered or modified by a
custom manager, by using the ``--base-manager`` flag.

.. code-block:: bash

    $ python manage.py clean_duplicate_history --auto --base-manager

clean_old_history
-----------------------

You may want to remove historical records that have existed for a certain amount of time.

If you find yourself with a lot of old history you can schedule the
``clean_old_history`` command

.. code-block:: bash

    $ python manage.py clean_old_history --auto

You can use ``--auto`` to remove old historical entries
with ``HistoricalRecords`` or enumerate specific models as args.
You may also specify a  ``--days`` parameter, which indicates how many
days of records you want to keep. The default it 30 days, meaning that
all records older than 30 days would be removed.

.. code-block:: bash

    $ python manage.py clean_old_history --days 60 --auto

Retention policies
^^^^^^^^^^^^^^^^^^

Some historical records must be kept even when they are older than the
retention window - for example archives belonging to an object that is under
a compliance freeze.  Pass ``--policy`` with the dotted path of a
``HistoryCleanupPolicy`` subclass to decide which expired records are
protected and why:

.. code-block:: python

    from simple_history.cleanup import HistoryCleanupPolicy


    class ComplianceFreezePolicy(HistoryCleanupPolicy):
        def protect_reason(self, history_record):
            instance = history_record.history_object
            if instance.compliance_frozen:
                return instance.freeze_reason or "Object is under a compliance freeze"
            return None

``protect_reason()`` is called for every expired record.  Returning ``None``
allows the record to be deleted; returning a string keeps the record and uses
the string as the protection reason.

.. code-block:: bash

    $ python manage.py clean_old_history --auto --policy myapp.cleanup.ComplianceFreezePolicy

A dry run (``--dry``) never deletes anything and prints one
``Protecting historical record ...`` line per protected record, including the
reason returned by the policy, followed by a summary of how many records were
kept.  Protected records are excluded from the deletion queryset, so they can
never be removed by the command.  Each run evaluates the policy against the
rules currently in force, which makes rerunning a failed cleanup safe: records
that have since become unfrozen become eligible, while any record that is
still frozen stays untouched.

If the historical table lives in another database, select it with
``--database``:

.. code-block:: bash

    $ python manage.py clean_old_history --auto --database other --policy myapp.cleanup.ComplianceFreezePolicy

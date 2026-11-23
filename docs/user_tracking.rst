User Tracking
=============


Recording Which User Changed a Model
------------------------------------
There are four documented ways to attach users to a tracked change:

1. Use the ``HistoryRequestMiddleware``. The middleware sets the
User instance that made the request as the ``history_user`` on the history
table.

2. Use ``simple_history.admin.SimpleHistoryAdmin``. Under the hood,
``SimpleHistoryAdmin`` actually sets the ``_history_user`` on the object to
attach the user to the tracked change by overriding the `save_model` method.

3. Assign a user to the ``_history_user`` attribute of the object as described
in the `_history_user section`_.

4. Track the user using an explicit ``history_user_id``, which is described in
`Manually Track User Model`_. This method is particularly useful when using multiple
databases (where your user model lives in a separate database to your historical model),
or when using a user that doesn't live within the Django app (i.e. a user model retrieved
from an API).

.. _`_history_user section`:

Using ``_history_user`` to Record Which User Changed a Model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To denote which user changed a model, assign a ``_history_user`` attribute on
your model.

For example if you have a ``changed_by`` field on your model that records which
user last changed the model, you could create a ``_history_user`` property
referencing the ``changed_by`` field:

.. code-block:: python

    from django.db import models
    from simple_history.models import HistoricalRecords

    class Poll(models.Model):
        question = models.CharField(max_length=200)
        pub_date = models.DateTimeField('date published')
        changed_by = models.ForeignKey('auth.User')
        history = HistoricalRecords()

        @property
        def _history_user(self):
            return self.changed_by

        @_history_user.setter
        def _history_user(self, value):
            self.changed_by = value

Admin integration requires that you use a ``_history_user.setter`` attribute with
your custom ``_history_user`` property (see :doc:`/admin`).

Another option for identifying the change user is by providing a function via ``get_user``.
If provided it will be called every time that the ``history_user`` needs to be
identified with the following key word arguments:

* ``instance``:  The current instance being modified
* ``request``:  If using the middleware the current request object will be provided if they are authenticated.

This is very helpful when using ``register``:

.. code-block:: python

    from django.db import models
    from simple_history.models import HistoricalRecords

    class Poll(models.Model):
        question = models.CharField(max_length=200)
        pub_date = models.DateTimeField('date published')
        changed_by = models.ForeignKey('auth.User')


    def get_poll_user(instance, **kwargs):
        return instance.changed_by

    register(Poll, get_user=get_poll_user)


.. _`Manually Track User Model`:


Manually Track User Model
~~~~~~~~~~~~~~~~~~~~~~~~~

Although ``django-simple-history`` tracks the ``history_user`` (the user who changed the
model) using a django foreign key, there are instances where we might want to track this
user but cannot use a Django foreign key.

**Note:** If you want to track a custom user model that is still accessible through a
Django foreign key, refer to `Change User Model`_.

The two most common cases where this feature will be helpful are:

1. You are working on a Django app with multiple databases, and your history table
   is in a separate database from the user table.

2. The user model that you want to use for ``history_user`` does not live within the
   Django app, but is only accessible elsewhere (i.e. through an API call).

There are three parameters to ``HistoricalRecords`` or ``register`` that facilitate
the ability to manually track a ``history_user``.


:history_user_id_field: An instance of field (i.e. ``IntegerField(null=True)`` or
    ``UUIDField(default=uuid.uuid4, null=True)`` that will uniquely identify your user
    object. This is generally the field type of the primary key on your user object.

:history_user_getter: *optional*. A callable that takes the historical instance of the
    model and returns the ``history_user`` object. The default getter is shown below:

.. code-block:: python

    def _history_user_getter(historical_instance):
        if historical_instance.history_user_id is None:
            return None
        User = get_user_model()
        try:
            return User.objects.get(pk=historical_instance.history_user_id)
        except User.DoesNotExist:
            return None


:history_user_setter: *optional*. A callable that takes the historical instance and
    the user instance, and sets ``history_user_id`` on the historical instance. The
    default setter is shown below:

.. code-block:: python

    def _history_user_setter(historical_instance, user):
        if user is not None:
            historical_instance.history_user_id = user.pk


.. _`Change User Model`:

Change User Model
-----------------

If you need to use a different user model then ``settings.AUTH_USER_MODEL``,
pass in the required model to ``user_model``.  Doing this requires ``_history_user``
or ``get_user`` is provided as detailed above.

.. code-block:: python

    from django.db import models
    from simple_history.models import HistoricalRecords

    class PollUser(models.Model):
        user_id = models.ForeignKey('auth.User')


    # Only PollUsers should be modifying a Poll
    class Poll(models.Model):
        question = models.CharField(max_length=200)
        pub_date = models.DateTimeField('date published')
        changed_by = models.ForeignKey(PollUser)
        history = HistoricalRecords(user_model=PollUser)

        @property
        def _history_user(self):
            return self.changed_by

        @_history_user.setter
        def _history_user(self, value):
            self.changed_by = value


.. _pseudonymizing_history_users:

Pseudonymizing Historical Users
-------------------------------

When a person leaves the organization, the historical rows that reference their
account must stop pointing at it -- but audits still need to show that the same
anonymous subject performed several operations. ``django-simple-history``
provides a controlled, one-way pseudonymization for that case.

Configure a secret outside the database first:

.. code-block:: python

    # settings.py
    SIMPLE_HISTORY_PSEUDONYM_SECRET = "a long random value kept outside the DB"

Then sever an account from a model's history:

.. code-block:: python

    from myapp.models import Approval

    result = Approval.history.anonymize_user(user=departed_user)
    result.pseudonymized          # rows changed by this batch
    result.already_pseudonymized  # rows already carrying the same pseudonym
    result.pseudonym              # stable, keyed digest for the anonymous subject

Every historical model has a ``history_user_pseudonym`` field. Severing a link
performs an in-place update that:

* clears the identity column (``history_user_id`` or the configured
  ``history_user_id_field``) for the matching rows;
* stores an HMAC-SHA256 digest of the identity in ``history_user_pseudonym``;
* leaves ``history_date``, ``history_type`` and all tracked field values intact.

The pseudonym is keyed and namespaced, so the same person can have different
pseudonyms in different audit scopes and an old pseudonym cannot be re-derived
without the secret. The database alone never contains enough information to
recover the account.

Reading history after severing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once a row carries a pseudonym:

* ``record.history_user`` returns ``None`` and does not query the user table.
  This applies to both the default foreign key and project-supplied
  ``history_user_getter`` callables.
* ``record.is_pseudonymized`` is ``True``.
* ``record.get_history_user_label()`` returns a short public label such as
  ``pseudonym:239d0af813e0`` that is safe to show in the admin history list.
* ``record.history_user_id`` is ``None``, so filters such as
  ``Model.history.filter(history_user=user)`` no longer match the row.

``as_of`` queries and ordinary history views read only what is stored on each
row, so a severed row never resolves back to the account even when the account
row still exists.

External and application-managed identities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Models that use ``history_user_id_field`` (for example an identity managed by an
external service) are handled the same way. When the external account no longer
exists, use the identity value directly. If one person is known under several
identifiers, pass ``subject`` so they share a pseudonym:

.. code-block:: python

    Record.history.anonymize_user(identity="ext-account-17")

    Record.history.anonymize_user(
        identities=["ext-account-17", "legacy-42"],
        subject="person-17",
    )

The batch only selects rows whose identity matches the given values. An unknown
identity changes nothing, and a custom ``history_user_getter`` is never called
for a severed row, so no false association can be produced.

Batching, retries and legacy rows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``anonymize_user`` accepts ``watermark`` (an exclusive upper bound on
``history_id``) and ``cutoff`` (an inclusive upper bound on ``history_date``) to
define exactly which rows a batch may touch. Rows created while a batch is
running -- with a higher ``history_id`` -- are outside the watermark and keep
their account link until a later batch includes them. ``dry_run=True`` reports
the same counts without writing.

Repeating a batch is safe: rows already carrying the derived pseudonym are
counted in ``already_pseudonymized`` and are not rewritten. If an identity-bearing
row already carries a *different* pseudonym, the batch raises
``PseudonymizationConflict`` instead of merging two anonymous subjects. Legacy
rows with neither an identity nor a pseudonym are left untouched, so a partial or
failed run never invents history.

The whole update runs in a single transaction. If the transaction rolls back,
both the historical rows and the user accounts are unchanged, and a retry can
sever exactly the same rows.

To make this available from the command line:

.. code-block:: shell

    python manage.py anonymize_history app.Model \
        --user-id 42 --namespace approvals --dry-run

    python manage.py anonymize_history app.Model \
        --identity ext-account-17 --identity legacy-42 --subject person-17

Use ``--auto`` to process every registered model that has a history manager.

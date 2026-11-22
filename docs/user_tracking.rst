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


Attributing History from Background Tasks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``HistoryRequestMiddleware`` is only appropriate for web requests. Background
work such as imports or management commands has no request, and its executor is
usually a service identity rather than a person. Use
``simple_history.attribution.history_user_context`` to declare the author for
the work inside a block:

.. code-block:: python

    from simple_history.attribution import history_user_context

    author = approval.approved_by if approval else service_account
    with history_user_context(user=service_account, approver=author):
        import_rows()

``user`` is the identity executing the task. If ``approver`` is supplied, the
approver is recorded as ``history_user`` instead, and the context yields that
effective author. Inside the block, records resolve their author in this order:

1. an explicit ``instance._history_user``
2. the author declared by ``history_user_context``
3. the authenticated user from ``HistoryRequestMiddleware``
4. the model's ``get_user`` callable

The task context therefore never changes how ordinary requests are attributed:
it is opt-in, and it takes precedence only while the block is active. When the
block exits, the declared author is removed from the current thread or async
task, even if the block raises, so a later request cannot inherit it:

.. code-block:: python

    with history_user_context(user=service_account, approver=author):
        import_rows()

    # No task author remains here; the next request uses its own user.
    handle_request()

Because the value is stored with ``asgiref.local.Local``, concurrent threads and
async tasks each see only the author they declared. Bulk helpers
(``bulk_create_with_history`` and ``bulk_update_with_history``) also honor the
context when no ``default_user`` is passed.


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

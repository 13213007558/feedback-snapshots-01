Per-field retention (``SESSION_FIELD_TTL``)
===========================================

Sometimes a single session field needs a shorter life than the rest of the
session. A customer-service flow may, for example, keep a contact detail in the
session just long enough to pre-fill the next form, while the login state and
the user's page preferences must remain available for the whole session.

``SESSION_FIELD_TTL`` gives individual session keys their own, *absolute*
retention period that is independent of the session-wide
``PERMANENT_SESSION_LIFETIME``.

Configuration
-------------

Map each session key to a lifetime, either as an integer number of seconds or a
:class:`datetime.timedelta`::

    from datetime import timedelta

    app.config["SESSION_FIELD_TTL"] = {
        "contact_info": timedelta(seconds=60),
        "one_time_token": 30,
    }

Only the listed keys are tracked. Any other key (``user_id``, ``theme``, ...)
behaves exactly as before and lives as long as the surrounding session.

How the timer behaves
---------------------

* The timer starts when the application **writes** the field
  (``flask.session["contact_info"] = ...``).
* Writing the same field again restarts only that field's timer.
* Reading the field does **not** extend it.
* Renewing the storage record or the session cookie (the normal
  ``SESSION_REFRESH_EACH_REQUEST`` behaviour) does **not** extend it either:
  the deadline is an absolute timestamp fixed at write time.
* Once the deadline passes, the field (and its expiry entry) are removed the
  next time the session is opened, and the pruned payload is written back to
  storage.

Because retention is enforced inside Flask-Session rather than by the storage
backend, it works identically with every supported backend. The per-field
deadlines are persisted inside the serialized session record under a reserved
``_field_expiry`` key; this key is added automatically just before saving and
stripped immediately after loading, so it never appears in ``flask.session``.

Worked example
--------------

A runnable, self-contained demonstration lives at
``examples/per_field_ttl.py``. It drives a real CacheLib ``FileSystemCache``
with a controllable fake clock and prints the outcome at three points after the
short-lived field expires:

1. **Business reads** - ``flask.session.get("contact_info")`` returns ``None``,
   while ``user_id`` and ``theme`` are still present.
2. **Serialized record** - the on-disk record no longer contains the field and
   its entry has disappeared from the embedded expiry table.
3. **Cookie/storage renewal** - the CacheLib record TTL is refreshed back to the
   full session lifetime and the cookie is re-emitted, yet the field remains
   expired because its deadline was fixed when it was first written.

Run it from the project root::

    python examples/per_field_ttl.py

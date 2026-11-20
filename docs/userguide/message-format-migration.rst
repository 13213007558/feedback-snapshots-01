.. _guide-message-format-migration:

=========================================
 Migrating Task Messages to a New Format
=========================================

This guide describes a phased migration from a legacy task-message encoding
to one approved encoding, using Kombu's serializer registry, producer
``serializer`` option, and consumer ``accept`` option.  It also states which
switches apply to a whole process and which can be limited to a single
integration.

Kombu does not provide a broker-wide schema registry or a single global
"only this format" switch.  Correctness therefore depends on deploying the
consumer switch before the producer switch, and on checking the resulting
wire format at each phase.

Test messages
=============

The two messages below are ordinary, public test data.  They contain no
credentials, hostnames, or customer content.  Both describe the same logical
task; only the wire format and the ``schema`` field differ.

Approved format (compact JSON, UTF-8)
-------------------------------------

.. code-block:: json

    {"schema":"task.v2","task_id":"T-1001","action":"echo","payload":{"text":"hello"}}

On the wire this is published with ``content_type``
``application/json`` and ``content_encoding`` ``utf-8``.  If the approved
format uses a dedicated serializer registration, use its own distinct MIME
type instead, for example ``application/vnd.example.task.v2+json``.

Legacy format (pickle protocol 4, binary)
-----------------------------------------

.. code-block:: text

    gASVVwAAAAAAAAB9lCiMBnNjaGVtYZSMB3Rhc2sudjGUjAd0YXNrX2lklIwGVC0x
    MDAxlIwGYWN0aW9ulIwEZWNob5SMB3BheWxvYWSUfZSMBHRleHSUjAVoZWxsb5Rz
    dS4=

The bytes decode to the same logical object, with ``schema`` set to
``task.v1``:

.. code-block:: python

    import base64, pickle
    old = pickle.loads(base64.b64decode(
        'gASVVwAAAAAAAAB9lCiMBnNjaGVtYZSMB3Rhc2sudjGUjAd0YXNrX2lklIwG'
        'VC0xMDAxlIwGYWN0aW9ulIwEZWNob5SMB3BheWxvYWSUfZSMBHRleHSUjAVo'
        'ZWxsb5RzdS4='
    ))
    assert old == {
        'schema': 'task.v1', 'task_id': 'T-1001', 'action': 'echo',
        'payload': {'text': 'hello'},
    }

It is published with ``content_type``
``application/x-python-serialize`` and ``content_encoding`` ``binary``.
The encoded body is Python-specific and is not safe to decode from an
untrusted publisher.

The executable version of these criteria lives in
``t/unit/test_serialization_migration.py``.

The two independent switches
============================

Encoding: the serializer registry and producer
----------------------------------------------

Serializers are registered process-wide in
``kombu.serialization.registry``:

.. code-block:: python

    from kombu.serialization import register, unregister

    register(
        'task_v2',
        encoder=my_json_dumps,
        decoder=my_json_loads,
        content_type='application/vnd.example.task.v2+json',
        content_encoding='utf-8',
    )

Registration is global to the Python process.  Every worker that must
*encode* or *decode* the new format needs this registration, normally at
application startup.  Registration is not propagated through the broker.

Producers choose the encoder per instance or per publish call:

.. code-block:: python

    producer = Producer(connection, serializer='task_v2')   # instance default
    producer.publish(task, routing_key='tasks')             # uses task_v2

    producer.publish(task, routing_key='tasks',             # per-call override
                     serializer='task_v2')

Kombu has no encoder allow-list.  ``Producer`` accepts any registered
serializer, and ``publish(..., content_type=...)`` skips serialization
entirely.  A process-wide decoder restriction therefore does **not** stop a
producer from emitting the legacy format.  New producers must enforce the
approved format in application code, ideally in one publish helper or
producer factory:

.. code-block:: python

    APPROVED = {'task_v2'}

    def publish_task(producer, body, **kwargs):
        serializer = kwargs.setdefault('serializer', 'task_v2')
        if serializer not in APPROVED:
            raise ValueError(f'serializer not approved: {serializer}')
        if 'content_type' in kwargs:
            raise ValueError('explicit content_type bypasses serialization')
        return producer.publish(body, **kwargs)

That guard is per helper call.  It is the encoder-side equivalent of the
consumer's per-integration ``accept`` list.

Decoding: consumer accept and the process-wide disabled set
-----------------------------------------------------------

A consumer declares the wire formats it will decode:

.. code-block:: python

    Consumer(connection, [queue], accept=['task_v2', 'pickle'])

``accept`` may contain serializer names or MIME types.  Names are resolved
to MIME types by ``prepare_accept_content`` when the ``Consumer`` is
constructed, so an unknown name fails immediately with
``SerializerNotInstalled`` instead of failing later during message handling.

The check is applied in ``Message._decode`` through
``kombu.serialization.loads(..., accept=...)``.  A message whose
``content_type`` is not in ``accept`` raises ``ContentDisallowed``.  Each
``Consumer`` owns its own list: consumers on the same connection or channel
may use different lists, and each is limited to the queues that consumer
actually consumes.

``accept=None`` (the default) means "consult the process-wide disabled set".
``accept=[]`` means "reject every content type except the always-trusted raw
types described below".  An explicit non-``None`` ``accept`` takes
precedence over the disabled set, including re-enabling a format that was
disabled globally.

The process-wide control is:

.. code-block:: python

    from kombu.serialization import disable_insecure_serializers

    disable_insecure_serializers(allowed=['json', 'task_v2'])

This disables every decoder registered at the moment of the call and then
re-enables the named ones.  It affects decoding only, not encoding, and it
applies to the current process only.  It is not duplicated to other workers.

Two consequences matter for a migration:

* It is a snapshot, not a default-deny policy for future registrations.  A
  serializer registered after the call is not added to the disabled set and
  will be accepted by ``accept=None`` consumers.
* Any consumer that passes an explicit ``accept`` containing the legacy
  format bypasses the process-wide disable.  The global switch is a safety
  floor, not a security boundary against in-process code.

Always-trusted content types
----------------------------

``application/data`` and ``application/text`` are always accepted, even with
``accept=[]``.  They are the content types produced by raw or un-serialized
publishing.  A legacy producer that publishes bytes with
``serializer='raw'``, or any producer that supplies ``content_type``
directly, can therefore bypass ``accept``.  If the approved format has a
dedicated MIME type, additionally check ``message.content_type`` in the
callback before processing, or use a transport policy that prevents raw
publishing.

Deferred decoding
-----------------

``accept`` is enforced when the body is decoded, not when the frame is
delivered.  With normal ``callbacks``, ``Consumer._receive_callback`` decodes
before invoking the callback, so ``ContentDisallowed`` is raised on the
delivery path.  With ``on_message=``, Kombu passes the ``Message`` through
undecoded; no ``ContentDisallowed`` occurs unless the callback calls
``message.decode()`` or ``message.payload``.  ``Queue.get()`` likewise
returns an undecoded message and raises only when ``.payload`` is accessed.
Use the callback path for the phase gates below, or decode explicitly in
``on_message``.

Per-worker configuration
========================

Each worker is a separate process and can be configured independently:

.. code-block:: python

    # Worker A: transition worker draining a shared historical queue.
    Consumer(connection, [shared_queue], accept=['task_v2', 'pickle'])

    # Worker B: new-format-only worker, e.g. a new integration.
    Consumer(connection, [new_queue], accept=['task_v2'])

    # Worker C: legacy-only worker kept during the first phase.
    Consumer(connection, [legacy_queue], accept=['pickle'])

Workers that share a queue receive messages from that queue in competition,
so a mixed set of consumers on one queue means each message is handled by
whichever consumer receives it.  During the transition, either give every
consumer of that queue the dual-read ``accept`` list, or route legacy and new
producers to separate queues until the backlog is gone.

The same scoping rules apply to the other Consumer-like interfaces:

* ``Consumer(..., accept=[...])``: one consumer/integration.
* ``SimpleQueue(..., accept=[...])``: the queue's internal consumer.
* ``Queue.get(accept=[...])``: one polling call.
* ``ConsumerMixin.get_consumers``: whichever list each returned ``Consumer``
  receives; there is no mixin-wide override.

The process-wide pieces are the serializer registry (``register`` /
``unregister``), the disabled-content-type set (``disable_insecure_serializers``
/ ``enable_insecure_serializers``), and serializer entry points loaded at
import time.  Put those in worker bootstrap code that every process runs.
Put ``accept`` and the producer guard in the integration's own worker and
publisher code.

Phase gates
===========

Before the upgrade: legacy only
-------------------------------

Consumers use ``accept=['pickle']`` (or the equivalent MIME type), and
producers still emit pickle.  The criteria using the two test messages are:

* The legacy message is delivered and its body equals the original dict.
* The approved JSON message is rejected with ``ContentDisallowed`` and is
  *not* passed to the callback.
* If the approved format uses a custom serializer, this phase must not
  construct a consumer with that serializer in ``accept``; an unknown name
  raises ``SerializerNotInstalled`` at startup.

During the transition: dual read
--------------------------------

Deploy worker bootstrap that registers the approved serializer, then change
consumers to ``accept=['task_v2', 'pickle']`` while producers are still on
the legacy format.  This drains the historical backlog.  Criteria:

* Both test messages are delivered, in either order, with their original
  bodies and content types.
* Neither message produces ``ContentDisallowed`` or reaches
  ``on_decode_error``.
* A canary producer using the approved serializer is delivered successfully,
  proving every worker in the pool has the new registration.

After the backlog is drained: new only
--------------------------------------

Only after queue depth and legacy-format delivery counters reach zero, switch
producers to the approved serializer via the guarded publish helper, then
change consumers to ``accept=['task_v2']``.  Criteria:

* The approved message is delivered and its body equals the original dict.
* The legacy message is rejected with ``ContentDisallowed`` and the callback
  is not invoked.
* The same result holds when ``accept=None`` after
  ``disable_insecure_serializers(allowed=['json', 'task_v2'])`` in that
  process; this confirms the process-wide floor is active as well.
* A producer that attempts ``serializer='pickle'``, ``serializer='raw'``, or
  an explicit legacy ``content_type`` fails in the publish guard before
  reaching the broker.

Finally, stop registering or unregister the legacy decoder in every worker
process.  This is a separate, process-wide cleanup; do it only after no
consumer still names the legacy format in ``accept``, because removing the
decoder makes an ``accept=['pickle']`` consumer fail at startup.

Rollback
========

Rollback is cheapest during the transition phase: keep the legacy producer
path deployable until the new-only consumer gate has passed.  If a new-only
consumer has already rejected legacy messages, restoring dual-read
``accept`` and re-deploying the legacy producer recovers newly published
messages, but messages already rejected without requeue are not restored by
Kombu.  During the gate, run rejected legacy messages through a dead-letter
queue or reject with ``requeue=True`` and a bounded retry policy rather than
discarding them permanently.

Migration checklist
===================

1. Register the approved serializer in every worker and publisher process.
2. Deploy dual-read consumers; verify both public test messages pass.
3. Canary the approved producer while legacy producers still run.
4. Drain historical queues to zero legacy deliveries.
5. Switch producers through the approved-serializer guard.
6. Switch consumers to the approved format only; verify the legacy message is
   rejected.
7. Apply the process-wide disable as a floor, then remove legacy decoder
   registration.

============================================================
 Virtual Transport Base Class - ``kombu.transport.virtual``
============================================================

.. currentmodule:: kombu.transport.virtual

.. automodule:: kombu.transport.virtual

    .. contents::
        :local:

    Transports
    ----------

    .. autoclass:: Transport

        .. autoattribute:: Channel

        .. autoattribute:: Cycle

        .. autoattribute:: polling_interval

        .. autoattribute:: default_port

        .. autoattribute:: state

        .. autoattribute:: cycle

        .. automethod:: establish_connection

        .. automethod:: close_connection

        .. automethod:: create_channel

        .. automethod:: close_channel

        .. automethod:: drain_events

    Channel
    -------

    .. autoclass:: AbstractChannel
        :members:

    .. autoclass:: Channel

        .. autoattribute:: Message

        .. autoattribute:: state

        .. autoattribute:: qos

        .. autoattribute:: do_restore

        .. autoattribute:: restore_to_original_queue

        .. autoattribute:: first_delivery_headers

        .. autoattribute:: requeue_message_callback

        .. autoattribute:: exchange_types

        .. automethod:: exchange_declare

        .. automethod:: exchange_delete

        .. automethod:: queue_declare

        .. automethod:: queue_delete

        .. automethod:: queue_bind

        .. automethod:: queue_purge

        .. automethod:: basic_publish

        .. automethod:: basic_consume

        .. automethod:: basic_cancel

        .. automethod:: basic_get

        .. automethod:: basic_ack

        .. automethod:: basic_recover

        .. automethod:: basic_reject

        .. automethod:: basic_qos

        .. automethod:: get_table

        .. automethod:: typeof

        .. automethod:: drain_events

        .. automethod:: prepare_message

        .. automethod:: message_to_python

        .. automethod:: flow

        .. automethod:: close

    Message
    -------

    .. autoclass:: Message
        :members:
        :undoc-members:
        :inherited-members:

    Quality Of Service
    ------------------

    .. autoclass:: QoS
        :members:
        :undoc-members:
        :inherited-members:

    In-memory State
    ---------------

    .. autoclass:: BrokerState
        :members:
        :undoc-members:
        :inherited-members:

Restoring unacknowledged deliveries
-----------------------------------

Virtual transports that implement unacknowledged message recovery return a
delivery to the queue that actually delivered it.  The queue is recorded in
``message.delivery_info['queue']`` by both :meth:`Channel.basic_consume` and
:meth:`Channel.basic_get`, and is used by explicit requeue and by close
recovery.  A copy that was delivered from one binding therefore never moves
to a queue bound to the same exchange later, even if the bindings change in
between.

Two transport options configure the behaviour:

.. code-block:: python

    Connection('memory://', transport_options={
        # Enable close recovery (the memory transport keeps it off by default).
        'do_restore': True,
        # Restore to the delivering queue (default); set False to route again.
        'restore_to_original_queue': True,
        # These headers stay on the first delivery only.
        'first_delivery_headers': ['x-debug-trace', 'x-request-start'],
    })

The redelivered copy keeps the body, the correlation id and the other
business properties, and is marked with ``redelivered`` in both
``delivery_info`` and the headers.  Only the copy that is requeued loses the
headers listed in ``first_delivery_headers``; the message object still held
by the application is not modified.

If the original queue no longer exists, or the transport raises while
writing the redelivered copy, :meth:`Channel.close` and
:meth:`QoS.restore_unacked` return the ``(exc, message)`` pairs that were not
restored.  A later restore attempt only retries those deliveries, so an
already restored delivery is never enqueued twice.

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

Redefining requeued messages
----------------------------

When a message is redelivered -- after ``Message.requeue``,
``basic_recover(requeue=True)`` or the restore of unacked messages -- the
``requeue_message_callback`` transport option lets the application decide
which headers and properties the redelivered message keeps. The callback
receives the :class:`~kombu.message.Message` being requeued and may return a
mapping with the optional keys ``headers`` and ``properties``; a returned
section replaces the corresponding section of the requeued message. The body,
content type, routing information and tracing attributes such as the
``correlation_id`` are preserved unless the callback replaces them.

This makes it possible to keep one-shot troubleshooting fields on the first
delivery only, while the normal correlation id still tracks the task across
redeliveries:

.. code-block:: python

    TEMPORARY_DEBUG_HEADER = 'x-debug-temp'

    def requeue_message(message):
        return {
            'headers': {
                key: value for key, value in message.headers.items()
                if key != TEMPORARY_DEBUG_HEADER
            },
        }

    connection = Connection(
        transport='memory',
        transport_options={'requeue_message_callback': requeue_message},
    )

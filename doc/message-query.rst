.. _message-query:

The dns.message.QueryMessage Class
----------------------------------

.. autoexception:: dns.message.NotQueryResponse
.. autoexception:: dns.message.ChainError
.. autoexception:: dns.message.ChainConflict
.. autoexception:: dns.message.ChainIncomplete
.. autoexception:: dns.message.ChainTruncated
.. autoexception:: dns.message.ChainLoop
.. autoexception:: dns.message.ChainTooLong
.. autoexception:: dns.message.AnswerForNXDOMAIN

The :py:class:`dns.message.QueryMessage` class is used for ordinary DNS query messages.

.. autoclass:: dns.message.QueryMessage
   :members:

The dns.message.ChainingResult Class
------------------------------------

Objects of the :py:class:`dns.message.ChainingResult` class are returned by the
:py:meth:`dns.message.QueryMessage.resolve_chaining` method.

.. autoclass:: dns.message.ChainingResult
   :members:

The dns.message.ChainLink Class
-------------------------------

.. autoclass:: dns.message.ChainLink
   :members:

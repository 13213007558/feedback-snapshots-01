API
===

.. currentmodule:: flask_limiter

Extension
---------
.. autoclass:: Limiter

Limit objects
--------------

The following dataclasses can be used to define rate limits with more
granularity than what is available through the :class:`Limiter` constructor
if needed (especially for **default**, **application wide** and **meta** limits).

.. autoclass:: Limit
.. autoclass:: ApplicationLimit
.. autoclass:: MetaLimit
.. autoclass:: MultiLimit

For consistency the :class:`RouteLimit` dataclass is also available to define limits
for decorating routes or blueprints.

.. autoclass:: RouteLimit

The :meth:`Limiter.multi_limit` decorator returns a :class:`MultiLimit` which declares
several independent budgets for the same request.

.. automethod:: Limiter.multi_limit
   :noindex:

Utilities
---------
.. autoclass:: ExemptionScope
.. autoclass:: RequestLimit
.. automodule:: flask_limiter.util

Exceptions
----------
.. currentmodule:: flask_limiter

.. autoexception:: RateLimitExceeded
   :no-inherited-members:

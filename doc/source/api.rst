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

For consistency the :class:`RouteLimit` dataclass is also available to define limits
for decorating routes or blueprints.

.. autoclass:: RouteLimit

Joint admission
---------------
.. autoclass:: MultiLimit
.. automethod:: Limiter.multi_limit

Atomic storage integration
~~~~~~~~~~~~~~~~~~~~~~~~~~
Grouped declarations reserve every budget in one storage transaction. The built-in
``memory://`` storage implements this. Third party storages can participate by
implementing:

.. autoclass:: AtomicReservationStorage
   :members: reserve_many

.. autoclass:: AtomicBudget

.. autoclass:: ReservationResult

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

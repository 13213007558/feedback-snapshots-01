.. write-access-policy.py sample application

.. _write-access-policy.py:

write-access-policy.py
======================

A commandable BACnet point does not have a single value: the effective
present-value is selected from the highest occupied slot in ``priorityArray``
and falls back to ``relinquishDefault``.  A backend that is allowed to adjust
a point still must not be able to take over, or release, another subsystem's
safety override.  Reaching a higher priority, or writing NULL, changes who
controls the point even when the displayed value does not change.

The :mod:`bacpypes3.policy` module provides a fail-closed allow-list for this.
The WriteProperty and WritePropertyMultiple services hand the policy the full
target - object, property, array index, priority and whether the write
relinquishes a slot - before the object is touched.

.. code-block:: python

    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = Application.from_args(args)
    app.write_access_policy = policy

Without a matching rule every write is denied.  A rule that grants
`priorities` only applies to commandable points, and only to the named
priority slots.  `relinquishDefault` is a separate target and needs
``allow_relinquish_default=True``.  Direct writes to ``priorityArray`` and to
``presentValue`` without an explicit priority are refused.

The policy remembers which priority slot it awarded to which principal, so a
NULL write can only release a slot that the same principal set through this
policy.  A request that would release a slot owned elsewhere is rejected
before the object changes.

Reports are slot based:

.. code-block:: python

    snapshot = snapshot_commandable(obj, policy)
    print(format_priority_report(snapshot))

    before = snapshot_commandable(obj, policy)
    # ... apply writes ...
    after = snapshot_commandable(obj, policy)
    print(diff_snapshots(before, after).format())

``diff_snapshots()`` reports a slot change even when the effective
present-value is the same before and after, so an unauthorized slot change
cannot be hidden by an equal displayed value.  ``policy.audit`` keeps every
allow and deny decision with its reason.

WritePropertyMultiple is decided in full before the first write is applied:
a denial anywhere in the batch leaves every object unchanged and is returned
as a ``WritePropertyMultipleError`` naming the first refused property.

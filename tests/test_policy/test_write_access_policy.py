"""
Test Write Access Policy
------------------------

WriteProperty and WritePropertyMultiple must hand the complete write target -
object, property, array index, priority and whether the write relinquishes a
slot - to the access policy before the object changes.  A policy that only
guards the plain scalar present-value path is not enough: an equal value at a
higher priority, or a NULL, can take or release another subsystem's override
without changing the visible present-value.
"""

from __future__ import annotations

import pytest

from typing import List

from bacpypes3.apdu import (
    APDU,
    ConfirmedServiceChoice,
    ErrorPDU,
    SimpleAckPDU,
    WritePropertyMultipleError,
    WritePropertyMultipleRequest,
    WritePropertyRequest,
)
from bacpypes3.app import Application
from bacpypes3.basetypes import (
    ErrorClass,
    ErrorCode,
    PriorityValue,
    PropertyValue,
    WriteAccessSpecification,
)
from bacpypes3.constructeddata import Any
from bacpypes3.local.analog import AnalogValueObject, AnalogValueObjectCmd
from bacpypes3.local.device import DeviceObject
from bacpypes3.pdu import Address
from bacpypes3.policy import (
    WriteAccessPolicy,
    diff_snapshots,
    format_priority_report,
    property_value_is_null,
    snapshot_commandable,
)
from bacpypes3.primitivedata import Null, ObjectIdentifier, Real

# some debugging
_debug = 0


class ResponseApplication(Application):
    """Collect responses rather than sending them downstream."""

    responses: List[APDU]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.responses = []

    async def response(self, apdu: APDU) -> None:  # type: ignore[override]
        self.responses.append(apdu)


def make_application(policy: WriteAccessPolicy) -> ResponseApplication:
    app = ResponseApplication(write_access_policy=policy)
    app.add_object(
        DeviceObject(
            objectIdentifier=("device", 1),
            objectName="dev",
            vendorIdentifier=999,
        )
    )
    app.add_object(
        AnalogValueObjectCmd(
            objectIdentifier=("analog-value", 1),
            objectName="av",
            presentValue=21.0,
            relinquishDefault=18.0,
        )
    )
    return app


def write_request(
    property_identifier,
    value,
    priority: int | None = None,
    array_index: int | None = None,
    invoke_id: int = 7,
) -> WritePropertyRequest:
    request = WritePropertyRequest(
        objectIdentifier=ObjectIdentifier("analog-value,1"),
        propertyIdentifier=property_identifier,
        propertyValue=Any(value),
    )
    if priority is not None:
        request.priority = priority
    if array_index is not None:
        request.propertyArrayIndex = array_index
    request.pduSource = Address("10.0.0.5")
    request.apduInvokeID = invoke_id
    return request


def slot_value(obj, priority: int):
    priority_value = obj.priorityArray[priority - 1]
    choice = priority_value._choice
    if (choice is None) or (choice == "null"):
        return None
    return getattr(priority_value, choice)


def seed_slot(obj, priority: int, value) -> None:
    """Set a slot as if another subsystem had already written it."""
    obj.priorityArray[priority - 1] = PriorityValue(value)


async def test_normal_write_and_effective_value():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    await app.indication(write_request("present-value", Real(23.0), 8))

    assert isinstance(app.responses[-1], SimpleAckPDU)
    assert av.presentValue == 23.0
    assert slot_value(av, 8) == 23.0
    assert policy.slot_owner("analog-value,1", 8) == "bms"

    report = format_priority_report(av, policy)
    assert "present-value = 23.0" in report
    assert "current-command-priority = 8" in report
    assert "priority  8: 23.0 (owner: bms)" in report
    assert "relinquish-default = 18.0" in report

    app.close()


async def test_priority_above_grant_is_denied_before_change():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))
    before = snapshot_commandable(av, policy)

    await app.indication(write_request("present-value", Real(23.0), 2))

    response = app.responses[-1]
    assert isinstance(response, ErrorPDU)
    assert response.errorClass == ErrorClass.property
    assert response.errorCode == ErrorCode.writeAccessDenied
    assert response.write_access_decision.allowed is False

    after = snapshot_commandable(av, policy)
    assert after == before
    assert av.presentValue == 21.0
    assert all(slot.is_null for slot in after.slots)

    app.close()


async def test_equal_value_cannot_hide_unauthorized_slot_change():
    """
    A denied write with the same value as the effective present-value must
    not change the slot either.  The snapshot diff is slot based.
    """
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    # slot 3 holds the current effective value
    seed_slot(av, 3, Real(21.0))
    assert av.presentValue == 21.0

    before = snapshot_commandable(av, policy)
    await app.indication(write_request("present-value", Real(21.0), 2))
    after = snapshot_commandable(av, policy)

    assert isinstance(app.responses[-1], ErrorPDU)
    diff = diff_snapshots(before, after)
    assert not diff.changed
    assert diff.effective_value_changed is False

    # and the authorization was refused even though the value was unchanged
    assert av.presentValue == 21.0
    assert slot_value(av, 2) is None
    assert slot_value(av, 3) == 21.0

    app.close()


async def test_authorized_equal_value_slot_change_is_visible():
    """
    An authorized write that leaves the present-value alone must still show
    up as a slot change in the report.
    """
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))
    seed_slot(av, 3, Real(21.0))

    before = snapshot_commandable(av, policy)
    await app.indication(write_request("present-value", Real(21.0), 8))
    after = snapshot_commandable(av, policy)

    assert isinstance(app.responses[-1], SimpleAckPDU)
    assert av.presentValue == 21.0

    diff = diff_snapshots(before, after)
    assert diff.effective_value_changed is False
    assert [change.priority for change in diff.slot_changes] == [8]
    assert "priority  8: <null> -> 21.0 (owner: bms)" in diff.format()

    app.close()


async def test_null_cannot_release_someone_elses_slot():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    # another subsystem owns priority 2 and is the highest occupant
    seed_slot(av, 2, Real(30.0))
    assert av.presentValue == 30.0

    await app.indication(write_request("present-value", Null(()), 2))

    assert isinstance(app.responses[-1], ErrorPDU)
    assert av.presentValue == 30.0
    assert slot_value(av, 2) == 30.0
    assert policy.slot_owner("analog-value,1", 2) is None

    app.close()


async def test_null_releases_own_slot_only():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))
    seed_slot(av, 2, Real(30.0))

    await app.indication(write_request("present-value", Real(23.0), 8))
    assert av.presentValue == 30.0
    assert policy.slot_owner("analog-value,1", 8) == "bms"

    before = snapshot_commandable(av, policy)
    await app.indication(write_request("present-value", Null(()), 8))
    after = snapshot_commandable(av, policy)

    assert isinstance(app.responses[-1], SimpleAckPDU)
    assert av.presentValue == 30.0
    assert slot_value(av, 8) is None
    assert policy.slot_owner("analog-value,1", 8) is None

    diff = diff_snapshots(before, after)
    assert [change.priority for change in diff.slot_changes] == [8]
    assert "priority  8: 23.0 (owner: bms) -> <null>" in diff.format()

    app.close()


async def test_null_without_explicit_priority_is_denied():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    await app.indication(write_request("present-value", Null(())))

    assert isinstance(app.responses[-1], ErrorPDU)
    assert av.presentValue == 21.0

    app.close()


async def test_priority_array_is_read_only():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="priority-array",
        array_index=4,
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    await app.indication(
        write_request(
            "priority-array", PriorityValue(Real(30.0)), array_index=4
        )
    )
    assert isinstance(app.responses[-1], ErrorPDU)
    assert slot_value(av, 4) is None
    assert av.presentValue == 21.0

    app.close()


async def test_relinquish_default_is_a_separate_target():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    await app.indication(write_request("relinquish-default", Real(19.0)))
    assert isinstance(app.responses[-1], ErrorPDU)
    assert av.relinquishDefault == 18.0

    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="relinquish-default",
        allow_relinquish_default=True,
    )
    await app.indication(write_request("relinquish-default", Real(19.0)))
    assert isinstance(app.responses[-1], SimpleAckPDU)
    assert av.relinquishDefault == 19.0

    app.close()


async def test_non_commandable_present_value_is_denied():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 2),
        property_identifier="present-value",
        priorities=range(8, 17),
    )
    app = make_application(policy)
    app.add_object(
        AnalogValueObject(
            objectIdentifier=("analog-value", 2),
            objectName="plain-av",
            presentValue=1.0,
        )
    )
    av = app.get_object_id(ObjectIdentifier("analog-value,2"))

    await app.indication(write_request("present-value", Real(2.0), 8))
    assert isinstance(app.responses[-1], ErrorPDU)
    assert av.presentValue == 1.0

    app.close()


async def test_no_policy_keeps_previous_behaviour():
    app = ResponseApplication()
    app.add_object(
        DeviceObject(
            objectIdentifier=("device", 1),
            objectName="dev",
            vendorIdentifier=999,
        )
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )
    app.add_object(av)

    await app.indication(write_request("present-value", Real(23.0), 4))
    assert isinstance(app.responses[-1], SimpleAckPDU)
    assert av.presentValue == 23.0

    app.close()


async def test_write_property_multiple_denied_before_any_change():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))
    before = snapshot_commandable(av, policy)

    request = WritePropertyMultipleRequest(
        listOfWriteAccessSpecs=[
            WriteAccessSpecification(
                objectIdentifier=ObjectIdentifier("analog-value,1"),
                listOfProperties=[
                    PropertyValue(
                        propertyIdentifier="present-value",
                        value=Any(Real(25.0)),
                        priority=10,
                    )
                ],
            ),
            WriteAccessSpecification(
                objectIdentifier=ObjectIdentifier("analog-value,1"),
                listOfProperties=[
                    PropertyValue(
                        propertyIdentifier="present-value",
                        value=Any(Real(11.0)),
                        priority=1,
                    )
                ],
            ),
        ]
    )
    request.pduSource = Address("10.0.0.5")
    request.apduInvokeID = 42

    await app.indication(request)

    response = app.responses[-1]
    assert isinstance(response, WritePropertyMultipleError)
    assert response.errorType.errorCode == ErrorCode.writeAccessDenied
    assert response.firstFailedWriteAttempt.objectIdentifier == ObjectIdentifier(
        "analog-value,1"
    )
    assert response.apduService == ConfirmedServiceChoice.writePropertyMultiple

    # the allowed first write must not be applied either
    after = snapshot_commandable(av, policy)
    assert after == before
    assert av.presentValue == 21.0
    assert slot_value(av, 10) is None
    assert policy.slot_owner("analog-value,1", 10) is None

    app.close()


async def test_write_property_multiple_allowed():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    request = WritePropertyMultipleRequest(
        listOfWriteAccessSpecs=[
            WriteAccessSpecification(
                objectIdentifier=ObjectIdentifier("analog-value,1"),
                listOfProperties=[
                    PropertyValue(
                        propertyIdentifier="present-value",
                        value=Any(Real(25.0)),
                        priority=10,
                    ),
                    PropertyValue(
                        propertyIdentifier="present-value",
                        value=Any(Real(22.0)),
                        priority=12,
                    ),
                ],
            )
        ]
    )
    request.pduSource = Address("10.0.0.5")
    request.apduInvokeID = 43

    await app.indication(request)

    assert isinstance(app.responses[-1], SimpleAckPDU)
    assert av.presentValue == 25.0
    assert slot_value(av, 10) == 25.0
    assert slot_value(av, 12) == 22.0
    assert policy.slot_owner("analog-value,1", 10) == "bms"
    assert policy.slot_owner("analog-value,1", 12) == "bms"

    app.close()


async def test_write_property_multiple_null_and_denied_release():
    """
    A batch that first writes a slot and then relinquishes it is allowed,
    but a batch that relinquishes a slot owned by another principal is not.
    """
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    app = make_application(policy)
    av = app.get_object_id(ObjectIdentifier("analog-value,1"))

    request = WritePropertyMultipleRequest(
        listOfWriteAccessSpecs=[
            WriteAccessSpecification(
                objectIdentifier=ObjectIdentifier("analog-value,1"),
                listOfProperties=[
                    PropertyValue(
                        propertyIdentifier="present-value",
                        value=Any(Null(())),
                        priority=2,
                    )
                ],
            )
        ]
    )
    request.pduSource = Address("10.0.0.5")
    request.apduInvokeID = 44

    await app.indication(request)
    assert isinstance(app.responses[-1], WritePropertyMultipleError)
    assert app.responses[-1].errorType.errorCode == ErrorCode.writeAccessDenied

    app.close()


def test_property_value_is_null_for_encoded_value():
    request = write_request("present-value", Null(()), 8)
    assert property_value_is_null(request.propertyValue) is True

    request = write_request("present-value", Real(1.0), 8)
    assert property_value_is_null(request.propertyValue) is False


async def test_policy_is_fail_closed_without_rules():
    policy = WriteAccessPolicy(principal="bms")
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    decision = policy.authorize(av, "present-value", priority=8)
    assert decision.allowed is False
    assert "no matching write rule" in decision.reason


async def test_rule_per_priority_list():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=[8, 10, 12],
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    for priority in (8, 10, 12):
        assert policy.authorize(av, "present-value", priority=priority).allowed
    for priority in (1, 9, 11, 16):
        assert not policy.authorize(av, "present-value", priority=priority).allowed

    # an explicit priority grant does not cover a priority-less write
    assert not policy.authorize(av, "present-value").allowed


async def test_relinquish_default_requires_its_own_rule():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    assert not policy.authorize(av, "relinquish-default").allowed

    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="relinquish-default",
        allow_relinquish_default=True,
    )
    assert policy.authorize(av, "relinquish-default").allowed


async def test_cancel_drops_in_flight_reservation():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    decision = policy.authorize(av, "present-value", priority=8)
    assert decision.allowed
    # the in-flight write is visible as the slot owner ...
    assert policy.slot_owner("analog-value,1", 8) == "bms"

    # ... and dropping it means a later NULL cannot claim a phantom slot
    policy.cancel(decision)
    assert policy.slot_owner("analog-value,1", 8) is None
    assert not policy.authorize(
        av, "present-value", priority=8, relinquish=True
    ).allowed


async def test_concurrent_denial_cannot_steal_reserved_slot():
    """
    A decision and the object mutation are separate steps.  While one write
    is in flight, another request with a higher priority must not be able to
    become the slot owner.
    """
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    first = policy.authorize(av, "present-value", priority=8)
    assert first.allowed
    assert policy.slot_owner("analog-value,1", 8) == "bms"

    second = policy.authorize(av, "present-value", priority=2)
    assert second.allowed is False
    assert policy.slot_owner("analog-value,1", 8) == "bms"

    # a relinquish of the still in-flight slot is refused
    assert not policy.authorize(
        av, "present-value", priority=8, relinquish=True
    ).allowed


async def test_ordinary_property_rule_without_priority():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="description",
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    assert policy.authorize(av, "description").allowed
    assert not policy.authorize(av, "description", priority=8).allowed


async def test_array_index_is_part_of_the_target():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="event-message-texts",
        array_index=1,
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    assert policy.authorize(av, "event-message-texts", property_array_index=1).allowed
    assert not policy.authorize(
        av, "event-message-texts", property_array_index=2
    ).allowed
    assert not policy.authorize(av, "event-message-texts").allowed


async def test_deny_rule_wins_over_allow():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
    )
    policy.deny(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=[8],
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    assert not policy.authorize(av, "present-value", priority=8).allowed
    assert policy.authorize(av, "present-value", priority=9).allowed


async def test_audit_reports_denied_slot_change():
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="av",
        presentValue=21.0,
        relinquishDefault=18.0,
    )

    policy.authorize(av, "present-value", priority=3)
    decision = policy.audit[-1]
    assert decision.allowed is False
    assert decision.slot == 3
    assert "priority 3" in str(decision)

"""
Limited property write access
-----------------------------

A small local device that only accepts commands at priorities 8 through 16.
Priority 8 is "lowest urgency" for this example; a supervisory system using
priorities 1 through 7 keeps control during an override.

The script does not use the network.  It feeds the same request objects the
service layer receives, applies the policy, then prints the effective value
and every priority slot before and after each write.
"""

import asyncio

from typing import List

from bacpypes3.apdu import (
    APDU,
    SimpleAckPDU,
    WritePropertyMultipleError,
    WritePropertyMultipleRequest,
    WritePropertyRequest,
)
from bacpypes3.app import Application
from bacpypes3.basetypes import PriorityValue, PropertyValue, WriteAccessSpecification
from bacpypes3.constructeddata import Any
from bacpypes3.local.analog import AnalogValueObjectCmd
from bacpypes3.local.device import DeviceObject
from bacpypes3.pdu import Address
from bacpypes3.policy import (
    WriteAccessPolicy,
    diff_snapshots,
    format_priority_report,
    snapshot_commandable,
)
from bacpypes3.primitivedata import Null, ObjectIdentifier, Real


class LocalApplication(Application):
    """Collect responses instead of sending them to a network layer."""

    responses: List[APDU]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.responses = []

    async def response(self, apdu: APDU) -> None:  # type: ignore[override]
        self.responses.append(apdu)


async def main() -> None:
    # the policy is an allow-list; without a rule every write is denied
    policy = WriteAccessPolicy(principal="bms")
    policy.allow(
        object_identifier=("analog-value", 1),
        property_identifier="present-value",
        priorities=range(8, 17),
        allow_relinquish=True,
    )

    app = LocalApplication(write_access_policy=policy)
    app.add_object(
        DeviceObject(
            objectIdentifier=("device", 1),
            objectName="policy-device",
            vendorIdentifier=999,
        )
    )
    av = AnalogValueObjectCmd(
        objectIdentifier=("analog-value", 1),
        objectName="supply-air-setpoint",
        presentValue=21.0,
        relinquishDefault=18.0,
    )
    app.add_object(av)

    # pretend a safety subsystem already holds priority 2
    av.priorityArray[1] = PriorityValue(Real(24.0))

    def request(value, priority=None, invoke_id=1) -> WritePropertyRequest:
        write_request = WritePropertyRequest(
            objectIdentifier=ObjectIdentifier("analog-value,1"),
            propertyIdentifier="present-value",
            propertyValue=Any(value),
        )
        if priority is not None:
            write_request.priority = priority
        write_request.pduSource = Address("10.0.0.5")
        write_request.apduInvokeID = invoke_id
        return write_request

    def show(title, before):
        after = snapshot_commandable(av, policy)
        print(title)
        print(diff_snapshots(before, after).format())
        print()
        print(format_priority_report(after))
        print()
        return after

    # a normal low-authority command
    before = snapshot_commandable(av, policy)
    await app.indication(request(Real(22.0), 8, 1))
    print("response:", app.responses[-1])
    before = show("write present-value at priority 8", before)

    # a higher authority is not granted
    await app.indication(request(Real(30.0), 3, 2))
    print("response:", app.responses[-1])
    before = show("write present-value at priority 3 (denied)", before)

    # an equal value at a denied priority must not change the slot
    await app.indication(request(Real(24.0), 4, 3))
    print("response:", app.responses[-1])
    before = show("equal value at priority 4 (denied, same value)", before)

    # NULL release of the safety subsystem's slot is refused
    await app.indication(request(Null(()), 2, 4))
    print("response:", app.responses[-1])
    before = show("relinquish priority 2 (denied, owned elsewhere)", before)

    # release our own slot
    await app.indication(request(Null(()), 8, 5))
    print("response:", app.responses[-1])
    before = show("relinquish priority 8 (allowed)", before)

    # WritePropertyMultiple is decided as a whole before anything changes
    wpm = WritePropertyMultipleRequest(
        listOfWriteAccessSpecs=[
            WriteAccessSpecification(
                objectIdentifier=ObjectIdentifier("analog-value,1"),
                listOfProperties=[
                    PropertyValue(
                        propertyIdentifier="present-value",
                        value=Any(Real(23.0)),
                        priority=10,
                    ),
                    PropertyValue(
                        propertyIdentifier="present-value",
                        value=Any(Real(9.0)),
                        priority=1,
                    ),
                ],
            )
        ]
    )
    wpm.pduSource = Address("10.0.0.5")
    wpm.apduInvokeID = 6
    await app.indication(wpm)
    response = app.responses[-1]
    assert isinstance(response, WritePropertyMultipleError)
    print("response:", response)
    before = show("batch with one denied write (nothing applied)", before)

    app.close()


if __name__ == "__main__":
    asyncio.run(main())

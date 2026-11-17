"""
Test ReadPropertyMultiple with read-denied properties
-----------------------------------------------------

Regression tests for serving ReadPropertyMultiple requests when some
properties of an object are not allowed to be read.

A property that cannot be read must be reported per item with its own
protocol error (property/readAccessDenied) so the refusal keeps its
identity - it must not be collapsed into "unknown property", must not
silently vanish from 'all'/'required'/'optional' expansions (which makes
a denial indistinguishable from a nonexistent property), and must not
fail the entire request, losing the results of the readable properties.

The value of a denied property must never leak into the response, and
the read must not be attempted at all: these tests use objects that
record every property getter call to prove the service does not read
everything first and mask values afterwards (getters may have side
effects).  Denial is expressed as a write-only property (no getter), so
the access check happens before any getter could run.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from bacpypes3.apdu import (
    APDU,
    Error,
    ReadPropertyMultipleACK,
    ReadPropertyMultipleRequest,
)
from bacpypes3.app import Application
from bacpypes3.basetypes import (
    ErrorClass,
    ErrorCode,
    PropertyReference,
    ReadAccessResultElement,
    ReadAccessSpecification,
)
from bacpypes3.local.analog import AnalogValueObject
from bacpypes3.local.device import DeviceObject
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import (
    CharacterString,
    ObjectIdentifier,
    PropertyIdentifier,
    Real,
    Unsigned,
)

# some debugging
_debug = 0

CLIENT_ADDRESS = Address("1.2.3.4")
INVOKE_ID = 7

DEVICE_ID = ObjectIdentifier("device,1")
ANALOG_ID = ObjectIdentifier("analog-value,1")
UNKNOWN_ID = ObjectIdentifier("analog-value,99")

# backing value of a read-denied property; must never appear in a response
SECRET = "classified"


class ResponseApplication(Application):
    """Collect the responses rather than sending them downstream."""

    responses: List[APDU]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.responses = []

    async def response(self, apdu: APDU) -> None:  # type: ignore[override]
        self.responses.append(apdu)


class RecordingDeviceObject(DeviceObject):
    """Device object that records every objectList getter call."""

    def __init__(self, **kwargs) -> None:
        self._access_log: List[Tuple[str, str]] = []
        super().__init__(**kwargs)

    @property
    def objectList(self):  # type: ignore[override]
        self._access_log.append(("get", "objectList"))
        return DeviceObject.objectList.fget(self)  # type: ignore[attr-defined]

    @objectList.setter
    def objectList(self, value) -> None:
        """Ignored, like the parent class."""


class RecordingAnalogValueObject(AnalogValueObject):
    """Analog value object that records property access.

    ``presentValue`` is readable and every getter call is recorded.
    ``description`` is write-only: reading it is denied and there is no
    getter that could be called, so a correct implementation reports
    readAccessDenied without touching the backing value.
    """

    def __init__(self, **kwargs) -> None:
        self._access_log: List[Tuple[str, str]] = []
        super().__init__(**kwargs)

    @property
    def presentValue(self):  # type: ignore[override]
        self._access_log.append(("get", "presentValue"))
        return self._present_value

    @presentValue.setter
    def presentValue(self, value) -> None:
        self._access_log.append(("set", "presentValue"))
        self._present_value = value

    def _set_description(self, value) -> None:
        self._access_log.append(("set", "description"))
        self._description_value = value

    # write-only property: no getter, reads are denied
    description = property(None, _set_description)


class DeniedPropertyObject(AnalogValueObject):
    """Object whose presentValue (required) and description (optional)
    are both write-only, so read access is denied for one property of
    each kind."""

    def __init__(self, **kwargs) -> None:
        self._access_log: List[Tuple[str, str]] = []
        super().__init__(**kwargs)

    def _set_present_value(self, value) -> None:
        self._access_log.append(("set", "presentValue"))
        self._present_value = value

    presentValue = property(None, _set_present_value)

    def _set_description(self, value) -> None:
        self._access_log.append(("set", "description"))
        self._description_value = value

    description = property(None, _set_description)


class DeniedArrayObject(RecordingAnalogValueObject):
    """Object whose priorityArray is write-only, so reads of the array
    (with or without an index) are denied."""

    def _set_priority_array(self, value) -> None:
        self._access_log.append(("set", "priorityArray"))
        self._priority_array = value

    priorityArray = property(None, _set_priority_array)


def make_app(*objects) -> ResponseApplication:
    app = ResponseApplication()
    for obj in objects:
        app.add_object(obj)
    return app


def make_device() -> RecordingDeviceObject:
    return RecordingDeviceObject(
        objectIdentifier=DEVICE_ID,
        objectName="dev",
        vendorIdentifier=999,
    )


def make_analog() -> RecordingAnalogValueObject:
    obj = RecordingAnalogValueObject(
        objectIdentifier=ANALOG_ID,
        objectName="av",
        presentValue=21.0,
        units="degreesCelsius",
        eventState="normal",
        outOfService=False,
    )
    # backing value of the write-only property, set directly because the
    # property itself rejects reads and the local object setattr path
    # reads the current value before writing
    obj._description_value = SECRET
    return obj


async def run_request(
    app: ResponseApplication, specs: List[ReadAccessSpecification]
) -> APDU:
    """Push a ReadPropertyMultiple request down the real service path."""
    request = ReadPropertyMultipleRequest(listOfReadAccessSpecs=specs)
    request.pduSource = CLIENT_ADDRESS
    request.apduInvokeID = INVOKE_ID

    await app.indication(request)

    assert len(app.responses) == 1
    return app.responses[0]


def spec(
    object_identifier: str, *property_references: PropertyReference
) -> ReadAccessSpecification:
    return ReadAccessSpecification(
        objectIdentifier=ObjectIdentifier(object_identifier),
        listOfPropertyReferences=list(property_references),
    )


def ref(identifier: str, array_index: Optional[int] = None) -> PropertyReference:
    return PropertyReference(
        propertyIdentifier=identifier, propertyArrayIndex=array_index
    )


def result_map(
    ack: ReadPropertyMultipleACK, object_identifier: ObjectIdentifier
) -> Dict[PropertyIdentifier, ReadAccessResultElement]:
    for read_access_result in ack.listOfReadAccessResults:
        if read_access_result.objectIdentifier == object_identifier:
            return {
                element.propertyIdentifier: element
                for element in read_access_result.listOfResults
            }
    raise AssertionError(f"no results for {object_identifier!r}")


def assert_error(
    element: ReadAccessResultElement,
    error_class: ErrorClass,
    error_code: ErrorCode,
    array_index: Optional[int] = None,
) -> None:
    """The element carries an error, not a value."""
    assert element.readResult.propertyValue is None
    access_error = element.readResult.propertyAccessError
    assert access_error is not None
    assert access_error.errorClass == error_class
    assert access_error.errorCode == error_code
    assert element.propertyArrayIndex == array_index


def assert_value(
    element: ReadAccessResultElement,
    cls: type,
    expected,
    array_index: Optional[int] = None,
) -> None:
    """The element carries a value, not an error."""
    assert element.readResult.propertyAccessError is None
    assert element.readResult.propertyValue.cast_out(cls) == expected
    assert element.propertyArrayIndex == array_index


def getter_calls(obj, name: str) -> int:
    return len([entry for entry in obj._access_log if entry == ("get", name)])


async def test_specific_denied_property_keeps_identity():
    """A read of a denied property is reported as readAccessDenied for
    that property only; the other properties in the same specification
    are still read and returned."""
    device = make_device()
    analog = make_analog()
    app = make_app(device, analog)
    analog._access_log.clear()

    response = await run_request(
        app,
        [
            spec(
                "analog-value,1",
                ref("description"),
                ref("present-value"),
                ref("object-name"),
            )
        ],
    )
    assert isinstance(response, ReadPropertyMultipleACK)
    assert response.apduInvokeID == INVOKE_ID
    assert response.pduDestination == CLIENT_ADDRESS

    results = result_map(response, ANALOG_ID)
    assert set(results) == {
        PropertyIdentifier.description,
        PropertyIdentifier.presentValue,
        PropertyIdentifier.objectName,
    }

    # the refusal keeps its identity - not unknownProperty, not a value
    assert_error(
        results[PropertyIdentifier.description],
        ErrorClass.property,
        ErrorCode.readAccessDenied,
    )

    # the readable properties are unaffected
    assert_value(results[PropertyIdentifier.presentValue], Real, 21.0)
    assert_value(results[PropertyIdentifier.objectName], CharacterString, "av")

    # the readable getter was called exactly once, the denied property
    # has no getter and no read of it was attempted
    assert getter_calls(analog, "presentValue") == 1
    assert getter_calls(analog, "description") == 0

    # the denied value does not leak into the encoded response
    assert SECRET.encode("utf-8") not in bytes(response.encode().pduData)

    app.close()


async def test_all_selector_keeps_denied_identity():
    """The 'all' expansion reports the denied property as an error
    element instead of silently dropping it (which would make a denial
    look like a nonexistent property)."""
    device = make_device()
    analog = make_analog()
    app = make_app(device, analog)
    analog._access_log.clear()

    response = await run_request(app, [spec("analog-value,1", ref("all"))])
    assert isinstance(response, ReadPropertyMultipleACK)

    results = result_map(response, ANALOG_ID)

    # the denied property is present as a per-item protocol error
    assert_error(
        results[PropertyIdentifier.description],
        ErrorClass.property,
        ErrorCode.readAccessDenied,
    )

    # readable properties carry their values
    assert_value(results[PropertyIdentifier.presentValue], Real, 21.0)
    assert_value(results[PropertyIdentifier.objectName], CharacterString, "av")

    # propertyList is not part of an 'all' response
    assert PropertyIdentifier.propertyList not in results

    # each readable getter ran exactly once, no denied read attempted
    assert getter_calls(analog, "presentValue") == 1
    assert getter_calls(analog, "description") == 0

    assert SECRET.encode("utf-8") not in bytes(response.encode().pduData)

    app.close()


async def test_required_selector_denied_required_property():
    """The 'required' expansion keeps a denied required property as an
    error element; optional properties are not included."""
    device = make_device()
    denied = DeniedPropertyObject(
        objectIdentifier=ANALOG_ID,
        objectName="av",
        units="degreesCelsius",
        eventState="normal",
        outOfService=False,
    )
    app = make_app(device, denied)
    denied._access_log.clear()

    response = await run_request(app, [spec("analog-value,1", ref("required"))])
    assert isinstance(response, ReadPropertyMultipleACK)

    results = result_map(response, ANALOG_ID)
    assert set(results) == {
        PropertyIdentifier.objectIdentifier,
        PropertyIdentifier.objectName,
        PropertyIdentifier.objectType,
        PropertyIdentifier.presentValue,
        PropertyIdentifier.statusFlags,
        PropertyIdentifier.eventState,
        PropertyIdentifier.outOfService,
        PropertyIdentifier.units,
    }

    # the denied required property keeps its identity
    assert_error(
        results[PropertyIdentifier.presentValue],
        ErrorClass.property,
        ErrorCode.readAccessDenied,
    )

    # the other required properties are still returned
    assert_value(results[PropertyIdentifier.objectName], CharacterString, "av")
    assert_value(
        results[PropertyIdentifier.objectIdentifier], ObjectIdentifier, ANALOG_ID
    )

    # no getter of the denied object was called at all
    assert denied._access_log == []

    app.close()


async def test_optional_selector_denied_optional_property():
    """The 'optional' expansion keeps a denied optional property as an
    error element; required properties are not included."""
    device = make_device()
    denied = DeniedPropertyObject(
        objectIdentifier=ANALOG_ID,
        objectName="av",
        units="degreesCelsius",
        eventState="normal",
        outOfService=False,
    )
    app = make_app(device, denied)
    denied._access_log.clear()

    response = await run_request(app, [spec("analog-value,1", ref("optional"))])
    assert isinstance(response, ReadPropertyMultipleACK)

    results = result_map(response, ANALOG_ID)

    # every other optional property is unset and skipped, only the
    # denied one remains - as an error, not a value
    assert set(results) == {PropertyIdentifier.description}
    assert_error(
        results[PropertyIdentifier.description],
        ErrorClass.property,
        ErrorCode.readAccessDenied,
    )

    assert denied._access_log == []

    app.close()


async def test_all_selector_denied_required_and_optional():
    """The 'all' expansion keeps denied required and optional properties
    as error elements next to the readable values."""
    device = make_device()
    denied = DeniedPropertyObject(
        objectIdentifier=ANALOG_ID,
        objectName="av",
        units="degreesCelsius",
        eventState="normal",
        outOfService=False,
    )
    app = make_app(device, denied)
    denied._access_log.clear()

    response = await run_request(app, [spec("analog-value,1", ref("all"))])
    assert isinstance(response, ReadPropertyMultipleACK)

    results = result_map(response, ANALOG_ID)

    assert_error(
        results[PropertyIdentifier.presentValue],
        ErrorClass.property,
        ErrorCode.readAccessDenied,
    )
    assert_error(
        results[PropertyIdentifier.description],
        ErrorClass.property,
        ErrorCode.readAccessDenied,
    )
    assert_value(results[PropertyIdentifier.objectName], CharacterString, "av")

    assert denied._access_log == []

    app.close()


async def test_array_index_reads():
    """Array index reads of a readable array return the element (or the
    length for index 0), and an out-of-range index is a per-item error
    that keeps the requested index."""
    device = make_device()
    analog = make_analog()
    app = make_app(device, analog)
    device._access_log.clear()

    response = await run_request(
        app,
        [
            spec(
                "device,1",
                ref("object-list", 0),
                ref("object-list", 1),
                ref("object-list", 2),
                ref("object-list", 99),
            )
        ],
    )
    assert isinstance(response, ReadPropertyMultipleACK)

    elements = [
        element for element in response.listOfReadAccessResults[0].listOfResults
    ]
    assert len(elements) == 4

    # index 0 is the array length, then the elements in order
    assert_value(elements[0], Unsigned, 2, array_index=0)
    assert_value(elements[1], ObjectIdentifier, DEVICE_ID, array_index=1)
    assert_value(elements[2], ObjectIdentifier, ANALOG_ID, array_index=2)

    # out-of-range index is a per-item error that keeps the index
    assert_error(
        elements[3],
        ErrorClass.property,
        ErrorCode.invalidArrayIndex,
        array_index=99,
    )

    # one getter call per read, the index is applied to the result
    assert getter_calls(device, "objectList") == 4

    app.close()


async def test_array_index_denied():
    """Reading a denied array property with an index reports
    readAccessDenied (not invalidArrayIndex, not unknownProperty) and
    keeps the requested index; the array is never touched."""
    device = make_device()
    denied_array = DeniedArrayObject(
        objectIdentifier=ANALOG_ID,
        objectName="av",
        presentValue=21.0,
        units="degreesCelsius",
    )
    app = make_app(device, denied_array)
    denied_array._access_log.clear()

    response = await run_request(
        app,
        [spec("analog-value,1", ref("priority-array", 0), ref("priority-array", 1))],
    )
    assert isinstance(response, ReadPropertyMultipleACK)

    elements = list(response.listOfReadAccessResults[0].listOfResults)
    assert len(elements) == 2
    for element, index in zip(elements, (0, 1)):
        assert element.propertyIdentifier == PropertyIdentifier.priorityArray
        assert_error(
            element,
            ErrorClass.property,
            ErrorCode.readAccessDenied,
            array_index=index,
        )

    # no getter of the denied array was called
    assert getter_calls(denied_array, "priorityArray") == 0

    app.close()


async def test_unknown_object_mixed_with_known():
    """An unknown object reference in a request that also references a
    known object produces per-item unknownObject errors - including for
    the 'all' selector - without losing the known object's results."""
    device = make_device()
    analog = make_analog()
    app = make_app(device, analog)
    analog._access_log.clear()

    response = await run_request(
        app,
        [
            spec("analog-value,1", ref("present-value")),
            spec("analog-value,99", ref("object-name"), ref("all")),
        ],
    )
    assert isinstance(response, ReadPropertyMultipleACK)

    # the known object is read normally
    results = result_map(response, ANALOG_ID)
    assert_value(results[PropertyIdentifier.presentValue], Real, 21.0)
    assert getter_calls(analog, "presentValue") == 1

    # each reference to the unknown object gets its own error element,
    # keeping the identity of what was asked for
    unknown_results = result_map(response, UNKNOWN_ID)
    assert set(unknown_results) == {
        PropertyIdentifier.objectName,
        PropertyIdentifier.all,
    }
    assert_error(
        unknown_results[PropertyIdentifier.objectName],
        ErrorClass.object,
        ErrorCode.unknownObject,
    )
    assert_error(
        unknown_results[PropertyIdentifier.all],
        ErrorClass.object,
        ErrorCode.unknownObject,
    )

    app.close()


async def test_unknown_object_only():
    """A request where no object reference exists at all is rejected
    with a single unknownObject error for the whole request."""
    device = make_device()
    analog = make_analog()
    app = make_app(device, analog)

    response = await run_request(app, [spec("analog-value,99", ref("present-value"))])
    assert isinstance(response, Error)
    assert response.apduInvokeID == INVOKE_ID
    assert response.errorClass == ErrorClass.object
    assert response.errorCode == ErrorCode.unknownObject

    app.close()

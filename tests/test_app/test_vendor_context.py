#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Test Vendor Context
-------------------

Two vendors may assign the same proprietary object type and property
identifier to different datatypes.  Interpreting a value must depend only on
the confirmed vendor context of the device it came from, never on the most
recently registered class for that number.
"""

from __future__ import annotations

import asyncio

import pytest

from bacpypes3.apdu import (
    APDU,
    ReadPropertyACK,
    ReadPropertyRequest,
    WritePropertyRequest,
)
from bacpypes3.app import Application
from bacpypes3.basetypes import PropertyReference
from bacpypes3.constructeddata import Any
from bacpypes3.errors import AbortOther
from bacpypes3.object import Object
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import (
    Boolean,
    ObjectIdentifier,
    ObjectType,
    PropertyIdentifier,
    Unsigned,
)
from bacpypes3.vendor import (
    ASHRAE_vendor_info,
    VendorInfo,
    lookup_vendor_info,
    resolve_object_class,
    resolve_property_type,
)

ADDRESS = Address("1.2.3.4")

# object type 128 and property 512 are both in the vendor ranges
vendor_object_type = 128
vendor_property = 512


class VendorAObjectType(ObjectType):
    vendor_object = vendor_object_type


class VendorAPropertyIdentifier(PropertyIdentifier):
    vendorAMode = vendor_property


class VendorBObjectType(ObjectType):
    vendor_object = vendor_object_type


class VendorBPropertyIdentifier(PropertyIdentifier):
    vendorBLevel = vendor_property


@pytest.fixture(scope="module")
def vendor_a() -> VendorInfo:
    return VendorInfo(9701, VendorAObjectType, VendorAPropertyIdentifier)


@pytest.fixture(scope="module")
def vendor_b() -> VendorInfo:
    return VendorInfo(9702, VendorBObjectType, VendorBPropertyIdentifier)


@pytest.fixture(scope="module")
def vendor_classes(vendor_a, vendor_b):
    class VendorAObject(Object):
        _vendor_id = 9701
        objectType = VendorAObjectType(vendor_object_type)
        vendorAMode: Boolean

    class VendorBObject(Object):
        _vendor_id = 9702
        objectType = VendorBObjectType(vendor_object_type)
        vendorBLevel: Unsigned

    return VendorAObject, VendorBObject


class TrapApplication(Application):
    """Answer ReadProperty with a raw encoded value and record writes."""

    def __init__(self, vendor_info, value, *args, **kwds):
        super().__init__(*args, **kwds)
        self.vendor_info = vendor_info
        self.value = value
        self.requests = []

    def request(self, apdu: APDU) -> asyncio.Future:
        self.requests.append(apdu)
        future: asyncio.Future = asyncio.Future()
        if isinstance(apdu, ReadPropertyRequest):
            future.set_result(
                ReadPropertyACK(
                    objectIdentifier=apdu.objectIdentifier,
                    propertyIdentifier=apdu.propertyIdentifier,
                    propertyValue=Any(self.value),
                )
            )
        else:
            future.set_result(AbortOther())
        return future


class TestSameNumberDifferentTypes:
    def test_registration_is_isolated(self, vendor_a, vendor_b, vendor_classes):
        VendorAObject, VendorBObject = vendor_classes

        assert vendor_a.get_object_class(vendor_object_type) is VendorAObject
        assert vendor_b.get_object_class(vendor_object_type) is VendorBObject
        assert (
            vendor_a.get_object_class(vendor_object_type).get_property_type(
                vendor_property
            )
            is Boolean
        )
        assert (
            vendor_b.get_object_class(vendor_object_type).get_property_type(
                vendor_property
            )
            is Unsigned
        )

    def test_registration_order_does_not_matter(self, vendor_a, vendor_b):
        # resolving repeatedly, in either order, keeps each definition
        for _ in range(3):
            assert (
                resolve_property_type(vendor_a, vendor_object_type, vendor_property)
                is Boolean
            )
            assert (
                resolve_property_type(vendor_b, vendor_object_type, vendor_property)
                is Unsigned
            )

    def test_no_context_keeps_proprietary_raw(self):
        assert resolve_object_class(None, vendor_object_type) is None
        assert resolve_property_type(None, vendor_object_type, vendor_property) is None

    def test_standard_numbers_still_resolve_without_vendor(self):
        analog_value = resolve_object_class(None, ObjectType.analogValue)
        assert analog_value is not None
        assert (
            resolve_property_type(
                None, ObjectType.analogValue, PropertyIdentifier.presentValue
            )
            is not None
        )

    def test_standard_fallback_is_not_proprietary(self, vendor_a):
        # a vendor interpretation may use standard classes for standard
        # object types, but never a proprietary class for a standard number
        assert vendor_a.get_object_class(ObjectType.analogValue) is not None
        assert vendor_a.get_object_class(vendor_object_type) is not None
        assert ASHRAE_vendor_info.get_object_class(vendor_object_type) is None


class TestInterleavedReadWrite:
    async def test_read_interleaved(self, vendor_a, vendor_b):
        app_a = TrapApplication(vendor_a, Boolean(True))
        app_b = TrapApplication(vendor_b, Unsigned(7))
        try:
            for _ in range(2):
                value_a = await app_a.read_property(
                    ADDRESS,
                    ObjectIdentifier((vendor_object_type, 1)),
                    VendorAPropertyIdentifier("vendorAMode"),
                    vendor_info=vendor_a,
                )
                value_b = await app_b.read_property(
                    ADDRESS,
                    ObjectIdentifier((vendor_object_type, 1)),
                    VendorBPropertyIdentifier("vendorBLevel"),
                    vendor_info=vendor_b,
                )
                assert type(value_a) is Boolean
                assert value_a == Boolean(True)
                assert type(value_b) is Unsigned
                assert value_b == Unsigned(7)
        finally:
            app_a.close()
            app_b.close()

    async def test_read_without_context_keeps_raw(self, vendor_a):
        app = TrapApplication(vendor_a, Unsigned(7))
        try:
            value = await app.read_property(
                ADDRESS,
                ObjectIdentifier((vendor_object_type, 1)),
                PropertyIdentifier(vendor_property),
            )
        finally:
            app.close()

        # not coerced to Boolean or Unsigned: the encoded value is kept
        assert isinstance(value, Any)
        assert value.tagList is not None

    async def test_write_uses_matching_context(self, vendor_a, vendor_b):
        app_a = TrapApplication(vendor_a, Unsigned(0))
        app_b = TrapApplication(vendor_b, Unsigned(0))
        try:
            await app_a.write_property(
                ADDRESS,
                ObjectIdentifier((vendor_object_type, 1)),
                VendorAPropertyIdentifier("vendorAMode"),
                True,
                vendor_info=vendor_a,
            )
            await app_b.write_property(
                ADDRESS,
                ObjectIdentifier((vendor_object_type, 1)),
                VendorBPropertyIdentifier("vendorBLevel"),
                9,
                vendor_info=vendor_b,
            )
        finally:
            app_a.close()
            app_b.close()

        request_a = app_a.requests[-1]
        request_b = app_b.requests[-1]
        assert isinstance(request_a, WritePropertyRequest)
        assert isinstance(request_b, WritePropertyRequest)

        # each write is encoded with its own vendor's datatype
        value_a = request_a.propertyValue.cast_out(Boolean)
        value_b = request_b.propertyValue.cast_out(Unsigned)
        assert value_a == Boolean(True)
        assert value_b == Unsigned(9)

    async def test_write_without_context_is_refused(self, vendor_a):
        app = TrapApplication(vendor_a, Unsigned(7))
        try:
            with pytest.raises(ValueError, match="no property type"):
                await app.write_property(
                    ADDRESS,
                    ObjectIdentifier((vendor_object_type, 1)),
                    PropertyIdentifier(vendor_property),
                    True,
                )
        finally:
            app.close()

        assert app.requests == []

    async def test_parse_and_read_share_context(self, vendor_a):
        app = TrapApplication(vendor_a, Boolean(True))
        try:
            reference = await app.parse_object_property_reference(
                "128,1",
                "vendorAMode",
                vendor_info=vendor_a,
            )
            assert reference.propertyIdentifier == VendorAPropertyIdentifier(
                "vendorAMode"
            )

            value = await app.read_property(
                ADDRESS,
                reference.objectIdentifier,
                reference.propertyIdentifier,
                reference.propertyArrayIndex,
                vendor_info=vendor_a,
            )
            assert value == Boolean(True)
        finally:
            app.close()


class TestFailedRegistration:
    def test_duplicate_vendor_does_not_replace(self, vendor_a):
        with pytest.raises(RuntimeError, match="already registered"):
            VendorInfo(
                vendor_a.vendor_identifier,
                VendorBObjectType,
                VendorBPropertyIdentifier,
            )
        assert lookup_vendor_info(vendor_a.vendor_identifier) is vendor_a

    def test_invalid_arguments_leave_registry_untouched(self):
        with pytest.raises(TypeError):
            VendorInfo(9710, object_type=Boolean)
        assert lookup_vendor_info(9710) is None

        with pytest.raises(ValueError):
            VendorInfo(-1)
        assert lookup_vendor_info(-1) is None

    def test_duplicate_object_class_is_preserved(self, vendor_b, vendor_classes):
        VendorAObject, _VendorBObject = vendor_classes
        previous = vendor_b.get_object_class(vendor_object_type)

        with pytest.warns(UserWarning, match="already registered"):
            vendor_b.register_object_class(vendor_object_type, VendorAObject)

        assert vendor_b.get_object_class(vendor_object_type) is previous

    def test_invalid_object_class_is_rejected(self, vendor_a):
        with pytest.raises(TypeError):
            vendor_a.register_object_class(vendor_object_type, "not a class")
        assert vendor_a.get_object_class(vendor_object_type) is not None


class TestIAmVendorIsNotTrusted:
    async def test_iam_vendor_does_not_select_interpretation(self, vendor_a):
        from bacpypes3.apdu import IAmRequest

        app = Application()
        i_am = IAmRequest(
            iAmDeviceIdentifier=ObjectIdentifier(("device", 42)),
            maxAPDULengthAccepted=1024,
            segmentationSupported="noSegmentation",
            vendorID=vendor_a.vendor_identifier,
            source=ADDRESS,
        )
        try:
            device_info = await app.device_info_cache.set_device_info(i_am)
            assert device_info.vendor_identifier == vendor_a.vendor_identifier
            assert device_info.vendor_identifier_trusted is False

            vendor_info = await app.get_vendor_info(device_address=ADDRESS)
            assert vendor_info is None

            # the proprietary name is not available without a trusted
            # context, and must not be guessed from another vendor
            with pytest.raises(ValueError):
                await app.parse_property_reference(
                    "vendorAMode", device_address=ADDRESS
                )

            # a numeric reference still parses, but stays a plain standard
            # enumerator carrying the raw number
            reference = await app.parse_property_reference(
                str(vendor_property), device_address=ADDRESS
            )
            assert reference.propertyIdentifier == vendor_property
        finally:
            app.close()

    async def test_explicit_trust_enables_context(self, vendor_a):
        from bacpypes3.apdu import IAmRequest

        app = Application()
        i_am = IAmRequest(
            iAmDeviceIdentifier=ObjectIdentifier(("device", 43)),
            maxAPDULengthAccepted=1024,
            segmentationSupported="noSegmentation",
            vendorID=vendor_a.vendor_identifier,
            source=ADDRESS,
        )
        try:
            await app.device_info_cache.set_device_info(
                i_am, vendor_identifier_trusted=True
            )
            vendor_info = await app.get_vendor_info(device_address=ADDRESS)
            assert vendor_info is vendor_a
        finally:
            app.close()

    async def test_changed_vendor_drops_trust(self, vendor_a, vendor_b):
        from bacpypes3.apdu import IAmRequest

        def i_am(vendor_identifier):
            return IAmRequest(
                iAmDeviceIdentifier=ObjectIdentifier(("device", 44)),
                maxAPDULengthAccepted=1024,
                segmentationSupported="noSegmentation",
                vendorID=vendor_identifier,
                source=ADDRESS,
            )

        app = Application()
        try:
            await app.device_info_cache.set_device_info(
                i_am(vendor_a.vendor_identifier), vendor_identifier_trusted=True
            )
            assert await app.get_vendor_info(device_address=ADDRESS) is vendor_a

            await app.device_info_cache.set_device_info(
                i_am(vendor_b.vendor_identifier)
            )
            device_info = await app.get_device_info(ADDRESS)
            assert device_info.vendor_identifier == vendor_b.vendor_identifier
            assert device_info.vendor_identifier_trusted is False
            assert await app.get_vendor_info(device_address=ADDRESS) is None
        finally:
            app.close()


class TestObjectConstruction:
    def test_object_identity_uses_vendor_types(self, vendor_classes):
        VendorAObject, VendorBObject = vendor_classes

        object_a = VendorAObject(
            objectIdentifier=(vendor_object_type, 1),
            objectName="vendor-a",
            vendorAMode=True,
        )
        object_b = VendorBObject(
            objectIdentifier=(vendor_object_type, 1),
            objectName="vendor-b",
            vendorBLevel=7,
        )

        # each object round-trips its proprietary identity and value with
        # its own enumeration, not the most recently defined one
        assert str(object_a.objectIdentifier) == "vendor_object,1"
        assert str(object_b.objectIdentifier) == "vendor_object,1"
        assert object_a.vendorAMode == Boolean(True)
        assert object_b.vendorBLevel == Unsigned(7)

    def test_unregistered_vendor_cannot_define_classes(self):
        with pytest.raises(RuntimeError, match="no vendor information"):

            class StrayObject(Object):
                _vendor_id = 9999
                objectType = ObjectType(201)
                strayProperty: Boolean


class TestReadPropertyMultiple:
    async def test_interleaved_multiple(self, vendor_a, vendor_b):
        from bacpypes3.apdu import ReadPropertyMultipleACK
        from bacpypes3.basetypes import (
            ReadAccessResult,
            ReadAccessResultElement,
            ReadAccessResultElementChoice,
        )

        class RPMApplication(Application):
            def __init__(self, results, *args, **kwds):
                super().__init__(*args, **kwds)
                self.results = results

            def request(self, apdu: APDU) -> asyncio.Future:
                future: asyncio.Future = asyncio.Future()
                future.set_result(
                    ReadPropertyMultipleACK(listOfReadAccessResults=self.results)
                )
                return future

        def result(value):
            return ReadAccessResult(
                objectIdentifier=ObjectIdentifier((vendor_object_type, 1)),
                listOfResults=[
                    ReadAccessResultElement(
                        propertyIdentifier=PropertyIdentifier(vendor_property),
                        readResult=ReadAccessResultElementChoice(
                            propertyValue=Any(value)
                        ),
                    )
                ],
            )

        app_a = RPMApplication([result(Boolean(True))])
        app_b = RPMApplication([result(Unsigned(7))])
        try:
            value_a = await app_a.read_property_multiple(
                ADDRESS,
                [(ObjectIdentifier((vendor_object_type, 1)), ["vendorAMode"])],
                vendor_info=vendor_a,
            )
            value_b = await app_b.read_property_multiple(
                ADDRESS,
                [(ObjectIdentifier((vendor_object_type, 1)), ["vendorBLevel"])],
                vendor_info=vendor_b,
            )
        finally:
            app_a.close()
            app_b.close()

        assert value_a[0][3] == Boolean(True)
        assert type(value_a[0][3]) is Boolean
        assert value_b[0][3] == Unsigned(7)
        assert type(value_b[0][3]) is Unsigned


class TestLegacyDefaults:
    def test_get_vendor_info_still_defaults_to_ashrae(self):
        from bacpypes3.vendor import get_vendor_info

        assert get_vendor_info(12345) is ASHRAE_vendor_info

    def test_property_reference_standard_default(self):
        reference = PropertyReference("present-value")
        assert reference.propertyIdentifier == PropertyIdentifier.presentValue

    def test_property_reference_numeric_vendor_value(self):
        reference = PropertyReference(str(vendor_property))
        assert reference.propertyIdentifier == vendor_property

    async def test_old_style_vendor_identifier_still_works(self, vendor_a):
        # the historical call style passes vendor_identifier rather than a
        # VendorInfo; a registered identifier still resolves strictly
        app = Application()
        try:
            reference = await app.parse_property_reference(
                "vendorAMode", vendor_identifier=vendor_a.vendor_identifier
            )
            assert reference.propertyIdentifier == VendorAPropertyIdentifier(
                "vendorAMode"
            )

        finally:
            app.close()

    def test_configured_standard_objects_work_without_vendor(self):
        # an application may be configured with only standard objects even
        # if its vendor identifier has no registered proprietary classes
        objects = [
            {
                "object-identifier": "device,1",
                "object-type": "device",
                "object-name": "unregistered-vendor",
                "vendor-identifier": 424242,
                "vendor-name": "v",
                "model-name": "m",
                "firmware-revision": "f",
                "application-software-version": "a",
                "protocol-version": 1,
                "protocol-revision": 22,
                "database-revision": 1,
                "max-apdu-length-accepted": 1024,
                "segmentation-supported": "no-segmentation",
                "apdu-timeout": 3000,
                "number-of-apdu-retries": 3,
                "apdu-segment-timeout": 1000,
                "system-status": "operational",
            }
        ]
        app = Application.from_json(objects)
        try:
            assert app.device_object.vendorIdentifier == 424242
        finally:
            app.close()

    def test_configured_proprietary_objects_need_vendor(self):
        objects = [
            {
                "object-identifier": "device,1",
                "object-type": "device",
                "object-name": "unregistered-vendor",
                "vendor-identifier": 424242,
            },
            {
                "object-identifier": f"{vendor_object_type},1",
                "object-type": str(vendor_object_type),
                "object-name": "proprietary",
            },
        ]
        with pytest.raises(RuntimeError, match="unsupported object type"):
            Application.from_json(objects)

    async def test_unknown_vendor_identifier_is_not_ashrae(self):
        # previously an unknown vendor silently got the ASHRAE tables; the
        # strict path now reports no context instead
        app = Application()
        try:
            with pytest.raises(ValueError):
                await app.parse_property_reference(
                    "vendorAMode", vendor_identifier=99999
                )
            assert await app.get_vendor_info(vendor_identifier=99999) is None
        finally:
            app.close()

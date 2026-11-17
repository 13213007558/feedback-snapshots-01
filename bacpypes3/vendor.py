"""
Vendor
"""

# mypy: ignore-errors

from __future__ import annotations

import threading
import warnings

from typing import (
    Callable,
    Dict,
    Optional,
    Tuple,
)

from .debugging import ModuleLogger, DebugContents, bacpypes_debugging
from .primitivedata import ObjectIdentifier, ObjectType, PropertyIdentifier

# some debugging
_debug = 0
_log = ModuleLogger(globals())


#
#   VendorInfo
#


ASHRAE_vendor_info: VendorInfo
_vendor_info: Dict[int, VendorInfo] = {}
_vendor_info_lock = threading.RLock()


def get_vendor_info(vendor_identifier: int) -> VendorInfo:
    """Return vendor information, defaulting to ASHRAE for unknown vendors.

    This is the historical lookup and is intentionally forgiving: an
    unregistered vendor gets the standard (vendor 0) interpretation.  New
    code that interprets wire values should use :func:`lookup_vendor_info`
    and keep values raw when the vendor has not been explicitly confirmed.
    """
    global _vendor_info, ASHRAE_vendor_info

    with _vendor_info_lock:
        return _vendor_info.get(vendor_identifier, ASHRAE_vendor_info)


def lookup_vendor_info(vendor_identifier: Optional[int]) -> Optional[VendorInfo]:
    """Return the vendor information registered for an identifier.

    Unlike :func:`get_vendor_info` this never substitutes the ASHRAE
    interpretation for an unknown vendor.  ``None`` means there is no
    confirmed vendor context, so callers must not guess proprietary object
    or property types from a number alone.
    """
    global _vendor_info

    if vendor_identifier is None:
        return None
    with _vendor_info_lock:
        return _vendor_info.get(vendor_identifier, None)


# The property and object type ranges reserved for vendors.  Values inside
# these ranges have no meaning without a vendor context.
_property_identifier_vendor_range = PropertyIdentifier._vendor_range
_object_type_vendor_range = ObjectType._vendor_range


def property_identifier_is_standard(identifier: int) -> bool:
    """Return True if a property identifier is in the standard range."""
    return not (
        _property_identifier_vendor_range[0]
        <= int(identifier)
        <= _property_identifier_vendor_range[1]
    )


def object_type_is_standard(identifier: int) -> bool:
    """Return True if an object type is in the standard range."""
    return not (
        _object_type_vendor_range[0] <= int(identifier) <= _object_type_vendor_range[1]
    )


def device_vendor_info(device_info) -> Optional[VendorInfo]:
    """Return the vendor context of a device record, if it is trusted.

    The vendor identifier in an I-Am is self-reported.  It is useful for
    discovery and diagnostics, but it is not authentication.  Only a
    device record explicitly marked as trusted contributes a vendor context
    to object construction or service decoding.
    """
    if device_info is None:
        return None
    if not getattr(device_info, "vendor_identifier_trusted", False):
        return None
    return lookup_vendor_info(getattr(device_info, "vendor_identifier", None))


def resolve_object_class(
    vendor_info: Optional[VendorInfo], object_type: int
) -> Optional[type]:
    """Resolve an object type with one consistent vendor interpretation.

    Standard object types may always be interpreted with the ASHRAE
    classes.  Proprietary object types require a vendor context; without
    one the caller gets ``None`` and must keep the wire value raw rather
    than applying the most recently registered class for that number.
    """
    object_type = int(object_type)

    if vendor_info is not None:
        return vendor_info.get_object_class(object_type)
    if object_type_is_standard(object_type):
        return ASHRAE_vendor_info.get_object_class(object_type)
    return None


def resolve_property_type(
    vendor_info: Optional[VendorInfo],
    object_type: int,
    property_identifier: int,
) -> Optional[type]:
    """Resolve a property type with one consistent vendor interpretation.

    This is the single lookup used by registration validation, object
    construction, and read/write services.  A proprietary property number
    without a vendor context is deliberately unresolved instead of falling
    back to a standard or recently registered definition.
    """
    object_type = int(object_type)
    property_identifier = int(property_identifier)

    if (vendor_info is None) and not property_identifier_is_standard(
        property_identifier
    ):
        return None

    object_class = resolve_object_class(vendor_info, object_type)
    if object_class is None:
        return None
    return object_class.get_property_type(property_identifier)


@bacpypes_debugging
class VendorInfo(DebugContents):
    """Object and property type interpretation for one vendor.

    Registration is transactional: all arguments are validated before the
    vendor is published in the global registry, and a duplicate identifier
    raises before any existing definition is changed.  Object classes are
    registered separately with :meth:`register_object_class`, which also
    preserves an existing class instead of replacing it.
    """

    _debug: Callable[..., None]
    _debug_contents: Tuple[str, ...] = (
        "vendor_identifier",
        "object_type",
        "object_identifier",
        "property_identifier",
    )

    vendor_identifier: int
    registered_object_classes: Dict[int, type]

    object_type: type
    object_identifier: type
    property_identifier: type

    def __init__(
        self,
        vendor_identifier: int,
        object_type: Optional[type] = None,
        property_identifier: Optional[type] = None,
    ) -> None:
        if _debug:
            VendorInfo._debug("__init__ %r ...", vendor_identifier)

        # Validate everything before touching the global registry so a
        # failed registration leaves the previous definitions untouched.
        if not isinstance(vendor_identifier, int) or isinstance(
            vendor_identifier, bool
        ):
            raise TypeError("vendor identifier must be an integer")
        if vendor_identifier < 0:
            raise ValueError("vendor identifier must be non-negative")
        if object_type is not None:
            if not isinstance(object_type, type) or not issubclass(
                object_type, ObjectType
            ):
                raise TypeError("object type must be an ObjectType subclass")
        if property_identifier is not None:
            if not isinstance(property_identifier, type) or not issubclass(
                property_identifier, PropertyIdentifier
            ):
                raise TypeError(
                    "property identifier must be a PropertyIdentifier subclass"
                )

        with _vendor_info_lock:
            if vendor_identifier in _vendor_info:
                raise RuntimeError(
                    f"vendor identifier already registered: {vendor_identifier!r}"
                )

        self.vendor_identifier = vendor_identifier
        self.registered_object_classes = {}

        # reference the object type class
        if object_type:
            self.object_type = object_type

            # build an object identifier class with the specialized object type
            self.object_identifier = type(
                "ObjectIdentifier!",
                (ObjectIdentifier,),
                {
                    "_vendor_id": vendor_identifier,
                    "object_type_class": object_type,
                },
            )
        else:
            self.object_type = ObjectType
            self.object_identifier = ObjectIdentifier

        # there might be special property identifiers
        self.property_identifier = property_identifier or PropertyIdentifier

        # Publish only after every attribute was built successfully.
        with _vendor_info_lock:
            if vendor_identifier in _vendor_info:
                raise RuntimeError(
                    f"vendor identifier already registered: {vendor_identifier!r}"
                )
            _vendor_info[vendor_identifier] = self

    def register_object_class(self, object_type: int, object_class: type) -> None:
        if _debug:
            VendorInfo._debug(
                "register_object_class(%d) %r %r",
                self.vendor_identifier,
                object_type,
                object_class,
            )

        if not isinstance(object_class, type):
            raise TypeError("object class must be a type")

        if object_type in self.registered_object_classes:
            # built-in classes have multiple classes with different features
            if self.vendor_identifier != 999:
                warnings.warn(
                    f"object type {object_type!r}"
                    f" for vendor identifier {self.vendor_identifier}"
                    f" already registered: {self.registered_object_classes[object_type]}"
                )
            return

        self.registered_object_classes[object_type] = object_class

    def get_object_class(self, object_type: int) -> Optional[type]:
        if _debug:
            VendorInfo._debug(
                "get_object_class(%d) %r",
                self.vendor_identifier,
                object_type,
            )

        object_class = self.registered_object_classes.get(object_type, None)
        if object_class is not None:
            return object_class

        # Standard object types are shared by every vendor.  Proprietary
        # object types are not: falling back to ASHRAE (or to another
        # vendor) here is what made the same number change meaning with the
        # most recent registration.
        if object_type_is_standard(object_type):
            return ASHRAE_vendor_info.registered_object_classes.get(object_type, None)
        return None


# ASHRAE is Vendor ID 0
ASHRAE_vendor_info = VendorInfo(0)

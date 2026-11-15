from __future__ import annotations

import struct
from enum import Enum, Flag, IntEnum, IntFlag, auto
from typing import TYPE_CHECKING, Any, NamedTuple

from dissect.util.sid import read_sid, write_sid
from dissect.util.ts import wintimestamp

from dissect.database.ese.ntds.c_ds import c_ds

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.objects import Object
    from dissect.database.ese.ntds.schema import AttributeEntry


class DatabaseFlag(Flag):
    """Database flags that are stored in the hiddentable.

    The flags are weirdly stored as ``1``, ``0`` or ``\x00`` in a byte array.
    To make parsing a bit easier, we use the index of each flag in this class as the character offset in the byte array.
    """

    AUXCLASS = auto()
    SD_CONVERSION_REQUIRED = auto()
    ROOT_GUID_UPDATED = auto()
    ADAM = auto()
    ASCII_INDICES_REBUILT = auto()
    SHOW_IN_AB_ARRAY_REBUILD = auto()
    UPDATE_NC_TYPE_REQUIRED = auto()
    LINK_QUOTA_USN = auto()


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
class InstanceType(IntFlag):
    HeadOfNamingContext = 0x00000001
    ReplicaNotInstantiated = 0x00000002
    Writable = 0x00000004
    ParentNamingContextHeld = 0x00000008
    NamingContextUnderConstruction = 0x00000010
    NamingContextDeleting = 0x00000020


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-systemflags
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1e38247d-8234-4273-9de3-bbf313548631
class SystemFlag(IntFlag):
    # The first 3 flags have an overlap whether it's set on an attributeSchema or crossRef object
    # We don't specify them here, see SystemFlagAttribute and SystemFlagCrossRef

    # The following flags are also specific to certain objects, but have no overlap
    ATTR_IS_OPERATIONAL = 0x00000008
    SCHEMA_BASE_OBJECT = 0x00000010
    ATTR_IS_RDN = 0x00000020
    DISALLOW_MOVE_ON_DELETE = 0x02000000
    DOMAIN_DISALLOW_MOVE = 0x04000000
    DOMAIN_DISALLOW_RENAME = 0x08000000
    CONFIG_ALLOW_LIMITED_MOVE = 0x10000000
    CONFIG_ALLOW_MOVE = 0x20000000
    CONFIG_ALLOW_RENAME = 0x40000000
    DISALLOW_DELETE = 0x80000000


# System flags that overlap with other flags and are specific to attributeSchema objects
class SystemFlagAttribute(IntFlag):
    ATTR_NOT_REPLICATED = 0x00000001
    ATTR_REQ_PARTIAL_SET_MEMBER = 0x00000002
    ATTR_IS_CONSTRUCTED = 0x00000004

    # TODO: When we drop Python 3.10 support, we can subclass SystemFlag
    # For now, just duplicate the flags here
    ATTR_IS_OPERATIONAL = 0x00000008
    SCHEMA_BASE_OBJECT = 0x00000010
    ATTR_IS_RDN = 0x00000020
    DISALLOW_MOVE_ON_DELETE = 0x02000000
    DOMAIN_DISALLOW_MOVE = 0x04000000
    DOMAIN_DISALLOW_RENAME = 0x08000000
    CONFIG_ALLOW_LIMITED_MOVE = 0x10000000
    CONFIG_ALLOW_MOVE = 0x20000000
    CONFIG_ALLOW_RENAME = 0x40000000
    DISALLOW_DELETE = 0x80000000


# For better readability when printing attributeSchema objects, we reset the name
SystemFlagAttribute.__name__ = "SystemFlag"


# System flags that overlap with other flags and are specific to crossRef objects
class SystemFlagCrossRef(IntFlag):
    CR_NTDS_NC = 0x00000001
    CR_NTDS_DOMAIN = 0x00000002
    CR_NTDS_NOT_GC_REPLICATED = 0x00000004

    # TODO: When we drop Python 3.10 support, we can subclass SystemFlag
    # For now, just duplicate the flags here
    ATTR_IS_OPERATIONAL = 0x00000008
    SCHEMA_BASE_OBJECT = 0x00000010
    ATTR_IS_RDN = 0x00000020
    DISALLOW_MOVE_ON_DELETE = 0x02000000
    DOMAIN_DISALLOW_MOVE = 0x04000000
    DOMAIN_DISALLOW_RENAME = 0x08000000
    CONFIG_ALLOW_LIMITED_MOVE = 0x10000000
    CONFIG_ALLOW_MOVE = 0x20000000
    CONFIG_ALLOW_RENAME = 0x40000000
    DISALLOW_DELETE = 0x80000000


# For better readability when printing crossRef objects, we reset the name
SystemFlagCrossRef.__name__ = "SystemFlag"


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557
class UserAccountControl(IntFlag):
    SCRIPT = 0x00000001
    ACCOUNTDISABLE = 0x00000002
    HOMEDIR_REQUIRED = 0x00000008
    LOCKOUT = 0x00000010
    PASSWD_NOTREQD = 0x00000020
    PASSWD_CANT_CHANGE = 0x00000040
    ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080
    TEMP_DUPLICATE_ACCOUNT = 0x00000100
    NORMAL_ACCOUNT = 0x00000200
    INTERDOMAIN_TRUST_ACCOUNT = 0x00000800
    WORKSTATION_TRUST_ACCOUNT = 0x00001000
    SERVER_TRUST_ACCOUNT = 0x00002000
    DONT_EXPIRE_PASSWORD = 0x00010000
    MNS_LOGON_ACCOUNT = 0x00020000
    SMARTCARD_REQUIRED = 0x00040000
    TRUSTED_FOR_DELEGATION = 0x00080000
    NOT_DELEGATED = 0x00100000
    USE_DES_KEY_ONLY = 0x00200000
    DONT_REQUIRE_PREAUTH = 0x00400000
    PASSWORD_EXPIRED = 0x00800000
    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000


class SAMAccountType(IntEnum):
    SAM_DOMAIN_OBJECT = 0x0
    SAM_GROUP_OBJECT = 0x10000000
    SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
    SAM_ALIAS_OBJECT = 0x20000000
    SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001
    SAM_USER_OBJECT = 0x30000000
    SAM_MACHINE_ACCOUNT = 0x30000001
    SAM_TRUST_ACCOUNT = 0x30000002
    SAM_APP_BASIC_GROUP = 0x40000000
    SAM_APP_QUERY_GROUP = 0x40000001


class SearchFlag(IntFlag):
    Indexed = 0x00000001
    ContainerIndexed = 0x00000002
    Anr = 0x00000004
    PreserveTombstone = 0x00000008
    CopyWithObject = 0x00000010
    TupleIndexed = 0x00000020
    VlvIndexed = 0x00000040
    Confidential = 0x00000080


class TrustType(IntEnum):
    DOWNLEVEL = 0x00000001
    UPLEVEL = 0x00000002
    MIT = 0x00000003
    DCE = 0x00000004
    AAD = 0x00000005


class TrustDirection(IntEnum):
    DISABLED = 0
    INBOUND = 1
    OUTBOUND = 2
    BIDIRECTIONAL = 3


class TrustAttribute(IntFlag):
    NON_TRANSITIVE = 0x00000001
    UPLEVEL_ONLY = 0x00000002
    FILTER_SIDS = 0x00000004
    FOREST_TRANSITIVE = 0x00000008
    CROSS_ORGANIZATION = 0x00000010
    WITHIN_FOREST = 0x00000020
    TREAT_AS_EXTERNAL = 0x00000040
    TRUST_USES_RC4_ENCRYPTION = 0x00000080
    TRUST_USES_AES_KEYS = 0x00000100
    CROSS_ORGANIZATION_NO_TGT_DELEGATION = 0x00000200
    PIM_TRUST = 0x00000400
    TREE_PARENT = 0x00400000
    TREE_ROOT = 0x00800000


class GroupPolicyOption(IntFlag):
    BLOCK_POLICY = 0x00000001


def _pek_decrypt(db: Database, value: bytes) -> bytes:
    """Decrypt a PEK-encrypted blob using the database's PEK, if it's unlocked.

    Args:
        db: The associated NTDS database instance.
        value: The PEK-encrypted data blob.

    Returns:
        The decrypted data blob, or the original value if the PEK is locked.
    """
    if db.pek is None or not db.pek.unlocked:
        return value

    return db.pek.decrypt(value)


def _decode_supplemental_credentials(db: Database, value: bytes) -> dict[str, bytes] | bytes:
    """Decode the ``supplementalCredentials`` attribute.

    Args:
        db: The associated NTDS database instance.
        value: The raw bytes of the ``supplementalCredentials`` attribute.

    Returns:
        A dictionary mapping credential types to their data blobs, or the original value if the PEK is locked.
    """
    if db.pek is None or not db.pek.unlocked:
        return value

    value = db.pek.decrypt(value)
    header = c_ds.USER_PROPERTIES_HEADER(value)

    result = {}
    if header.PropertySignature == 0x50:  # 'P' as WORD in UTF-16-LE
        for prop in c_ds.USER_PROPERTY[header.PropertyCount](value[len(header) :]):
            prop_name = prop.PropertyName
            prop_value = bytes.fromhex(prop.PropertyValue.decode())

            if prop_name == "Packages":
                prop_value = prop_value.decode("utf-16-le").split("\x00")
            elif prop_name == "Primary:CLEARTEXT":
                prop_value = prop_value.decode("utf-16-le")
            elif prop_name == "Primary:Kerberos":
                parsed = c_ds.KERB_STORED_CREDENTIAL(prop_value)
                prop_value = {
                    "DefaultSalt": prop_value[
                        parsed.DefaultSaltOffset : parsed.DefaultSaltOffset + parsed.DefaultSaltLength
                    ],
                    "Credentials": [
                        {"KeyType": cred.KeyType, "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength]}
                        for cred in parsed.Credentials
                    ],
                    "OldCredentials": [
                        {"KeyType": cred.KeyType, "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength]}
                        for cred in parsed.OldCredentials
                    ],
                }
            elif prop_name == "Primary:Kerberos-Newer-Keys":
                parsed = c_ds.KERB_STORED_CREDENTIAL_NEW(prop_value)
                prop_value = {
                    "DefaultSalt": prop_value[
                        parsed.DefaultSaltOffset : parsed.DefaultSaltOffset + parsed.DefaultSaltLength
                    ],
                    "DefaultIterationCount": parsed.DefaultIterationCount,
                    "Credentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.Credentials
                    ],
                    "ServiceCredentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.ServiceCredentials
                    ],
                    "OldCredentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.OldCredentials
                    ],
                    "OlderCredentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.OlderCredentials
                    ],
                }
            elif prop_name == "Primary:WDigest":
                parsed = c_ds.WDIGEST_CREDENTIALS(prop_value)
                prop_value = list(parsed.Hash)

            result[prop_name] = prop_value
    else:
        # Probably AD LDS format, check some heuristics
        # TODO: Properly research AD LDS supplementalCredentials format
        header = c_ds.ADAM_PROPERTIES_HEADER(value)
        if header.Reserved6 == len(value) - len(header) and header.Reserved3 == len(value) - len(header) + 8:
            # Looks like AD LDS format
            parsed = c_ds.WDIGEST_CREDENTIALS(value[len(header) :])

            # Make up some keys to match the other result
            result["Packages"] = ["WDigest"]
            result["Primary:WDigest"] = list(parsed.Hash)
        else:
            # Bail out, unknown format
            return value

    return result


def _decode_pwd_history(db: Database, value: list[bytes]) -> list[bytes]:
    """Decode the ``ntPwdHistory`` or ``lmPwdHistory`` attribute value.

    Args:
        db: The associated NTDS database instance.
        value: The raw list of bytes values for the password history attribute.

    Returns:
        A list of decrypted password hashes, or the original value if the PEK is locked.
    """
    if db.pek is None or not db.pek.unlocked:
        return value

    result = []
    for buf in value:
        buf = db.pek.decrypt(buf)
        # The history attributes can contain multiple hashes concatenated together, so we need to split them up
        # NT and LM hashes are both 16 bytes long
        result.extend(buf[i : i + 16] for i in range(0, len(buf), 16))

    return result


ATTRIBUTE_ENCODE_DECODE_MAP: dict[
    str, tuple[Callable[[Database, Any], Any] | None, Callable[[Database, Any], Any] | None]
] = {
    # Protected attributes
    "unicodePwd": (None, _pek_decrypt),
    "dBCSPwd": (None, _pek_decrypt),
    "ntPwdHistory": (None, _pek_decrypt),
    "lmPwdHistory": (None, _pek_decrypt),
    "supplementalCredentials": (None, _decode_supplemental_credentials),
    "currentValue": (None, _pek_decrypt),
    "priorValue": (None, _pek_decrypt),
    "initialAuthIncoming": (None, _pek_decrypt),
    "initialAuthOutgoing": (None, _pek_decrypt),
    "trustAuthIncoming": (None, _pek_decrypt),
    "trustAuthOutgoing": (None, _pek_decrypt),
    "msDS-ExecuteScriptPassword": (None, _pek_decrypt),
}

ATTRIBUTE_LIST_ENCODE_DECODE_MAP: dict[
    str, tuple[Callable[[Database, list[Any]], list[Any]], Callable[[Database, list[Any]], list[Any]]]
] = {
    "ntPwdHistory": (None, _decode_pwd_history),
    "lmPwdHistory": (None, _decode_pwd_history),
}


def _ldapDisplayName_to_DNT(db: Database, value: str) -> int | str:
    """Convert an LDAP display name to its corresponding DNT value.

    Args:
        db: The associated NTDS database instance.
        value: The LDAP display name to look up.

    Returns:
        The DNT value or the original value if not found.
    """
    if (schema := db.data.schema.lookup(name=value)) is not None:
        return schema.dnt
    return value


def _DNT_to_ldapDisplayName(db: Database, value: int) -> str | DN | int:
    """Convert a DNT value to its corresponding LDAP display name or distinguished name.

    For attributes and classes, the LDAP display name is returned. For objects, the distinguished name is returned.

    Args:
        db: The associated NTDS database instance.
        value: The Directory Number Tag to look up.

    Returns:
        The LDAP display name or the original value if not found.
    """
    if (schema := db.data.schema.lookup(dnt=value)) is not None:
        return schema.name

    try:
        return db.data._make_dn(value)
    except Exception:
        return value


class DN(str):
    """A distinguished name (DN) string wrapper. Presents the DN as a string but also retains the underlying object."""

    __slots__ = ("object", "parent")

    object: Object
    parent: DN | None

    def __new__(cls, value: str, object: Object, parent: DN | None = None):
        instance = super().__new__(cls, value)
        instance.object = object
        instance.parent = parent
        return instance


def _oid_to_attrtyp(db: Database, value: str) -> int:
    """Convert OID string or LDAP display name to ATTRTYP value.

    Supported formats::

        objectClass=person          (LDAP display name)
        objectClass=2.5.6.6         (OID string)
        objectClass=OID.2.5.6.6     (OID string)

    Args:
        db: The associated NTDS database instance.
        value: Either an OID string (contains dots) or LDAP display name.

    Returns:
        ATTRTYP integer value.
    """
    if "." in value:
        value = value.removeprefix("OID.")
        if (schema := db.data.schema.lookup_oid(value)) is not None:
            return schema.id

    if (schema := db.data.schema.lookup(name=value)) is not None:
        return schema.id

    raise ValueError(f"Attribute or class not found for value: {value!r}")


def _attrtyp_to_oid(db: Database, value: int) -> str:
    """Convert ATTRTYP integer value to attribute name.

    For convenience, we return the attribute or class name instead of the OID string.

    Args:
        db: The associated NTDS database instance.
        value: The ATTRTYP integer value.

    Returns:
        The attribute name or the original value if not found.
    """
    if (schema := db.data.schema.lookup(attrtyp=value)) is not None:
        return schema.name

    raise ValueError(f"Attribute not found for ATTRTYP value: {value!r}")


def _attrtyp_to_oid_lenient(db: Database, value: int) -> str | int:
    """Convert an ATTRTYP value to a name/OID without raising, for decoding stored values.

    Used on the decode path where an extended schema may contain ATTRTYP values (for example in
    ``objectClass``) that have no registered class or attribute definition. The raw integer is preserved
    instead of raising, so a single unknown class cannot make the whole object unreadable.

    Args:
        db: The associated NTDS database instance.
        value: The ATTRTYP integer value.

    Returns:
        The resolved display name, the resolved OID string, or the original integer if unresolved.
    """
    if (schema := db.data.schema.lookup(attrtyp=value)) is not None:
        return schema.name

    return db.data.schema.attrtyp_to_oid(value) or value


def _binary_to_dn(db: Database, value: bytes) -> tuple[int, bytes]:
    """Convert DN-Binary to the separate (DN, binary) tuple.

    Args:
        db: The associated NTDS database instance.
        value: The binary DN value.

    Returns:
        A tuple of the DNT and the binary data as hex.
    """
    dnt, length = struct.unpack("<II", value[:8])
    return dnt, value[8 : 8 + length].hex()


# To be used when parsing LDAP queries into ESE-compatible data types
SYNTAX_ENCODE_DECODE_MAP: dict[
    int, tuple[Callable[[Database, Any], Any] | None, Callable[[Database, Any], Any] | None]
] = {
    # Object(DN-DN); The fully qualified name of an object
    1: (_ldapDisplayName_to_DNT, _DNT_to_ldapDisplayName),
    # String(Object-Identifier); The object identifier
    2: (_oid_to_attrtyp, _attrtyp_to_oid_lenient),
    # String(Object-Identifier); The object identifier
    3: (None, lambda db, value: str(value)),
    4: (None, lambda db, value: str(value)),
    5: (None, lambda db, value: str(value)),
    # String(Numeric); A sequence of digits
    6: (None, lambda db, value: str(value)),
    # Object(DN-Binary); A distinguished name plus a binary large object
    7: (None, _binary_to_dn),
    # Boolean; TRUE or FALSE values
    8: (lambda db, value: bool(value), lambda db, value: bool(value)),
    # Integer, Enumeration; A 32-bit number or enumeration
    9: (lambda db, value: int(value), lambda db, value: int(value)),
    # String(Octet); A string of bytes
    10: (None, lambda db, value: bytes(value)),
    # String(UTC-Time), String(Generalized-Time); UTC time or generalized-time
    11: (None, lambda db, value: wintimestamp(value * 10000000)),
    # String(Unicode); A Unicode string
    12: (None, lambda db, value: str(value)),
    # TODO: Object(Presentation-Address); Presentation address
    13: (None, None),
    # TODO: Object(DN-String); A DN-String plus a Unicode string
    14: (None, None),
    # NTSecurityDescriptor; A security descriptor
    15: (None, lambda db, value: db.sd.sd(int.from_bytes(value, byteorder="little"))),
    # LargeInteger; A 64-bit number
    16: (None, lambda db, value: int(value)),
    # String(Sid); Security identifier (SID)
    17: (
        lambda db, value: write_sid(value, swap_last=True),
        lambda db, value: read_sid(value, swap_last=True),
    ),
}


class DecodeReason(Enum):
    """Why a value could not be decoded with a specific rule.

    Each member names the exact definition that turned out to be insufficient, so callers never have to
    rely on a generic string to distinguish the cases.
    """

    NO_DECODER = "no decoder registered for the selected rule"
    UNKNOWN_SYNTAX = "attributeSyntax is not a known syntax"
    NAME_COLLISION = "lDAPDisplayName is shared by multiple distinct attributes; the name-specific rule was not applied"
    MISSING_SCHEMA = "no schema entry maps the column to an attribute definition"


class UndecodedValue:
    """A value that could not be decoded, kept losslessly together with the reason.

    The raw value is always retained (and still reachable as bytes), together with the schema entry and
    the precise reason decoding was not possible. Multi-valued attributes may contain a mix of decoded
    values and :class:`UndecodedValue` instances.

    Args:
        raw: The original, untouched value as stored in the record.
        schema: The attribute schema entry, or ``None`` if no schema entry exists at all.
        reason: The precise reason no decoding rule could be applied.
        detail: An optional human-readable clarification of the reason.
    """

    __slots__ = ("detail", "raw", "reason", "schema")

    def __init__(
        self,
        raw: Any,
        schema: AttributeEntry | None,
        reason: DecodeReason,
        detail: str | None = None,
    ):
        self.raw = raw
        self.schema = schema
        self.reason = reason
        self.detail = detail

    def __repr__(self) -> str:
        name = self.schema.name if self.schema is not None else "<unknown attribute>"
        detail = f": {self.detail}" if self.detail else ""
        return f"<UndecodedValue attribute={name!r} reason={self.reason.name}{detail} raw={self.raw!r}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UndecodedValue):
            return NotImplemented
        return (
            self.raw == other.raw
            and self.reason is other.reason
            and self.detail == other.detail
            and (self.schema is None) == (other.schema is None)
            and (self.schema is None or self.schema.id == other.schema.id)
        )

    def __bytes__(self) -> bytes:
        if isinstance(self.raw, bytes):
            return self.raw
        if isinstance(self.raw, memoryview):
            return self.raw.tobytes()
        raise TypeError(f"Raw value of {self!r} is not bytes")


class DecodeDecision(NamedTuple):
    """The rule selected (or not) for decoding an attribute, with the justification.

    Attributes:
        schema: The schema entry the decision is based on, or ``None`` if it could not be resolved.
        rule: Either ``"attribute"`` (name-specific rule), ``"syntax"`` (syntax-based rule) or ``None``.
        decoder: The callable that would be applied, or ``None`` when no usable decoder exists.
        reason: The precise reason a decoder could not be selected, or ``None`` when one was selected.
        detail: Optional human-readable clarification.
        ambiguous_name: Whether the attribute name collides with another distinct definition.
    """

    schema: AttributeEntry | None
    rule: str | None
    decoder: Callable[[Database, Any], Any] | None
    reason: DecodeReason | None
    detail: str | None
    ambiguous_name: bool


def _select_decoder(db: Database, schema: AttributeEntry | None) -> DecodeDecision:
    """Resolve which decoder applies to ``schema`` and record exactly why if none does.

    Name-specific rules only apply when the ``lDAPDisplayName`` uniquely identifies one attribute. On a
    name collision we deliberately fall through to the syntax-based rule rather than borrowing another
    attribute's decoder; the collision is retained as the rationale even when syntax decoding succeeds.
    When the syntax itself is unknown the raw value is wrapped instead of guessed.
    """
    if schema is None:
        return DecodeDecision(None, None, None, DecodeReason.MISSING_SCHEMA, None, False)

    ambiguous_name = db.data.schema.is_ambiguous_name(schema.name)

    collision_reason = None
    collision_detail = None
    if ambiguous_name:
        # The name maps to more than one ATTRTYP; any name-specific rule would decode this attribute with
        # a different attribute's rule. Even when no name rule happens to be registered, record that the
        # name alone is insufficient and continue with the syntax-based selection.
        collision_reason = DecodeReason.NAME_COLLISION
        collision_detail = f"lDAPDisplayName {schema.name!r} is shared by multiple attributes; resolved by syntax"
    else:
        _, decode = ATTRIBUTE_ENCODE_DECODE_MAP.get(schema.name, (None, None))
        if decode is not None:
            return DecodeDecision(schema, "attribute", decode, None, None, False)

    _, decode = SYNTAX_ENCODE_DECODE_MAP.get(schema.syntax, (None, None))
    if decode is not None:
        # On a collision the syntax rule still works, but the decision keeps the collision as rationale.
        return DecodeDecision(schema, "syntax", decode, collision_reason, collision_detail, ambiguous_name)

    if schema.syntax not in SYNTAX_ENCODE_DECODE_MAP:
        reason = DecodeReason.UNKNOWN_SYNTAX
        detail = f"attributeSyntax {schema.syntax} has no registered decoder"
    else:
        reason = DecodeReason.NO_DECODER
        detail = f"attributeSyntax {schema.syntax} is registered but has no decoder implementation"

    # A name collision that also lacks a usable syntax decoder is reported with the collision first,
    # since that is the more specific reason the obvious name rule could not be used.
    return DecodeDecision(
        schema,
        None,
        None,
        collision_reason or reason,
        collision_detail or detail,
        ambiguous_name,
    )


def encode_value(db: Database, schema: AttributeEntry, value: str) -> int | bytes | str:
    """Encode a string value according to the attribute's type.

    Args:
        db: The associated NTDS database instance.
        schema: The LDAP attribute schema.
        value: The string value to encode.

    Returns:
        The encoded value in the appropriate type for the attribute.
    """
    # First check the list of deviations
    encode, _ = ATTRIBUTE_ENCODE_DECODE_MAP.get(schema.name, (None, None))
    if encode is None:
        encode, _ = SYNTAX_ENCODE_DECODE_MAP.get(schema.syntax, (None, None))

    if encode is None:
        return value

    return encode(db, value)


def _decode_single(db: Database, schema: AttributeEntry | None, value: Any, decision: DecodeDecision) -> Any:
    """Apply a selected decoder to one value, wrapping it if the decoder itself cannot handle it."""
    try:
        return decision.decoder(db, value)
    except Exception as exc:  # noqa: BLE001 - keep the raw value losslessly on any decoder failure
        return UndecodedValue(
            value,
            schema,
            DecodeReason.NO_DECODER,
            f"{decision.rule} decoder failed: {exc}",
        )


def explain_decode(db: Database, schema: AttributeEntry | None, value: Any) -> tuple[Any, DecodeDecision]:
    """Decode ``value`` while also returning the :class:`DecodeDecision` that explains the selection.

    Undecodable values come back as :class:`UndecodedValue`, never as a generic string, and the decision
    states which definition (name rule, syntax rule, or none) was used and why.

    Args:
        db: The associated NTDS database instance.
        schema: The LDAP attribute schema, or ``None`` if unresolved.
        value: The raw value to decode.

    Returns:
        A tuple of the decoded value (or an :class:`UndecodedValue`) and the decision behind it.
    """
    if value is None:
        return None, _select_decoder(db, schema)

    # Multi-valued attributes have a separate set of name-specific list decoders (e.g. password history)
    if isinstance(value, list):
        name = schema.name if schema is not None else ""
        ambiguous = schema is not None and db.data.schema.is_ambiguous_name(schema.name)
        _, list_decode = ATTRIBUTE_LIST_ENCODE_DECODE_MAP.get(name, (None, None))
        if list_decode is not None and not ambiguous:
            decision = DecodeDecision(schema, "attribute", list_decode, None, None, False)
            return list_decode(db, value), decision

        base_decision = _select_decoder(db, schema)
        if not value:
            return [], base_decision

        # Decode each member independently so a single bad member never hides the rest
        decisions = [_select_decoder(db, schema) for _ in value]
        result = [
            UndecodedValue(member, schema, member_decision.reason, member_decision.detail)
            if member_decision.decoder is None
            else _decode_single(db, schema, member, member_decision)
            for member, member_decision in zip(value, decisions)
        ]
        return result, decisions[0]

    decision = _select_decoder(db, schema)
    if decision.decoder is None:
        return UndecodedValue(value, schema, decision.reason, decision.detail), decision

    return _decode_single(db, schema, value, decision), decision


def decode_value(db: Database, schema: AttributeEntry, value: Any) -> Any:
    """Decode a value according to the attribute's type.

    Args:
        db: The associated NTDS database instance.
        schema: The LDAP attribute schema.
        value: The value to decode.

    Returns:
        The decoded value in the appropriate Python type for the attribute, or an
        :class:`UndecodedValue` (possibly inside a list for multi-valued attributes) when no rule applies.
    """
    decoded, _ = explain_decode(db, schema, value)
    return decoded

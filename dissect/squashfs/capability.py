"""Interpretation of Linux ``security.capability`` extended attributes.

The ``security.capability`` attribute is a serialised ``struct vfs_cap_data`` (or
``struct vfs_ns_cap_data`` for revision 3). The revisions handled here are:

``VFS_CAP_REVISION_1``
    Obsolete 32-bit layout. It is decoded for completeness but is not supported by
    current kernels, so it never yields an effectiveness conclusion.
``VFS_CAP_REVISION_2``
    64-bit capability sets. 20 bytes: ``magic_etc`` followed by two interleaved
    ``{permitted, inheritable}`` 32-bit word pairs. Revision 2 values predate user
    namespace-aware file capabilities and are treated as belonging to the initial
    user namespace (implicit ``rootid`` 0).
``VFS_CAP_REVISION_3``
    Same as revision 2 plus a trailing 32-bit ``rootid``. 24 bytes.

The low bit of ``magic_etc`` is ``VFS_CAP_FLAGS_EFFECTIVE``. When set, the permitted
bits are also made effective when the file is executed. ``rootid`` records the UID of
the root user in the user namespace in which the capability was set, as seen from the
initial user namespace.

This module never executes firmware binaries. It decodes the stored attribute and
reasons about the user namespace supplied by the caller; it never uses the identity of
the machine performing the analysis. A conclusion of "effective" only means the
stored declaration is structurally valid, has the effective flag, and belongs to the
requested namespace. It is not a promise that a process can exploit the file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.squashfs.xattr import Xattr, XattrSource

SECURITY_CAPABILITY = "security.capability"

VFS_CAP_REVISION_MASK = 0xFF000000
VFS_CAP_REVISION_SHIFT = 24
VFS_CAP_FLAGS_EFFECTIVE = 0x000001
VFS_CAP_FLAGS_MASK = ~(VFS_CAP_REVISION_MASK | VFS_CAP_FLAGS_EFFECTIVE) & 0xFFFFFFFF
VFS_CAP_U32_1 = 1
VFS_CAP_U32_2 = 2

VFS_CAP_REVISION_1 = 0x01000000
VFS_CAP_REVISION_2 = 0x02000000
VFS_CAP_REVISION_3 = 0x03000000

# Exact serialised sizes. Revision 1 is included so a legacy value can be decoded,
# but only revisions 2 and 3 are supported by current kernels.
VFS_CAP_SIZES = {
    VFS_CAP_REVISION_1: 12,
    VFS_CAP_REVISION_2: 20,
    VFS_CAP_REVISION_3: 24,
}
SUPPORTED_REVISIONS = frozenset({VFS_CAP_REVISION_2, VFS_CAP_REVISION_3})

CAPABILITY_NAMES = (
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
)
CAP_LAST_CAP = len(CAPABILITY_NAMES) - 1


class CapabilityRevision(Enum):
    """Known ``VFS_CAP_REVISION_*`` values."""

    V1 = VFS_CAP_REVISION_1
    V2 = VFS_CAP_REVISION_2
    V3 = VFS_CAP_REVISION_3


class CapabilityStatus(str, Enum):
    """Integrity and support status of a stored capability value."""

    VALID = "valid"
    TRUNCATED = "truncated"
    UNKNOWN_REVISION = "unknown-revision"
    UNSUPPORTED_REVISION = "unsupported-revision"
    MALFORMED = "malformed"


class CapabilityApplicability(str, Enum):
    """Whether the stored declaration is applicable in the supplied namespace."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not-applicable"
    UNKNOWN = "unknown"


class CapabilitySetKind(str, Enum):
    """Which capability set a decoded mask represents."""

    PERMITTED = "permitted"
    INHERITABLE = "inheritable"
    EFFECTIVE = "effective"


@dataclass(frozen=True)
class CapabilitySet:
    """A decoded capability set.

    Args:
        raw: Raw bit mask. Bit ``n`` corresponds to capability number ``n``.
        names: Names of all recognised capabilities that are set.
        unknown_bits: Set bit positions that have no recognised capability name.
        kind: Which set this mask represents.
        source: Provenance of the underlying xattr value, if known.
        word_offset: Byte offset of the set's first 32-bit word in the value.
        word_count: Number of 32-bit words used by this set for the revision.
        word_offsets: Byte offset of every 32-bit word that contributed to this set.
        derived_from: For an effective set, the set it was derived from.
    """

    raw: int
    names: tuple[str, ...]
    unknown_bits: tuple[int, ...]
    kind: CapabilitySetKind
    source: XattrSource | None = None
    word_offset: int | None = None
    word_count: int = 2
    word_offsets: tuple[int, ...] = ()
    derived_from: CapabilitySetKind | None = None

    @property
    def bits(self) -> tuple[int, ...]:
        """Positions of all set bits."""
        return tuple(bit for bit in range(self.raw.bit_length()) if self.raw & (1 << bit))

    @property
    def unknown_mask(self) -> int:
        """Bit mask of all set bits that have no recognised capability name."""
        mask = 0
        for bit in self.unknown_bits:
            mask |= 1 << bit
        return mask

    def __contains__(self, capability: str | int) -> bool:
        if isinstance(capability, int):
            return bool(self.raw & (1 << capability))

        name = capability.upper()
        if not name.startswith("CAP_"):
            name = f"CAP_{name}"
        return name in self.names

    def __bool__(self) -> bool:
        return bool(self.raw)


@dataclass(frozen=True)
class CapabilityDeclaration:
    """The declaration exactly as stored in the ``security.capability`` attribute.

    This object says what the image contains. It deliberately does not say whether the
    capabilities take effect in any namespace; use :func:`assess_capability` for that.
    """

    raw: bytes
    magic: int
    revision: CapabilityRevision | None
    revision_value: int
    status: CapabilityStatus
    effective_flag: bool
    unknown_flags: int
    permitted: CapabilitySet | None
    inheritable: CapabilitySet | None
    effective: CapabilitySet | None
    rootid: int | None
    declared_size: int
    expected_size: int | None
    trailing_bytes: int
    source: XattrSource | None = None

    @property
    def size(self) -> int:
        """Size of the stored value in bytes."""
        return self.declared_size

    @property
    def flags(self) -> int:
        """Raw flag bits from ``magic_etc``, including unknown bits."""
        return self.magic & ~VFS_CAP_REVISION_MASK

    @property
    def stored_effective(self) -> bool:
        """Whether the stored declaration has the effective flag set."""
        return self.effective_flag

    @property
    def supported_revision(self) -> bool:
        """Whether the revision is supported by current kernels."""
        return self.revision_value in SUPPORTED_REVISIONS


@dataclass(frozen=True)
class NamespaceConclusion:
    """What can be concluded for one caller-supplied user namespace."""

    namespace_rootid: int | None
    applicability: CapabilityApplicability
    effective: bool | None
    effective_capabilities: tuple[str, ...]
    effective_unknown_bits: tuple[int, ...]
    reason: str

    @property
    def definitely_effective(self) -> bool:
        """Whether the declaration is definitely effective in this namespace."""
        return self.effective is True

    @property
    def supported(self) -> bool:
        """Whether the declaration applies to this namespace."""
        return self.applicability is CapabilityApplicability.APPLICABLE


@dataclass(frozen=True)
class FileCapabilityReport:
    """Stored declaration and its interpretation for a target user namespace.

    ``declaration`` describes what the firmware image stores. ``namespace`` describes
    what can be concluded for the namespace supplied by the caller. An ``effective``
    value of ``None`` means no definite conclusion can be made.
    """

    attribute: Xattr | None
    declaration: CapabilityDeclaration | None
    namespace: NamespaceConclusion
    conflicts: tuple[Xattr, ...] = ()
    reason: str = ""

    @property
    def raw(self) -> bytes | None:
        """The complete raw attribute value."""
        return self.declaration.raw if self.declaration is not None else None

    @property
    def source(self) -> XattrSource | None:
        """Provenance of the attribute value."""
        return self.attribute.source if self.attribute is not None else None

    @property
    def stored(self) -> CapabilityDeclaration | None:
        """Alias for :attr:`declaration`."""
        return self.declaration

    @property
    def conclusion(self) -> NamespaceConclusion:
        """Alias for :attr:`namespace`."""
        return self.namespace

    @property
    def status(self) -> CapabilityStatus | None:
        return self.declaration.status if self.declaration is not None else None

    @property
    def revision(self) -> CapabilityRevision | None:
        return self.declaration.revision if self.declaration is not None else None

    @property
    def rootid(self) -> int | None:
        """The stored ``rootid`` (revision 3 only)."""
        return self.declaration.rootid if self.declaration is not None else None

    @property
    def rootid_matches(self) -> bool | None:
        """Whether the stored namespace identity matches the target namespace."""
        if self.namespace.applicability is CapabilityApplicability.APPLICABLE:
            return True
        if self.namespace.applicability is CapabilityApplicability.NOT_APPLICABLE:
            return False
        return None

    @property
    def permitted(self) -> CapabilitySet | None:
        return self.declaration.permitted if self.declaration is not None else None

    @property
    def inheritable(self) -> CapabilitySet | None:
        return self.declaration.inheritable if self.declaration is not None else None

    @property
    def effective_set(self) -> CapabilitySet | None:
        """The stored effective set, if the effective flag is set."""
        return self.declaration.effective if self.declaration is not None else None

    @property
    def stored_effective(self) -> bool:
        """Whether the stored declaration claims effective capabilities."""
        return bool(self.declaration and self.declaration.effective_flag)

    @property
    def permitted_capabilities(self) -> tuple[str, ...]:
        return self.declaration.permitted.names if self.declaration and self.declaration.permitted else ()

    @property
    def inheritable_capabilities(self) -> tuple[str, ...]:
        return self.declaration.inheritable.names if self.declaration and self.declaration.inheritable else ()

    @property
    def effective_capabilities(self) -> tuple[str, ...]:
        """Capability names that are definitely effective in the target namespace."""
        return self.namespace.effective_capabilities

    @property
    def unknown_capability_bits(self) -> tuple[int, ...]:
        """All set capability bits that have no recognised name."""
        bits = set()
        if self.declaration is not None:
            for capability_set in (self.declaration.permitted, self.declaration.inheritable):
                if capability_set is not None:
                    bits.update(capability_set.unknown_bits)
        return tuple(sorted(bits))

    @property
    def applicable(self) -> bool | None:
        applicability = self.namespace.applicability
        if applicability is CapabilityApplicability.APPLICABLE:
            return True
        if applicability is CapabilityApplicability.NOT_APPLICABLE:
            return False
        return None

    @property
    def effective(self) -> bool | None:
        """Whether capabilities are definitely effective in the target namespace."""
        return self.namespace.effective

    @property
    def effective_in_namespace(self) -> bool | None:
        """Alias for :attr:`effective`."""
        return self.namespace.effective


def capability_name(bit: int) -> str | None:
    """Return the name for a capability bit, or ``None`` if it is not recognised."""
    if 0 <= bit < len(CAPABILITY_NAMES):
        return CAPABILITY_NAMES[bit]
    return None


def decode_capability_set(
    raw: int,
    kind: CapabilitySetKind,
    *,
    word_offset: int | None = None,
    word_count: int = 2,
    word_offsets: tuple[int, ...] = (),
    source: XattrSource | None = None,
    derived_from: CapabilitySetKind | None = None,
) -> CapabilitySet:
    """Decode a capability bit mask into names and unrecognised bit positions."""
    names = []
    unknown = []

    for bit in range(max(64, raw.bit_length())):
        if not raw & (1 << bit):
            continue
        name = capability_name(bit)
        if name is None:
            unknown.append(bit)
        else:
            names.append(name)

    return CapabilitySet(
        raw=raw,
        names=tuple(names),
        unknown_bits=tuple(unknown),
        kind=kind,
        source=source,
        word_offset=word_offset,
        word_count=word_count,
        word_offsets=word_offsets,
        derived_from=derived_from,
    )


def _split_permitted_inheritable(value: bytes, words: int) -> tuple[int, int]:
    """Decode the interleaved ``{permitted, inheritable}`` word pairs."""
    permitted = 0
    inheritable = 0

    for word in range(words):
        base = 4 + word * 8
        if base + 8 <= len(value):
            permitted |= struct.unpack_from("<I", value, base)[0] << (word * 32)
            inheritable |= struct.unpack_from("<I", value, base + 4)[0] << (word * 32)

    return permitted, inheritable


def parse_security_capability(
    value: bytes,
    *,
    source: XattrSource | None = None,
) -> CapabilityDeclaration:
    """Parse a raw ``security.capability`` value.

    Truncated values are decoded as far as possible but are marked
    :attr:`CapabilityStatus.TRUNCATED`. Unknown revisions are marked
    :attr:`CapabilityStatus.UNKNOWN_REVISION` and their sets are not interpreted because
    the layout is not known. The obsolete revision 1 is decoded but marked
    :attr:`CapabilityStatus.UNSUPPORTED_REVISION`. Values with unknown flag bits or
    unexpected trailing bytes are marked :attr:`CapabilityStatus.MALFORMED`.

    Args:
        value: The complete value bytes of the attribute.
        source: Optional provenance to retain on decoded sets.

    Returns:
        The stored declaration.
    """
    raw = bytes(value)
    size = len(raw)

    if size < 4:
        return CapabilityDeclaration(
            raw=raw,
            magic=0,
            revision=None,
            revision_value=0,
            status=CapabilityStatus.TRUNCATED,
            effective_flag=False,
            unknown_flags=0,
            permitted=None,
            inheritable=None,
            effective=None,
            rootid=None,
            declared_size=size,
            expected_size=None,
            trailing_bytes=0,
            source=source,
        )

    magic = struct.unpack_from("<I", raw, 0)[0]
    revision_value = magic & VFS_CAP_REVISION_MASK
    revision = {
        VFS_CAP_REVISION_1: CapabilityRevision.V1,
        VFS_CAP_REVISION_2: CapabilityRevision.V2,
        VFS_CAP_REVISION_3: CapabilityRevision.V3,
    }.get(revision_value)

    effective_flag = bool(magic & VFS_CAP_FLAGS_EFFECTIVE)
    unknown_flags = magic & VFS_CAP_FLAGS_MASK

    if revision is None:
        return CapabilityDeclaration(
            raw=raw,
            magic=magic,
            revision=None,
            revision_value=revision_value,
            status=CapabilityStatus.UNKNOWN_REVISION,
            effective_flag=effective_flag,
            unknown_flags=unknown_flags,
            permitted=None,
            inheritable=None,
            effective=None,
            rootid=None,
            declared_size=size,
            expected_size=None,
            trailing_bytes=max(0, size - 4),
            source=source,
        )

    expected_size = VFS_CAP_SIZES[revision_value]
    words = VFS_CAP_U32_1 if revision is CapabilityRevision.V1 else VFS_CAP_U32_2

    permitted_raw, inheritable_raw = _split_permitted_inheritable(raw, words)

    rootid = None
    if revision is CapabilityRevision.V3 and size >= 4 + words * 8 + 4:
        rootid = struct.unpack_from("<I", raw, 4 + words * 8)[0]

    if size < expected_size:
        status = CapabilityStatus.TRUNCATED
    elif revision is CapabilityRevision.V1:
        status = CapabilityStatus.UNSUPPORTED_REVISION
    elif unknown_flags or size > expected_size:
        status = CapabilityStatus.MALFORMED
    else:
        status = CapabilityStatus.VALID

    permitted_word_offsets = tuple(4 + word * 8 for word in range(words))
    inheritable_word_offsets = tuple(8 + word * 8 for word in range(words))

    permitted = decode_capability_set(
        permitted_raw,
        CapabilitySetKind.PERMITTED,
        word_offset=4,
        word_count=words,
        word_offsets=permitted_word_offsets,
        source=source,
    )
    inheritable = decode_capability_set(
        inheritable_raw,
        CapabilitySetKind.INHERITABLE,
        word_offset=8,
        word_count=words,
        word_offsets=inheritable_word_offsets,
        source=source,
    )

    effective = None
    if effective_flag:
        effective = decode_capability_set(
            permitted_raw,
            CapabilitySetKind.EFFECTIVE,
            word_offset=4,
            word_count=words,
            word_offsets=permitted_word_offsets,
            source=source,
            derived_from=CapabilitySetKind.PERMITTED,
        )

    return CapabilityDeclaration(
        raw=raw,
        magic=magic,
        revision=revision,
        revision_value=revision_value,
        status=status,
        effective_flag=effective_flag,
        unknown_flags=unknown_flags,
        permitted=permitted,
        inheritable=inheritable,
        effective=effective,
        rootid=rootid,
        declared_size=size,
        expected_size=expected_size,
        trailing_bytes=max(0, size - expected_size),
        source=source,
    )


def assess_capability(
    declaration: CapabilityDeclaration,
    *,
    namespace_rootid: int | None = None,
    rootid: int | None = None,
) -> NamespaceConclusion:
    """Assess a stored declaration for a caller-supplied user namespace.

    Args:
        declaration: The parsed stored declaration.
        namespace_rootid: Root UID of the target user namespace, as seen from the
            initial user namespace. ``None`` means the caller did not provide one.
        rootid: Alias for ``namespace_rootid``.

    Returns:
        The namespace conclusion. ``effective`` is ``True`` only when the declaration is
        structurally valid, has the effective flag set, and belongs to the requested
        namespace. It is ``False`` when the declaration definitely does not apply or
        does not claim effectiveness. It is ``None`` when no definite conclusion is
        possible.
    """
    if rootid is not None:
        if namespace_rootid is not None and namespace_rootid != rootid:
            raise ValueError("conflicting namespace_rootid and rootid arguments")
        namespace_rootid = rootid

    if declaration.status is CapabilityStatus.UNKNOWN_REVISION:
        reason = f"unknown capability revision {declaration.revision_value:#010x}"
        return _indeterminate(namespace_rootid, reason)

    if declaration.status is CapabilityStatus.UNSUPPORTED_REVISION:
        reason = "capability revision 1 is obsolete and not supported by current kernels"
        return _indeterminate(namespace_rootid, reason)

    if declaration.status is CapabilityStatus.TRUNCATED:
        return _indeterminate(namespace_rootid, "truncated capability value")

    if declaration.status is CapabilityStatus.MALFORMED:
        return _indeterminate(namespace_rootid, "malformed capability value")

    if namespace_rootid is None:
        return _indeterminate(namespace_rootid, "target user namespace root not provided")

    if declaration.revision is CapabilityRevision.V3:
        stored_rootid = declaration.rootid
        if stored_rootid is None:
            return _indeterminate(namespace_rootid, "revision 3 capability value has no rootid")
        applies = stored_rootid == namespace_rootid
    else:
        # Revision 2 has no rootid and is only valid in the initial user namespace.
        stored_rootid = 0
        applies = namespace_rootid == 0

    if not applies:
        return NamespaceConclusion(
            namespace_rootid=namespace_rootid,
            applicability=CapabilityApplicability.NOT_APPLICABLE,
            effective=False,
            effective_capabilities=(),
            effective_unknown_bits=(),
            reason=(f"capability rootid {stored_rootid} does not match target namespace root {namespace_rootid}"),
        )

    if not declaration.effective_flag:
        return NamespaceConclusion(
            namespace_rootid=namespace_rootid,
            applicability=CapabilityApplicability.APPLICABLE,
            effective=False,
            effective_capabilities=(),
            effective_unknown_bits=(),
            reason="capability value does not have the effective flag set",
        )

    effective = declaration.effective
    assert effective is not None

    return NamespaceConclusion(
        namespace_rootid=namespace_rootid,
        applicability=CapabilityApplicability.APPLICABLE,
        effective=True,
        effective_capabilities=effective.names,
        effective_unknown_bits=effective.unknown_bits,
        reason="capability value is structurally valid and applies to the target namespace",
    )


def _indeterminate(namespace_rootid: int | None, reason: str) -> NamespaceConclusion:
    return NamespaceConclusion(
        namespace_rootid=namespace_rootid,
        applicability=CapabilityApplicability.UNKNOWN,
        effective=None,
        effective_capabilities=(),
        effective_unknown_bits=(),
        reason=reason,
    )


def read_file_capabilities(
    xattrs: Iterable[Xattr],
    *,
    namespace_rootid: int | None = None,
    rootid: int | None = None,
) -> FileCapabilityReport | None:
    """Read and analyse ``security.capability`` from a sequence of xattrs.

    This is the same operation as :func:`analyze_file_capabilities`; it is provided
    under a name that matches the vocabulary of a firmware audit. ``rootid`` is an
    alias for ``namespace_rootid``.
    """
    if rootid is not None:
        if namespace_rootid is not None and namespace_rootid != rootid:
            raise ValueError("conflicting namespace_rootid and rootid arguments")
        namespace_rootid = rootid

    return analyze_file_capabilities(xattrs, namespace_rootid=namespace_rootid)


def analyze_file_capabilities(
    xattrs: Iterable[Xattr],
    *,
    namespace_rootid: int | None = None,
    rootid: int | None = None,
) -> FileCapabilityReport | None:
    """Read and analyse ``security.capability`` from a sequence of xattrs.

    If the attribute is absent, ``None`` is returned. If more than one
    ``security.capability`` attribute is present, no single declaration can be trusted,
    so the report contains the conflicts and an indeterminate conclusion.

    Args:
        xattrs: All xattrs of one inode.
        namespace_rootid: Root UID of the target user namespace, as seen from the
            initial user namespace.
        rootid: Alias for ``namespace_rootid``.

    Returns:
        A capability report, or ``None`` if no ``security.capability`` is present.
    """
    if rootid is not None:
        if namespace_rootid is not None and namespace_rootid != rootid:
            raise ValueError("conflicting namespace_rootid and rootid arguments")
        namespace_rootid = rootid

    attributes = [xattr for xattr in xattrs if xattr.name == SECURITY_CAPABILITY]

    if not attributes:
        return None

    if len(attributes) > 1:
        declaration = parse_security_capability(
            attributes[0].value,
            source=attributes[0].source,
        )
        reason = "conflicting security.capability attributes"
        return FileCapabilityReport(
            attribute=attributes[0],
            declaration=declaration,
            namespace=_indeterminate(namespace_rootid, reason),
            conflicts=tuple(attributes),
            reason=reason,
        )

    attribute = attributes[0]
    declaration = parse_security_capability(
        attribute.value,
        source=attribute.source,
    )
    conclusion = assess_capability(declaration, namespace_rootid=namespace_rootid)

    return FileCapabilityReport(
        attribute=attribute,
        declaration=declaration,
        namespace=conclusion,
        reason=conclusion.reason,
    )


# Descriptive aliases for callers that prefer different names.
CapabilityAssessment = NamespaceConclusion
CapabilityReport = FileCapabilityReport
CapabilitySetSource = CapabilitySetKind
StoredCapability = CapabilityDeclaration

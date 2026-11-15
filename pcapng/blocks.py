"""
Module containing the definition of known / supported "blocks" of the
pcap-ng format.

Each block is a struct-like object with some fields and possibly
a variable amount of "items" (usually options).

They can optionally expose some other properties, used eg. to provide
better access to decoded information, ...
"""


import copy
import io

from pcapng import strictness as strictness
from pcapng.constants import link_types
from pcapng.structs import (
    IntField,
    ListField,
    NameResolutionRecordField,
    Option,
    Options,
    OptionsField,
    PacketBytes,
    RawBytes,
    struct_decode,
    write_bytes_padded,
    write_int,
)
from pcapng.utils import unpack_timestamp_resolution

KNOWN_BLOCKS = {}


def _slot_names(cls):
    """Return all ``__slots__`` names declared by ``cls`` and its bases."""
    names = []
    for base in cls.__mro__:
        for name in getattr(base, "__slots__", ()):
            if name not in names:
                names.append(name)
    return names


def _copy_decoded(decoded, memo=None):
    """Copy a decoded-fields mapping, keeping ``Options`` independent."""
    new = {}
    for key, value in decoded.items():
        if memo is None:
            new[key] = copy.deepcopy(value)
        else:
            new[key] = copy.deepcopy(value, memo)
    return new


def _rebind_options(block):
    """Re-attach the edit hook after a block has been copied."""
    try:
        decoded = object.__getattribute__(block, "_decoded")
    except AttributeError:
        return
    options = decoded.get("options")
    if isinstance(options, Options):
        options.on_change = block._options_changed


def _copy_raw_state(state, memo=None):
    if state is None:
        return None
    clone = {}
    for key, value in state.items():
        if value is None or isinstance(value, _InterfaceSnapshot):
            # Snapshots are immutable; sharing one cannot couple two blocks.
            clone[key] = value
        else:
            clone[key] = copy.deepcopy(value, memo)
    return clone


_INTERNAL_ATTRS = frozenset(
    (
        "_decoded",
        "_raw_state",
        "_from_raw",
        "_tracking",
        "_edit_log",
        "section",
    )
)


class EditRecord(object):
    """One recorded change to a block's fields or options."""

    __slots__ = ("index", "source", "name", "before", "after")

    def __init__(self, index, source, name, before, after):
        self.index = index
        self.source = source
        self.name = name
        self.before = before
        self.after = after

    def __eq__(self, other):
        if not isinstance(other, EditRecord):
            return NotImplemented
        return (
            self.index,
            self.source,
            self.name,
            self.before,
            self.after,
        ) == (
            other.index,
            other.source,
            other.name,
            other.before,
            other.after,
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __repr__(self):
        return (
            "EditRecord(index={0}, source={1!r}, name={2!r}, "
            "before={3!r}, after={4!r})"
        ).format(self.index, self.source, self.name, self.before, self.after)


def _snapshot_block(block):
    """
    Return a stable dictionary of a block's interpretation values.

    Schema fields are deep-copied, and derived values are resolved once, using
    the metadata that is in effect right now.  The result intentionally holds
    no reference to the mutable section graph.
    """
    values = {}
    for name, field, default in getattr(block, "schema", ()):
        try:
            value = copy.deepcopy(getattr(block, name))
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
        if isinstance(value, Options):
            # Snapshots are inert: they must not report edits to the block.
            value.on_change = None
        values[name] = value

    def capture(key, getter):
        try:
            values[key] = getter()
        except (AttributeError, KeyError, TypeError, ValueError):
            pass

    capture("endianness", lambda: block.endianness)
    if not isinstance(block, SectionHeader):
        capture("endianness", lambda: block.section.endianness)

    if isinstance(block, SectionHeader):
        capture("version", lambda: block.version)
        capture("length", lambda: block.length)

    if isinstance(block, InterfaceDescription):
        capture("interface_id", lambda: block.interface_id)
        capture("timestamp_resolution", lambda: block.timestamp_resolution)
        capture("link_type_description", lambda: block.link_type_description)
        capture(
            "statistics",
            lambda: block.section.interface_stats.get(block.interface_id),
        )

    if isinstance(block, BlockWithInterfaceMixin):
        capture("interface_id", lambda: block.interface_id)
        capture("interface", lambda: _InterfaceSnapshot(block.interface))
        capture(
            "link_type_description",
            lambda: block.interface.link_type_description,
        )

    if isinstance(block, BlockWithTimestampMixin):
        capture("timestamp_resolution", lambda: block.timestamp_resolution)
        capture("timestamp", lambda: block.timestamp)

    if isinstance(block, BasePacketBlock):
        capture("captured_len", lambda: block.captured_len)
        capture("packet_len", lambda: block.packet_len)
    return values


class _InterfaceSnapshot(object):
    """Read-only snapshot of the interface metadata used to decode a block."""

    __slots__ = (
        "interface_id",
        "link_type",
        "link_type_description",
        "snaplen",
        "timestamp_resolution",
        "options",
        "statistics",
    )

    def __init__(self, interface):
        self.interface_id = interface.interface_id
        self.link_type = interface.link_type
        self.link_type_description = interface.link_type_description
        self.snaplen = interface.snaplen
        self.timestamp_resolution = interface.timestamp_resolution
        self.options = copy.deepcopy(interface.options)
        self.options.on_change = None
        self.statistics = interface.statistics

    def __eq__(self, other):
        if isinstance(other, _InterfaceSnapshot):
            return self._key() == other._key()
        if isinstance(other, InterfaceDescription):
            return self._key() == _InterfaceSnapshot(other)._key()
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.interface_id, self.link_type, self.snaplen))

    def __deepcopy__(self, memo):
        clone = object.__new__(_InterfaceSnapshot)
        memo[id(self)] = clone
        for name in self.__slots__:
            object.__setattr__(clone, name, getattr(self, name))
        clone.options = copy.deepcopy(self.options, memo)
        clone.options.on_change = None
        return clone

    def _key(self):
        return (
            self.interface_id,
            self.link_type,
            self.snaplen,
            self.timestamp_resolution,
            dict(self.options),
        )

    def __repr__(self):
        return (
            "<interface snapshot id={0} link_type={1} snaplen={2} "
            "timestamp_resolution={3!r}>"
        ).format(
            self.interface_id,
            self.link_type,
            self.snaplen,
            self.timestamp_resolution,
        )



class BlockView(object):
    """
    Read-only view over a block.

    Two views are exposed by :py:class:`Block`:

    * :py:attr:`Block.raw_view` contains the values decoded when the block was
      read (or constructed), together with the interface/section metadata that
      was effective at that moment.  It does not follow later edits.
    * :py:attr:`Block.edit_view` computes values from the block's current
      fields and the section/interface metadata that is current *now*.

    A view supports both attribute and item access, and :py:meth:`diff` can be
    used to make the difference between the two views explicit.
    """

    __slots__ = ("_block", "_raw")

    def __init__(self, block, raw):
        object.__setattr__(self, "_block", block)
        object.__setattr__(self, "_raw", bool(raw))

    @property
    def is_raw(self):
        return self._raw

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        try:
            return self._block._view_value(name, self._raw)
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, name):
        return getattr(self, name)

    def __contains__(self, name):
        try:
            getattr(self, name)
        except AttributeError:
            return False
        return True

    def __dir__(self):
        names = set(super(BlockView, self).__dir__())
        names.update(self.as_dict().keys())
        return sorted(names)

    def keys(self):
        return self.as_dict().keys()

    def items(self):
        return self.as_dict().items()

    def as_dict(self):
        names = [x[0] for x in getattr(self._block, "schema", ())]
        names.extend(
            [
                "interface_id",
                "timestamp",
                "timestamp_resolution",
                "captured_len",
                "packet_len",
                "interface",
                "statistics",
                "link_type_description",
                "version",
                "length",
                "endianness",
            ]
        )
        result = {}
        for name in names:
            try:
                result[name] = getattr(self, name)
            except (AttributeError, KeyError):
                pass
        # Derived values shared by both views, resolved through the view so
        # that the raw side uses the captured interface/section metadata.
        if "endianness" not in result:
            try:
                result["endianness"] = self._block.section.endianness
            except AttributeError:
                pass
        if "link_type_description" not in result:
            try:
                result["link_type_description"] = self.interface.link_type_description
            except (AttributeError, KeyError):
                pass
        return result

    def diff(self, other=None):
        """
        Return ``{name: (raw_value, edit_value)}`` for differing values.

        Without an argument, compare the block's raw and edit views in a stable
        direction (raw first, edit second), regardless of which view called it.
        """
        if other is None:
            raw = self._block.raw_view
            edit = self._block.edit_view
            left, right = raw.as_dict(), edit.as_dict()
        else:
            left, right = self.as_dict(), other.as_dict()
        names = set(left) | set(right)
        result = {}
        for name in names:
            if name not in left or name not in right:
                result[name] = (left.get(name), right.get(name))
                continue
            try:
                equal = left[name] == right[name]
            except Exception:
                equal = False
            if not equal:
                result[name] = (left[name], right[name])
        return result

    def __repr__(self):
        kind = "raw" if self._raw else "edit"
        return "<{0} view {1!r}>".format(kind, self._block)



class Block(object):
    """Base class for blocks

    Blocks keep two interpretations of their data:

    * the *raw* view, snapshotted at the moment the block was decoded or
      constructed, and
    * the *edit* view, computed from the current fields and the section /
      interface metadata as they are now.

    Reading attributes directly (``block.packet_len``, ``block.timestamp``)
    keeps the historical behaviour and follows edits.  Use
    :py:attr:`raw_view` when the value must be tied to the bytes that were
    actually read.
    """

    schema = []
    readonly_fields = set()
    __slots__ = [
        # These are in addition to the above two properties
        "magic_number",
        "_decoded",
        "_raw_state",
        "_from_raw",
        "_tracking",
        "_edit_log",
    ]
    _edit_log_limit = 1000

    def __init__(self, **kwargs):
        object.__setattr__(self, "_tracking", False)
        self._init_tracking(from_raw="raw" in kwargs)
        if "raw" in kwargs:
            self._decoded = struct_decode(
                self.schema, io.BytesIO(kwargs["raw"]), kwargs["endianness"]
            )
        else:
            self._decoded = {}
            for key, packed_type, default in self.schema:
                if key == "options":
                    self._decoded[key] = Options(
                        schema=packed_type.options_schema,
                        data={},
                        endianness=kwargs["endianness"],
                        on_change=self._options_changed,
                    )
                    if "options" in kwargs:
                        for oky, ovl in kwargs["options"].items():
                            self.options[oky] = ovl
                else:
                    try:
                        self._decoded[key] = kwargs[key]
                    except KeyError:
                        self._decoded[key] = default

        # Options parsed from raw data need the hook attached after decoding.
        _rebind_options(self)
        object.__setattr__(self, "_tracking", True)

    # ------------------------------------------------------------------
    # Tracking / views
    # ------------------------------------------------------------------

    def _init_tracking(self, from_raw):
        object.__setattr__(self, "_from_raw", bool(from_raw))
        object.__setattr__(self, "_raw_state", None)
        object.__setattr__(self, "_edit_log", [])

    @property
    def raw_view(self):
        """Snapshot of the block as it was decoded/constructed."""
        return BlockView(self, raw=True)

    @property
    def edit_view(self):
        """Values computed from the block's current fields and metadata."""
        return BlockView(self, raw=False)

    @property
    def from_raw(self):
        """Whether this block was decoded from a capture stream."""
        return self._from_raw

    @property
    def edited(self):
        """Whether a schema field or option has been changed since parsing."""
        try:
            return bool(object.__getattribute__(self, "_edit_log"))
        except AttributeError:
            return False

    @property
    def edit_log(self):
        """Immutable sequence of recorded edits."""
        try:
            return tuple(object.__getattribute__(self, "_edit_log"))
        except AttributeError:
            return ()

    def _view_value(self, name, raw):
        if raw:
            try:
                state = object.__getattribute__(self, "_raw_state")
            except AttributeError:
                state = None
            if state is not None:
                if name not in state:
                    # The raw view is intentionally closed: it never falls
                    # back to live metadata that the snapshot did not see.
                    raise AttributeError(name)
                value = state[name]
                if isinstance(value, (_InterfaceSnapshot, Options)):
                    # The raw view is evidence: callers must not be able to
                    # mutate the stored snapshot through a returned object.
                    return copy.deepcopy(value)
                return value
        if name == "endianness":
            try:
                return self.section.endianness
            except AttributeError:
                raise AttributeError(name)
        return getattr(self, name)

    def _set_raw_value(self, name, value):
        """
        Record metadata discovered while reading, without refreshing edits.

        Used for capture facts that only become known later in the stream
        (an interface id assigned at registration, an ISB read after its IDB).
        It must never be used for user edits.
        """
        state = object.__getattribute__(self, "_raw_state")
        if state is not None:
            if isinstance(value, Block):
                # Metadata links identify another capture block; copying it
                # would create a detached object that is not the evidence.
                state[name] = value
            else:
                state[name] = copy.deepcopy(value)

    def _capture_raw_state(self):
        """Freeze the current interpretation as the block's raw view."""
        try:
            snapshot = _snapshot_block(self)
        except Exception:
            # A half-built block has no meaningful snapshot yet; views then
            # fall back to live values instead of breaking construction.
            snapshot = None
        object.__setattr__(self, "_raw_state", snapshot)

    def _options_changed(self, name, before, after):
        self._record_edit("options", name, before, after)

    def _record_edit(self, source, name, before, after):
        if not getattr(self, "_tracking", False):
            return
        log = object.__getattribute__(self, "_edit_log")
        try:
            before = copy.deepcopy(before)
        except Exception:
            pass
        try:
            after = copy.deepcopy(after)
        except Exception:
            pass
        log.append(EditRecord(len(log), source, name, before, after))
        if len(log) > self._edit_log_limit:
            del log[: len(log) - self._edit_log_limit]

    def __copy__(self):
        return self._copy_block(deep_sections=False)

    def __deepcopy__(self, memo):
        clone = self._copy_block(deep_sections=True, memo=memo)
        memo[id(self)] = clone
        return clone

    def _copy_block(self, deep_sections, memo=None):
        """Copy a block with independent fields, options and edit history."""
        cls = type(self)
        clone = object.__new__(cls)
        if memo is None:
            memo = {}
        memo[id(self)] = clone
        for name in _slot_names(cls):
            if name == "magic_number":
                continue
            if name == "section" and not deep_sections:
                value = object.__getattribute__(self, name)
            elif name == "_decoded":
                value = _copy_decoded(object.__getattribute__(self, name), memo)
            elif name == "_raw_state":
                value = _copy_raw_state(object.__getattribute__(self, name), memo)
            elif name == "_edit_log":
                value = list(object.__getattribute__(self, name))
            else:
                try:
                    value = object.__getattribute__(self, name)
                except AttributeError:
                    continue
                value = copy.deepcopy(value, memo)
            object.__setattr__(clone, name, value)
        _rebind_options(clone)
        return clone

    def __eq__(self, other):
        if self.__class__ != other.__class__:
            return False
        keys = [x[0] for x in self.schema]
        # Use `getattr()` so eg. @property calls are used
        return [getattr(self, k) for k in keys] == [getattr(other, k) for k in keys]

    def _write(self, outstream):
        """Writes this block into the given output stream"""
        encoded_block = io.BytesIO()
        self._encode(encoded_block)
        encoded_block = encoded_block.getvalue()
        subblock_length = len(encoded_block)
        if subblock_length == 0:
            return
        block_length = 12 + subblock_length
        if subblock_length % 4 != 0:
            block_length += 4 - (subblock_length % 4)
        write_int(self.magic_number, outstream, 32, endianness=self.section.endianness)
        write_int(block_length, outstream, 32, endianness=self.section.endianness)
        write_bytes_padded(outstream, encoded_block)
        write_int(block_length, outstream, 32, endianness=self.section.endianness)

    def _encode(self, outstream):
        """Encodes the fields of this block into raw data"""
        endianness = self.section.endianness
        for name, field, default in self.schema:
            value = getattr(self, name)
            if isinstance(field, OptionsField) and isinstance(value, Options):
                # Options cache the section endianness used to decode them.
                # Writing must use the section's current endianness, or the
                # block header and its option headers would disagree.
                value.endianness = endianness
            field.encode(value, outstream, endianness=endianness)

    def __getattr__(self, name):
        # __getattr__ is only called when getting an attribute that
        # this object doesn't have.  Never route our own bookkeeping
        # attributes through the schema dictionary: during copy/pickle
        # they are not initialised yet and recursion would follow.
        if name in _INTERNAL_ATTRS or name.startswith("__"):
            raise AttributeError(name)
        try:
            decoded = object.__getattribute__(self, "_decoded")
        except AttributeError as e:
            raise AttributeError(name) from e
        try:
            return decoded[name]
        except KeyError as e:
            raise AttributeError(name) from e

    def __setattr__(self, name, value):
        # __setattr__ is called for *any* attribute, real or not.
        try:
            # See it if it names an attribute we defined in our __slots__
            return object.__setattr__(self, name, value)
        except AttributeError:
            # It's not an attribute.
            # Proceed with our nice interface to the schema.
            pass
        if name.startswith("__") or name in _INTERNAL_ATTRS:
            # Bookkeeping attributes are never schema fields.  This matters
            # during unpickling, when they are restored one at a time.
            return object.__setattr__(self, name, value)
        if name in self.readonly_fields:
            raise AttributeError(
                "'{cls}' object property '{prop}' is read-only".format(
                    prop=name, cls=self.__class__.__name__
                )
            )
        try:
            decoded = object.__getattribute__(self, "_decoded")
        except AttributeError:
            decoded = None
        if decoded is None:
            decoded = {}
            for key, packed_type, default in self.schema:
                decoded[key] = None
            object.__setattr__(self, "_decoded", decoded)
        old_value = decoded.get(name)
        decoded[name] = value
        self._record_edit("field", name, old_value, value)

    def __repr__(self):
        args = []
        for item in self.schema:
            name = item[0]
            value = getattr(self, name)
            try:
                value = repr(value)
            except Exception:
                value = "<{0} (repr failed)>".format(type(value).__name__)
            args.append("{0}={1}".format(name, value))
        return "<{0} {1}>".format(self.__class__.__name__, " ".join(args))


class SectionMemberBlock(Block):
    """Block which must be a member of a section"""

    __slots__ = ["section"]

    def __init__(self, section, **kwargs):
        super(SectionMemberBlock, self).__init__(**kwargs)
        self.section = section
        self._capture_raw_state()


def register_block(block):
    """Handy decorator to register a new known block type"""
    KNOWN_BLOCKS[block.magic_number] = block
    return block


@register_block
class SectionHeader(Block):
    """
    "The Section Header Block (SHB) is mandatory. It identifies the beginning
    of a section of the capture file. The Section Header Block does not contain
    data but it rather identifies a list of blocks (interfaces, packets) that
    are logically correlated."
    - pcapng spec, section 4.1. Other quoted citations are from this section
    unless otherwise noted.
    """

    magic_number = 0x0A0D0D0A
    __slots__ = [
        "endianness",
        "_interfaces_id",
        "interfaces",
        "interface_stats",
    ]
    schema = [
        ("version_major", IntField(16, False), 1),
        ("version_minor", IntField(16, False), 0),
        ("section_length", IntField(64, True), -1),
        (
            "options",
            OptionsField(
                [
                    Option(2, "shb_hardware", "string"),
                    Option(3, "shb_os", "string"),
                    Option(4, "shb_userappl", "string"),
                ]
            ),
            None,
        ),
    ]

    def __init__(self, endianness="<", **kwargs):
        self.endianness = endianness
        self._interfaces_id = 0
        self.interfaces = {}
        self.interface_stats = {}
        super(SectionHeader, self).__init__(endianness=endianness, **kwargs)
        self._capture_raw_state()

    def _encode(self, outstream):
        write_int(0x1A2B3C4D, outstream, 32, endianness=self.endianness)
        super(SectionHeader, self)._encode(outstream)

    def new_member(self, cls, **kwargs):
        """Helper method to create a block that's a member of this section"""
        assert issubclass(cls, SectionMemberBlock)
        blk = cls(section=self, endianness=self.endianness, **kwargs)
        # Some blocks (eg. SPB) don't have options
        if any([x[0] == "options" for x in blk.schema]):
            blk.options.endianness = self.endianness
        if isinstance(blk, InterfaceDescription):
            self.register_interface(blk)
        elif isinstance(blk, InterfaceStatistics):
            self.add_interface_stats(blk)
        # Registration assigns the interface id (and may attach statistics),
        # so refresh the raw snapshot to include that read-time metadata.
        blk._capture_raw_state()
        return blk

    def register_interface(self, interface):
        """Helper method to register an interface within this section"""
        assert isinstance(interface, InterfaceDescription)
        interface_id = self._interfaces_id
        self._interfaces_id = interface_id + 1
        interface.interface_id = interface_id
        self.interfaces[interface_id] = interface

    def add_interface_stats(self, interface_stats):
        """Helper method to register interface stats within this section"""
        assert isinstance(interface_stats, InterfaceStatistics)
        self.interface_stats[interface_stats.interface_id] = interface_stats
        interface = self.interfaces.get(interface_stats.interface_id)
        if interface is not None:
            # The ISB was read after its IDB; this is read-time discovery,
            # not an edit, so only the raw snapshot gains the reference.
            interface._set_raw_value("statistics", interface_stats)

    @property
    def version(self):
        return (self.version_major, self.version_minor)

    @property
    def length(self):
        return self.section_length

    # Block.decode() assumes all blocks have sections -- technically true...
    @property
    def section(self):
        return self

    def __repr__(self):
        return (
            "<{name} version={version} endianness={endianness} "
            "length={length} options={options}>"
        ).format(
            name=self.__class__.__name__,
            version=".".join(str(x) for x in self.version),
            endianness=repr(self.endianness),
            length=self.length,
            options=repr(self.options),
        )


@register_block
class InterfaceDescription(SectionMemberBlock):
    """
    "An Interface Description Block (IDB) is the container for information
    describing an interface on which packet data is captured."
    - pcapng spec, section 4.2. Other quoted citations are from this section
    unless otherwise noted.
    """

    magic_number = 0x00000001
    __slots__ = ["interface_id"]
    schema = [
        ("link_type", IntField(16, False), 0),  # todo: enc/decode
        ("reserved", IntField(16, False), 0),
        ("snaplen", IntField(32, False), 0),
        (
            "options",
            OptionsField(
                [
                    Option(2, "if_name", "string"),
                    Option(3, "if_description", "string"),
                    Option(4, "if_IPv4addr", "ipv4+mask", multiple=True),
                    Option(5, "if_IPv6addr", "ipv6+prefix", multiple=True),
                    Option(6, "if_MACaddr", "macaddr"),
                    Option(7, "if_EUIaddr", "euiaddr"),
                    Option(8, "if_speed", "u64"),
                    Option(9, "if_tsresol"),  # Just keep the raw data
                    Option(10, "if_tzone", "u32"),
                    Option(11, "if_filter", "type+bytes"),
                    Option(12, "if_os", "string"),
                    Option(13, "if_fcslen", "u8"),
                    Option(14, "if_tsoffset", "i64"),
                    Option(15, "if_hardware", "string"),
                    Option(16, "if_txspeed", "u64"),
                    Option(17, "if_rxspeed", "u64"),
                ]
            ),
            None,
        ),
    ]

    @property  # todo: cache this property
    def timestamp_resolution(self):
        # ------------------------------------------------------------
        # Resolution of timestamps. If the Most Significant Bit is
        # equal to zero, the remaining bits indicates the resolution
        # of the timestamp as as a negative power of 10 (e.g. 6 means
        # microsecond resolution, timestamps are the number of
        # microseconds since 1/1/1970). If the Most Significant Bit is
        # equal to one, the remaining bits indicates the resolution as
        # as negative power of 2 (e.g. 10 means 1/1024 of second). If
        # this option is not present, a resolution of 10^-6 is assumed
        # (i.e. timestamps have the same resolution of the standard
        # 'libpcap' timestamps).
        # ------------------------------------------------------------

        if "if_tsresol" in self.options:
            return unpack_timestamp_resolution(self.options["if_tsresol"])

        return 1e-6

    @property
    def statistics(self):
        # todo: ensure we always have an interface id -> how??
        return self.section.interface_stats.get(self.interface_id)

    @property
    def link_type_description(self):
        try:
            return link_types.LINKTYPE_DESCRIPTIONS[self.link_type]
        except KeyError:
            return "Unknown link type: 0x{0:04x}".format(self.link_type)


class BlockWithTimestampMixin(object):
    """
    Block mixin adding properties to better access timestamps
    of blocks that provide one.
    """

    __slots__ = []

    @property
    def timestamp(self):
        # First, get the accuracy from the ts_resol option
        return (
            (self.timestamp_high << 32) + self.timestamp_low
        ) * self.timestamp_resolution

    @property
    def timestamp_resolution(self):
        return self.interface.timestamp_resolution

    # todo: add some property returning a datetime() with timezone..


class BlockWithInterfaceMixin(object):
    """
    Block mixin for blocks that have/require an interface.
    This includes all packet blocks as well as InterfaceStatistics.
    """

    __slots__ = []

    @property
    def interface(self):
        # We need to get the correct interface from the section
        # by looking up the interface_id
        return self.section.interfaces[self.interface_id]

    def _encode(self, outstream):
        if len(self.section.interfaces) < 1:
            strictness.problem(
                "writing {cls} for section with no interfaces".format(
                    cls=self.__class__.__name__
                )
            )
            if strictness.should_fix():
                # Only way to "fix" is to not write the block
                return
        super(BlockWithInterfaceMixin, self)._encode(outstream)


class BasePacketBlock(SectionMemberBlock, BlockWithInterfaceMixin):
    """
    Base class for blocks with packet data.
    They must have these fields in their schema:

    * ``packet_len`` is the original amount of data that was "on the wire"
        (this can differ from ``captured_len``)
    * ``packet_data`` is the actual binary packet data (of course)

    This class makes the ``captured_len`` a read-only property returning
    the current length of the packet data.
    """

    __slots__ = []
    readonly_fields = set(("captured_len",))

    @property
    def captured_len(self):
        return len(self.packet_data)

    # Helper function. If the user hasn't explicitly set an original packet
    # length, use the length of the captured packet data. And if they *have*
    # set a length but it's smaller than the captured data, make it the same as
    # the captured data length.
    @property
    def packet_len(self):
        plen = self.__getattr__("packet_len") or 0  # this call prevents recursion
        return plen or len(self.packet_data)


@register_block
class EnhancedPacket(BasePacketBlock, BlockWithTimestampMixin):
    """
    "An Enhanced Packet Block (EPB) is the standard container for storing the
    packets coming from the network."
    - pcapng spec, section 4.3. Other quoted citations are from this section
    unless otherwise noted.
    """

    magic_number = 0x00000006
    __slots__ = []
    schema = [
        ("interface_id", IntField(32, False), 0),
        ("timestamp_high", IntField(32, False), 0),
        ("timestamp_low", IntField(32, False), 0),
        ("captured_len", IntField(32, False), 0),
        ("packet_len", IntField(32, False), 0),
        ("packet_data", PacketBytes("captured_len"), b""),
        (
            "options",
            OptionsField(
                [
                    Option(2, "epb_flags", "epb_flags"),
                    Option(3, "epb_hash", "type+bytes", multiple=True),  # todo: process
                    Option(4, "epb_dropcount", "u64"),
                    Option(5, "epb_packetid", "u64"),
                    Option(6, "epb_queue", "u32"),
                    Option(
                        7, "epb_verdict", "type+bytes", multiple=True
                    ),  # todo: process
                ]
            ),
            None,
        ),
    ]


@register_block
class SimplePacket(BasePacketBlock):
    """
    "The Simple Packet Block (SPB) is a lightweight container for storing the
    packets coming from the network."
    - pcapng spec, section 4.4. Other quoted citations are from this section
    unless otherwise noted.
    """

    magic_number = 0x00000003
    __slots__ = []
    schema = [
        # packet_len is NOT the captured length
        ("packet_len", IntField(32, False), 0),
        # We don't actually use this field; see _decode()/_encode()
        ("packet_data", PacketBytes("captured_len"), b""),
    ]

    def __init__(self, section, **kwargs):
        self.section = section
        if "raw" in kwargs:
            object.__setattr__(self, "_tracking", False)
            self._init_tracking(from_raw=True)
            # Since we can't be sure of the packet length without the snap length,
            # we have to do a bit of work here
            stream = io.BytesIO(kwargs["raw"])
            self._decoded = struct_decode(self.schema[:1], stream, kwargs["endianness"])
            # Now we can get our ``captured_len`` property which is required
            # to really know how much data we can load
            rb = RawBytes(self.captured_len)
            self._decoded["packet_data"] = rb.load(stream)
            self._capture_raw_state()
            object.__setattr__(self, "_tracking", True)
        else:
            super(SimplePacket, self).__init__(section, **kwargs)

    readonly_fields = set(("captured_len", "interface_id"))

    @property
    def interface_id(self):
        """
        "The Simple Packet Block does not contain the Interface ID field.
        Therefore, it MUST be assumed that all the Simple Packet Blocks have
        been captured on the interface previously specified in the first
        Interface Description Block."
        """
        return 0

    @property
    def captured_len(self):
        """
        "...the SnapLen value MUST be used to determine the size of the Packet
        Data field length."
        """
        snap_len = self.interface.snaplen
        if snap_len == 0:  # unlimited
            return self.packet_len
        else:
            return min(snap_len, self.packet_len)

    def _encode(self, outstream):
        fld_size = IntField(32, False)
        fld_data = RawBytes(0)
        if len(self.section.interfaces) > 1:
            # Spec is a bit ambiguous here. Section 4.4 says "it MUST
            # be assumed that all the Simple Packet Blocks have been captured
            # on the interface previously specified in the first Interface
            # Description Block." but later adds "A Simple Packet Block cannot
            # be present in a Section that has more than one interface because
            # of the impossibility to refer to the correct one (it does not
            # contain any Interface ID field)." Why would it say "the first"
            # IDB and not "the only" IDB if this was really forbidden?
            strictness.problem(
                "writing SimplePacket for section with multiple interfaces"
            )
            if strictness.should_fix():
                # Can't fix this. The IDBs have already been written.
                pass
        snap_len = self.interface.snaplen
        if snap_len > 0 and snap_len < self.captured_len:
            # This isn't a strictness issue, it *will* break other readers
            # if we write more bytes than the snaplen says to expect.
            fld_size.encode(
                self.packet_len, outstream, endianness=self.section.endianness
            )
            fld_data.encode(self.packet_data[:snap_len], outstream)
        else:
            fld_size.encode(
                self.packet_len, outstream, endianness=self.section.endianness
            )
            fld_data.encode(self.packet_data, outstream)


@register_block
class ObsoletePacket(BasePacketBlock, BlockWithTimestampMixin):
    """
    "The Packet Block is obsolete, and MUST NOT be used in new files. [...] A
    Packet Block was a container for storing packets coming from the network."
    - pcapng spec, Appendix A. Other quoted citations are from this appendix
    unless otherwise noted.
    """

    magic_number = 0x00000002
    __slots__ = []
    schema = [
        ("interface_id", IntField(16, False), 0),
        ("drops_count", IntField(16, False), 0),
        ("timestamp_high", IntField(32, False), 0),
        ("timestamp_low", IntField(32, False), 0),
        ("captured_len", IntField(32, False), 0),
        ("packet_len", IntField(32, False), 0),
        ("packet_data", PacketBytes("captured_len"), None),
        (
            # The options have the same definitions as their epb_ equivalents
            "options",
            OptionsField(
                [
                    Option(2, "pack_flags", "epb_flags"),
                    Option(3, "pack_hash", "type+bytes", multiple=True),
                ]
            ),
            None,
        ),
    ]

    def enhanced(self):
        """Return an EnhancedPacket with this block's attributes."""
        opts_dict = dict(self.options)
        opts_dict["epb_dropcount"] = self.drops_count
        for a in ("flags", "hash"):
            try:
                opts_dict["epb_" + a] = opts_dict.pop("pack_" + a)
            except KeyError:
                pass
        return self.section.new_member(
            EnhancedPacket,
            interface_id=self.interface_id,
            timestamp_high=self.timestamp_high,
            timestamp_low=self.timestamp_low,
            packet_len=self.packet_len,
            packet_data=self.packet_data,
            options=opts_dict,
        )

    # Do this check in _write() instead of _encode() to ensure the block gets written
    # with the correct magic number.
    def _write(self, outstream):
        strictness.problem("Packet Block is obsolete and must not be used")
        if strictness.should_fix():
            self.enhanced()._write(outstream)
        else:
            super(ObsoletePacket, self)._write(outstream)


@register_block
class NameResolution(SectionMemberBlock):
    """
    "The Name Resolution Block (NRB) is used to support the correlation of
    numeric addresses (present in the captured packets) and their corresponding
    canonical names [...]. Having the literal names saved in the file prevents
    the need for performing name resolution at a later time, when the
    association between names and addresses may be different from the one in
    use at capture time."
    - pcapng spec, section 4.5. Other quoted citations are from this section
    unless otherwise noted.
    """

    magic_number = 0x00000004
    __slots__ = []
    schema = [
        ("records", ListField(NameResolutionRecordField()), []),
        (
            "options",
            OptionsField(
                [
                    Option(2, "ns_dnsname", "string"),
                    Option(3, "ns_dnsIP4addr", "ipv4"),
                    Option(4, "ns_dnsIP6addr", "ipv6"),
                ]
            ),
            None,
        ),
    ]


@register_block
class InterfaceStatistics(
    SectionMemberBlock, BlockWithTimestampMixin, BlockWithInterfaceMixin
):
    """
    "The Interface Statistics Block (ISB) contains the capture statistics for a
    given interface [...]. The statistics are referred to the interface defined
    in the current Section identified by the Interface ID field."
    - pcapng spec, section 4.6. Other quoted citations are from this section
    unless otherwise noted.
    """

    magic_number = 0x00000005
    __slots__ = []
    schema = [
        ("interface_id", IntField(32, False), 0),
        ("timestamp_high", IntField(32, False), 0),
        ("timestamp_low", IntField(32, False), 0),
        (
            "options",
            OptionsField(
                [
                    Option(2, "isb_starttime", "u64"),  # todo: consider resolution
                    Option(3, "isb_endtime", "u64"),
                    Option(4, "isb_ifrecv", "u64"),
                    Option(5, "isb_ifdrop", "u64"),
                    Option(6, "isb_filteraccept", "u64"),
                    Option(7, "isb_osdrop", "u64"),
                    Option(8, "isb_usrdeliv", "u64"),
                ]
            ),
            None,
        ),
    ]


class UnknownBlock(Block):
    """
    Class used to represent an unknown block.

    Its block type and raw data will be stored directly with no further
    processing.
    """

    __slots__ = ["block_type", "data"]

    def __init__(self, block_type, data):
        self.block_type = block_type
        self.data = data

    def __repr__(self):
        return "UnknownBlock(0x{0:08X}, {1!r})".format(self.block_type, self.data)

"""Preservation of unknown PER/UPER extension additions.

The objects in this module are metadata only.  They never merge unknown
extension contents into the decoded dictionary of known ASN.1 fields.  A
relay can forward the original open type bits while still validating only
the fields its own schema knows about.

"""

import hashlib


UNKNOWN_EXTENSIONS_KEY = '_unknown_extensions'


def _freeze(value):
    """Convert a decoded value to a stable hashable representation.

    Preservation metadata is not part of the ASN.1 value and is ignored
    recursively.

    """

    if isinstance(value, PreservedUnknownExtension):
        return ('unknown',
                value.kind,
                value.index,
                bytes(value.data),
                value.fragments)

    if isinstance(value, dict):
        items = []

        for key in sorted(value):
            if key == UNKNOWN_EXTENSIONS_KEY:
                continue

            items.append((key, _freeze(value[key])))

        return ('dict', tuple(items))

    if isinstance(value, (list, tuple)):
        return (type(value).__name__, tuple([_freeze(item) for item in value]))

    if isinstance(value, (bytes, bytearray)):
        return ('bytes', bytes(value))

    if isinstance(value, bool):
        return ('bool', value)

    if isinstance(value, (int, float)):
        return ('number', value)

    return (type(value).__name__, repr(value))


def fingerprint(value):
    """Return a digest of the known (non-preservation) value.

    Unknown extension records and the metadata container itself are
    excluded, but unknown CHOICE markers are included because replacing
    such a marker is a change of the value being forwarded.

    """

    data = repr(_freeze(value)).encode('utf-8')

    return hashlib.sha256(data).digest()


class PreservedUnknownExtension(object):
    """One raw extension addition or CHOICE alternative.

    `data` is the complete open type content, excluding its length
    determinant(s).  It is kept as opaque bytes and is never decoded as a
    known ASN.1 field.

    """

    KIND = 'sequence-addition'
    ALIASES = {
        'data': 'data',
        'open_type': 'data',
        'raw': 'data',
        'index': 'index',
        'kind': 'kind',
        'alignment': 'alignment_bits',
        'alignment_bits': 'alignment_bits',
        'bit_length': 'bit_length',
        'fragments': 'fragments',
        'bit_offset': 'bit_offset',
        'content_bit_offset': 'content_bit_offset',
        'length_bit_offset': 'length_bit_offset'
    }

    def __init__(self,
                 index,
                 data,
                 kind=None,
                 bit_offset=None,
                 content_bit_offset=None,
                 length_bit_offset=None,
                 fragments=None):
        self.index = index
        self.data = bytes(data)
        self.kind = kind or self.KIND
        self.bit_offset = bit_offset
        self.content_bit_offset = content_bit_offset
        self.length_bit_offset = length_bit_offset
        self.fragments = None if fragments is None else tuple(fragments)
        self.verified = False
        self.root_fingerprint = None
        self.root_type_name = None
        self.entries_fingerprint = None

    @property
    def open_type(self):
        return self.data

    @property
    def raw(self):
        return self.data

    @property
    def bit_length(self):
        return 8 * len(self.data)

    @property
    def open_type_length(self):
        return len(self.data)

    @property
    def alignment_bits(self):
        if self.bit_offset is None:
            return None

        return self.bit_offset % 8

    @property
    def is_verified(self):
        return self.verified

    def __getitem__(self, key):
        try:
            attribute = self.ALIASES[key]
        except KeyError:
            raise KeyError(key)

        return getattr(self, attribute)

    def __eq__(self, other):
        if not isinstance(other, PreservedUnknownExtension):
            return NotImplemented

        return ((self.index, self.data, self.kind)
                == (other.index, other.data, other.kind))

    def __ne__(self, other):
        result = self.__eq__(other)

        if result is NotImplemented:
            return result

        return not result

    def __repr__(self):
        return ('{}(index={}, {!r}, alignment_bits={})'.format(
            self.__class__.__name__,
            self.index,
            self.data,
            self.alignment_bits))


class UnknownChoiceExtension(PreservedUnknownExtension):
    """An unknown CHOICE extension alternative.

    A decoder exposes this as ``(None, marker)`` so that the alternative
    name is visibly absent rather than pretending to be a known branch.

    """

    KIND = 'choice-alternative'


class PreservedUnknownExtensions(list):
    """Unknown extension additions at one SEQUENCE/SET level.

    The object is a list of :class:`PreservedUnknownExtension` entries,
    which makes ``decoded['_unknown_extensions'][0]['index']`` and normal
    list operations work.  The extra attributes keep the context needed
    to decide whether the preserved open types may be re-sent.

    """

    def __init__(self,
                 extensions=None,
                 presence_length=0,
                 container_name=None,
                 local_fingerprint=None):
        super(PreservedUnknownExtensions, self).__init__(extensions or [])
        self.presence_length = presence_length
        self.container_name = container_name
        self.local_fingerprint = local_fingerprint
        self.root_fingerprint = None
        self.root_type_name = None
        self.entries_fingerprint = None

    @property
    def extensions(self):
        return list(self)

    @property
    def entries(self):
        return list(self)

    @property
    def max_index(self):
        if len(self) == 0:
            return -1

        return max(extension.index for extension in self)

    def is_unchanged(self, data):
        """Return True if the known fields at this level are unchanged."""

        if self.local_fingerprint is None:
            return True

        return fingerprint(data) == self.local_fingerprint

    def can_resend(self, data):
        """Return True if the preserved open types are safe to re-send."""

        return self.is_unchanged(data)

    def __repr__(self):
        return ('PreservedUnknownExtensions({}, presence_length={})'.format(
            list.__repr__(self),
            self.presence_length))


def has_unknown_extensions(value):
    """Return True if preservation metadata is attached anywhere."""

    if isinstance(value, PreservedUnknownExtension):
        return True

    if isinstance(value, dict):
        metadata = value.get(UNKNOWN_EXTENSIONS_KEY, None)

        if isinstance(metadata, PreservedUnknownExtensions):
            return True

        for key, item in value.items():
            if key != UNKNOWN_EXTENSIONS_KEY and has_unknown_extensions(item):
                return True
    elif isinstance(value, (list, tuple)):
        for item in value:
            if has_unknown_extensions(item):
                return True

    return False


def get_unknown_extensions(data):
    """Return preservation metadata attached to given decoded value."""

    if isinstance(data, dict):
        metadata = data.get(UNKNOWN_EXTENSIONS_KEY, None)

        if isinstance(metadata, PreservedUnknownExtensions):
            return metadata

    return None


def iter_unknown_extension_containers(value):
    """Yield ``(container, metadata)`` pairs recursively."""

    if isinstance(value, dict):
        metadata = value.get(UNKNOWN_EXTENSIONS_KEY, None)

        if isinstance(metadata, PreservedUnknownExtensions):
            yield value, metadata

        for key, item in value.items():
            if key == UNKNOWN_EXTENSIONS_KEY:
                continue

            for entry in iter_unknown_extension_containers(item):
                yield entry
    elif isinstance(value, (list, tuple)):
        for item in value:
            for entry in iter_unknown_extension_containers(item):
                yield entry


def iter_preserved_unknown_extensions(value):
    """Yield every unknown addition and CHOICE marker recursively."""

    if isinstance(value, PreservedUnknownExtension):
        yield value
    elif isinstance(value, dict):
        metadata = value.get(UNKNOWN_EXTENSIONS_KEY, None)

        if isinstance(metadata, PreservedUnknownExtensions):
            for extension in metadata:
                yield extension

        for key, item in value.items():
            if key == UNKNOWN_EXTENSIONS_KEY:
                continue

            for extension in iter_preserved_unknown_extensions(item):
                yield extension
    elif isinstance(value, (list, tuple)):
        for item in value:
            for extension in iter_preserved_unknown_extensions(item):
                yield extension


def iter_unknown_extensions(value):
    """Yield preservation metadata objects recursively."""

    for _, metadata in iter_unknown_extension_containers(value):
        yield metadata


def set_root_fingerprint(value, root_fingerprint, root_type_name=None):
    """Attach the fingerprint of the complete decoded message."""

    for metadata in iter_unknown_extensions(value):
        metadata.root_fingerprint = root_fingerprint
        metadata.root_type_name = root_type_name
        metadata.entries_fingerprint = fingerprint(list(metadata))

    for extension in iter_preserved_unknown_extensions(value):
        extension.root_fingerprint = root_fingerprint
        extension.root_type_name = root_type_name
        extension.entries_fingerprint = fingerprint([extension])


def unknown_extensions_can_resend(value):
    """Return False if known fields changed after preservation.

    Both the complete message fingerprint and each local container
    fingerprint must still match.  A copy of an unmodified decoded
    value can be re-sent; any edit to known fields, including nested
    ones, is rejected.

    """

    metadata = list(iter_unknown_extensions(value))
    markers = list(iter_preserved_unknown_extensions(value))

    if not metadata and not markers:
        return True

    root_digest = fingerprint(value)

    for entry in metadata + markers:
        if (entry.root_fingerprint is not None
                and root_digest != entry.root_fingerprint):
            return False

    for entry in metadata:
        if (entry.entries_fingerprint is not None
                and fingerprint(list(entry)) != entry.entries_fingerprint):
            return False

    # A top-level CHOICE marker is itself the value.  Its ``data`` is
    # not part of the value fingerprint, so check it explicitly.
    for entry in markers:
        if (entry.entries_fingerprint is not None
                and fingerprint([entry]) != entry.entries_fingerprint):
            return False

    for container, entry in iter_unknown_extension_containers(value):
        if not entry.is_unchanged(container):
            return False

    return True


class DecodedMessage(dict):
    """Decoded dictionary with convenience preservation accessors."""

    @property
    def unknown_extensions(self):
        return get_unknown_extensions(self)

    def can_resend_unknown_extensions(self):
        return unknown_extensions_can_resend(self)


def _wrap_nested_dicts(value):
    if isinstance(value, dict):
        for key, item in list(value.items()):
            if key == UNKNOWN_EXTENSIONS_KEY:
                continue

            value[key] = _wrap_nested_dicts(item)

        if not isinstance(value, DecodedMessage):
            value = DecodedMessage(value)
    elif isinstance(value, tuple):
        value = type(value)([_wrap_nested_dicts(item) for item in value])
    elif isinstance(value, list):
        value = [_wrap_nested_dicts(item) for item in value]

    return value


def wrap_decoded_message(value, root_type_name=None):
    """Return a decoded value with root fingerprints attached.

    Dictionaries are returned as :class:`DecodedMessage` so callers can
    use the convenience methods as well as the module level functions.

    """

    value = _wrap_nested_dicts(value)
    set_root_fingerprint(value, fingerprint(value), root_type_name)

    return value

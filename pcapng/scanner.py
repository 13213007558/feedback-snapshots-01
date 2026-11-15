import pcapng.blocks as blocks
from pcapng import strictness as _strictness
from pcapng.constants.block_types import BLK_RESERVED, BLK_RESERVED_CORRUPTED
from pcapng.exceptions import CorruptedFile, StreamEmpty
from pcapng.structs import (
    SECTION_HEADER_MAGIC,
    read_block_data,
    read_int,
    read_section_header,
)


def _first_policy(*values):
    for value in values:
        if value is not None:
            return value
    return None


class FileScanner(object):
    """
    pcap-ng file scanner.

    This object can be iterated to get blocks out of a pcap-ng
    stream (a file or file-like object providing a .read() method).

    Example usage:

        .. code-block:: python

            from pcapng import FileScanner

            with open('/tmp/mycapture.pcap', 'rb') as fp:
                scanner = FileScanner(fp)
                for block in scanner:
                    pass  # do something with the block...

    :param stream:
        a file-like object from which to read the data.
        If you need to parse data from some string you have entirely in-memory,
        just wrap it in a :py:class:`io.BytesIO` object.

    :param policy:
        optional :py:class:`pcapng.strictness.StrictnessPolicy` (or
        :py:class:`pcapng.strictness.Strictness`) owned by the task reading
        this stream.  Blocks produced by the scanner keep this policy, so
        lazy option decoding performed while iterating is attributed to the
        task that owns the scanner rather than to whichever global setting
        happens to be active at iteration time.  When omitted, an active
        :py:func:`pcapng.strictness.strictness_scope` is captured; otherwise
        the legacy global setting is consulted dynamically.
    """

    __slots__ = ["stream", "current_section", "endianness", "_strictness_policy"]

    def __init__(
        self,
        stream,
        policy=None,
        strictness_policy=None,
        strictness=None,
        strictness_level=None,
    ):
        self.stream = stream
        self.current_section = None
        self.endianness = "="
        explicit = _first_policy(policy, strictness_policy)
        if explicit is None:
            explicit = strictness_level
        if explicit is None:
            explicit = strictness
        self._strictness_policy = _strictness.capture_policy(explicit)

    @property
    def strictness_policy(self):
        """The task policy this scanner belongs to (may be None)."""
        return self._strictness_policy

    @strictness_policy.setter
    def strictness_policy(self, policy):
        self._strictness_policy = _strictness.capture_policy(policy)

    @property
    def policy(self):
        """The effective policy used for diagnostics from this scanner."""
        return _strictness.operation_policy(self)

    @policy.setter
    def policy(self, policy):
        self._strictness_policy = _strictness.capture_policy(policy)

    def use_policy(self, policy):
        """Explicitly bind this scanner to a task policy."""
        self._strictness_policy = _strictness.capture_policy(policy)
        return self

    def __iter__(self):
        while True:
            try:
                yield self._read_next_block()
            except StreamEmpty:
                return

    def _read_next_block(self):
        block_type = self._read_int(32, False)

        if block_type == SECTION_HEADER_MAGIC:
            block = self._read_section_header()
            self.current_section = block
            self.endianness = block.endianness
            return block

        if self.current_section is None:
            raise ValueError("File not starting with a proper section header")

        block = self._read_block(block_type)

        return block

    def _read_section_header(self):
        """
        Section information headers are special blocks in that they
        modify the state of the FileScanner instance (to change current
        section / endianness)
        """

        section_info = read_section_header(self.stream)
        self.endianness = section_info["endianness"]  # todo: use property?

        # todo: make this use the standard schema facilities as well!
        return blocks.SectionHeader(
            raw=section_info["data"],
            endianness=section_info["endianness"],
            strictness_policy=self._strictness_policy,
        )

    def _read_block(self, block_type):
        """
        Read the block payload and pass to the appropriate block constructor
        """
        data = read_block_data(self.stream, endianness=self.endianness)

        if block_type in blocks.KNOWN_BLOCKS:
            # This is a known block -- instantiate it.  new_member() carries
            # the section's task policy over to the new block.
            return self.current_section.new_member(
                blocks.KNOWN_BLOCKS[block_type], raw=data
            )

        if block_type in BLK_RESERVED_CORRUPTED:
            raise CorruptedFile(
                "Block type 0x{0:08X} is reserved to detect a corrupted file".format(
                    block_type
                )
            )

        if block_type == BLK_RESERVED:
            raise CorruptedFile(
                "Block type 0x00000000 is reserved and should not be used "
                "in capture files!"
            )

        return blocks.UnknownBlock(
            block_type, data, strictness_policy=self._strictness_policy
        )

    def _read_int(self, size, signed=False):
        """
        Read an integer from the stream, using current endianness
        """
        return read_int(self.stream, size, signed=signed, endianness=self.endianness)

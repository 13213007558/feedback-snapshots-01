import pcapng.blocks as blocks
from pcapng import strictness as strictness_module
from pcapng.constants.block_types import BLK_RESERVED, BLK_RESERVED_CORRUPTED
from pcapng.exceptions import CorruptedFile, StreamEmpty
from pcapng.structs import (
    SECTION_HEADER_MAGIC,
    read_block_data,
    read_int,
    read_section_header,
)


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

    :param strictness:
        a :py:class:`~pcapng.strictness.Strictness` value or
        :py:class:`~pcapng.strictness.StrictnessPolicy` to use for this
        reader.  When omitted, the policy active in the current task context
        is captured; if there is none, the compatibility global level is used
        dynamically.
    """

    __slots__ = [
        "stream",
        "current_section",
        "endianness",
        "_strictness",
        "_strictness_explicit",
    ]

    def __init__(self, stream, strictness=None, **kwargs):
        # Accept the common spellings without making them part of the
        # canonical signature.
        if strictness is None:
            strictness = kwargs.pop(
                "strict_level", kwargs.pop("policy", kwargs.pop("strict", None))
            )
        self._strictness_explicit = strictness is not None
        if kwargs:
            raise TypeError(
                "unexpected keyword argument(s): {}".format(", ".join(sorted(kwargs)))
            )
        self.stream = stream
        self.current_section = None
        self.endianness = "="
        self._strictness = strictness_module.capture_strictness(strictness)

    @property
    def strictness(self):
        """Return the policy this scanner uses for reading."""
        return strictness_module.resolve_for_object(
            None, self._strictness, self._strictness_explicit
        )

    @property
    def strictness_policy(self):
        return self.strictness

    @property
    def strict_level(self):
        return self.strictness.level

    @property
    def policy(self):
        return self.strictness

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
            strictness=self._strictness,
            _strictness_explicit=self._strictness_explicit,
        )

    def _read_block(self, block_type):
        """
        Read the block payload and pass to the appropriate block constructor
        """
        data = read_block_data(self.stream, endianness=self.endianness)

        if block_type in blocks.KNOWN_BLOCKS:
            # This is a known block -- instantiate it
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
            block_type,
            data,
            strictness=self._strictness,
            _strictness_explicit=self._strictness_explicit,
        )

    def _read_int(self, size, signed=False):
        """
        Read an integer from the stream, using current endianness
        """
        return read_int(self.stream, size, signed=signed, endianness=self.endianness)

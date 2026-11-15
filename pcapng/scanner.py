import pcapng.blocks as blocks
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
    """

    __slots__ = [
        "stream",
        "current_section",
        "endianness",
        "block_offset",
        "block_length",
        "block_type",
        "block_data",
        "block_index",
    ]

    def __init__(self, stream):
        self.stream = stream
        self.current_section = None
        self.endianness = "="
        # Location, type and raw payload of the block most recently returned
        # by the iterator. ``block_offset``/``block_length`` cover the whole
        # block, including its 8-byte header and 4-byte trailer.
        self.block_offset = None
        self.block_length = None
        self.block_type = None
        self.block_data = None
        self.block_index = -1

    def __iter__(self):
        while True:
            try:
                yield self._read_next_block()
            except StreamEmpty:
                return

    def _read_next_block(self):
        start = self.stream.tell()
        block_type = self._read_int(32, False)

        if block_type == SECTION_HEADER_MAGIC:
            block, data = self._read_section_header()
            self.current_section = block
            self.endianness = block.endianness
        else:
            if self.current_section is None:
                raise ValueError("File not starting with a proper section header")

            data = read_block_data(self.stream, endianness=self.endianness)
            block = self._make_block(block_type, data)

        self.block_offset = start
        self.block_length = self.stream.tell() - start
        self.block_type = block_type
        self.block_data = data
        self.block_index += 1
        return block

    def _make_block(self, block_type, data):
        """
        Instantiate the appropriate block class for the given type and payload.
        """
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

        return blocks.UnknownBlock(block_type, data)

    def _read_section_header(self):
        """
        Section information headers are special blocks in that they
        modify the state of the FileScanner instance (to change current
        section / endianness)
        """

        section_info = read_section_header(self.stream)
        self.endianness = section_info["endianness"]  # todo: use property?

        # todo: make this use the standard schema facilities as well!
        block = blocks.SectionHeader(
            raw=section_info["data"], endianness=section_info["endianness"]
        )
        return block, section_info["data"]

    def _read_int(self, size, signed=False):
        """
        Read an integer from the stream, using current endianness
        """
        return read_int(self.stream, size, signed=signed, endianness=self.endianness)

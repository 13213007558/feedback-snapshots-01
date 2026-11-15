from __future__ import annotations


class Error(Exception):
    pass


class MetadataError(Error, ValueError):
    """Raised when a metadata chain cannot be followed.

    Attributes:
        block: The physical offset of the metadata block that is currently being processed.
        offset: The logical offset in the decompressed metadata block.
    """

    def __init__(self, message: str, block: int, offset: int):
        super().__init__(f"{message} (block={block}, offset={offset})")
        self.block = block
        self.offset = offset

    @property
    def frame(self) -> int:
        """Alias for the physical metadata block offset."""
        return self.block

    @property
    def physical_block(self) -> int:
        """Alias for the physical metadata block offset."""
        return self.block

    @property
    def logical_offset(self) -> int:
        """Alias for the logical offset in the decompressed metadata block."""
        return self.offset


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotAFileError(Error):
    pass


class NotASymlinkError(Error):
    pass

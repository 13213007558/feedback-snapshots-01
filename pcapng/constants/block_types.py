# PCAPNG Block types

BLK_RESERVED = 0x00000000  # Reserved
BLK_INTERFACE = 0x00000001  # Interface description block
BLK_PACKET = 0x00000002  # Packet Block
BLK_PACKET_SIMPLE = 0x00000003  # Simple Packet block
BLK_NAME_RESOLUTION = 0x00000004  # Name Resolution Block
BLK_INTERFACE_STATS = 0x00000005  # Interface Statistics Block
BLK_ENHANCED_PACKET = 0x00000006  # Enhanced Packet Block

# IRIG Timestamp Block (requested by Gianluca Varenni
# <gianluca.varenni@cacetech.com>, CACE Technologies LLC)
BLK_IRIG_TIMESTAMP = 0x00000007

# Arinc 429 in AFDX Encapsulation Information Block
# (requested by Gianluca Varenni <gianluca.varenni@cacetech.com>,
# CACE Technologies LLC)
BLK_ARINC429 = 0x00000008

BLK_SECTION_HEADER = 0x0A0D0D0A  # Section Header Block

# Ranges of reserved blocks used to indicate corrupted file.
# Reserved. Used to detect trace files corrupted because
# of file transfers using the HTTP protocol in text mode.
# Each entry is a (value, mask) pair: a block type is flagged when
# ``(block_type & mask) == value``.
BLK_RESERVED_CORRUPTED = [
    (0x0A0D0A00, 0x0A0D0AFF),
    (0x000A0D0A, 0xFF0A0D0A),
    (0x000A0D0D, 0xFF0A0D0D),
    (0x0D0D0A00, 0x0D0D0AFF),
]


def is_corruption_detection_block_type(block_type):
    """
    Return whether ``block_type`` matches one of the patterns reserved to
    detect files corrupted by a text-mode transfer.
    """
    return any(
        (block_type & mask) == value for value, mask in BLK_RESERVED_CORRUPTED
    )


def is_reserved_block_type(block_type):
    """
    Return whether ``block_type`` is reserved and must never appear as a
    real block: the all-zero reserved type, or a corruption-detection pattern.
    """
    return block_type == BLK_RESERVED or is_corruption_detection_block_type(
        block_type
    )

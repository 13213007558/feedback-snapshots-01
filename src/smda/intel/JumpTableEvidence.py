"""Provenance for a recovered x86 jump table.

A security analyst auditing SMDA's switch recovery needs to know how many entries of a
recovered table are backed by evidence - a compare or mask against the value the dispatch
indexes with, or the case-number table of a two-level switch - and how many the scan
admitted because it simply had not hit anything that failed the entry checks yet. These
records keep that distinction: every resolved dispatch gets one JumpTableEvidence naming
the bound's kind and source instruction, and every target it produced names the table
entry it was read from and whether the bound covers it.
"""

from dataclasses import dataclass, field
from typing import List, Optional

# a `cmp` against the value the dispatch indexes with, tied through to the branch
BOUND_COMPARE = "compare"
# an `and` mask on the dispatch index, with no compare narrowing it further
BOUND_MASK = "mask"
# a compare narrower than a mask on the same index; the smaller of the two holds
BOUND_COMPARE_MASK = "compare+mask"
# the first compare in the backtrack window, not tied to the dispatch index: the register
# or cell it tested was rewritten (or never was the index) before the branch
BOUND_UNTIED_COMPARE = "untied-compare"
# the case-number table of a two-level switch: its bytes are all valid jump table indices
BOUND_INDEX_TABLE = "index-table"
# nothing in the window bounds the index; the scan stopped at the first failed entry check
BOUND_NONE = "unbounded"

# `jmp dword ptr [table]` / `jmp qword ptr [table]`: the table address stands in the branch
TABLE_EXPLICIT = "explicit"
# `mov reg, [reg*size + table]; jmp reg`: whole pointers read through a register
TABLE_ABSOLUTE = "absolute"
# entries are target - table_base as int32, added back onto the table's base
TABLE_RELATIVE = "relative"
# a 64-bit absolute table whose base a rip-relative lea left in a register
TABLE_REGISTER_BASE = "register-base"


@dataclass
class BoundEvidence:
    """How the entry count of one jump table was bounded.

    `size` is the proven entry count, 0 when no bound could be proven. `source` is the
    address of the instruction the bound was read from (the compare or the mask), and
    `tied_to` the register family or memory cell it tested. `index_intact` records
    whether that register or cell survived to the branch unmodified - an untied compare
    bounds a value the dispatch never indexes with, so its size is a scan limit, not a
    proven bound.
    """

    kind: str
    size: int
    source: Optional[int]
    tied_to: Optional[str]
    index_intact: bool


@dataclass
class JumpTableEntry:
    """One scanned table slot: where it was read, what it held, whether the bound covers it."""

    index: int
    address: int
    target: int
    confirmed: bool


@dataclass
class IndexTableEvidence:
    """The case-number table of a two-level switch, booked as data beside the jump table."""

    address: int
    length: int
    source: int
    # every byte is a case number, so max + 1 jump table entries are reachable through it
    proven_entries: int


@dataclass
class JumpTableEvidence:
    """Everything one resolved dispatch can answer for, keyed by its jump instruction."""

    jump_instruction: int
    table_kind: str
    table_address: Optional[int]
    entry_size: int
    bound: BoundEvidence
    entries: List[JumpTableEntry] = field(default_factory=list)
    index_table: Optional[IndexTableEvidence] = None

    @property
    def confirmed_targets(self):
        """Targets backed by a proven bound, each traceable to its entry and that bound."""
        return sorted(entry.target for entry in self.entries if entry.confirmed)

    @property
    def candidate_targets(self):
        """Targets the scan admitted without a proven bound; kept as a range, not branches."""
        return sorted(entry.target for entry in self.entries if not entry.confirmed)

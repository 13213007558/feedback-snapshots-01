"""Pure-data metadata required to interpret tokens without loading assemblies.

dncil parses IL bytes but deliberately cannot resolve metadata tokens. Loading
an assembly or executing metadata-resolution helpers would cross the safety
boundary of this analysis, so callers instead supply plain data:

* string tokens encountered by ``ldstr`` map to their literal text;
* method tokens map to a :class:`MethodBinding` naming one of the small set of
  whitelisted operations in :class:`KnownOp`.

Any token that is absent from these maps is treated as an *unknown* method or
*unknown* string and drives the result to pending instead of being guessed.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Mapping, Optional


class KnownOp(enum.Enum):
    """Whitelisted, side-effect-free operations the interpreter understands.

    Nothing else is evaluated: an unlisted method is unknown and produces
    pending results.
    """

    STRING_CONCAT = "System.String::Concat"
    STRING_CTOR_CHARS = "System.String::.ctor(char[])"
    CONVERT_TO_CHAR = "System.Convert::ToChar(int)"
    CONVERT_TO_CHAR_FROM_CHAR = "System.Convert::ToChar(char)"


@dataclass(frozen=True)
class MethodBinding:
    """Static description of one method token.

    ``op`` selects a whitelisted semantic; ``name`` is the human-readable
    member reference kept for evidence/reporting only. No callable code is
    involved.
    """

    op: KnownOp
    name: str


@dataclass(frozen=True)
class AnalysisBudget:
    """Explicit resource limits for one analysis run.

    Exceeding any limit stops the fixed-point computation and reports pending
    results rather than producing a truncated-but-complete-looking answer.
    """

    max_instructions: int = 4096
    max_states: int = 8192
    max_iterations: int = 20000
    max_stack_depth: int = 64
    max_array_length: int = 4096
    max_string_length: int = 1 << 20
    max_evidence_per_value: int = 64


class LimitExceeded(Exception):
    """Raised internally when an :class:`AnalysisBudget` limit is exceeded."""


@dataclass
class Metadata:
    """Caller-provided token tables.

    Both tables are ordinary dictionaries of integers to immutable data; the
    analyzer never imports, loads or invokes anything described by a token.
    """

    strings: Mapping[int, str] = field(default_factory=dict)
    methods: Mapping[int, MethodBinding] = field(default_factory=dict)

    def lookup_string(self, token: int) -> Optional[str]:
        return self.strings.get(token)

    def lookup_method(self, token: int) -> Optional[MethodBinding]:
        return self.methods.get(token)

    @staticmethod
    def from_tables(
        strings: Optional[Mapping[int, str]] = None,
        methods: Optional[Mapping[int, MethodBinding]] = None,
    ) -> "Metadata":
        return Metadata(dict(strings or {}), dict(methods or {}))

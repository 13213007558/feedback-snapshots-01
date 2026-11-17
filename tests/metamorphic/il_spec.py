# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""Symbolic CIL method-body specifications for the branch-width regression tests.

Instructions are named by logical labels and every control-flow edge is expressed as a
label target, never as a byte offset.  :mod:`tests.metamorphic.layout` turns a
specification into bytes and into an independent layout record.  This module does not
import dncil, so a decoding bug cannot silently agree with the fixture builder.
"""

from __future__ import annotations

import enum
from typing import Dict, List, Tuple, Union, Optional
from dataclasses import dataclass

#: operand of a branch-like instruction: one label, labels for switch, else None
Target = Union[None, str, Tuple[str, ...]]


class Form(enum.Enum):
    """on-disk encoding of a branch instruction"""

    SHORT = "short"
    LONG = "long"

    @property
    def branch_size(self) -> int:
        """instruction size in bytes (opcode + displacement)"""

        return 2 if self is Form.SHORT else 5


@dataclass(frozen=True)
class BranchEncoding:
    """short/long opcode pair for one branch semantic"""

    short_name: str
    short_byte: int
    long_name: str
    long_byte: int
    conditional: bool


#: branch semantics -> ECMA-335 III opcode pair
BRANCHES: Dict[str, BranchEncoding] = {
    "br": BranchEncoding("br.s", 0x2B, "br", 0x38, False),
    "brtrue": BranchEncoding("brtrue.s", 0x2D, "brtrue", 0x3A, True),
    "brfalse": BranchEncoding("brfalse.s", 0x2C, "brfalse", 0x39, True),
    "beq": BranchEncoding("beq.s", 0x2E, "beq", 0x3B, True),
    "bge": BranchEncoding("bge.s", 0x2F, "bge", 0x3C, True),
    "bgt": BranchEncoding("bgt.s", 0x30, "bgt", 0x3D, True),
    "ble": BranchEncoding("ble.s", 0x31, "ble", 0x3E, True),
    "blt": BranchEncoding("blt.s", 0x32, "blt", 0x3F, True),
    "bne.un": BranchEncoding("bne.un.s", 0x33, "bne.un", 0x40, True),
    "bge.un": BranchEncoding("bge.un.s", 0x34, "bge.un", 0x41, True),
    "bgt.un": BranchEncoding("bgt.un.s", 0x35, "bgt.un", 0x42, True),
    "ble.un": BranchEncoding("ble.un.s", 0x36, "ble.un", 0x43, True),
    "blt.un": BranchEncoding("blt.un.s", 0x37, "blt.un", 0x44, True),
    "leave": BranchEncoding("leave.s", 0xDE, "leave", 0xDD, False),
}

#: mnemonic -> branch semantic, for both encodings
BRANCH_SEMANTICS: Dict[str, str] = {}
for _semantic, _encoding in BRANCHES.items():
    BRANCH_SEMANTICS[_encoding.short_name] = _semantic
    BRANCH_SEMANTICS[_encoding.long_name] = _semantic

#: single-byte (and one two-byte) non-branch opcodes used by the fixtures
SIMPLE_OPCODES: Dict[str, bytes] = {
    "nop": b"\x00",
    "ldarg.0": b"\x02",
    "ldloc.0": b"\x06",
    "ldloc.1": b"\x07",
    "ldloc.2": b"\x08",
    "ldloc.3": b"\x09",
    "stloc.0": b"\x0a",
    "stloc.1": b"\x0b",
    "stloc.2": b"\x0c",
    "stloc.3": b"\x0d",
    "ldnull": b"\x14",
    "ldc.i4.m1": b"\x15",
    "ldc.i4.0": b"\x16",
    "ldc.i4.1": b"\x17",
    "ldc.i4.2": b"\x18",
    "ldc.i4.3": b"\x19",
    "ldc.i4.4": b"\x1a",
    "ldc.i4.5": b"\x1b",
    "ldc.i4.6": b"\x1c",
    "ldc.i4.7": b"\x1d",
    "ldc.i4.8": b"\x1e",
    "dup": b"\x25",
    "pop": b"\x26",
    "ret": b"\x2a",
    "add": b"\x58",
    "sub": b"\x59",
    "mul": b"\x5a",
    "div": b"\x5b",
    "throw": b"\x7a",
    "endfinally": b"\xdc",
    "rethrow": b"\xfe\x1a",
    "endfilter": b"\xfe\x11",
}

SWITCH_OPCODE = b"\x45"

#: instructions after which control never falls through
TERMINATORS = {"ret", "throw", "rethrow", "endfinally", "endfilter"}


@dataclass(frozen=True)
class InsnSpec:
    """one CIL instruction; ``target`` is a logical label (labels for switch)"""

    label: str
    opcode: str
    target: Target = None
    form: Optional[Form] = None

    @property
    def is_branch(self) -> bool:
        return self.opcode in BRANCHES

    @property
    def is_switch(self) -> bool:
        return self.opcode == "switch"

    @property
    def encoding(self) -> BranchEncoding:
        return BRANCHES[self.opcode]

    def effective_form(self) -> Form:
        """encoding the specification asks for; short unless explicitly widened"""

        if not self.is_branch:
            raise ValueError("%r is not a branch" % self.opcode)
        return self.form or Form.SHORT

    def branch_target(self) -> str:
        assert isinstance(self.target, str)
        return self.target

    def switch_targets(self) -> Tuple[str, ...]:
        assert isinstance(self.target, tuple)
        return self.target

    def size(self, form: Optional[Form] = None) -> int:
        if self.is_branch:
            return (form or self.effective_form()).branch_size
        if self.is_switch:
            return 1 + 4 + 4 * len(self.switch_targets())
        return len(SIMPLE_OPCODES[self.opcode])


@dataclass(frozen=True)
class ExceptionSpec:
    """one exception clause with logical labels for every boundary"""

    kind: str
    try_start: str
    try_end: str
    handler_start: str
    handler_end: str
    catch_type: Optional[int] = None
    filter_start: Optional[str] = None

    @property
    def flags(self) -> int:
        return {"catch": 0, "filter": 1, "finally": 2, "fault": 4}[self.kind]


@dataclass(frozen=True)
class MethodSpec:
    """a complete managed method body in symbolic form"""

    name: str
    instructions: Tuple[InsnSpec, ...]
    exception_handlers: Tuple[ExceptionSpec, ...] = ()
    max_stack: int = 2
    init_locals: bool = True
    local_sig: int = 0x11000001
    exception_section_format: str = "tiny"
    header_format: str = "fat"

    def labels(self) -> Tuple[str, ...]:
        return tuple(insn.label for insn in self.instructions)

    def instruction(self, label: str) -> InsnSpec:
        for insn in self.instructions:
            if insn.label == label:
                return insn
        raise KeyError("unknown instruction label %r" % label)

    def short_branch_labels(self) -> List[str]:
        return [insn.label for insn in self.instructions if insn.is_branch and insn.effective_form() is Form.SHORT]

    def validate(self) -> None:
        """check the specification is internally consistent without using bytes"""

        if self.header_format not in ("tiny", "fat"):
            raise ValueError("bad header format %r" % self.header_format)
        if self.exception_section_format not in ("tiny", "fat"):
            raise ValueError("bad exception section format %r" % self.exception_section_format)
        if self.exception_handlers and self.header_format != "fat":
            raise ValueError("exception handlers require a fat header")
        labels = self.labels()
        if not labels:
            raise ValueError("method %s has no instructions" % self.name)
        if len(labels) != len(set(labels)):
            raise ValueError("duplicate instruction labels in %s" % self.name)
        known = set(labels)
        for index, insn in enumerate(self.instructions):
            if insn.is_branch:
                if not isinstance(insn.target, str):
                    raise ValueError("branch %r needs one label target" % insn.label)
            elif insn.is_switch:
                if not isinstance(insn.target, tuple):
                    raise ValueError("switch %r needs a tuple of label targets" % insn.label)
            elif insn.target is not None:
                raise ValueError("instruction %r must not have a target" % insn.label)
            if insn.form is not None and not insn.is_branch:
                raise ValueError("instruction %r cannot have a branch form" % insn.label)
            if not insn.is_branch and not insn.is_switch and insn.opcode not in SIMPLE_OPCODES:
                raise ValueError("unknown opcode %r in method %s" % (insn.opcode, self.name))
            if index == len(labels) - 1 and not insn.is_branch and insn.opcode not in TERMINATORS:
                raise ValueError("method %s ends with a fallthrough instruction %r" % (self.name, insn.label))
            targets: Tuple[str, ...]
            if isinstance(insn.target, str):
                targets = (insn.target,)
            elif isinstance(insn.target, tuple):
                targets = insn.target
            else:
                targets = ()
            for target in targets:
                if target not in known:
                    raise ValueError("instruction %r targets unknown label %r" % (insn.label, target))
        for spec in self.exception_handlers:
            if spec.kind not in ("catch", "filter", "finally", "fault"):
                raise ValueError("unknown exception clause kind %r" % spec.kind)
            for boundary in (spec.try_start, spec.try_end, spec.handler_start, spec.handler_end):
                if boundary not in known:
                    raise ValueError("exception clause references unknown label %r" % boundary)
            if spec.kind == "filter" and spec.filter_start not in known:
                raise ValueError("filter clause references unknown filter label %r" % spec.filter_start)
            if spec.kind == "catch" and spec.catch_type is None:
                raise ValueError("catch clause needs a catch type token")

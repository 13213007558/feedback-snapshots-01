# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Hand-assembled method bodies used by the stack-height tests.

Each fixture is a complete fat-format method body.  Offsets inside the body
start at 0 for the header; code offsets therefore start at ``header_size`` (12
for a fat header).  The metadata tokens are arbitrary but stable so a test can
plug in a resolver for just the tokens it wants to know about.
"""

from __future__ import annotations

import struct
from typing import List, Tuple, Iterable, Optional, Sequence

from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBytes


def _u8(value: int) -> bytes:
    return struct.pack("<B", value)


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def build_fat_method_body(
    code: bytes,
    max_stack: int,
    handlers: Sequence[Tuple[int, int, int, int, int, int]] = (),
) -> bytes:
    """Build a fat-format method body.

    ``handlers`` entries are ``(kind, try_start, try_length, handler_start,
    handler_length, extra)``.  ``extra`` is the catch type token for catch
    handlers and the filter start offset for filter handlers; it is ignored for
    finally and fault handlers.  All offsets are relative to the first code
    byte.
    """
    flags = 0x3 | (3 << 12) | (0x8 if handlers else 0)
    body = _u16(flags) + _u16(max_stack) + _u32(len(code)) + _u32(0) + code

    if handlers:
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        extra_sections = b""
        for kind, try_start, try_length, handler_start, handler_length, extra in handlers:
            extra_sections += (
                _u32(kind)
                + _u32(try_start)
                + _u32(try_length)
                + _u32(handler_start)
                + _u32(handler_length)
                + _u32(extra)
            )
        # Section header: flags byte followed by a 24-bit little-endian size.
        body += _u8(0x41) + _u32(len(extra_sections))[:3] + extra_sections

    return body


def read_body(raw: bytes) -> CilMethodBody:
    return CilMethodBody(CilMethodBodyReaderBytes(raw))


def code_base(body: CilMethodBody) -> int:
    return body.offset + body.header_size


def absolute_chain(body: CilMethodBody, relative_offsets: Iterable[int]) -> Tuple[int, ...]:
    base = code_base(body)
    return tuple(base + offset for offset in relative_offsets)


# ---------------------------------------------------------------------------
# Legal loop
#
#   IL_0000: ldc.i4.0
#   IL_0001: brfalse.s IL_000D
#   IL_0003: ldc.i4.0
#   IL_0004: ldc.i4.0
#   IL_0005: call int32 StackFixtures::Add(int32, int32)
#   IL_000A: pop
#   IL_000B: br.s IL_0000
#   IL_000D: ret
#
# The loop body starts and ends at height 0, so the fixpoint settles after the
# first back-edge.  The call needs two arguments and returns one value.
# ---------------------------------------------------------------------------
LOOP_CODE = (
    b"\x16"  # 00 ldc.i4.0
    b"\x2c\x0a"  # 01 brfalse.s IL_000D
    b"\x16"  # 03 ldc.i4.0
    b"\x16"  # 04 ldc.i4.0
    b"\x28\x01\x00\x00\x0a"  # 05 call token 0x0A000001
    b"\x26"  # 0A pop
    b"\x2b\xf3"  # 0B br.s IL_0000
    b"\x2a"  # 0D ret
)
LOOP_BODY = build_fat_method_body(LOOP_CODE, max_stack=2)

LOOP_CALL_TOKEN = 0x0A000001
LOOP_CALL_CHAIN = (0x0, 0x1, 0x3, 0x4, 0x5)


# ---------------------------------------------------------------------------
# Join conflict
#
#   IL_0000: ldc.i4.0
#   IL_0001: brtrue.s IL_0006
#   IL_0003: ldc.i4.0
#   IL_0004: br.s IL_0006
#   IL_0006: nop
#   IL_0007: ret
#
# The merge at IL_0006 receives height 0 from the branch and height 1 from the
# fall-through-plus-branch path.
# ---------------------------------------------------------------------------
JOIN_CODE = (
    b"\x16"  # 00 ldc.i4.0
    b"\x2d\x03"  # 01 brtrue.s IL_0006
    b"\x16"  # 03 ldc.i4.0
    b"\x2b\x00"  # 04 br.s IL_0006
    b"\x00"  # 06 nop
    b"\x2a"  # 07 ret
)
JOIN_BODY = build_fat_method_body(JOIN_CODE, max_stack=1)

JOIN_MERGE_OFFSET = 0x6
JOIN_BRANCH_CHAIN = (0x0, 0x1, 0x6)
JOIN_FALLTHROUGH_CHAIN = (0x0, 0x1, 0x3, 0x4, 0x6)


# ---------------------------------------------------------------------------
# Missing call signature
#
#   IL_0000: ldc.i4.0
#   IL_0001: brfalse.s IL_0009
#   IL_0003: ldc.i4.0
#   IL_0004: call void StackFixtures::Unknown(int32)
#   IL_0009: ret
#
# The call token has no resolver entry.  The other branch reaches ret with a
# known height 0, but ret must be reported as unknown, not verified.
# ---------------------------------------------------------------------------
MISSING_SIGNATURE_CODE = (
    b"\x16"  # 00 ldc.i4.0
    b"\x2c\x06"  # 01 brfalse.s IL_0009
    b"\x16"  # 03 ldc.i4.0
    b"\x28\x02\x00\x00\x0a"  # 04 call token 0x0A000002
    b"\x2a"  # 09 ret
)
MISSING_SIGNATURE_BODY = build_fat_method_body(MISSING_SIGNATURE_CODE, max_stack=1)

MISSING_SIGNATURE_CALL_TOKEN = 0x0A000002
MISSING_SIGNATURE_CALL_CHAIN = (0x0, 0x1, 0x3, 0x4)
MISSING_SIGNATURE_RET_OFFSET = 0x9


# ---------------------------------------------------------------------------
# Exception handler entries
# ---------------------------------------------------------------------------
# try { ldstr; call void(string); leave.s ret } catch { pop; leave.s ret } ret
CATCH_CODE = (
    b"\x72\x01\x00\x00\x70"  # 00 ldstr token 0x70000001
    b"\x28\x01\x00\x00\x0a"  # 05 call token 0x0A000001
    b"\xde\x03"  # 0A leave.s IL_000F? (target computed below)
    b"\x26"  # 0C pop
    b"\xde\x00"  # 0D leave.s IL_000F
    b"\x2a"  # 0F ret
)
CATCH_BODY = build_fat_method_body(
    CATCH_CODE,
    max_stack=1,
    handlers=((0, 0x0, 0xA, 0xC, 0x3, 0x01000002),),
)

# try { ldc.i4.0; leave.s ret } finally { endfinally } ret
FINALLY_CODE = (
    b"\x16"  # 00 ldc.i4.0
    b"\xde\x01"  # 01 leave.s IL_0004
    b"\xdc"  # 03 endfinally
    b"\x2a"  # 04 ret
)
FINALLY_BODY = build_fat_method_body(
    FINALLY_CODE,
    max_stack=1,
    handlers=((2, 0x0, 0x3, 0x3, 0x2, 0x0),),
)


def all_issue_kinds(result) -> List[str]:
    return [issue.kind.value for issue in result.issues]

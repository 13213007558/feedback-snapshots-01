# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import struct
import binascii

import pytest

from dncil.cil.body import CilMethodBody
from dncil.cil.enums import CorILMethod, OpCodeValue, CorILMethodSect
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token
from dncil.cil.body.reader import CilMethodBodyReaderBytes

"""
.method private hidebysig static
    void Main (
        string[] args
    ) cil managed
{
    // Header Size: 12 bytes
    // Code Size: 37 (0x25) bytes
    .maxstack 1
    .entrypoint

    .try
    {
        .try
        {
            /* 0x0000025C 7201000070   */ IL_0000: ldstr     "Hello World!"
            /* 0x00000261 280B00000A   */ IL_0005: call      void [System.Console]System.Console::WriteLine(string)
            /* 0x00000266 DE18         */ IL_000A: leave.s   IL_0024
        } // end .try
        catch [System.Runtime]System.Exception
        {
            /* 0x00000268 26           */ IL_000C: pop
            /* 0x00000269 721B000070   */ IL_000D: ldstr     "Exception occurred."
            /* 0x0000026E 280B00000A   */ IL_0012: call      void [System.Console]System.Console::WriteLine(string)
            /* 0x00000273 DE0B         */ IL_0017: leave.s   IL_0024
        } // end handler
    } // end .try
    finally
    {
        /* 0x00000275 7243000070   */ IL_0019: ldstr     "Finally occurred."
        /* 0x0000027A 280B00000A   */ IL_001E: call      void [System.Console]System.Console::WriteLine(string)
        /* 0x0000027F DC           */ IL_0023: endfinally
    } // end handler

    /* 0x00000280 2A           */ IL_0024: ret
} // end of method Program::Main
"""
method_body_fat = binascii.unhexlify(
    "1B30010025000000000000007201000070280B00000ADE1826721B000070280B00000ADE0B7243000070280B00000ADC2A000000011C0000000000000C0C000D0D000001020000001919000B00000000"
)

"""
.method public hidebysig specialname rtspecialname
    instance void .ctor () cil managed
{
    // Header Size: 1 byte
    // Code Size: 7 (0x7) bytes
    .maxstack 8

    /* 0x000002A1 02           */ IL_0000: ldarg.0
    /* 0x000002A2 280C00000A   */ IL_0001: call      instance void [System.Runtime]System.Object::.ctor()
    /* 0x000002A7 2A           */ IL_0006: ret
} // end of method Program::.ctor
"""
method_body_tiny = binascii.unhexlify("1E02280C00000A2A")


def test_invalid_header_format():
    reader = CilMethodBodyReaderBytes(b"\x00")

    with pytest.raises(MethodBodyFormatError):
        _ = CilMethodBody(reader)


def test_empty_method_body():
    reader = CilMethodBodyReaderBytes(b"")

    with pytest.raises(MethodBodyFormatError):
        _ = CilMethodBody(reader)


def test_read_tiny_header():
    reader = CilMethodBodyReaderBytes(method_body_tiny)
    body = CilMethodBody(reader)

    assert body.header_size == 0x1
    assert body.flags.TinyFormat1
    assert not body.flags.TinyFormat
    assert not body.flags.SmallFormat
    assert not body.flags.MoreSects
    assert not body.flags.FatFormat
    assert body.flags.is_tiny()
    assert body.flags.value == CorILMethod.TinyFormat1
    assert body.max_stack == 0x8
    assert body.local_var_sig_tok is None
    assert body.code_size == 0x7
    assert body.size == len(method_body_tiny)
    assert body.header_size + body.code_size == body.size
    assert body.header_size + body.code_size + body.exception_handlers_size == body.size
    assert body.get_bytes() == method_body_tiny
    assert (
        body.get_header_bytes() + body.get_instruction_bytes() + body.get_exception_handler_bytes() == method_body_tiny
    )


def test_read_tiny_header_instructions():
    reader = CilMethodBodyReaderBytes(method_body_tiny)
    body = CilMethodBody(reader)

    assert len(body.instructions) == 0x3
    assert body.instructions[0].offset == 0x1
    assert body.instructions[0].opcode.value == OpCodeValue.Ldarg_0
    assert isinstance(body.instructions[1].operand, Token)
    assert body.instructions[1].operand.table == 0xA
    assert body.instructions[1].operand.rid == 0xC
    assert body.instructions[1].get_bytes() == b"\x28\x0c\x00\x00\x0a"
    assert (
        body.instructions[1].get_opcode_bytes() + body.instructions[1].get_operand_bytes()
        == body.instructions[1].get_bytes()
    )
    assert body.instructions[2].offset == 0x7
    assert body.instructions[2].opcode.value == OpCodeValue.Ret

    insn_bytes = bytes()
    for insn in body.instructions:
        insn_bytes += insn.get_bytes()

    assert insn_bytes == body.get_instruction_bytes()


def test_read_fat_header():
    reader = CilMethodBodyReaderBytes(method_body_fat)
    body = CilMethodBody(reader)

    assert body.flags.FatFormat
    assert body.flags.MoreSects
    assert body.flags.InitLocals
    assert body.flags.is_fat()
    assert body.header_size == 0xC
    assert body.max_stack == 0x1
    assert body.code_size == 0x25
    assert body.size == len(method_body_fat)
    assert body.header_size + body.code_size <= body.size
    assert body.header_size + body.code_size + body.exception_handlers_size == body.size
    assert body.get_bytes() == method_body_fat
    assert (
        body.get_header_bytes() + body.get_instruction_bytes() + body.get_exception_handler_bytes() == method_body_fat
    )


def test_read_fat_header_instructions():
    reader = CilMethodBodyReaderBytes(method_body_fat)
    body = CilMethodBody(reader)

    assert len(body.instructions) == 0xB
    assert body.instructions[0].offset == body.offset + body.header_size
    assert body.instructions[0].opcode.value == OpCodeValue.Ldstr
    assert body.instructions[0].mnemonic == "ldstr"
    assert isinstance(body.instructions[1].operand, Token)
    assert body.instructions[1].operand.table == 0xA
    assert body.instructions[1].operand.rid == 0xB
    assert body.instructions[1].get_bytes() == b"\x28\x0b\x00\x00\x0a"
    assert (
        body.instructions[1].get_opcode_bytes() + body.instructions[1].get_operand_bytes()
        == body.instructions[1].get_bytes()
    )
    assert body.instructions[1].size == len(body.instructions[1].get_bytes())
    assert body.instructions[1].get_opcode_size() + body.instructions[1].get_operand_size() == body.instructions[1].size
    assert body.instructions[9].offset == 0x2F
    assert body.instructions[9].opcode.value == OpCodeValue.Endfinally

    insn_bytes = bytes()
    for insn in body.instructions:
        insn_bytes += insn.get_bytes()

    assert insn_bytes == body.get_instruction_bytes()


def test_read_fat_header_exception_handlers():
    reader = CilMethodBodyReaderBytes(method_body_fat)
    body = CilMethodBody(reader)

    assert len(body.exception_handlers) == 0x2
    assert body.exception_handlers[0].try_start == 0x0
    assert body.exception_handlers[0].try_end == 0xC
    assert body.exception_handlers[0].handler_start == 0xC
    assert body.exception_handlers[0].handler_end == 0x19
    assert isinstance(body.exception_handlers[0].catch_type, Token)
    assert body.exception_handlers[1].is_finally()
    # regression: handler length is a distinct field (fat handler_start was read twice,
    # and tiny handler_len was incorrectly read as a 16-bit value)
    assert body.exception_handlers[1].try_start == 0x0
    assert body.exception_handlers[1].try_end == 0x19
    assert body.exception_handlers[1].handler_start == 0x19
    assert body.exception_handlers[1].handler_end == 0x24


# ---------------------------------------------------------------------------
# Multiple extra data sections (MoreSects chaining)
#
# Hand-built fat method body whose code is five nop instructions plus a ret
# (code size 6). Two extra data sections follow, each starting on a 4-byte
# boundary. A single marker byte standing in for an adjacent method's first
# byte is appended so we can prove a failed parse never consumes it.
# ---------------------------------------------------------------------------

multi_section_code = b"\x00" * 5 + b"\x2a"
multi_section_fat_header = struct.pack("<HHII", 0x301B, 1, len(multi_section_code), 0)
# first byte of an "adjacent method"; intentionally not a valid body on its own
neighbor_byte = b"\x06"


def _section_header(flags: int, kind: int, size: int) -> bytes:
    section_flags = (flags | kind) & 0xFF
    return struct.pack("<BBBB", section_flags, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF)


def _tiny_section(more_sects: bool, clauses):
    # clause tuple: (flags, try_start, try_end, handler_start, handler_end, token)
    body = b"".join(
        struct.pack("<HHBHBI", flags, ts, te - ts, hs, he - hs, token) for flags, ts, te, hs, he, token in clauses
    )
    assert struct.calcsize("<HHBHBI") == 12
    header_flags = CorILMethodSect.MoreSects if more_sects else 0
    return _section_header(header_flags, CorILMethodSect.EHTable, 4 + len(body)) + body


def _fat_section(more_sects: bool, clauses):
    body = b"".join(
        struct.pack("<IIIIII", flags, ts, te - ts, hs, he - hs, token) for flags, ts, te, hs, he, token in clauses
    )
    assert struct.calcsize("<IIIIII") == 24
    header_flags = CorILMethodSect.FatFormat | (CorILMethodSect.MoreSects if more_sects else 0)
    return _section_header(header_flags, CorILMethodSect.EHTable, 4 + len(body)) + body


def _build_two_tiny_sections():
    section_one = _tiny_section(True, [(0x0, 0x0, 0x2, 0x2, 0x4, 0x02000001)])
    section_two = _tiny_section(False, [(0x2, 0x2, 0x4, 0x4, 0x6, 0x0)])

    method = multi_section_fat_header + multi_section_code
    method += b"\x00" * ((-len(method)) % 4) + section_one
    section_two_start = len(method)
    method += section_two
    return method, section_two_start


def test_multiple_extra_data_sections():
    """two legal tiny EH sections parse as one method, leaving the neighbor byte alone"""
    method, section_two_start = _build_two_tiny_sections()
    reader = CilMethodBodyReaderBytes(method + neighbor_byte)

    body = CilMethodBody(reader)

    assert body.flags.MoreSects
    assert body.code_size == len(multi_section_code)
    assert body.size == len(method)
    assert body.get_bytes() == method
    # reader sits exactly on the first byte of the adjacent method
    assert reader.tell() == len(method)
    assert reader.read(1) == neighbor_byte
    assert body.unparsed_sections == []

    assert len(body.exception_handlers) == 2
    first, second = body.exception_handlers
    assert first.is_catch()
    assert (first.try_start, first.try_end, first.handler_start, first.handler_end) == (0, 2, 2, 4)
    assert first.catch_type == Token(0x02000001)
    assert second.is_finally()
    assert (second.try_start, second.try_end, second.handler_start, second.handler_end) == (2, 4, 4, 6)
    assert second.catch_type is None

    # section offsets used to build the corruption case below
    assert section_two_start == 36


def test_multiple_fat_extra_data_sections():
    """two fat EH sections use 24-byte clauses and still resolve all handlers"""
    section_one = _fat_section(True, [(0x0, 0x0, 0x2, 0x2, 0x4, 0x02000001)])
    section_two = _fat_section(False, [(0x2, 0x2, 0x4, 0x4, 0x6, 0x0)])

    method = multi_section_fat_header + multi_section_code
    method += b"\x00" * ((-len(method)) % 4) + section_one + section_two

    reader = CilMethodBodyReaderBytes(method + neighbor_byte)
    body = CilMethodBody(reader)

    assert body.size == len(method)
    assert body.get_bytes() == method
    assert reader.tell() == len(method)
    assert reader.read(1) == neighbor_byte
    assert len(body.exception_handlers) == 2
    first, second = body.exception_handlers
    assert (first.try_start, first.try_end, first.handler_start, first.handler_end) == (0, 2, 2, 4)
    assert first.catch_type == Token(0x02000001)
    assert (second.try_start, second.try_end, second.handler_start, second.handler_end) == (2, 4, 4, 6)


def test_corrupted_second_section_does_not_swallow_neighbor():
    """a bad declared size in the second section fails and rewinds to its header"""
    method, section_two_start = _build_two_tiny_sections()
    corrupted = bytearray(method + neighbor_byte)
    # shrink the declared section size to a value that cannot hold whole 12-byte clauses
    corrupted[section_two_start + 1] = 0x0A

    reader = CilMethodBodyReaderBytes(bytes(corrupted))
    with pytest.raises(MethodBodyFormatError):
        CilMethodBody(reader)

    # the failed parse rewinds to the start of the bad section instead of running
    # into whatever follows the method body
    assert reader.tell() == section_two_start
    reader.seek(len(method))
    assert reader.read(1) == neighbor_byte


def test_truncated_second_section_rewinds():
    """a stream ending inside the second section is reported instead of silently accepted"""
    method, section_two_start = _build_two_tiny_sections()

    reader = CilMethodBodyReaderBytes(method[: section_two_start + 6])
    with pytest.raises(MethodBodyFormatError):
        CilMethodBody(reader)

    assert reader.tell() == section_two_start


def test_handler_range_outside_code_rejected():
    """clause offsets must stay within the method's code_size"""
    method, section_two_start = _build_two_tiny_sections()
    corrupted = bytearray(method + neighbor_byte)
    # overwrite try_start (first u16 inside the second section's only clause)
    corrupted[section_two_start + 4 + 2] = 0xFF

    reader = CilMethodBodyReaderBytes(bytes(corrupted))
    with pytest.raises(MethodBodyFormatError):
        CilMethodBody(reader)

    assert reader.tell() == section_two_start
    reader.seek(len(method))
    assert reader.read(1) == neighbor_byte


def test_section_size_smaller_than_header_rejected():
    """a declared section size must cover its own 4-byte header"""
    method, section_two_start = _build_two_tiny_sections()
    corrupted = bytearray(method + neighbor_byte)
    corrupted[section_two_start + 1] = 0x02

    reader = CilMethodBodyReaderBytes(bytes(corrupted))
    with pytest.raises(MethodBodyFormatError):
        CilMethodBody(reader)

    assert reader.tell() == section_two_start


def test_unknown_section_kind_kept_raw():
    """an unknown section kind is preserved verbatim and chained sections still parse"""
    unknown_section = _section_header(CorILMethodSect.MoreSects, CorILMethodSect.OptILTable, 8)
    unknown_section += b"\xde\xad\xbe\xef"
    section_two = _tiny_section(False, [(0x2, 0x2, 0x4, 0x4, 0x6, 0x0)])

    method = multi_section_fat_header + multi_section_code
    method += b"\x00" * ((-len(method)) % 4) + unknown_section + section_two

    reader = CilMethodBodyReaderBytes(method + neighbor_byte)
    body = CilMethodBody(reader)

    assert body.size == len(method)
    assert body.get_bytes() == method
    assert body.unparsed_sections == [b"\xde\xad\xbe\xef"]
    assert len(body.exception_handlers) == 1
    eh = body.exception_handlers[0]
    assert (eh.try_start, eh.try_end, eh.handler_start, eh.handler_end) == (2, 4, 4, 6)
    assert reader.tell() == len(method)
    assert reader.read(1) == neighbor_byte


def test_fat_section_with_partial_clause_rejected():
    """a fat section whose table size is not a whole number of 24-byte clauses fails"""
    section_one = _fat_section(True, [(0x0, 0x0, 0x2, 0x2, 0x4, 0x02000001)])
    # header claims 12 bytes of table data, which cannot hold a 24-byte fat clause
    bad_section = _section_header(0, CorILMethodSect.EHTable | CorILMethodSect.FatFormat, 16)
    bad_section += b"\x00" * 12

    method = multi_section_fat_header + multi_section_code
    method += b"\x00" * ((-len(method)) % 4) + section_one + bad_section
    bad_section_start = len(method) - 16

    reader = CilMethodBodyReaderBytes(method + neighbor_byte)
    with pytest.raises(MethodBodyFormatError):
        CilMethodBody(reader)

    assert reader.tell() == bad_section_start


def test_filter_start_outside_code_rejected():
    """a filter handler's filter_start is also bounded by code_size"""
    # fat filter clause: flags=1 (filter), try 0..2, handler 2..4, filter_start beyond code
    clause = struct.pack("<IIIIII", 0x1, 0x0, 0x2, 0x2, 0x2, 0xFFFF)
    section = _section_header(CorILMethodSect.FatFormat, CorILMethodSect.EHTable, 4 + len(clause)) + clause

    method = multi_section_fat_header + multi_section_code
    method += b"\x00" * ((-len(method)) % 4) + section
    section_start = len(method) - len(section)

    reader = CilMethodBodyReaderBytes(method + neighbor_byte)
    with pytest.raises(MethodBodyFormatError):
        CilMethodBody(reader)

    assert reader.tell() == section_start

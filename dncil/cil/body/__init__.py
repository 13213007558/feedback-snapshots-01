# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from dncil.cil.instruction import Instruction
    from dncil.cil.body.reader import CilMethodBodyReaderBase

from dncil.cil.enums import CorILMethod, CorILMethodSect
from dncil.cil.error import MethodBodyFormatError, MethodBodyParseIssue
from dncil.clr.token import Token
from dncil.cil.exception import ExceptionHandler
from dncil.cil.body.flags import CilMethodBodyFlags
from dncil.cil.instruction import Instruction


class CilMethodBody:
    """store managed method body

    strict parsing is the default: malformed or truncated input raises MethodBodyFormatError.
    pass partial=True to keep the confirmed prefix instead. Partial bodies expose an explicit
    complete flag and a list of MethodBodyParseIssue records; they never resynchronize by
    scanning for opcode-like bytes after a failure.
    """

    def __init__(self, reader: CilMethodBodyReaderBase, partial: bool = False):
        self.offset: int
        self.header_size: int = 0
        self.flags: Optional[CilMethodBodyFlags] = None
        self.max_stack: int = 0
        self.code_size: int = 0
        self.local_var_sig_tok: Optional[Token] = None
        self.size: int = 0
        self.raw_bytes: bytes = b""
        self.exception_handlers_size: int = 0

        self.instructions: List[Instruction] = []
        self.exception_handlers: List[ExceptionHandler] = []

        self.parse_mode: str = "partial" if partial else "strict"
        self.issues: List[MethodBodyParseIssue] = []
        self.header_parsed: bool = False
        # number of bytes present in the input for this method
        self.available_size: int = 0
        # total body size declared by the header, when it can be determined
        self.declared_size: Optional[int] = None
        self.parser_error: Optional[MethodBodyFormatError] = None

        # set method offset
        self.offset = reader.tell()

        if partial:
            self.parse_partial(reader)
        else:
            self.parse_strict(reader)

    def __int__(self) -> int:
        return self.offset

    @property
    def is_complete(self) -> bool:
        """check if the entire declared method body was confirmed"""
        return not self.issues

    @property
    def is_partial(self) -> bool:
        """check if this result only holds a confirmed prefix of the method"""
        return bool(self.issues)

    def get_parse_report(self) -> Dict[str, Any]:
        """
        export a machine readable summary of what was confirmed.

        This is intended for forensic consumers: complete is always present, and partial
        results name the confirmed prefix and the unconfirmed remainder instead of quietly
        presenting the acquired bytes as a whole method.
        """
        confirmed_end: int = self.offset
        if self.is_complete:
            confirmed_end = self.offset + self.size
        elif self.instructions:
            last = self.instructions[-1]
            confirmed_end = last.offset + last.size
        elif self.header_parsed:
            confirmed_end = self.offset + self.header_size

        confirmed_instruction_bytes: int = sum(insn.size for insn in self.instructions)

        report: Dict[str, Any] = {
            "offset": self.offset,
            "parse_mode": self.parse_mode,
            "complete": self.is_complete,
            "partial": self.is_partial,
            "header_parsed": self.header_parsed,
            "declared_size": self.declared_size,
            "available_size": self.available_size,
            "acquired_size": self.size,
            "declared_code_size": self.code_size if self.header_parsed else None,
            "acquired_code_bytes": self._acquired_code_bytes(),
            "confirmed_instruction_bytes": confirmed_instruction_bytes,
            "confirmed_end": confirmed_end,
            "instruction_count": len(self.instructions),
            "exception_handler_count": len(self.exception_handlers),
            "issues": [issue.to_dict() for issue in self.issues],
        }

        if not self.is_complete:
            # partial bodies must never be mistaken for complete ones by a consumer that only
            # looks at the status field
            report["status"] = "partial"
        else:
            report["status"] = "complete"

        for issue in self.issues:
            report["first_error_offset"] = issue.error_offset
            report["first_missing_offset"] = issue.first_missing_offset
            if issue.unconfirmed_end > issue.unconfirmed_start:
                report["unconfirmed_start"] = issue.unconfirmed_start
                report["unconfirmed_end"] = issue.unconfirmed_end
            break

        return report

    def parse_strict(self, reader: CilMethodBodyReaderBase):
        """parse the method body, raising MethodBodyFormatError on any problem"""
        # parse the method body
        self.parse_header(reader)
        self.header_parsed = True
        self.parse_instructions(reader)
        self.parse_exception_handlers(reader)

        # use initial offset + method body size to read method body bytes (not the most efficient)
        final_pos = reader.tell()
        reader.seek(self.offset)
        self.raw_bytes = reader.read(self.size)
        reader.seek(final_pos)

        # calculate exception handlers size
        self.exception_handlers_size = self.size - self.header_size - self.code_size
        self.available_size = len(self.raw_bytes)
        self.declared_size = self.size

    def parse_partial(self, reader: CilMethodBodyReaderBase):
        """parse as much of the method body as can be confirmed, recording every failure"""
        start: int = self.offset
        available_end: Optional[int] = self._available_end(reader)

        first_byte = self._peek(reader, start, 1)
        if not first_byte:
            self._add_issue(
                kind="header",
                reason="truncated_header",
                message="method body is empty",
                error_offset=start,
                confirmed_end=start,
                unconfirmed_start=start,
                unconfirmed_end=available_end if available_end is not None else start,
                required=1,
                available=0,
            )
            self._finish_partial(reader)
            return

        header_format: int = first_byte[0] & CorILMethod.FormatMask

        try:
            self.parse_header(reader)
        except MethodBodyFormatError as e:
            self.parser_error = e
            if header_format not in (CorILMethod.TinyFormat, CorILMethod.TinyFormat1, CorILMethod.FatFormat):
                reason = "bad_header_format"
            elif header_format == CorILMethod.FatFormat:
                reason = "truncated_fat_header"
            else:
                reason = "truncated_header"

            # when the fat header format byte was read, it also declares the header size in
            # 4-byte words. parse_header only converts that to bytes once the header is read,
            # so derive it from the format byte for an accurate unconfirmed range.
            declared_header_words: int = self.header_size
            if header_format == CorILMethod.FatFormat:
                if not declared_header_words:
                    declared_header_words = first_byte[0] >> 12
                if declared_header_words:
                    declared_header_end = start + declared_header_words * 4
                elif available_end is not None:
                    declared_header_end = max(start + 1, available_end)
                else:
                    declared_header_end = start + 1
            elif available_end is not None:
                # the declared size is not knowable; all acquired bytes remain unconfirmed
                declared_header_end = max(start + 1, available_end)
            else:
                declared_header_end = start + 1

            # the header was not fully read, so no part of it is confirmed. Do not expose a
            # partial size as if it were the real one.
            self.header_size = 0
            self.flags = None
            self.code_size = 0
            self.max_stack = 0
            self.local_var_sig_tok = None

            self._add_issue(
                kind="header",
                reason=reason,
                message=e.value,
                error_offset=e.offset if e.offset is not None else start,
                confirmed_end=start,
                unconfirmed_start=start,
                unconfirmed_end=declared_header_end,
                required=e.required,
                available=e.available,
            )
            self._finish_partial(reader)
            return

        self.header_parsed = True
        header_end: int = start + self.header_size

        # a fat header declares its own size (in 4-byte words). If the input ends before
        # that declared header end, the header is not complete and nothing after it is trusted.
        if (
            header_format == CorILMethod.FatFormat
            and available_end is not None
            and header_end > available_end
        ):
            # parse_header may have computed a negative code size from bytes that do not
            # belong to this header; drop all of it.
            available_header_bytes: int = max(0, available_end - start)
            message = "incomplete fat header: declared 0x%X bytes but only 0x%X available" % (
                self.header_size,
                available_header_bytes,
            )
            self.parser_error = MethodBodyFormatError(
                message, offset=start, required=self.header_size, available=available_header_bytes
            )
            self.header_size = 0
            self.flags = None
            self.code_size = 0
            self.max_stack = 0
            self.local_var_sig_tok = None
            self.header_parsed = False
            self._add_issue(
                kind="header",
                reason="truncated_fat_header",
                message=message,
                error_offset=start,
                confirmed_end=start,
                unconfirmed_start=start,
                unconfirmed_end=header_end,
                required=self.parser_error.required,
                available=available_header_bytes,
            )
            self._finish_partial(reader)
            return

        code_start: int = header_end
        code_end: int = code_start + self.code_size

        # bound instruction reads to the declared code region so an operand can never be
        # satisfied by bytes that belong to the exception handler table
        instruction_reader = self._limited_reader(reader, code_end)
        try:
            self.parse_instructions(instruction_reader)
        except MethodBodyFormatError as e:
            self.parser_error = e
            self._record_instruction_error(e, code_start, code_end, reader)
            self._finish_partial(reader)
            return

        # if the stream ended exactly on an instruction boundary, the code section is still
        # short of its declared size. the prefix is valid, but the method is not complete.
        confirmed_end = self._last_instruction_end(code_start)
        if confirmed_end < code_end:
            self.parser_error = MethodBodyFormatError(
                "not enough data while parsing method body @ offset 0x%X" % confirmed_end,
                offset=confirmed_end,
                required=code_end - confirmed_end,
                available=0,
            )
            self._add_issue(
                kind="instructions",
                reason="truncated_code",
                message=self.parser_error.value,
                error_offset=confirmed_end,
                confirmed_end=confirmed_end,
                unconfirmed_start=confirmed_end,
                unconfirmed_end=code_end,
                required=code_end - confirmed_end,
                available=0,
            )
            self._finish_partial(reader)
            return

        try:
            self._parse_exception_handlers_partial(reader, code_end)
        except MethodBodyFormatError as e:
            self.parser_error = e
            self._record_exception_handler_error(reader, e, code_end)
            self._finish_partial(reader)
            return

        self._finish_partial(reader)

    def _parse_exception_handlers_partial(self, reader: CilMethodBodyReaderBase, code_end: int):
        """parse exception handlers, enforcing declared section boundaries"""
        if self.flags is None or not self.flags.MoreSects:
            return

        # extra data sections start at first 4-byte boundary
        section_start: int = (code_end + 3) & ~3
        info = self._section_header_info(reader, section_start)

        if info is None or info["status"] != "ok":
            raise MethodBodyFormatError(
                "missing exception handler table @ offset 0x%X" % section_start,
                offset=section_start,
                reason="truncated_eh_header",
            )

        if info["kind"] != "eh":
            # MoreSects points at a section kind that does not hold exception handlers.
            # Strict parsing accepts this, so partial parsing must not turn it into a failure.
            return

        # position the stream just after the section header byte: the tiny parser then reads
        # the 8-bit data size, while the fat parser rewinds one byte to read the 32-bit size
        declared_end: int = section_start + info["total"]
        # bound reads to the declared table so trailing bytes can never be mistaken for
        # additional clauses
        section_reader = self._limited_reader(reader, declared_end)
        section_reader.seek(section_start + 1)
        if info["fat"]:
            self.parse_fat_exception_handlers(section_reader)
        else:
            self.parse_tiny_exception_handlers(section_reader)

        actual_end: int = section_reader.tell()
        if actual_end < declared_end:
            raise MethodBodyFormatError(
                "not enough data while parsing exception handlers @ offset 0x%X" % actual_end,
                offset=actual_end,
                required=declared_end - actual_end,
                available=0,
            )

    def _record_exception_handler_error(self, reader: CilMethodBodyReaderBase, e: MethodBodyFormatError, code_end: int):
        """turn an exception handler parsing error into a partial result record"""
        section_start: int = (code_end + 3) & ~3
        info = self._section_header_info(reader, section_start)
        available_end: Optional[int] = self._available_end(reader)

        if info is None or (available_end is not None and section_start >= available_end):
            # the method says more sections follow, but there is no exception handler table.
            # the unconfirmed range covers the padding and the section header that should
            # have started at the aligned offset.
            self._add_issue(
                kind="exception_handlers",
                reason="missing_exception_handlers",
                message="missing exception handler table @ offset 0x%X" % section_start,
                error_offset=section_start,
                confirmed_end=code_end,
                unconfirmed_start=code_end,
                unconfirmed_end=section_start + 4,
                required=4,
                available=0 if available_end is None else max(0, available_end - section_start),
            )
            return

        if info["kind"] != "eh":
            self._add_issue(
                kind="exception_handlers",
                reason="missing_exception_handlers",
                message="missing exception handler table @ offset 0x%X" % section_start,
                error_offset=section_start,
                confirmed_end=code_end,
                unconfirmed_start=code_end,
                unconfirmed_end=section_start + 4,
            )
            return

        if info["status"] == "truncated_header":
            # both tiny and fat section headers occupy four bytes
            declared_end = section_start + 4
            self._add_issue(
                kind="exception_handlers",
                reason="truncated_exception_handler_header",
                message=e.value,
                error_offset=section_start,
                confirmed_end=code_end,
                unconfirmed_start=code_end,
                unconfirmed_end=declared_end,
                required=4,
                available=info.get("available"),
            )
            return

        entry_size: int = info["entry_size"]
        handler_start: int = info["handler_start"]
        confirmed_end = handler_start + len(self.exception_handlers) * entry_size
        self._add_issue(
            kind="exception_handlers",
            reason="truncated_exception_handlers",
            message=e.value,
            error_offset=e.offset if e.offset is not None else confirmed_end,
            confirmed_end=confirmed_end,
            unconfirmed_start=confirmed_end,
            unconfirmed_end=max(info["declared_end"], confirmed_end),
            required=e.required,
            available=e.available,
        )

    def _available_end(self, reader: CilMethodBodyReaderBase) -> Optional[int]:
        """absolute end offset of the input, if the reader knows it"""
        try:
            return reader.available()
        except Exception:
            return None

    def _limited_reader(self, reader: CilMethodBodyReaderBase, limit: int) -> Any:
        """wrap a reader so it cannot read at or beyond limit (imported lazily: cycle)"""
        from dncil.cil.body.reader import LimitedMethodBodyReader

        return LimitedMethodBodyReader(reader, limit)

    def _peek(self, reader: CilMethodBodyReaderBase, off: int, n: int) -> bytes:
        """read bytes without moving the stream position"""
        pos: int = reader.tell()
        try:
            reader.seek(off)
            return reader.read(n)
        except Exception:
            return b""
        finally:
            reader.seek(pos)

    def _last_instruction_end(self, code_start: int) -> int:
        """end offset of the last complete instruction, or the start of the code section"""
        if not self.instructions:
            return code_start
        insn: Instruction = self.instructions[-1]
        return insn.offset + insn.size

    def _record_instruction_error(self, e: MethodBodyFormatError, code_start: int, code_end: int, reader: Any = None):
        """turn an instruction parsing error into a partial result record"""
        confirmed_end: int = self._last_instruction_end(code_start)
        available_end: Optional[int] = None
        if reader is not None:
            available_end = self._available_end(reader)

        crosses_code_end: bool = (
            available_end is not None
            and available_end > code_end
            and e.offset is not None
            and e.offset < code_end
        )

        if e.reason == "operand":
            reason = "instruction_exceeds_code_size" if crosses_code_end else "truncated_operand"
        elif e.reason == "opcode":
            reason = "truncated_opcode"
        elif e.reason == "bad_opcode":
            reason = "bad_opcode"
        elif e.reason == "bad_operand":
            reason = "bad_operand"
        elif e.reason == "instruction_exceeds_code_size":
            reason = "instruction_exceeds_code_size"
        elif e.offset is not None and e.available is not None and e.available < (e.required or 0):
            reason = "truncated_instruction"
        else:
            reason = "bad_instruction"

        message = e.value
        if reason == "instruction_exceeds_code_size":
            message = "instruction @ offset 0x%X crosses declared code size boundary 0x%X" % (
                e.offset if e.offset is not None else confirmed_end,
                code_end,
            )

        self._add_issue(
            kind="instructions",
            reason=reason,
            message=message,
            error_offset=e.offset if e.offset is not None else confirmed_end,
            confirmed_end=confirmed_end,
            unconfirmed_start=confirmed_end,
            unconfirmed_end=code_end,
            required=e.required,
            available=e.available,
        )

    def _section_header_info(self, reader: CilMethodBodyReaderBase, section_start: int) -> Optional[Dict[str, Any]]:
        """inspect an extra-data section header without consuming it"""
        first = self._peek(reader, section_start, 1)
        if not first:
            return None

        header_byte: int = first[0]
        if header_byte & CorILMethodSect.KindMask != CorILMethodSect.EHTable:
            return {
                "kind": "none",
                "fat": bool(header_byte & CorILMethodSect.FatFormat),
                "status": "ok",
                "total": 0,
                "handler_start": section_start + 4,
                "entry_size": 0,
                "declared_end": section_start,
            }

        if header_byte & CorILMethodSect.FatFormat:
            raw = self._peek(reader, section_start, 4)
            if len(raw) < 4:
                return {
                    "kind": "eh",
                    "fat": True,
                    "status": "truncated_header",
                    "total": None,
                    "handler_start": section_start + 4,
                    "entry_size": ExceptionHandler.FAT_SIZE,
                    "declared_end": None,
                    "required": 4,
                    "available": len(raw),
                }
            # the 24-bit size counts exception handler bytes only; the 4-byte section header
            # is not part of it. Like the parser, count whole clauses.
            data_size: int = int.from_bytes(raw, "little") >> 8
            num_clauses: int = data_size // ExceptionHandler.FAT_SIZE
            return {
                "kind": "eh",
                "fat": True,
                "status": "ok",
                "total": 4 + num_clauses * ExceptionHandler.FAT_SIZE,
                "handler_start": section_start + 4,
                "entry_size": ExceptionHandler.FAT_SIZE,
                "declared_end": section_start + 4 + num_clauses * ExceptionHandler.FAT_SIZE,
            }

        raw = self._peek(reader, section_start, 4)
        if len(raw) < 4:
            return {
                "kind": "eh",
                "fat": False,
                "status": "truncated_header",
                "total": None,
                "handler_start": section_start + 4,
                "entry_size": ExceptionHandler.TINY_SIZE,
                "declared_end": None,
                "required": 4,
                "available": len(raw),
            }
        # the 8-bit size is a byte count. the parser consumes whole 12-byte clauses, so the
        # declared section length is the 4-byte header plus those whole clauses.
        num_clauses: int = raw[1] // ExceptionHandler.TINY_SIZE
        return {
            "kind": "eh",
            "fat": False,
            "status": "ok",
            "total": 4 + num_clauses * ExceptionHandler.TINY_SIZE,
            "handler_start": section_start + 4,
            "entry_size": ExceptionHandler.TINY_SIZE,
            "declared_end": section_start + 4 + num_clauses * ExceptionHandler.TINY_SIZE,
        }

    def _compute_declared_size(self, reader: CilMethodBodyReaderBase) -> Optional[int]:
        """calculate the total body size declared by the header, when possible"""
        if not self.header_parsed:
            return None

        base: int = self.header_size + self.code_size
        if self.flags is None or not self.flags.MoreSects:
            return base

        section_start: int = (self.offset + base + 3) & ~3
        padding: int = section_start - (self.offset + base)
        info = self._section_header_info(reader, section_start)
        if info is None or info["status"] != "ok":
            return None
        if info["kind"] != "eh":
            # strict parsing consumes the one section header byte and stops
            return base + padding + 1
        return base + padding + info["total"]

    def _finish_partial(self, reader: CilMethodBodyReaderBase):
        """collect the bytes that were available and finalize partial result metadata"""
        available_end: Optional[int] = self._available_end(reader)
        if available_end is None:
            available_end = max(self.offset, reader.tell())
        self.available_size = max(0, available_end - self.offset)

        self.declared_size = self._compute_declared_size(reader)

        raw_end: int = available_end
        if self.declared_size is not None:
            raw_end = min(raw_end, self.offset + self.declared_size)

        try:
            reader.seek(self.offset)
            self.raw_bytes = reader.read(max(0, raw_end - self.offset))
        except Exception:
            self.raw_bytes = b""

        # keep the declared code size untouched; size only reports bytes actually acquired
        self.size = len(self.raw_bytes)
        if self.header_parsed and self.size > self.header_size + self.code_size:
            self.exception_handlers_size = self.size - self.header_size - self.code_size
        else:
            self.exception_handlers_size = 0

    def _add_issue(
        self,
        kind: str,
        reason: str,
        message: str,
        error_offset: int,
        confirmed_end: int,
        unconfirmed_start: int,
        unconfirmed_end: int,
        required: Optional[int] = None,
        available: Optional[int] = None,
    ):
        issue = MethodBodyParseIssue(
            kind=kind,
            reason=reason,
            message=message,
            error_offset=error_offset,
            confirmed_end=confirmed_end,
            unconfirmed_start=unconfirmed_start,
            unconfirmed_end=unconfirmed_end,
            required=required,
            available=available,
        )
        self.issues.append(issue)

    def _acquired_code_bytes(self) -> int:
        """number of code bytes present in the input, capped at the declared code size"""
        if not self.header_parsed:
            return 0
        return max(0, min(self.code_size, self.size - self.header_size))

    def get_bytes(self) -> bytes:
        """get method body bytes that were acquired"""
        return self.raw_bytes

    def get_header_bytes(self) -> bytes:
        """get method header bytes"""
        return self.raw_bytes[: self.header_size]

    def get_instruction_bytes(self) -> bytes:
        """get method instruction bytes"""
        return self.raw_bytes[self.header_size : self.header_size + self.code_size]

    def get_exception_handler_bytes(self) -> bytes:
        """get method exception handler bytes"""
        return self.raw_bytes[self.header_size + self.code_size :]

    def parse_header(self, reader: CilMethodBodyReaderBase):
        """get method body header"""
        # header byte gives us the format and, in fat format, implementation flags used at runtime
        header_byte: int = reader.read_uint8()[0]
        if header_byte & CorILMethod.FormatMask in (CorILMethod.TinyFormat, CorILMethod.TinyFormat1):
            # tiny format - use default values specified by ECMA for all fields other than code size
            self.flags = CilMethodBodyFlags(header_byte & CorILMethod.FormatMask)
            self.header_size = 1
            self.max_stack = 8
            self.code_size = header_byte >> 2
            self.local_var_sig_tok = None
        elif header_byte & CorILMethod.FormatMask in (CorILMethod.FatFormat,):
            # fat format
            self.flags = CilMethodBodyFlags((reader.read_uint8()[0] << 8) | header_byte)
            self.header_size = self.flags.value >> 12
            self.max_stack = reader.read_uint16()[0]
            self.code_size = reader.read_uint32()[0]

            local_var_sig_tok = reader.read_uint32()[0]
            if local_var_sig_tok == 0:
                # zero indicates there are no local variables
                self.local_var_sig_tok = None
            else:
                self.local_var_sig_tok = Token(local_var_sig_tok)

            # ECMA states fat format size is "currently" 3; we may need to change this calculation if that ever changes
            reader.seek(reader.tell() - 12 + self.header_size * 4)

            # unsure on this check - may be some edge case handled by dnlib
            if self.header_size < 3:
                self.flags.value &= 0xFFF7

            # size indicates the number of 32-bit integers so we need to calc the total number of bytes
            self.header_size *= 4
        else:
            raise MethodBodyFormatError("bad header format 0x%02X" % (header_byte & CorILMethod.FormatMask))

    def parse_instructions(self, reader: CilMethodBodyReaderBase):
        """get CIL instructions"""
        current_offset: int = self.offset + self.header_size
        code_end_offset: int = reader.tell() + self.code_size

        # instructions are stored sequentially so we just read through the stream
        while reader.tell() < code_end_offset:
            insn: Instruction = reader.read_instruction(current_offset)
            if insn.offset + insn.size > code_end_offset:
                # the instruction is not boundary complete: its operand extends past the
                # declared code size. Never present it as a whole instruction.
                raise MethodBodyFormatError(
                    "instruction @ offset 0x%X crosses declared code size boundary 0x%X"
                    % (insn.offset, code_end_offset),
                    offset=insn.offset,
                    reason="instruction_exceeds_code_size",
                    required=insn.size,
                    available=code_end_offset - insn.offset,
                )
            current_offset += insn.size
            self.instructions.append(insn)

    def parse_exception_handlers(self, reader: CilMethodBodyReaderBase):
        """get exception handlers"""
        if not self.flags.MoreSects:
            # exception handlers are stored in extra data sections so bail if there are none
            self.size = reader.tell() - self.offset
            return

        # extra data sections start at first 4-byte boundary
        reader.seek((reader.tell() + 3) & ~3)

        # header byte gives us the format
        header_byte: int = reader.read_uint8()[0]

        # unsure on this check - may be some edge case handler by dnlib
        if header_byte & CorILMethodSect.KindMask != 1:
            self.size = reader.tell() - self.offset
            return

        if header_byte & CorILMethodSect.FatFormat:
            # fat format
            self.parse_fat_exception_handlers(reader)
        else:
            # tiny format
            self.parse_tiny_exception_handlers(reader)

        self.size = reader.tell() - self.offset

    def parse_fat_exception_handlers(self, reader: CilMethodBodyReaderBase):
        """get exception handlers in fat format"""
        # fat header is 8 bits (flags) + 24 bits (size) so to get the size we rewind 8 bits, read a 32-bit integer, and shift for the 24-bit integer
        reader.seek(reader.tell() - 1)
        total_size: int = reader.read_uint32()[0] >> 8

        # size is total bytes so we need to calc the number of exception handlers
        num_exceptions: int = total_size // ExceptionHandler.FAT_SIZE
        for _ in range(num_exceptions):
            eh: ExceptionHandler = ExceptionHandler(reader.read_uint32()[0])

            eh.try_start = reader.read_uint32()[0]
            eh.try_end = eh.try_start + reader.read_uint32()[0]

            eh.handler_start = reader.read_uint32()[0]
            eh.handler_end = eh.handler_start + reader.read_uint32()[0]

            if eh.is_catch():
                eh.catch_type = Token(reader.read_uint32()[0])
            elif eh.is_filter():
                eh.filter_start = reader.read_uint32()[0]
            else:
                _ = reader.read_uint32()[0]

            self.exception_handlers.append(eh)

    def parse_tiny_exception_handlers(self, reader: CilMethodBodyReaderBase):
        """get exception handlers in tiny format"""
        # size is total bytes so we need to calc the number of exception handlers
        num_exceptions: int = reader.read_uint8()[0] // ExceptionHandler.TINY_SIZE

        # skip padding (16 bits)
        reader.seek(reader.tell() + 2)

        for _ in range(num_exceptions):
            eh: ExceptionHandler = ExceptionHandler(reader.read_uint16()[0])

            eh.try_start = reader.read_uint16()[0]
            eh.try_end = eh.try_start + reader.read_uint8()[0]

            eh.handler_start = reader.read_uint16()[0]
            eh.handler_end = eh.handler_start + reader.read_uint8()[0]

            if eh.is_catch():
                eh.catch_type = Token(reader.read_uint32()[0])
            elif eh.is_filter():
                eh.filter_start = reader.read_uint32()[0]
            else:
                _ = reader.read_uint32()[0]

            self.exception_handlers.append(eh)

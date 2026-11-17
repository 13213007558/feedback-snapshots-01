# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import Optional


class MethodBodyFormatError(Exception):
    """
    generic method body format exception.

    Besides the human readable message, errors raised while parsing may carry
    structured information about a short or out-of-bounds read.  This lets the
    partial parser report exactly where parsing stopped without changing the
    strict-mode API, which only ever exposes the message.
    """

    def __init__(
        self,
        value: str,
        offset: Optional[int] = None,
        reason: Optional[str] = None,
        required: Optional[int] = None,
        available: Optional[int] = None,
    ):
        self.value: str = value
        # absolute stream offset of the read that failed
        self.offset: Optional[int] = offset
        # machine readable reason, e.g. "truncated" or "bad_opcode"
        self.reason: Optional[str] = reason
        # number of bytes the parser wanted and how many it could get
        self.required: Optional[int] = required
        self.available: Optional[int] = available

    def __str__(self) -> str:
        return repr(self.value)

    def annotate(self, reason: str) -> "MethodBodyFormatError":
        """set the reason if the error does not have one yet"""
        if self.reason is None:
            self.reason = reason
        return self


class MethodBodyParseIssue:
    """
    record where a managed method body could not be fully confirmed.

    This is a data record, not an exception. It is attached to method bodies that were
    parsed with the partial reader enabled.
    """

    def __init__(
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
        # parse stage: "header", "instructions" or "exception_handlers"
        self.kind: str = kind
        # specific failure: e.g. "truncated_operand", "missing_exception_handlers"
        self.reason: str = reason
        self.message: str = message
        # absolute offset of the first read that could not be satisfied
        self.error_offset: int = error_offset
        # end of the last completely parsed element (confirmed prefix)
        self.confirmed_end: int = confirmed_end
        # range of input bytes that were present but could not be confirmed
        self.unconfirmed_start: int = unconfirmed_start
        self.unconfirmed_end: int = unconfirmed_end
        # number of bytes required by the failed read and how many were available
        self.required: Optional[int] = required
        self.available: Optional[int] = available

    def __str__(self) -> str:
        return "%s (%s) @ offset 0x%X" % (self.kind, self.reason, self.error_offset)

    def __repr__(self) -> str:
        return str(self)

    @property
    def first_missing_offset(self) -> int:
        """
        offset of the first byte that could not be obtained.

        error_offset is the start of the read that failed; when a partial read was
        observed, the first actually missing byte follows the bytes that were available.
        """
        if self.available:
            return self.error_offset + self.available
        return self.error_offset

    def to_dict(self) -> dict:
        """export the issue for reporting"""
        return {
            "kind": self.kind,
            "reason": self.reason,
            "message": self.message,
            "error_offset": self.error_offset,
            "first_missing_offset": self.first_missing_offset,
            "confirmed_end": self.confirmed_end,
            "unconfirmed_start": self.unconfirmed_start,
            "unconfirmed_end": self.unconfirmed_end,
            "required": self.required,
            "available": self.available,
        }

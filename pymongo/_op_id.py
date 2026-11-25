# Copyright 2026-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You
# may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

"""Internal helpers for the APM operation id and retry attempt.

The retryable read/write logic sets OP_ID if APM/logging is enabled for the duration of each attempt
so that every attempt of one logical operation publishes the same operation_id.
Commands run outside that scope (handshake, auth, killCursors, pinned-cursor
getMores) read the default None and fall back to their request_id.

The retry attempt number is tracked alongside OP_ID so that the command events
published for a failed attempt and for the retry attempt that follows can be
linked to the same logical operation.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from types import TracebackType

OP_ID: ContextVar[int | None] = ContextVar("OP_ID", default=None)
ATTEMPT: ContextVar[int | None] = ContextVar("ATTEMPT", default=None)


def reset() -> None:
    OP_ID.set(None)
    ATTEMPT.set(None)


class _OpIdContext(AbstractContextManager[Any]):
    """Set OP_ID and ATTEMPT for the duration of a with block.

    :param op_id: The operation id shared by every attempt of one operation.
    :param attempt: The 1-based attempt number, or ``None`` when the command is
        not part of a retryable operation.
    """

    def __init__(self, op_id: int | None, attempt: int | None = None):
        self._op_id = op_id
        self._attempt = attempt

    def __enter__(self) -> None:
        self._token = OP_ID.set(self._op_id)
        self._attempt_token = ATTEMPT.set(self._attempt)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        ATTEMPT.reset(self._attempt_token)
        OP_ID.reset(self._token)

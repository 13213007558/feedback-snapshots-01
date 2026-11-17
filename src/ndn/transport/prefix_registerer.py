# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import abc
import dataclasses as dc
from enum import Enum

from .. import encoding as enc


class ManagementOutcome(str, Enum):
    """Outcome of one NFD management command."""

    CONFIRMED = 'confirmed'
    r"""The response is a valid, matching success response for this command."""

    REJECTED = 'rejected'
    r"""The forwarder returned a management error status (4xx or 5xx)."""

    NACKED = 'nacked'
    r"""The Interest was rejected with a NetworkNack."""

    TIMEOUT = 'timeout'
    r"""No matching response arrived before the Interest lifetime expired."""

    CANCELED = 'canceled'
    r"""The face was shut down while the command was outstanding."""

    UNKNOWN_STATUS = 'unknown_status'
    r"""The response has no status, or a status that is neither success nor rejection."""

    VALIDATION_FAILED = 'validation_failed'
    r"""The response Data did not pass the caller-provided validator."""

    NAME_MISMATCH = 'name_mismatch'
    r"""The response Data name is not the name of this command Interest."""

    PARAMETER_MISMATCH = 'parameter_mismatch'
    r"""The response describes different control parameters than the request."""

    MALFORMED_RESPONSE = 'malformed_response'
    r"""The response content is not a decodable NFD ControlResponse."""


@dc.dataclass(frozen=True, eq=False)
class ManagementResult:
    """
    Evidence for the result of one management command.

    ``bool(result)``, :attr:`confirmed`, :attr:`ok` and :attr:`success` are true only when
    the response matched this exact request, had a success status, and passed the
    caller's validation policy.
    """

    command: str
    name: str
    outcome: ManagementOutcome
    expected_name: str | None = None
    data_name: str | None = None
    status_code: int | None = None
    status_text: str | None = None
    request_parameters: dict | None = None
    response_parameters: dict | None = None
    request_digest: str | None = None
    validation_result: object | None = None
    nack_reason: int | None = None
    error: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.outcome is ManagementOutcome.CONFIRMED

    @property
    def ok(self) -> bool:
        return self.confirmed

    @property
    def kind(self) -> ManagementOutcome:
        return self.outcome

    @property
    def is_success(self) -> bool:
        return self.confirmed

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.confirmed is other
        if isinstance(other, ManagementOutcome):
            return self.outcome is other
        if isinstance(other, str):
            return self.outcome.value == other
        if isinstance(other, ManagementResult):
            return dc.astuple(self) == dc.astuple(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.command, self.name, self.outcome,
                     self.data_name, self.status_code))

    @property
    def success(self) -> bool:
        return self.confirmed

    def __bool__(self) -> bool:
        return self.confirmed


# Compatibility-friendly aliases for callers that name these types by command.
RegistrationOutcome = ManagementOutcome
RegistrationResult = ManagementResult
RegisterResult = ManagementResult


class PrefixRegisterer(abc.ABC):
    def __init__(self):
        self.app = None

    def set_app(self, app):
        self.app = app

    @abc.abstractmethod
    async def register(self, name: enc.NonStrictName, validator=None) -> bool:
        pass

    @abc.abstractmethod
    async def unregister(self, name: enc.NonStrictName, validator=None) -> bool:
        pass

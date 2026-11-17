# -----------------------------------------------------------------------------
# Copyright (C) 2019-2023 The python-ndn authors
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
import asyncio as aio
import logging
import struct
from hashlib import sha256

from .. import encoding as enc
from .. import security as sec
from .. import types
from .. import utils
from ..app_support import nfd_mgmt
from ..encoding import ndn_format_0_3 as fmt
from .prefix_registerer import ManagementOutcome, ManagementResult, PrefixRegisterer


_LOGGER = logging.getLogger(__name__)

# ControlResponse status codes defined by the NFD management protocol.
_SUCCESS_STATUS = frozenset({200, 201, 202, 204})
_REJECTION_STATUS = frozenset({
    400, 401, 403, 404, 405, 406, 409, 412, 413, 415, 422, 429,
    500, 501, 502, 503, 504,
})

_DEFAULT_LIFETIME = 1000


async def pass_all(_name, _sig, _context):
    return types.ValidResult.PASS


async def _accept_for_inspection(_name, _sig, _context):
    # Correlation checks must run before the caller's signature policy, so the
    # pipeline is asked to deliver the response for inspection. The caller's
    # policy is applied explicitly afterwards.
    return types.ValidResult.PASS


class _CommandSigner(sec.DigestSha256Signer):
    """Digest-SHA256 command signer with a reserved, strictly increasing signature time."""

    def __init__(self, signature_time: int):
        super().__init__(for_interest=True)
        self._signature_time = signature_time

    def write_signature_info(self, signature_info):
        super().write_signature_info(signature_info)
        signature_info.signature_time = self._signature_time


def _classify_status(status_code: int | None) -> ManagementOutcome | None:
    """Return the outcome implied by a status code, or None for a success status."""
    if status_code in _SUCCESS_STATUS:
        return None
    if status_code in _REJECTION_STATUS:
        return ManagementOutcome.REJECTED
    return ManagementOutcome.UNKNOWN_STATUS


def _normalized_name(value) -> enc.FormalName | None:
    if value is None:
        return None
    try:
        return enc.Name.normalize(value)
    except (TypeError, ValueError, IndexError, enc.DecodeError):
        return None


def _request_digest(command_name: enc.FormalName) -> str:
    """Hex SHA-256 of the encoded ControlParameters component, for caller auditing."""
    return sha256(bytes(command_name[-1])).hexdigest()


class NfdRegister(PrefixRegisterer):
    def __init__(self, lifetime: int = _DEFAULT_LIFETIME):
        super().__init__()
        self._lifetime = lifetime
        self._last_command_timestamp = 0
        # Commands are exchanged one at a time for two reasons: NFD rejects
        # commands signed with a reused timestamp, and the response for one
        # command must never be delivered to another command's pending Interest.
        self._command_semaphore = aio.Semaphore(1)

    def _reserve_signature_time(self) -> int:
        now = utils.timestamp()
        if now <= self._last_command_timestamp:
            now = self._last_command_timestamp + 1
        self._last_command_timestamp = now
        return now

    async def _execute(self, action: str, name: enc.NonStrictName,
                       validator=None) -> ManagementResult:
        command = f'rib/{action}'
        requested = enc.Name.normalize(name)
        request_parameters = {'name': enc.Name.to_str(requested)}

        if not self.app.face.running:
            raise types.NetworkError('cannot send management command before connected')

        # The caller's policy is the only signature policy for the response.
        # With no policy, keep the library's historical behavior.
        if validator is None:
            validator = pass_all

        async with self._command_semaphore:
            timestamp = self._reserve_signature_time()
            command_name = nfd_mgmt.make_command_v2('rib', action, self.app.face,
                                                    name=requested)
            interest_param = fmt.InterestParam(lifetime=self._lifetime,
                                               nonce=utils.gen_nonce())
            interest, final_name = fmt.make_interest(
                command_name, interest_param, b'',
                signer=_CommandSigner(timestamp), need_final_name=True)
            # The response must name this exact signed Interest, so derive the
            # expected name from the bytes actually sent rather than rebuilding it.
            expected_name = enc.Name.normalize(final_name)

            def result(outcome: ManagementOutcome, **fields) -> ManagementResult:
                return ManagementResult(
                    command=command,
                    name=enc.Name.to_str(requested),
                    outcome=outcome,
                    expected_name=enc.Name.to_str(expected_name),
                    request_parameters=request_parameters,
                    request_digest=_request_digest(command_name),
                    **fields)

            # The wire Interest is a canonical, non-prefix signed command.
            # For correlation, watch the command's module/action root: a success
            # packet belonging to another management request is then observed and
            # rejected by the exact-name and parameter checks below instead of
            # being silently mistaken for a timeout or for this command's success.
            root = command_name[:4]
            watch_param = fmt.InterestParam(
                lifetime=interest_param.lifetime,
                nonce=interest_param.nonce,
                can_be_prefix=True)
            try:
                data_name, content, pkt_context = await self.app.express_raw_interest(
                    root, watch_param, interest, _accept_for_inspection)
            except types.InterestTimeout:
                _LOGGER.error('Management command %s for %s timed out',
                              command, enc.Name.to_str(requested))
                return result(ManagementOutcome.TIMEOUT, error='response timed out')
            except types.InterestNack as e:
                _LOGGER.error('Management command %s for %s was nacked: %s',
                              command, enc.Name.to_str(requested), e.reason)
                return result(ManagementOutcome.NACKED, nack_reason=e.reason,
                              error=f'NetworkNack reason={e.reason}')
            except types.InterestCanceled:
                _LOGGER.error('Management command %s for %s was canceled',
                              command, enc.Name.to_str(requested))
                return result(ManagementOutcome.CANCELED, error='face was shut down')

        # A response must name this exact command, not merely share its prefix.
        if enc.Name.normalize(data_name) != expected_name:
            _LOGGER.error('Management response for %s has unrelated name %s',
                          enc.Name.to_str(requested), enc.Name.to_str(data_name))
            return result(ManagementOutcome.NAME_MISMATCH,
                          data_name=enc.Name.to_str(data_name),
                          error='response name does not match the command Interest')

        try:
            response = nfd_mgmt.parse_response(content)
        except (enc.DecodeError, ValueError, IndexError, TypeError, struct.error) as e:
            _LOGGER.error('Management response for %s is malformed: %s',
                          enc.Name.to_str(requested), e)
            return result(ManagementOutcome.MALFORMED_RESPONSE,
                          data_name=enc.Name.to_str(data_name),
                          error=f'cannot decode ControlResponse: {e}')

        status_code = response['status_code']
        status_text = response['status_text']
        response_parameters = {
            key: value for key, value in response.items()
            if key not in ('status_code', 'status_text')
        }
        fields = dict(data_name=enc.Name.to_str(data_name),
                      status_code=status_code,
                      status_text=status_text,
                      response_parameters=response_parameters)

        status_outcome = _classify_status(status_code)
        if status_outcome is not None:
            _LOGGER.error('Management command %s for %s failed: %s %s',
                          command, enc.Name.to_str(requested), status_code, status_text)
            return result(status_outcome, **fields,
                          error=f'forwarder status {status_code} {status_text}')

        # A success status alone does not associate the response with this request.
        # The response must echo the parameters of this command.
        response_name = _normalized_name(response.get('name'))
        if response_name is None:
            _LOGGER.error('Management response for %s has no control parameters',
                          enc.Name.to_str(requested))
            return result(ManagementOutcome.PARAMETER_MISMATCH, **fields,
                          error='successful response does not echo request parameters')
        if response_name != requested:
            _LOGGER.error('Management response for %s describes %s',
                          enc.Name.to_str(requested), enc.Name.to_str(response_name))
            return result(ManagementOutcome.PARAMETER_MISMATCH, **fields,
                          error='response control parameters belong to another request')

        # The response belongs to this command. Only now is the caller's
        # signature policy meaningful; apply it to this response alone.
        policy_error = None
        try:
            valid = await validator(data_name, pkt_context.get('sig_ptrs'), pkt_context)
        except (TimeoutError, aio.CancelledError):
            valid = types.ValidResult.TIMEOUT
        except Exception as e:
            # A policy that raises does not approve the packet.
            policy_error = f'{e.__class__.__name__}: {e}'
            valid = types.ValidResult.FAIL
        if valid not in (types.ValidResult.PASS, types.ValidResult.ALLOW_BYPASS):
            _LOGGER.error('Management response for %s failed validation: %s',
                          enc.Name.to_str(requested), valid)
            return result(ManagementOutcome.VALIDATION_FAILED, **fields,
                          validation_result=valid,
                          error=policy_error or
                          'response failed the caller validation policy: '
                          f'{getattr(valid, "name", valid)}')

        _LOGGER.debug('Management command %s for %s confirmed: %s %s',
                      command, enc.Name.to_str(requested), status_code, status_text)
        return result(ManagementOutcome.CONFIRMED, **fields,
                      validation_result=valid)

    async def register(self, name: enc.NonStrictName, validator=None) -> ManagementResult:
        return await self._execute('register', name, validator)

    async def unregister(self, name: enc.NonStrictName, validator=None) -> ManagementResult:
        return await self._execute('unregister', name, validator)

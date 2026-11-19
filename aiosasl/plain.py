########################################################################
# File name: plain.py
# This file is part of: aiosasl
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
import logging
import typing

from . import authzid, common, statemachine


logger = logging.getLogger(__name__)


class PLAIN(statemachine.SASLMechanism):
    """
    The password-based ``PLAIN`` SASL mechanism (see :rfc:`4616`).

    .. warning::

       This is generally unsafe over unencrypted connections and should not be
       used there. Exclusion of the ``PLAIN`` mechanism over unsafe connections
       is out of scope for :mod:`aiosasl` and needs to be handled by the
       protocol implementation!

    `credential_provider` must be coroutine which returns a ``(user,
    password)`` tuple.

    If `authzid` is given, the client asks to act as that identity after
    authenticating as the identity returned by `credential_provider`.
    The request is encoded in the leading field of the PLAIN payload
    (``authzid NUL authcid NUL password``).  It is only a request: the
    caller must resolve the effective identity from a trusted server
    result or an explicit mapping (see :func:`.resolve_authorization`).

    .. versionadded:: 0.4

       The `authzid` argument was added.
    """
    def __init__(
            self,
            credential_provider: common.CredentialProvider,
            authzid: typing.Optional[str] = None):
        super().__init__()
        self._credential_provider = credential_provider
        self._authzid = authzid

    @classmethod
    def any_supported(
            cls,
            mechanisms: typing.Iterable[str],
            ) -> typing.Any:
        if "PLAIN" in mechanisms:
            return "PLAIN"
        return None

    async def authenticate(
            self,
            sm: statemachine.SASLStateMachine,
            mechanism: typing.Any,
            ) -> None:
        logger.info("attempting PLAIN mechanism")
        username, password = await self._credential_provider()
        payload = authzid.encode_plain_payload(
            username,
            password,
            self._authzid,
        )

        state, _ = await sm.initiate(
            mechanism="PLAIN",
            payload=payload,
        )

        if state != common.SASLState.SUCCESS:
            raise common.SASLFailure(
                None,
                text="SASL protocol violation")

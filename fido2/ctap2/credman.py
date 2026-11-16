# Copyright (c) 2020 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import contextlib
import logging
import struct
from enum import IntEnum, unique
from threading import RLock
from typing import Any, Iterator, Mapping, Sequence

from .. import cbor
from ..ctap import CtapError
from ..webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialUserEntity,
    _as_cbor,
)
from .base import Ctap2, Info
from .pin import PinProtocol, _PinUv

logger = logging.getLogger(__name__)


class EnumerationError(Exception):
    """Base class for errors related to credential enumeration sessions."""


class EnumerationConflictError(EnumerationError):
    """An enumeration operation conflicts with an active enumeration session.

    CTAP begin/next enumeration relies on server-side enumeration state held by
    the authenticator. Only one enumeration (of RPs or credentials) can own
    that state at a time. Starting a new enumeration, or issuing a next call
    without a matching session, while another session is active raises this
    error rather than silently mixing the two enumerations.
    """


class EnumerationSession:
    """Owns one in-progress authenticator enumeration.

    A session binds the client to a single begin/next sequence on the
    authenticator. It must not be instantiated directly; use the
    ``enumerate_rps_session`` or ``enumerate_creds_session`` context managers of
    :class:`CredentialManagement`. The session is iterable and releases its
    ownership of the authenticator enumeration state when exhausted, closed, or
    when the surrounding context is exited (including due to an error).

    :ivar kind: Whether this session enumerates RPs or credentials.
    :ivar total: The number of entities reported by the begin call. The value
        is fixed for the lifetime of the session, so a change in the stored
        count mid-enumeration never silently changes the result.
    :ivar rp_id_hash: For a credential session, the RP whose credentials are
        enumerated. Every returned credential is checked against this hash.
    """

    @unique
    class Kind(IntEnum):
        RP = 0
        CREDENTIAL = 1

        @property
        def label(self) -> str:
            return (
                "credentials"
                if self is EnumerationSession.Kind.CREDENTIAL
                else "RPs"
            )

    def __init__(
        self,
        credman: "CredentialManagement",
        kind: "EnumerationSession.Kind",
        first: Mapping[int, Any],
        total: int,
        rp_id_hash: bytes | None = None,
    ):
        self._credman = credman
        self.kind = kind
        self.total = total
        self.rp_id_hash = rp_id_hash
        self._done = False
        self._seen = 1
        self._buffer: list[Mapping[int, Any]] = []
        # The first entity has already been fetched by the begin call.
        self._buffer.append(self._validate(first))

    @classmethod
    def empty(
        cls,
        credman: "CredentialManagement",
        kind: "EnumerationSession.Kind",
        rp_id_hash: bytes | None = None,
    ) -> "EnumerationSession":
        # An empty session never owns authenticator enumeration state.
        session = cls.__new__(cls)
        session._credman = credman
        session.kind = kind
        session.total = 0
        session.rp_id_hash = rp_id_hash
        session._done = True
        session._seen = 0
        session._buffer = []
        return session

    @property
    def exhausted(self) -> bool:
        """True when the session holds no ownership of enumeration state."""
        return self._done

    def take_first(self) -> Mapping[int, Any]:
        """Consume and return the entity fetched by the begin call.

        Used by the low-level ``*_begin`` methods so that a following ``*_next``
        returns the second entity rather than repeating the first one.
        """
        if not self._buffer:
            raise EnumerationError("The begin response has already been consumed.")
        entity = self._buffer.pop(0)
        if self._seen >= self.total:
            # The only entity has been handed out, so ownership ends.
            self._release()
        return entity

    def _validate(self, entity: Mapping[int, Any]) -> Mapping[int, Any]:
        if (
            self.kind is EnumerationSession.Kind.CREDENTIAL
            and self.rp_id_hash is not None
            and CredentialManagement.RESULT.RP_ID_HASH in entity
            and entity[CredentialManagement.RESULT.RP_ID_HASH] != self.rp_id_hash
        ):
            raise EnumerationError(
                "Credential belongs to a different RP than the one being "
                "enumerated; the authenticator enumeration state is inconsistent."
            )
        return entity

    def _next_cmd(self) -> "CredentialManagement.CMD":
        return (
            CredentialManagement.CMD.ENUMERATE_CREDS_NEXT
            if self.kind is EnumerationSession.Kind.CREDENTIAL
            else CredentialManagement.CMD.ENUMERATE_RPS_NEXT
        )

    def _fetch_next(self) -> Mapping[int, Any]:
        if self._done:
            raise EnumerationConflictError(
                "The enumeration session has already ended."
            )
        # next calls are not authenticated per the CTAP spec.
        entity = self._credman._call(self._next_cmd(), auth=False)
        entity = self._validate(entity)
        self._seen += 1
        if self._seen >= self.total:
            # The entity just returned is the last one.
            self._release()
        return entity

    def _release(self) -> None:
        if not self._done:
            self._done = True
            if self._credman._active_session is self:
                self._credman._active_session = None

    def close(self) -> None:
        """Release the authenticator enumeration state owned by the session.

        Safe to call more than once. Abandoning a session this way leaves any
        partially collected entities available via iteration, but performs no
        automatic restart, so data from two points in time is never mixed.
        """
        with self._credman._enum_lock:
            self._release()

    def __iter__(self) -> Iterator[Mapping[int, Any]]:
        return self

    def __next__(self) -> Mapping[int, Any]:
        if self._buffer:
            entity = self._buffer.pop(0)
            if self._seen >= self.total:
                self._release()
            return entity
        if self._done:
            raise StopIteration
        with self._credman._enum_lock:
            if self._done:
                raise StopIteration
            return self._fetch_next()

    def __enter__(self) -> "EnumerationSession":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class CredentialManagement:
    """Implementation of a draft specification of the Credential Management API.
    WARNING: This specification is not final and this class is likely to change.

    :param ctap: An instance of a CTAP2 object.
    :param pin_uv_protocol: An instance of a PinUvAuthProtocol.
    :param pin_uv_token: A valid PIN/UV Auth Token for the current CTAP session.
    """

    @unique
    class CMD(IntEnum):
        GET_CREDS_METADATA = 0x01
        ENUMERATE_RPS_BEGIN = 0x02
        ENUMERATE_RPS_NEXT = 0x03
        ENUMERATE_CREDS_BEGIN = 0x04
        ENUMERATE_CREDS_NEXT = 0x05
        DELETE_CREDENTIAL = 0x06
        UPDATE_USER_INFO = 0x07

    @unique
    class PARAM(IntEnum):
        RP_ID_HASH = 0x01
        CREDENTIAL_ID = 0x02
        USER = 0x03

    @unique
    class RESULT(IntEnum):
        EXISTING_CRED_COUNT = 0x01
        MAX_REMAINING_COUNT = 0x02
        RP = 0x03
        RP_ID_HASH = 0x04
        TOTAL_RPS = 0x05
        USER = 0x06
        CREDENTIAL_ID = 0x07
        PUBLIC_KEY = 0x08
        TOTAL_CREDENTIALS = 0x09
        CRED_PROTECT = 0x0A
        LARGE_BLOB_KEY = 0x0B
        THIRD_PARTY_PAYMENT = 0x0C

    @staticmethod
    def is_supported(info: Info) -> bool:
        if info.options.get("credMgmt"):
            return True
        # We also support the Prototype command
        if "FIDO_2_1_PRE" in info.versions and "credentialMgmtPreview" in info.options:
            return True
        return False

    @staticmethod
    def is_update_supported(info: Info) -> bool:
        # Not supported in credentialMgmtPreview
        return bool(info.options.get("credMgmt"))

    @staticmethod
    def is_readonly_supported(info: Info) -> bool:
        return bool(info.options.get("perCredMgmtRO"))

    def __init__(
        self,
        ctap: Ctap2,
        pin_uv_protocol: PinProtocol,
        pin_uv_token: bytes,
    ):
        if not self.is_supported(ctap.info):
            raise ValueError("Authenticator does not support Credential Management")

        self.ctap = ctap
        self.pin_uv = _PinUv(pin_uv_protocol, pin_uv_token)
        # Serializes access to the authenticator-side enumeration state and
        # tracks which enumeration (if any) currently owns it.
        self._enum_lock = RLock()
        self._active_session: EnumerationSession | None = None

    def _call(self, sub_cmd, params=None, auth=True):
        kwargs: dict[str, Any] = {"sub_cmd": sub_cmd, "sub_cmd_params": params}
        if auth:
            msg = struct.pack(">B", sub_cmd)
            if params is not None:
                msg += cbor.encode(params)
            kwargs["pin_uv_protocol"] = self.pin_uv.protocol.VERSION
            kwargs["pin_uv_param"] = self.pin_uv.protocol.authenticate(
                self.pin_uv.token, msg
            )
        return self.ctap.credential_mgmt(**kwargs)

    def _check_no_active_session(self, cmd: "CredentialManagement.CMD") -> None:
        session = self._active_session
        if session is not None and not session.exhausted:
            raise EnumerationConflictError(
                f"{cmd.name} cannot start while an enumeration of "
                f"{session.kind.label} is still in progress."
            )

    def _check_active_session(
        self, cmd: "CredentialManagement.CMD", kind: "EnumerationSession.Kind"
    ) -> None:
        session = self._active_session
        if session is None or session.exhausted:
            raise EnumerationConflictError(
                f"{cmd.name} requires an active {kind.label} enumeration, "
                "but none is open. Call the matching begin first."
            )
        if session.kind is not kind:
            raise EnumerationConflictError(
                f"{cmd.name} belongs to a {kind.label} enumeration, but a "
                f"{session.kind.label} enumeration is currently active."
            )

    def _begin_session(
        self,
        cmd: "CredentialManagement.CMD",
        kind: "EnumerationSession.Kind",
        params: Mapping[int, Any] | None = None,
        rp_id_hash: bytes | None = None,
    ) -> EnumerationSession:
        # Caller must hold self._enum_lock.
        self._check_no_active_session(cmd)
        try:
            first = self._call(cmd, params)
        except CtapError as e:
            if e.code == CtapError.ERR.NO_CREDENTIALS:
                return EnumerationSession.empty(self, kind, rp_id_hash)
            raise
        if kind is EnumerationSession.Kind.RP:
            total = first[CredentialManagement.RESULT.TOTAL_RPS]
        else:
            total = first.get(CredentialManagement.RESULT.TOTAL_CREDENTIALS, 1)
        session = EnumerationSession(self, kind, first, total, rp_id_hash)
        self._active_session = session
        return session

    @property
    def active_session(self) -> "EnumerationSession | None":
        """The enumeration session currently owning the device, if any.

        A session opened through the low-level ``*_begin`` methods must be
        driven with the matching ``*_next`` calls or closed via
        :meth:`EnumerationSession.close`; sessions opened through the
        ``*_session`` context managers are closed automatically.
        """
        return self._active_session

    def get_metadata(self) -> Mapping[int, Any]:
        """Get credentials metadata.

        This returns the existing resident credentials count, and the max
        possible number of remaining resident credentials (the actual number of
        remaining credentials may depend on algorithm choice, etc).

        :return: A dict containing EXISTING_CRED_COUNT, and MAX_REMAINING_COUNT.
        """
        return self._call(CredentialManagement.CMD.GET_CREDS_METADATA)

    def enumerate_rps_begin(self) -> Mapping[int, Any]:
        """Start enumeration of RP entities of resident credentials.

        This will begin enumeration of stored RP entities, returning the first
        entity, as well as a count of the total number of entities stored.

        The authenticator can only hold one enumeration cursor at a time, so
        this raises :class:`EnumerationConflictError` if another enumeration
        session is active on this CredentialManagement instance.

        :return: A dict containing RP, RP_ID_HASH, and TOTAL_RPS.
        """
        with self._enum_lock:
            session = self._begin_session(
                CredentialManagement.CMD.ENUMERATE_RPS_BEGIN,
                EnumerationSession.Kind.RP,
            )
        if session.exhausted:
            # NO_CREDENTIALS: nothing to return, and no state was claimed.
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        return session.take_first()

    def enumerate_rps_next(self) -> Mapping[int, Any]:
        """Get the next RP entity stored.

        This continues enumeration of stored RP entities, returning the next
        entity. It must be paired with an open RP enumeration session; calling
        it otherwise raises :class:`EnumerationConflictError`.

        :return: A dict containing RP, and RP_ID_HASH.
        """
        with self._enum_lock:
            self._check_active_session(
                CredentialManagement.CMD.ENUMERATE_RPS_NEXT,
                EnumerationSession.Kind.RP,
            )
            session = self._active_session
            assert session is not None
            return next(session)

    @contextlib.contextmanager
    def enumerate_rps_session(self) -> Iterator["EnumerationSession"]:
        """Open an owned session enumerating all RP entities.

        Unlike :meth:`enumerate_rps`, the returned :class:`EnumerationSession`
        keeps explicit ownership of the authenticator enumeration state until
        the context is exited, so other begin/next calls cannot interleave with
        it. An authenticator with no RPs yields a session whose ``total`` is 0
        rather than raising.

        Usage::

            with credman.enumerate_rps_session() as session:
                for rp in session:
                    ...
        """
        with self._enum_lock:
            session = self._begin_session(
                CredentialManagement.CMD.ENUMERATE_RPS_BEGIN,
                EnumerationSession.Kind.RP,
            )
        try:
            yield session
        finally:
            session.close()

    def enumerate_rps(self) -> Sequence[Mapping[int, Any]]:
        """Convenience method to enumerate all RPs.

        The enumeration runs inside an owned session. A NO_CREDENTIALS response
        is reported as an empty list; any other failure (including an
        interruption partway through) propagates instead of returning a partial
        or empty list.

        See enumerate_rps_session for an explicit, interruptible alternative.
        """
        with self.enumerate_rps_session() as session:
            return list(session)

    def enumerate_creds_begin(self, rp_id_hash: bytes) -> Mapping[int, Any]:
        """Start enumeration of resident credentials.

        This will begin enumeration of resident credentials for a given RP,
        returning the first credential, as well as a count of the total number
        of resident credentials stored for the given RP.

        The authenticator can only hold one enumeration cursor at a time, so
        this raises :class:`EnumerationConflictError` if another enumeration
        session is active on this CredentialManagement instance.

        :param rp_id_hash: SHA256 hash of the RP ID.
        :return: A dict containing USER, CREDENTIAL_ID, PUBLIC_KEY, and
            TOTAL_CREDENTIALS.
        """
        with self._enum_lock:
            session = self._begin_session(
                CredentialManagement.CMD.ENUMERATE_CREDS_BEGIN,
                EnumerationSession.Kind.CREDENTIAL,
                {CredentialManagement.PARAM.RP_ID_HASH: rp_id_hash},
                rp_id_hash=rp_id_hash,
            )
        if session.exhausted:
            # NO_CREDENTIALS: nothing to return, and no state was claimed.
            raise CtapError(CtapError.ERR.NO_CREDENTIALS)
        return session.take_first()

    def enumerate_creds_next(self) -> Mapping[int, Any]:
        """Get the next resident credential stored.

        This continues enumeration of resident credentials, returning the next
        credential. It must be paired with an open credential enumeration
        session; calling it otherwise raises :class:`EnumerationConflictError`.

        :return: A dict containing USER, CREDENTIAL_ID, and PUBLIC_KEY.
        """
        with self._enum_lock:
            self._check_active_session(
                CredentialManagement.CMD.ENUMERATE_CREDS_NEXT,
                EnumerationSession.Kind.CREDENTIAL,
            )
            session = self._active_session
            assert session is not None
            return next(session)

    @contextlib.contextmanager
    def enumerate_creds_session(
        self, rp_id_hash: bytes
    ) -> Iterator["EnumerationSession"]:
        """Open an owned session enumerating credentials for one RP.

        Every credential produced by the session belongs to ``rp_id_hash``;
        responses claiming a different RP_ID_HASH raise
        :class:`EnumerationError`. The session owns the authenticator
        enumeration state until the context is exited. An RP with no
        credentials yields a session whose ``total`` is 0 rather than raising.

        Usage::

            with credman.enumerate_creds_session(rp_id_hash) as session:
                for cred in session:
                    ...
        """
        with self._enum_lock:
            session = self._begin_session(
                CredentialManagement.CMD.ENUMERATE_CREDS_BEGIN,
                EnumerationSession.Kind.CREDENTIAL,
                {CredentialManagement.PARAM.RP_ID_HASH: rp_id_hash},
                rp_id_hash=rp_id_hash,
            )
        try:
            yield session
        finally:
            session.close()

    def enumerate_creds(self, *args, **kwargs) -> Sequence[Mapping[int, Any]]:
        """Convenience method to enumerate all resident credentials for an RP.

        The enumeration runs inside an owned session. A NO_CREDENTIALS response
        is reported as an empty list; any other failure (including an
        interruption partway through) propagates instead of returning a partial
        or empty list.

        See enumerate_creds_session for an explicit, interruptible alternative.
        """
        with self.enumerate_creds_session(*args, **kwargs) as session:
            return list(session)

    def delete_cred(self, cred_id: PublicKeyCredentialDescriptor) -> None:
        """Delete a resident credential.

        :param cred_id: The PublicKeyCredentialDescriptor of the credential to delete.
        """
        cred_id = PublicKeyCredentialDescriptor.from_dict(cred_id)
        logger.debug(f"Deleting credential with ID: {cred_id}")
        self._call(
            CredentialManagement.CMD.DELETE_CREDENTIAL,
            {CredentialManagement.PARAM.CREDENTIAL_ID: _as_cbor(cred_id)},
        )
        logger.info("Credential deleted")

    def update_user_info(
        self,
        cred_id: PublicKeyCredentialDescriptor,
        user_info: PublicKeyCredentialUserEntity,
    ) -> None:
        """Update the user entity of a resident key.

        :param cred_id: The PublicKeyCredentialDescriptor of the credential to update.
        :param user_info: The user info update.
        """
        if not CredentialManagement.is_update_supported(self.ctap.info):
            raise ValueError("Authenticator does not support update_user_info")

        cred_id = PublicKeyCredentialDescriptor.from_dict(cred_id)
        user_info = PublicKeyCredentialUserEntity.from_dict(user_info)
        logger.debug(f"Updating credential: {cred_id} with user info: {user_info}")
        self._call(
            CredentialManagement.CMD.UPDATE_USER_INFO,
            {
                CredentialManagement.PARAM.CREDENTIAL_ID: _as_cbor(cred_id),
                CredentialManagement.PARAM.USER: _as_cbor(user_info),
            },
        )
        logger.info("Credential user info updated")

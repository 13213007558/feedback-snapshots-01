# SPDX-FileCopyrightText: Copyright (c) 2023-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License

from typing import TYPE_CHECKING, Optional

import httpx

if TYPE_CHECKING:
    from ._access import AccessDecision


class NotFoundError(Exception):
    """Unable to find the requested resource."""


class AccessDeniedError(PermissionError):
    """A discovered resource version is not approved for the requested verb.

    This is a client-side preflight failure: the request is rejected before it
    is sent to the Kubernetes API server. The attached
    :class:`AccessDecision <kr8s.AccessDecision>` explains which resource
    version was targeted, whether it is visible in discovery, and which verbs
    are approved.

    Attributes:
        decision: The access decision that denied the request.
    """

    def __init__(
        self, message: str, decision: Optional["AccessDecision"] = None
    ) -> None:
        self.decision = decision
        super().__init__(message)


class ConnectionClosedError(Exception):
    """A connection has been closed."""


class APITimeoutError(Exception):
    """A timeout has occurred while waiting for a response from the Kubernetes API server."""


class ExecError(Exception):
    """Internal error in the exec protocol."""


class ServerError(Exception):
    """Error from the Kubernetes API server.

    Attributes:
        status: The Status object from the Kubernetes API server
        response: The httpx response object
    """

    def __init__(
        self,
        message: str,
        status: Optional[str] = None,
        response: Optional[httpx.Response] = None,
    ) -> None:
        self.status = status
        self.response = response
        super().__init__(message)

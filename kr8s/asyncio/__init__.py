# SPDX-FileCopyrightText: Copyright (c) 2023-2026, Kr8s Developers (See LICENSE for list)
# SPDX-License-Identifier: BSD 3-Clause License
"""The `kr8s` asynchronous API.

This module provides an asynchronous API for interacting with a Kubernetes cluster.
"""

from kr8s._access import AccessDecision, AccessPolicy, AccessRule
from kr8s._api import Api
from kr8s._exceptions import AccessDeniedError

from . import objects, portforward
from ._api import api
from ._helpers import (
    api_resource_access,
    api_resources,
    create,
    get,
    version,
    watch,
    whoami,
)

__all__ = [
    "AccessDecision",
    "AccessDeniedError",
    "AccessPolicy",
    "AccessRule",
    "api",
    "api_resource_access",
    "api_resources",
    "create",
    "get",
    "objects",
    "portforward",
    "version",
    "watch",
    "whoami",
    "Api",
]

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tracks the client certificate authorization pinned to the current call.

This module deliberately has no dependencies on the rest of the package so that
credential code can consult it without creating an import cycle.
"""

import contextlib
import contextvars

_active_authorization = contextvars.ContextVar(
    "google_auth_active_certificate_authorization", default=None
)


def get_active():
    """Returns the certificate authorization pinned to the current call.

    Returns:
        The active authorization object, or ``None`` when the current call does
        not pin a client certificate authorization.
    """
    return _active_authorization.get()


def set_active(authorization):
    """Pins ``authorization`` for the current context and returns a reset token."""
    return _active_authorization.set(authorization)


def reset_active(token):
    """Restores the authorization that was active before ``token`` was issued."""
    _active_authorization.reset(token)


@contextlib.contextmanager
def activate(authorization):
    """Pins ``authorization`` for the duration of the context."""
    token = _active_authorization.set(authorization)
    try:
        yield authorization
    finally:
        _active_authorization.reset(token)

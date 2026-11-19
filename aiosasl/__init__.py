########################################################################
# File name: __init__.py
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
"""
Using SASL in a protocol
========================

To make use of SASL over an existing protocol, you first need to subclass and
implement :class:`SASLInterface`.

The usable mechanisms need to be detected by your application using the
protocol over which to implement SASL. This is generally protocol-specific. For
example, XMPP uses stream features to announce which SASL mechanisms are
supported by the server.

When a set of SASL mechanism strings has been obtained by the server (let us
call a set with the mechanism strings ``sasl_mechanisms``), the mechanisms
supported by your application (a list of :class:`SASLMechanism` subclass
instances, let us call it ``mechanism_impls``) can be queried for support::

    # intf = <instance of your subclass of SASLInterface>
    for impl in mechanism_impl:
        token = impl.any_supported(sasl_mechanisms)
        if token is not None:
            sm = aiosasl.SASLStateMachine(intf)
            try:
                await impl.authenticate(sm, token)
            except aiosasl.AuthenticationFailure:
                # handle authentication failure
                # it is generally not sensible to re-try with other mechanisms
            except aiosasl.SASLFailure:
                # this is a protocol problem, it is sensible to re-try other
                # mechanisms
            else:
                # authentication was successful!

The instances for the mechanisms can be re-used; they do not save any state,
the state is held by :class:`SASLStateMachine` instead. The different
mechanisms require different arguments (the password-based mechanisms generally
require a callback which provides credentials).

The mechanisms which are currently supported by :mod:`aiosasl` are summarised
below:

.. autosummary::

   ANONYMOUS
   PLAIN
   SCRAM
   SCRAMPLUS

Transport-aware mechanism selection
===================================

The loop above trusts the server advertisement and the surrounding code to
avoid sending passwords over unsafe transports.  :mod:`aiosasl` also ships an
explicit, policy-driven selector in :mod:`aiosasl.policy` which keeps the
server advertisement, client capabilities, verified-TLS state and channel
binding availability apart.  It refuses password-bearing mechanisms on an
untrusted transport (so a server advertising only ``PLAIN`` over cleartext
never triggers the credential callback), prefers SCRAM-PLUS when channel
binding is available and preserves the SCRAM downgrade signal otherwise.

A single coroutine performs the whole, policy-governed exchange::

    from aiosasl import (
        ClientCapabilities,
        SASLPolicy,
        TransportSecurity,
        authenticate,
    )

    transport = TransportSecurity(
        tls_established=True,
        tls_verified=True,
        channel_binding=cb_provider,  # or None
    )
    capabilities = ClientCapabilities(credential_provider=provide_creds)

    candidate = await authenticate(
        intf,
        sasl_mechanisms,            # what the server advertised
        capabilities,               # what the client can do
        transport,                  # verified TLS / channel binding
        SASLPolicy(),               # the trusted policy
    )

See :mod:`aiosasl.policy` for the full reference, including
:class:`~aiosasl.policy.MechanismCandidates`,
:class:`~aiosasl.policy.NoAcceptableMechanism` and the
:data:`~aiosasl.policy.SASLMechanismSelector` hook.

Interface for protocols using SASL
==================================

To implement SASL on an existing protocol, you need to subclass
:class:`SASLInterface` and implement the abstract methods:

.. autoclass:: SASLInterface

.. autoclass:: SASLState

SASL mechanisms
===============

.. autoclass:: PLAIN

.. autoclass:: SCRAM(credential_provider, *[, after_scram_plus=False][, enforce_minimum_iteration_count=True])

.. autoclass:: SCRAMPLUS(credential_provider, cb_provider, *[, enforce_minimum_iteration_count=True])

.. autoclass:: ANONYMOUS

Base class
----------

.. autoclass:: SASLMechanism

A note for implementers
-----------------------

The :class:`SASLStateMachine` unwraps `(SASLState.SUCCESS, payload)` messages
passed in from a :class:`SASLInterface` to the equivalent sequence
`(SASLState.CHALLENGE, payload)` (requiring the empty string as response) and
`(SASLState.SUCCESS, None)`. The two forms are equivalent as per the SASL
specification and this unwrapping allows uniform treatment of both
forms by the :class:`SASLMechanism` implementations.

SASL state machine
==================

.. autoclass:: SASLStateMachine

Exception classes
=================

.. autoclass:: SASLError

.. autoclass:: SASLFailure

.. autoclass:: AuthenticationFailure

Version information
===================

.. autodata:: __version__

.. autodata:: version_info
"""  # NOQA

from .common import (  # noqa:F401
    AuthenticationFailure,
    SASLError,
    SASLFailure,
    SASLState,
)

from .statemachine import (  # noqa:F401
    SASLInterface,
    SASLMechanism,
    SASLStateMachine,
)

from .scram import (  # noqa:F401
    SCRAM,
    SCRAMPLUS,
)

from .plain import (  # noqa:F401
    PLAIN,
)

from .anonymous import (  # noqa:F401
    ANONYMOUS,
)

from .policy import (  # noqa:F401
    ClientCapabilities,
    MechanismCandidate,
    MechanismCandidates,
    NoAcceptableMechanism,
    SASLMechanismSelector,
    SASLPolicy,
    TransportSecurity,
    authenticate,
    select_mechanism,
)

from .version import version, __version__, version_info  # noqa:F401

#: The imported :mod:`aiosasl` version as a tuple.
#:
#: The components of the tuple are, in order: `major version`, `minor version`,
#: `patch level`, and `pre-release identifier`.
version_info = version_info

#: The imported :mod:`aiosasl` version as a string.
#:
#: The version number is dot-separated; in pre-release or development versions,
#: the version number is followed by a hypen-separated pre-release identifier.
__version__ = __version__

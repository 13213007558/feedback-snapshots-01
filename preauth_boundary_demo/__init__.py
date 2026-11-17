"""PREAUTH trust-boundary demo for aioimaplib.

The public surface groups the three layers of the design:

* transport evidence  :mod:`preauth_boundary_demo.transport` -- what the
  channel itself can prove;
* greeting parsing    :mod:`preauth_boundary_demo.greeting` -- what the
  server self-reports (OK / PREAUTH / BYE);
* trust policy        :mod:`preauth_boundary_demo.policy` -- the single place
  that turns those facts into an accept/reject decision.
"""

from .greeting import Greeting, GreetingStatus, parse_greeting
from .policy import (
    DecisionCode,
    GateDecision,
    TrustedPreauthSource,
    TrustPolicy,
)
from .transport import (
    TransportEvidence,
    TransportKind,
    classify_asyncio_transport,
    classify_ssl_object,
    local_trusted_evidence,
)

__all__ = [
    "Greeting",
    "GreetingStatus",
    "parse_greeting",
    "DecisionCode",
    "GateDecision",
    "TrustedPreauthSource",
    "TrustPolicy",
    "TransportEvidence",
    "TransportKind",
    "classify_asyncio_transport",
    "classify_ssl_object",
    "local_trusted_evidence",
]

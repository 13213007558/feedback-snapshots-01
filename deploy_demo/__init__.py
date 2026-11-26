"""Runnable reference for safe multi-target wheel deployment.

This package is an *in-repo demonstration* built strictly on the public
``installer`` extension contracts:

* :class:`installer.sources.WheelSource` -- sequential wheel content access.
* :class:`installer.destinations.WheelDestination` -- write/script/finalize.

It adds four things a deployment platform needs around stock ``installer``:

* a pre-touch review plan (:mod:`deploy_demo.plan`),
* a stageable, committable target (:mod:`deploy_demo.staging`),
* a write-once / WORM test double (:mod:`deploy_demo.worm`),
* independent post-landing verification (:mod:`deploy_demo.verify`).

Nothing here modifies the shipped ``installer`` package.
"""

from deploy_demo.errors import (
    CommitFailed,
    TransitReadError,
    VerificationFailure,
    WriteOnceViolation,
)

__all__ = [
    "CommitFailed",
    "TransitReadError",
    "VerificationFailure",
    "WriteOnceViolation",
]

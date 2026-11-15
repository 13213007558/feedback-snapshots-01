"""
Module for alerting the user when attempting to do things with pcapng that
aren't strictly valid.

The strictness level is a policy, not a process-wide switch: readers,
blocks, options and writers capture the policy that was active when they
were created, so data can safely move between independently configured
request handlers.  :py:func:`set_strictness` and the module-level
``strict_level`` are kept as compatibility entry points for callers that
still need a global default.
"""

import contextlib
import contextvars
import warnings
from enum import Enum

from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning


class Strictness(Enum):
    NONE = 0  # No warnings, do what you want
    WARN = 1  # Do what you want, but warn of potential issues
    FIX = 2  # Warn of potential issues, fix *if possible*
    FORBID = 3  # raise exception on potential issues


class StrictnessPolicy(object):
    """
    An immutable strictness policy.

    A policy can be passed explicitly to readers, writers, blocks and
    options.  Objects which did not receive an explicit policy use the
    policy active in their task context, falling back to the global
    level set through :py:func:`set_strictness`.
    """

    __slots__ = ("_level",)

    def __init__(self, level=Strictness.FORBID):
        if isinstance(level, StrictnessPolicy):
            level = level.level
        if not isinstance(level, Strictness):
            raise TypeError("expected a Strictness value, got {!r}".format(level))
        self._level = level

    @property
    def level(self):
        return self._level

    # A few descriptive aliases, for callers that prefer them.
    @property
    def strict_level(self):
        return self._level

    @property
    def strictness(self):
        return self._level

    def problem(self, msg):
        "Warn or raise an exception with the given message."
        if self._level == Strictness.FORBID:
            raise PcapngStrictnessError(msg)
        elif self._level in (Strictness.WARN, Strictness.FIX):
            warnings.warn(PcapngStrictnessWarning(msg), stacklevel=3)

    def warn(self, msg):
        "Show a warning with the given message."
        if self._level != Strictness.NONE:
            warnings.warn(PcapngStrictnessWarning(msg), stacklevel=3)

    def should_fix(self):
        "Return True if questionable input should be repaired automatically."
        return self._level == Strictness.FIX

    def scope(self):
        """Return a context manager activating this policy for this task."""
        return _policy_scope(self)

    context = scope
    activate = scope

    def __eq__(self, other):
        if isinstance(other, StrictnessPolicy):
            return self._level == other._level
        if isinstance(other, Strictness):
            return self._level == other
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self._level)

    def __repr__(self):
        return "StrictnessPolicy({!r})".format(self._level)


# ----------------------------------------------------------------------
# Compatibility global
#
# Existing applications call ``set_strictness()`` and may even read the
# module-level ``strict_level`` directly.  Keep both working, but only as
# the fallback when no task-local policy is active.
# ----------------------------------------------------------------------

strict_level = Strictness.FORBID

_ACTIVE_POLICY = contextvars.ContextVar("pcapng_strictness_policy", default=None)


def _normalize(value):
    if isinstance(value, StrictnessPolicy):
        return value
    if isinstance(value, Strictness):
        return StrictnessPolicy(value)
    raise TypeError("expected a Strictness or StrictnessPolicy, got {!r}".format(value))


def _global_policy():
    level = strict_level
    if isinstance(level, StrictnessPolicy):
        return level
    if not isinstance(level, Strictness):
        raise TypeError(
            "strict_level must be a Strictness or StrictnessPolicy, got {!r}".format(
                level
            )
        )
    return StrictnessPolicy(level)


def current_policy():
    """
    Return the policy explicitly active in the current task context.

    Unlike :py:func:`get_strictness`, this does not fall back to the
    process-wide global setting.  It is useful when deciding whether an
    object should carry its own policy or keep following the global one.
    """

    return _ACTIVE_POLICY.get()


def capture_strictness(value=None):
    """
    Capture a policy for storage on an object.

    An explicit value wins.  Otherwise the task-local policy is captured,
    if there is one.  If neither exists, ``None`` is returned so legacy
    objects keep following the global setting dynamically.
    """

    if value is not None:
        return _normalize(value)
    return current_policy()


def resolve_for_object(value, captured, explicit):
    """
    Resolve a policy for an object or operation.

    An explicit per-call/per-object value always wins.  Otherwise a policy
    explicitly configured on the object wins over any ambient task scope,
    so a strict request cannot be silently downgraded by unrelated work.
    A policy merely captured from a task scope yields to a scope that is
    active now; once no scope is active, the captured policy remains
    available for later processing stages.
    """

    if value is not None:
        return _normalize(value)
    if explicit and captured is not None:
        return _normalize(captured)
    active = current_policy()
    if active is not None:
        return active
    if captured is not None:
        return _normalize(captured)
    return _global_policy()


def resolve_strictness(value=None, fallback=None):
    """
    Resolve the policy to use for an operation.

    Precedence is: explicit value, the task-local scope, the policy
    captured by the object being operated on, then the compatibility
    global.

    A nested scope therefore applies to operations performed inside it,
    including on objects created elsewhere, and stops applying as soon as
    the scope exits.  An object handed to another processing stage keeps
    its captured policy for stages that do not establish their own.
    """

    if value is not None:
        return _normalize(value)
    active = current_policy()
    if active is not None:
        return active
    if fallback is not None:
        return _normalize(fallback)
    return _global_policy()


def get_strictness():
    "Return the policy that applies to the current operation."
    return resolve_strictness()


def get_strict_level():
    "Return the :py:class:`Strictness` level for the current operation."
    return get_strictness().level


def current():
    "Alias for :py:func:`current_policy`."
    return current_policy()


def effective_policy():
    "Alias for :py:func:`get_strictness`."
    return get_strictness()


@contextlib.contextmanager
def _policy_scope(policy):
    token = _ACTIVE_POLICY.set(_normalize(policy))
    try:
        yield policy
    finally:
        _ACTIVE_POLICY.reset(token)


def strictness_scope(level):
    """
    Temporarily activate a strictness policy for the current task.

    The previous policy is always restored, including when the body raises
    an exception, so nested scopes and failed conversions cannot leak
    policy into unrelated work.
    """

    return _policy_scope(level)


# Friendly aliases for the same scoped override.
strictness_context = strictness_scope
use_strictness = strictness_scope
scoped_strictness = strictness_scope
scope = strictness_scope


def set_strictness(level):
    """
    Set the compatibility global strictness level.

    New code should prefer passing a policy to the relevant reader/writer
    or using :py:func:`strictness_scope`, so concurrent tasks remain
    independent.
    """

    global strict_level
    if not isinstance(level, (Strictness, StrictnessPolicy)):
        raise TypeError(
            "expected a Strictness or StrictnessPolicy, got {!r}".format(level)
        )
    strict_level = level


def problem(msg):
    "Warn or raise an exception with the given message."
    get_strictness().problem(msg)


def warn(msg):
    "Show a warning with the given message."
    get_strictness().warn(msg)


def should_fix():
    "Helper function for showing code used to fix questionable pcapng data."
    return get_strictness().should_fix()


# Descriptive alias for callers that use the class name as an entry point.
StrictnessContext = StrictnessPolicy

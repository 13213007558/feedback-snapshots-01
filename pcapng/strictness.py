"""
Module for alerting the user when attempting to do things with pcapng that
aren't strictly valid.

Strictness has historically been configured process-wide through
:py:func:`set_strictness`.  That is convenient for small scripts, but a
backend serving several requests at once cannot use one global setting: a
tolerant conversion request must not make a concurrent forensic validation
request accept questionable data (and vice versa).

This module therefore also exposes :py:class:`StrictnessPolicy` objects and
:py:func:`strictness_scope` context managers.  The effective policy for an
operation is, in priority order:

For diagnostics produced while working with an object (including delayed
option decoding), the policy is resolved in this order:

1. a policy passed explicitly to the operation;
2. the innermost active :py:func:`strictness_scope` (an explicit override);
3. the policy attached to the object at construction time, so it remains
   explainable after being handed to another processing stage;
4. the legacy process-wide level configured by :py:func:`set_strictness`
   (``Strictness.FORBID`` by default).

Write-time diagnostics and automatic fixes follow the same order, with the
writer's own task policy passed as the explicit argument.  This ensures a
conversion task's fixes never depend on which task read the blocks, while the
reading task can still be identified from the objects afterwards.

Policies are attached to objects at construction time when a scope is active,
so a block read by a strict task keeps its provenance when a tolerant
conversion task writes it.  Read-time diagnostics (including delayed option
decoding) use that attached policy, while automatic fixes and write-time
warnings are attributed to the task performing the write.

:py:func:`set_strictness` remains supported for backwards compatibility.
"""

import functools
import sys
import threading
import warnings
from enum import Enum

from pcapng.exceptions import PcapngStrictnessError, PcapngStrictnessWarning

try:  # pragma: no cover - Python < 3.7 fallback
    from contextvars import ContextVar
except ImportError:  # pragma: no cover
    ContextVar = None


__all__ = [
    "Strictness",
    "StrictnessPolicy",
    "StrictnessScope",
    "set_strictness",
    "strictness_scope",
    "scoped_strictness",
    "use_strictness",
    "strictness_context",
    "policy_context",
    "get_strictness",
    "get_strictness_policy",
    "current_policy",
    "policy_for",
    "capture_policy",
    "bind_policy",
    "effective_policy",
    "operation_policy",
    "has_task_policy",
    "problem",
    "warn",
    "should_fix",
]


class Strictness(Enum):
    NONE = 0  # No warnings, do what you want
    WARN = 1  # Do what you want, but warn of potential issues
    FIX = 2  # Warn of potential issues, fix *if possible*
    FORBID = 3  # raise exception on potential issues


_DEFAULT_LEVEL = Strictness.FORBID


def _coerce_level(level):
    if isinstance(level, StrictnessPolicy):
        return level.level
    if isinstance(level, Strictness):
        return level
    if isinstance(level, str):
        try:
            return Strictness[level.upper()]
        except KeyError:
            pass
    if isinstance(level, int) and not isinstance(level, bool):
        try:
            return Strictness(level)
        except ValueError:
            pass
    raise TypeError("expected Strictness, got {!r}".format(level))


class _ContextStack(object):
    """A stack of values isolated per thread/async task."""

    __slots__ = ("_var", "_local", "_attr")

    def __init__(self, name):
        self._var = (
            ContextVar("pcapng_" + name, default=()) if ContextVar else None
        )
        self._local = threading.local()
        self._attr = name

    def get(self):
        if self._var is not None:
            return self._var.get()
        return getattr(self._local, self._attr, ())

    def push(self, value):
        previous = self.get()
        updated = previous + (value,)
        if self._var is not None:
            self._var.set(updated)
        else:  # pragma: no cover
            setattr(self._local, self._attr, updated)
        return previous

    def reset(self, previous):
        if self._var is not None:
            self._var.set(previous)
        else:  # pragma: no cover
            setattr(self._local, self._attr, previous)


class StrictnessPolicy(object):
    """
    An explicit strictness policy owned by one task/request.

    Instances are comparable (by level and task name), usable as context
    managers (``with policy:``), decorators (``@policy``) and as values for
    the ``policy=``/``strictness_policy=`` arguments of scanners, writers,
    blocks and options containers.

    :param level:
        a :py:class:`Strictness` value, another policy (to copy its level),
        or one of the strings ``NONE``/``WARN``/``FIX``/``FORBID``.
    :param name:
        optional human-readable owner of the policy (for example a request
        id).  It is attached to warnings and exceptions raised under it.
    :param record:
        when true, warnings produced under this policy are appended to
        :py:attr:`diagnostics`.  Diagnostics belong to the policy, so give
        each request its own policy object when they must be kept apart.
    :param warning_sink:
        optional callable receiving every warning instance produced under
        this policy.
    """

    __slots__ = (
        "_level",
        "_name",
        "_record",
        "_warning_sink",
        "_diagnostics",
        "_scopes",
    )

    NONE = Strictness.NONE
    WARN = Strictness.WARN
    FIX = Strictness.FIX
    FORBID = Strictness.FORBID

    def __init__(
        self, level=_DEFAULT_LEVEL, name=None, record=False, warning_sink=None
    ):
        if isinstance(level, StrictnessPolicy):
            if name is None:
                name = level.name
            level = level.level
        self._level = _coerce_level(level)
        self._name = name
        self._record = bool(record)
        self._warning_sink = warning_sink
        self._diagnostics = []
        self._scopes = _ContextStack("scopes")

    # -------------------- convenience accessors --------------------

    @property
    def level(self):
        return self._level

    # Names used by older/alternative call sites.
    @property
    def strictness(self):
        return self._level

    @property
    def strictness_level(self):
        return self._level

    @property
    def name(self):
        return self._name

    @property
    def label(self):
        return self._name

    @property
    def diagnostics(self):
        """Warnings recorded by this policy, or ``None`` if not recording."""
        if not self._record:
            return None
        return self._diagnostics

    @property
    def messages(self):
        """Diagnostic messages recorded by this policy."""
        return [str(w) for w in (self.diagnostics or ())]

    def scope(self):
        """Return a context manager/decorator activating this policy."""
        return StrictnessScope(self)

    # Friendly aliases for callers that prefer an explicit method.
    context = scope
    activate = scope

    def with_name(self, name):
        """Return a copy of this policy bound to a different task name."""
        return StrictnessPolicy(
            self._level,
            name=name,
            record=self._record,
            warning_sink=self._warning_sink,
        )

    def with_level(self, level):
        """Return a copy of this policy with a different strictness level."""
        return StrictnessPolicy(
            level,
            name=self._name,
            record=self._record,
            warning_sink=self._warning_sink,
        )

    # -------------------- behaviour helpers --------------------

    def raises(self):
        return self._level == Strictness.FORBID

    def fixes(self):
        return self._level == Strictness.FIX

    def warns(self):
        return self._level != Strictness.NONE

    def should_fix(self):
        "Helper function for showing code used to fix questionable pcapng data."
        return self._level == Strictness.FIX

    def problem(self, msg):
        "Warn or raise an exception with the given message."
        if self._level == Strictness.FORBID:
            exc = PcapngStrictnessError(msg)
            _tag_exception(exc, self)
            raise exc
        elif self._level in (Strictness.WARN, Strictness.FIX):
            self._emit(msg, stacklevel=3)

    def warn(self, msg):
        "Show a warning with the given message."
        if self.warns():
            self._emit(msg, stacklevel=3)

    def _emit(self, msg, stacklevel=2):
        warning = PcapngStrictnessWarning(msg)
        _tag_warning(warning, self)
        diagnostics = self.diagnostics
        if diagnostics is not None:
            diagnostics.append(warning)
        if self._warning_sink is not None:
            self._warning_sink(warning)
        warnings.warn(warning, stacklevel=stacklevel)

    def describe(self):
        """A short, stable description suitable for logs and diagnostics."""
        if self._name:
            return "strictness={} task={!r}".format(self._level.name, self._name)
        return "strictness={}".format(self._level.name)

    def __repr__(self):
        extra = ""
        if self._name is not None:
            extra += ", name={!r}".format(self._name)
        if self._record:
            extra += ", recorded={}".format(len(self.diagnostics or ()))
        return "{}({}{})".format(self.__class__.__name__, self._level.name, extra)

    def __eq__(self, other):
        if isinstance(other, StrictnessPolicy):
            return self._level == other._level and self._name == other._name
        if isinstance(other, Strictness):
            return self._level == other
        return NotImplemented

    def __hash__(self):
        return hash((self._level, self._name))

    def __enter__(self):
        # Support ``with policy:`` as a shorthand for
        # ``with strictness_scope(policy):``.  A stack (kept per execution
        # context) makes nested entries unwind in the correct order.
        scope = StrictnessScope(self)
        self._scopes.push(scope)
        return scope.__enter__()

    def __exit__(self, exc_type, exc, tb):
        stack = self._scopes.get()
        if not stack:
            return False
        scope = stack[-1]
        self._scopes.reset(stack[:-1])
        return scope.__exit__(exc_type, exc, tb)


class StrictnessScope(object):
    """
    Select an explicit policy for the duration of the block, restoring the
    previous state on exit including when an exception is raised.

    Scopes are re-entrant; each entry restores exactly the state that
    preceded it.  A scope object can be shared between threads because the
    active stack itself is kept per execution context.
    """

    __slots__ = ("policy", "_tokens")

    def __init__(self, policy):
        self.policy = _policy_from(policy)
        self._tokens = _ContextStack("scope_tokens")

    def __enter__(self):
        self._tokens.push(_scope_stack.push(self.policy))
        return self.policy

    def __exit__(self, exc_type, exc, tb):
        tokens = self._tokens.get()
        if not tokens:
            return False
        token = tokens[-1]
        self._tokens.reset(tokens[:-1])
        _scope_stack.reset(token)
        return False

    def __call__(self, func):
        """Allow using a scope instance as a decorator (@strictness_scope(...))."""

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with StrictnessScope(self.policy):
                return func(*args, **kwargs)

        return wrapper


def _policy_from(level, name=None):
    if isinstance(level, StrictnessPolicy):
        if name is None:
            return level
        return level.with_name(name)
    return StrictnessPolicy(level, name=name)


def policy_for(value=None, name=None):
    """
    Normalise ``value`` to a :py:class:`StrictnessPolicy`.

    ``None`` means "the effective policy for the current task".  A bare
    :py:class:`Strictness` value is accepted for convenience.
    """
    if value is None:
        return get_strictness_policy()
    return _policy_from(value, name=name)


# The legacy process-wide setting.  It intentionally remains mutable for
# compatibility with ``set_strictness``; task-local code should use scopes
# or explicit policies instead.
class _GlobalPolicy(object):
    __slots__ = ("policy",)

    def __init__(self):
        self.policy = StrictnessPolicy(_DEFAULT_LEVEL)


_global = _GlobalPolicy()
_scope_stack = _ContextStack("policy")


def _active_policy():
    stack = _scope_stack.get()
    if stack:
        return stack[-1]
    return None


def get_strictness_policy():
    """Return the effective policy for the current task."""
    policy = _active_policy()
    if policy is not None:
        return policy
    return _global.policy


def get_strictness():
    """Return the effective :py:class:`Strictness` level for the current task."""
    return get_strictness_policy().level


current_policy = get_strictness_policy


def capture_policy(policy=None, name=None):
    """
    Policy to attach to a newly constructed object.

    An explicitly supplied policy wins.  Otherwise, if a scope is active we
    snapshot its policy so the object keeps its task's behaviour when passed
    to another stage or after the scope exits.  Outside a scope we return
    ``None``: the object then follows the legacy global setting dynamically,
    preserving historical behaviour.
    """
    if policy is not None:
        return _policy_from(policy, name=name)
    active = _active_policy()
    if active is not None:
        if name is not None:
            return active.with_name(name)
        return active
    return None


def has_task_policy(obj=None):
    """
    Whether diagnostics should be strict (raise) rather than only warn.

    An explicit policy or an active scope means the caller opted into
    task-local strictness and expects strict rejection.  Pure legacy use
    keeps the historical read behaviour of warning instead of aborting.
    """
    if _active_policy() is not None:
        return True
    return obj is not None and getattr(obj, "_strictness_policy", None) is not None


def bind_policy(obj, policy=None, name=None):
    """
    Attach a policy to an existing object and return it.

    Useful when an object was created outside a task scope and is then handed
    to a processing stage that owns an explicit policy.
    """
    obj._strictness_policy = capture_policy(policy, name=name)
    return obj


def effective_policy(obj=None, policy=None, name=None):
    """
    Resolve the policy attached to an object (or the current task's).

    ``policy`` is an explicit override; otherwise the object's attached
    policy wins; otherwise the current scope/global setting applies.
    """
    if policy is not None:
        return _policy_from(policy, name=name)
    bound = getattr(obj, "_strictness_policy", None) if obj is not None else None
    if bound is not None:
        return bound
    return get_strictness_policy()


def operation_policy(obj=None, policy=None, name=None):
    """
    Resolve the policy governing a write/repair operation performed *now*.

    Priority is: explicit argument, the innermost active task scope, the
    policy carried by the object, then the legacy global setting.  The scope
    comes before the object so that blocks read by one task are converted
    under the policy of the task performing the conversion.
    """
    if policy is not None:
        return _policy_from(policy, name=name)
    active = _active_policy()
    if active is not None:
        return active
    bound = getattr(obj, "_strictness_policy", None) if obj is not None else None
    if bound is not None:
        return bound
    return _global.policy


def set_strictness(level):
    """
    Set the legacy process-wide strictness level.

    This remains supported for existing scripts.  Concurrent tasks should use
    :py:func:`strictness_scope` or pass a :py:class:`StrictnessPolicy` to the
    scanner/writer instead, because a process-wide setting inherently cannot
    isolate requests from each other.  A global change does not alter an
    already-entered :py:func:`strictness_scope`.
    """
    if isinstance(level, StrictnessPolicy):
        _global.policy = level
    else:
        assert type(level) is Strictness
        _global.policy = StrictnessPolicy(level)


# Legacy code reads ``strictness.strict_level``.  Resolve it dynamically so
# that a scope's level is visible, while keeping ``set_strictness`` as the
# mutating entry point.
def __getattr__(name):
    if name == "strict_level":
        return get_strictness_policy().level
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))


def strictness_scope(policy):
    """Context manager/decorator selecting an explicit task policy."""
    return StrictnessScope(policy)


# Friendly aliases; all behave identically.
scoped_strictness = strictness_scope
use_strictness = strictness_scope
strictness_context = strictness_scope
policy_context = strictness_scope


# ---------------------------------------------------------------------------
# Legacy functional interface, now policy-aware
# ---------------------------------------------------------------------------


def _tag_warning(warning, policy):
    warning.policy = policy
    warning.policy_name = policy.name
    warning.task = policy.name
    warning.task_name = policy.name
    warning.strictness = policy.level
    warning.strictness_level = policy.level


def _tag_exception(exc, policy):
    exc.policy = policy
    exc.policy_name = policy.name
    exc.task = policy.name
    exc.task_name = policy.name
    exc.strictness = policy.level
    exc.strictness_level = policy.level


def problem(msg, policy=None, name=None):
    "Warn or raise an exception with the given message."
    operation_policy(policy=policy, name=name).problem(msg)


def warn(msg, policy=None, name=None):
    "Show a warning with the given message."
    operation_policy(policy=policy, name=name).warn(msg)


def should_fix(policy=None, name=None):
    "Helper function for showing code used to fix questionable pcapng data."
    return operation_policy(policy=policy, name=name).should_fix()


# ---------------------------------------------------------------------------
# Module attribute compatibility
# ---------------------------------------------------------------------------


class _StrictnessModule(sys.modules[__name__].__class__):
    """Support legacy ``strictness.strict_level = ...`` assignments."""

    def __setattr__(self, name, value):  # pragma: no cover - trivial shim
        if name == "strict_level":
            set_strictness(value)
            return
        super(_StrictnessModule, self).__setattr__(name, value)


sys.modules[__name__].__class__ = _StrictnessModule
